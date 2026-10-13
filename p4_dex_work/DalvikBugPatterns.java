/* =============================================================================
 * DalvikBugPatterns.java -- DEX/Android bug-pattern detector (KP14 P4)
 *
 * The pipeline's VULN rules are x86-C-centric (allocator/lock/user-copy name
 * lists) and produce ZERO findings on Dalvik programs, while the mobile
 * campaigns proved real bugs behind three reusable smali/Dalvik shapes.
 * This detector turns those proven shapes into pipeline rules:
 *
 *   DEX.RNG.WEAK       new java.util.Random() CONSTRUCTIONS -- matched as
 *                      invoke-direct to java::util::Random::<init>. SecureRandom
 *                      dispatches nextInt/nextLong through Random's method
 *                      table, so mere Ljava/util/Random;-> method refs would
 *                      false-positive on every SecureRandom user and are
 *                      deliberately NOT counted. Only construction sites are.
 *                      Severity HIGH when the owning PACKAGE looks security-
 *                      relevant (transport/crypto/sync/connection/session/
 *                      protocol), MEDIUM otherwise (UI/test/jitter).
 *
 *   DEX.TLS.TRUSTALL   methods named checkServerTrusted whose body is trivial
 *                      (only return-void and nop instructions -- no validation, no
 *                      throw). The X509TrustManager interface contract is
 *                      corroborated by the sibling trio (checkClientTrusted +
 *                      getAcceptedIssuers in the same class) when present;
 *                      confidence MEDIUM when only the method name matches.
 *
 *   DEX.KEY.HARDCODED  SecretKeySpec(byte[],...) constructions whose array
 *                      argument is constant-fed: backward register slice from
 *                      the invoke's first non-this register to its defining
 *                      instruction, one level through an internal producer
 *                      call when the array arrives via move-result-object.
 *                      Constant-fed means: fill-array-data on the array, or
 *                      aput of a directly const-defined value. Honest
 *                      approximation: anything weaker than that clean chain
 *                      is either not reported or reported at confidence LOW
 *                      with the reason "proximity heuristic" in the
 *                      description -- nobody should read it as a proof.
 *
 * Findings are appended to the DriverPostProcessPipeline findings stream
 * (<outdir>/<name>_decompiled.c.findings.jsonl) in the EXACT line shape the
 * existing detectors emit, plus two trailing additive keys ("class",
 * "evidence") after the core fields, mirroring how DriverPostProcessPipeline
 * appends vpu_proba/pcode_evidence. Append is idempotent: lines already
 * present with the same ruleId|rva are skipped, so a stage rerun over a
 * cache-hit driver-post cannot duplicate findings.
 *
 * Summary sidecar: <outdir>/dalvik_bug_patterns.json (always written -- a
 * skipped non-Dalvik program still reports status=skipped, cache-artifact
 * discipline F4).
 *
 * Non-Dalvik programs: clean skip (sidecar + one log line, exit 0) so the
 * stage can run unconditionally in UnifiedDriverPipeline.
 *
 * Usage:
 *   analyzeHeadless <proj> P -import classes.dex \
 *     -postScript DalvikBugPatterns.java <output_dir> [<findings.jsonl>]
 *
 * Limitations (documented, deliberate):
 *   - invoke-*-range forms are not decoded for the KEY rule; SecretKeySpec
 *     constructors never exceed the plain 5-register invoke form, and RNG
 *     constructors cannot either. TRUSTALL/RNG do not need register decode.
 *   - The KEY slice is intra-procedural plus ONE call level. Deeper constant
 *     propagation (2+ producer hops) is out of scope for v1.
 * ========================================================================== */
//@category Analysis

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.lang.Register;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class DalvikBugPatterns extends GhidraScript {

    private static final String VERSION = "1";

    private static final String RULE_RNG = "DEX.RNG.WEAK";
    private static final String RULE_TRUSTALL = "DEX.TLS.TRUSTALL";
    private static final String RULE_KEY = "DEX.KEY.HARDCODED";

    /** Package-segment words that make a weak-RNG construction HIGH. */
    private static final Set<String> SENSITIVE_PACKAGE_WORDS = new HashSet<>(Arrays.asList(
        "transport", "crypto", "sync", "connection", "session", "protocol"));

    /** Same-class siblings that corroborate the X509TrustManager pattern. */
    private static final Set<String> TRUSTMANAGER_SIBLINGS = new HashSet<>(Arrays.asList(
        "checkClientTrusted", "getAcceptedIssuers"));

    private long imageBase;

    /** One emitted finding (core fields mirror DriverPostProcessPipeline.Finding). */
    private static final class Finding {
        String ruleId;
        long rva;
        String function;     // <class path>::<method> so DEX names are unambiguous
        String severity;     // HIGH, MEDIUM, LOW
        String confidence;   // HIGH, MEDIUM, LOW
        String description;  // one-line WHY
        String className;    // owning class namespace path
        String evidence;     // structural evidence string

        Finding(String ruleId, long rva, String function, String severity,
                String confidence, String description, String className, String evidence) {
            this.ruleId = ruleId;
            this.rva = rva;
            this.function = function;
            this.severity = severity;
            this.confidence = confidence;
            this.description = description;
            this.className = className;
            this.evidence = evidence;
        }

        String key() {
            return ruleId + "|0x" + Long.toHexString(rva);
        }
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outDir = args.length > 0 ? args[0] : ".";
        String findingsPath = args.length > 1 ? args[1] : null;
        long start = System.currentTimeMillis();
        imageBase = currentProgram.getImageBase().getOffset();

        String format = safeFormat();
        if (!isDalvik()) {
            println("[DalvikPatterns] SKIP: not a Dalvik program (format=" + format
                + ", language=" + safeLanguage() + ")");
            writeSidecar(outDir, "skipped", new ArrayList<Finding>(),
                "not a Dalvik program (format=" + json(format) + ")");
            return;
        }

        // Default findings stream: same base name DriverPostProcessPipeline uses.
        if (findingsPath == null) {
            File dir = new File(outDir);
            findingsPath = new File(dir, dir.getName() + "_decompiled.c.findings.jsonl").getPath();
        }

        List<Finding> findings = new ArrayList<>();
        int functionsSeen = 0;

        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            if (monitor.isCancelled()) break;
            Function f = it.next();
            if (f.isExternal()) continue;
            functionsSeen++;
            List<Instruction> body = functionBody(f);
            if (body.isEmpty()) continue;
            String classPath = f.getParentNamespace() == null
                ? "" : f.getParentNamespace().getName(true);
            detectWeakRng(f, classPath, body, findings);
            detectTrustAll(f, classPath, body, findings);
            detectHardcodedKey(f, classPath, body, findings);
        }

        int appended = appendFindings(findingsPath, findings);
        writeSidecar(outDir, "ok", findings, null);
        println("[DalvikPatterns] functions=" + functionsSeen
            + " findings=" + findings.size() + " appended=" + appended
            + " -> " + findingsPath + " ("
            + (System.currentTimeMillis() - start) + " ms)");
    }

    // ------------------------------------------------------------------
    // Rule 1: DEX.RNG.WEAK -- new-instance+invoke-direct java::util::Random::<init>
    // ------------------------------------------------------------------

    private void detectWeakRng(Function f, String classPath, List<Instruction> body,
            List<Finding> out) {
        for (Instruction in : body) {
            String mn = in.getMnemonicString();
            if (!mn.startsWith("invoke_direct")) continue;   // covers invoke_direct_range too
            String callee = calleeName(in);
            if (!isJavaUtilRandomCtor(callee)) continue;
            // Construction site confirmed: this-reg receives a fresh Random.
            String pkg = packageOf(classPath);
            boolean sensitive = isSensitivePackage(pkg);
            String severity = sensitive ? "HIGH" : "MEDIUM";
            String why = sensitive
                ? "package token '" + matchedToken(pkg) + "'"
                : "no security-relevant package token in '" + (pkg.isEmpty() ? "(default)" : pkg) + "'";
            String desc = "new java.util.Random() constructed here (weak, seedable RNG); "
                + why + " -- security values must use SecureRandom";
            out.add(new Finding(RULE_RNG, rvaOf(in), qualifiedName(f, classPath),
                severity, "HIGH", desc, classPath,
                "invoke-direct -> " + callee));
        }
    }

    private static boolean isJavaUtilRandomCtor(String callee) {
        // callee looks like "java::util::Random::<init>" (Ghidra DEX external
        // symbols); accept the raw descriptor form as well in case a future
        // loader changes the namespace rendering.
        return "java::util::Random::<init>".equals(callee)
            || "Ljava/util/Random;-><init>".equals(callee);
    }

    // ------------------------------------------------------------------
    // Rule 2: DEX.TLS.TRUSTALL -- trivial checkServerTrusted override
    // ------------------------------------------------------------------

    private void detectTrustAll(Function f, String classPath, List<Instruction> body,
            List<Finding> out) {
        if (!"checkServerTrusted".equals(f.getName())) return;
        if (!isTrivialBody(body)) return;

        int siblings = countSiblings(classPath, TRUSTMANAGER_SIBLINGS);
        String confidence = siblings == TRUSTMANAGER_SIBLINGS.size() ? "HIGH" : "MEDIUM";
        String desc = "checkServerTrusted body is trivial ("
            + bodySummary(body) + ") -- returns without validating the chain, "
            + "accepting any server certificate"
            + (siblings > 0
                ? "; X509TrustManager pattern corroborated (" + siblings
                    + "/2 sibling methods in class)"
                : "; only the method name matches (approximation)");
        out.add(new Finding(RULE_TRUSTALL, rvaOf(f.getEntryPoint()),
            qualifiedName(f, classPath), "HIGH", confidence, desc, classPath,
            "body=" + bodySummary(body)));
    }

    /** Trivial = every instruction is a return or nop (no invoke, throw, branch, arithmetic). */
    private static boolean isTrivialBody(List<Instruction> body) {
        if (body.isEmpty()) return false;
        for (Instruction in : body) {
            String mn = in.getMnemonicString();
            if (mn.startsWith("return") || mn.equals("nop")) continue;
            return false;
        }
        return true;
    }

    private String bodySummary(List<Instruction> body) {
        StringBuilder sb = new StringBuilder();
        for (Instruction in : body) {
            if (sb.length() > 0) sb.append(' ');
            sb.append(in.getMnemonicString());
        }
        return sb.toString();
    }

    private int countSiblings(String classPath, Set<String> wanted) {
        Set<String> found = new HashSet<>();
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext() && found.size() < wanted.size()) {
            Function f = it.next();
            if (f.isExternal()) continue;
            String ns = f.getParentNamespace() == null ? "" : f.getParentNamespace().getName(true);
            if (ns.equals(classPath) && wanted.contains(f.getName())) found.add(f.getName());
        }
        return found.size();
    }

    // ------------------------------------------------------------------
    // Rule 3: DEX.KEY.HARDCODED -- SecretKeySpec(byte[],...) with constant-fed array
    // ------------------------------------------------------------------

    private void detectHardcodedKey(Function f, String classPath, List<Instruction> body,
            List<Finding> out) {
        for (int i = 0; i < body.size(); i++) {
            Instruction in = body.get(i);
            String mn = in.getMnemonicString();
            if (!mn.startsWith("invoke_direct")) continue;
            String callee = calleeName(in);
            if (!isSecretKeySpecCtor(callee)) continue;

            List<Register> regs = argumentRegisters(in);
            if (regs.size() < 2) continue;      // need this + at least one arg
            Register thisReg = regs.get(0);
            Register arrayReg = regs.get(1);    // first ctor arg: every SecretKeySpec ctor starts with byte[]

            ConstFeed feed = traceArrayFeed(body, i, arrayReg, 0);
            if (feed == null) continue;
            String desc = "SecretKeySpec byte[] argument is constant-fed ("
                + feed.reason + ") -- proximity heuristic, not a proof";
            out.add(new Finding(RULE_KEY, rvaOf(in), qualifiedName(f, classPath),
                "HIGH", feed.confidence, desc, classPath,
                "invoke-direct -> " + callee + "; this=" + thisReg.getName()
                    + " array=" + arrayReg.getName() + "; " + feed.reason));
        }
    }

    private static boolean isSecretKeySpecCtor(String callee) {
        return callee != null
            && (callee.startsWith("javax::crypto::spec::SecretKeySpec::<init>")
                || callee.startsWith("Ljavax/crypto/spec/SecretKeySpec;-><init>"));
    }

    private static final class ConstFeed {
        String confidence;  // MEDIUM (clean constant chain) or LOW (proximity only)
        String reason;
        ConstFeed(String confidence, String reason) {
            this.confidence = confidence;
            this.reason = reason;
        }
    }

    /**
     * Backward slice: what defines {@code arrayReg} before index {@code invokeIdx}?
     * Tier A (MEDIUM): fill-array-data on the array, a direct const-defined
     * aput into it, or move-result-object from an INTERNAL producer call
     * whose own body is constant-fed.
     * Tier B (LOW): producer body merely shows constant array material
     * (numeric const + new-array + aput without the clean chain) --
     * proximity heuristic, explicitly labeled.
     * null: nothing constant-looking (params, derived data, external producer).
     */
    private ConstFeed traceArrayFeed(List<Instruction> body, int invokeIdx,
            Register arrayReg, int depth) {
        for (int i = invokeIdx - 1; i >= 0; i--) {
            Instruction in = body.get(i);
            String mn = in.getMnemonicString();
            List<Register> ops = registerOperands(in);

            // new-array rX: the array is born here; keep scanning for its fills.
            if (mn.equals("new_array") && !ops.isEmpty() && ops.get(0).equals(arrayReg)) {
                ConstFeed same = scanSameMethodFills(body, i, arrayReg);
                if (same != null) return same;
                return null; // array created here, no constant fill found before use
            }

            // move-result-object rX: array comes from the producer call at i-1.
            if (mn.startsWith("move_result_object") && !ops.isEmpty() && ops.get(0).equals(arrayReg)) {
                if (i == 0 || depth >= 1) return null; // no producer visible / no deeper recursion
                Instruction producer = body.get(i - 1);
                if (!producer.getMnemonicString().startsWith("invoke")) return null;
                Function producerFn = calledFunction(producer);
                if (producerFn == null) {
                    return null; // external producer (e.g. String.getBytes): no constant proof
                }
                ConstFeed producerFeed = producerFeed(producerFn, producer, depth);
                if (producerFeed != null) return producerFeed;
                return null;
            }

            // move/move_object rX, rY: follow one rename hop.
            if ((mn.equals("move") || mn.startsWith("move_object") || mn.startsWith("move_16")
                    || mn.startsWith("move_object_16") || mn.startsWith("move_object_from16"))
                    && ops.size() >= 2 && ops.get(0).equals(arrayReg)) {
                ConstFeed via = traceArrayFeed(body, i, ops.get(1), depth);
                if (via != null) return via;
                return null;
            }

            // fill-array-data rX: direct constant bulk fill of the array.
            if (mn.equals("fill_array_data") && !ops.isEmpty() && ops.get(0).equals(arrayReg)) {
                return new ConstFeed("MEDIUM", "fill-array-data payload "
                    + payloadSize(in) + " into " + arrayReg.getName());
            }
        }
        return null; // never defined here (parameter) -- derived data, not constant-fed
    }

    /** Scan forward from a new-array for fill-array-data or const-defined aput on the array. */
    private ConstFeed scanSameMethodFills(List<Instruction> body, int newArrayIdx,
            Register arrayReg) {
        int constAputs = 0;
        int constParticipatingAputs = 0;
        for (int i = newArrayIdx + 1; i < body.size(); i++) {
            Instruction in = body.get(i);
            String mn = in.getMnemonicString();
            List<Register> ops = registerOperands(in);
            if (mn.equals("fill_array_data") && !ops.isEmpty() && ops.get(0).equals(arrayReg)) {
                return new ConstFeed("MEDIUM", "fill-array-data payload "
                    + payloadSize(in) + " into " + arrayReg.getName());
            }
            if (mn.startsWith("aput") && ops.size() >= 2 && ops.get(1).equals(arrayReg)) {
                Register valueReg = ops.get(0);
                if (isDirectConstDefined(body, i, valueReg)) {
                    constAputs++;
                } else if (constParticipatesInDef(body, i, valueReg)) {
                    constParticipatingAputs++;
                }
            }
        }
        if (constAputs > 0) {
            return new ConstFeed("MEDIUM", constAputs + " const-defined aput"
                + (constAputs == 1 ? "" : "s") + " into " + arrayReg.getName());
        }
        if (constParticipatingAputs > 0) {
            // Values stored into the key array mix constants with other data:
            // weaker than a clean chain -- proximity heuristic, LOW confidence.
            return new ConstFeed("LOW", constParticipatingAputs + " aput"
                + (constParticipatingAputs == 1 ? "" : "s")
                + " whose value chains through a constant load (proximity heuristic)");
        }
        return null;
    }

    /** Analyze an internal producer call's body for constant array material. */
    private ConstFeed producerFeed(Function producerFn, Instruction producerCall, int depth) {
        List<Instruction> body = functionBody(producerFn);
        boolean hasFill = false;
        boolean hasNewArray = false;
        boolean hasAput = false;
        boolean hasConst = false;
        for (Instruction in : body) {
            String mn = in.getMnemonicString();
            if (mn.equals("fill_array_data")) hasFill = true;
            else if (mn.equals("new_array")) hasNewArray = true;
            else if (mn.startsWith("aput")) hasAput = true;
            else if (isNumericConst(mn)) hasConst = true;
        }
        String producer = qualifiedName(producerFn,
            producerFn.getParentNamespace() == null ? "" : producerFn.getParentNamespace().getName(true));
        if (hasFill) {
            return new ConstFeed("MEDIUM",
                "array returned by " + producer + " whose body fill-array-data payloads it");
        }
        if (hasNewArray && hasAput && hasConst) {
            return new ConstFeed("LOW",
                "array returned by " + producer + " whose body mixes new-array/aput with "
                    + "constant loads (proximity heuristic)");
        }
        return null;
    }

    /** Is the register defined directly (or via one move hop) by a numeric const instruction? */
    private boolean isDirectConstDefined(List<Instruction> body, int beforeIdx, Register reg) {
        for (int i = beforeIdx - 1; i >= 0; i--) {
            Instruction in = body.get(i);
            String mn = in.getMnemonicString();
            List<Register> ops = registerOperands(in);
            if (ops.isEmpty() || !ops.get(0).equals(reg)) continue;
            if (isNumericConst(mn)) return true;
            if ((mn.equals("move") || mn.startsWith("move_object")) && ops.size() >= 2) {
                return isDirectConstDefined(body, i, ops.get(1));
            }
            return false;
        }
        return false;
    }

    /** Does ANY numeric const load participate in the register's def chain (weaker)? */
    private boolean constParticipatesInDef(List<Instruction> body, int beforeIdx, Register reg) {
        for (int i = beforeIdx - 1; i >= 0; i--) {
            Instruction in = body.get(i);
            String mn = in.getMnemonicString();
            List<Register> ops = registerOperands(in);
            if (ops.isEmpty() || !ops.get(0).equals(reg)) continue;
            if (isNumericConst(mn)) return true;
            if (mn.startsWith("const")) return true;      // any const feeding the def
            if (mn.startsWith("move") && !mn.startsWith("move_result") && ops.size() >= 2) {
                return constParticipatesInDef(body, i, ops.get(1));
            }
            if (mn.contains("lit") || mn.contains("literal")) return true; // const-operand arithmetics (xor-int/lit8)
            if (ops.size() >= 2) {
                // binary op: constant participation via either source register
                return constParticipatesInDef(body, i, ops.get(1))
                    || (ops.size() >= 3 && constParticipatesInDef(body, i, ops.get(2)));
            }
            return false;
        }
        return false;
    }

    // ------------------------------------------------------------------
    // Shared Dalvik plumbing
    // ------------------------------------------------------------------

    private boolean isDalvik() {
        String lang = safeLanguage();
        String fmt = safeFormat();
        return lang.toLowerCase().contains("dalvik")
            || fmt.toUpperCase().contains("DEX");
    }

    private String safeFormat() {
        try {
            String f = currentProgram.getExecutableFormat();
            return f == null ? "unknown" : f;
        } catch (Exception ex) {
            return "unknown";
        }
    }

    private String safeLanguage() {
        try {
            Object id = currentProgram.getLanguageID();
            return id == null ? "unknown" : id.toString();
        } catch (Exception ex) {
            return "unknown";
        }
    }

    private List<Instruction> functionBody(Function f) {
        List<Instruction> out = new ArrayList<>();
        try {
            InstructionIterator it = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (it.hasNext()) {
                if (monitor.isCancelled()) break;
                out.add(it.next());
            }
        } catch (Exception ignored) {
        }
        return out;
    }

    /** All Register operands in instruction order (invoke: [this, arg1, arg2, ...]). */
    private static List<Register> registerOperands(Instruction in) {
        List<Register> out = new ArrayList<>();
        for (int i = 0; i < in.getNumOperands(); i++) {
            for (Object o : in.getOpObjects(i)) {
                if (o instanceof Register) out.add((Register) o);
            }
        }
        return out;
    }

    /** Registers of an invoke's argument list -- excludes the cpool-index Scalar operand. */
    private static List<Register> argumentRegisters(Instruction in) {
        return registerOperands(in);
    }

    /** "java::util::Random::<init>" for a call ref, or null when unresolvable. */
    private String calleeName(Instruction in) {
        for (Reference ref : in.getReferencesFrom()) {
            if (!ref.getReferenceType().isCall()) continue;
            Symbol[] syms = currentProgram.getSymbolTable().getSymbols(ref.getToAddress());
            if (syms == null || syms.length == 0) continue;
            Symbol s = syms[0];
            String ns = s.getParentNamespace() == null ? "" : s.getParentNamespace().getName(true);
            if (ns.isEmpty()) return s.getName();
            return ns + "::" + s.getName();
        }
        return null;
    }

    /** Internal (in-program) function called by this invoke, or null for external/unresolved. */
    private Function calledFunction(Instruction in) {
        for (Reference ref : in.getReferencesFrom()) {
            if (!ref.getReferenceType().isCall()) continue;
            Function fn = currentProgram.getFunctionManager().getFunctionAt(ref.getToAddress());
            if (fn != null && !fn.isExternal()) return fn;
        }
        return null;
    }

    private static boolean isNumericConst(String mn) {
        return mn.startsWith("const") && !mn.contains("string");
    }

    /** fill-array-data payload element count from the Ghidra payload label (?_1_16_addr). */
    private String payloadSize(Instruction fillInst) {
        try {
            for (Reference ref : fillInst.getReferencesFrom()) {
                if (ref.getToAddress() == null) continue;
                Symbol[] syms = currentProgram.getSymbolTable().getSymbols(ref.getToAddress());
                if (syms == null || syms.length == 0) continue;
                String n = syms[0].getName();
                if (!n.startsWith("filled_array_data_payload")) continue;
                String[] parts = n.split("_");
                // filled_array_data_payload_<elemsize>_<count>_<addr>
                if (parts.length >= 6) return parts[5] + " x " + parts[4] + "-byte constant payload";
            }
        } catch (Exception ignored) {
        }
        return "constant";
    }

    private long rvaOf(Address a) {
        return a.getOffset() - imageBase;
    }

    private long rvaOf(Instruction in) {
        return rvaOf(in.getAddress());
    }

    private static String qualifiedName(Function f, String classPath) {
        return classPath.isEmpty() ? f.getName() : classPath + "::" + f.getName();
    }

    /** Package portion of a Ghidra DEX namespace path (drop the class segment). */
    private static String packageOf(String classPath) {
        if (classPath == null || classPath.isEmpty()) return "";
        int idx = classPath.lastIndexOf("::");
        return idx < 0 ? "" : classPath.substring(0, idx);
    }

    /** Word-token match on package segments: word equals or starts with a token. */
    private static boolean isSensitivePackage(String pkg) {
        return matchedToken(pkg) != null;
    }

    private static String matchedToken(String pkg) {
        if (pkg == null || pkg.isEmpty()) return null;
        for (String segment : pkg.split("(::|/|\\.)")) {
            String lower = segment.toLowerCase();
            for (String word : lower.split("[^a-z0-9]+")) {
                if (word.isEmpty()) continue;
                for (String token : SENSITIVE_PACKAGE_WORDS) {
                    // startsWith keeps connection(s)/protocol(s)/synchroniz*
                    // while rejecting async/asynchronous (word-boundary safe).
                    if (word.equals(token) || word.startsWith(token)) return token;
                }
            }
        }
        return null;
    }

    // ------------------------------------------------------------------
    // Output
    // ------------------------------------------------------------------

    /**
     * Append findings to the pipeline findings stream, skipping ruleId|rva
     * keys already present (idempotent over a cache-hit driver-post stream).
     */
    private int appendFindings(String path, List<Finding> findings) {
        Set<String> existing = new HashSet<>();
        File file = new File(path);
        try {
            if (file.isFile()) {
                for (String line : Files.readAllLines(file.toPath(), StandardCharsets.UTF_8)) {
                    String rule = jsonField(line, "ruleId");
                    String rva = jsonField(line, "rva");
                    if (rule != null && rva != null) existing.add(rule + "|" + rva);
                }
            }
        } catch (Exception ex) {
            println("[DalvikPatterns] could not read existing findings stream ("
                + ex.getMessage() + "); appending without dedup");
        }
        int appended = 0;
        try (PrintWriter pw = new PrintWriter(new FileWriter(file, true))) {
            for (Finding f : findings) {
                if (existing.contains(f.key())) continue;
                pw.print("{\"ruleId\":\"" + f.ruleId + "\",\"rva\":\"0x" + Long.toHexString(f.rva)
                    + "\",\"function\":\"" + json(f.function)
                    + "\",\"severity\":\"" + f.severity
                    + "\",\"confidence\":\"" + f.confidence
                    + "\",\"description\":\"" + json(f.description) + "\"");
                // Additive trailing keys (same discipline as vpu_proba/pcode_evidence).
                pw.print(",\"class\":\"" + json(f.className) + "\"");
                pw.print(",\"evidence\":\"" + json(f.evidence) + "\"");
                pw.println("}");
                appended++;
            }
            if (pw.checkError()) throw new java.io.IOException("write error on " + path);
        } catch (Exception ex) {
            println("[DalvikPatterns] ERROR appending findings: " + ex);
            return appended;
        }
        return appended;
    }

    /** Summary sidecar -- always written, including for skipped programs. */
    private void writeSidecar(String outDir, String status, List<Finding> findings, String skipReason) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"schema_version\": 1,\n");
        sb.append("  \"detector\": \"DalvikBugPatterns.java\",\n");
        sb.append("  \"detector_version\": \"").append(VERSION).append("\",\n");
        sb.append("  \"program_format\": \"").append(json(safeFormat())).append("\",\n");
        sb.append("  \"language\": \"").append(json(safeLanguage())).append("\",\n");
        sb.append("  \"status\": \"").append(status).append("\",\n");
        if (skipReason != null) {
            sb.append("  \"skip_reason\": \"").append(json(skipReason)).append("\",\n");
        }
        Map<String, Integer> byRule = new LinkedHashMap<>();
        for (Finding f : findings) byRule.merge(f.ruleId, 1, Integer::sum);
        sb.append("  \"rule_counts\": {");
        boolean first = true;
        for (Map.Entry<String, Integer> e : byRule.entrySet()) {
            if (!first) sb.append(",");
            first = false;
            sb.append("\n    \"").append(e.getKey()).append("\": ").append(e.getValue());
        }
        sb.append(first ? "},\n" : "\n  },\n");
        sb.append("  \"findings\": [");
        for (int i = 0; i < findings.size(); i++) {
            Finding f = findings.get(i);
            if (i > 0) sb.append(",");
            sb.append("\n    {\"ruleId\":\"").append(f.ruleId)
              .append("\",\"rva\":\"0x").append(Long.toHexString(f.rva))
              .append("\",\"function\":\"").append(json(f.function))
              .append("\",\"severity\":\"").append(f.severity)
              .append("\",\"confidence\":\"").append(f.confidence)
              .append("\",\"class\":\"").append(json(f.className))
              .append("\",\"evidence\":\"").append(json(f.evidence))
              .append("\"}");
        }
        sb.append(findings.isEmpty() ? "],\n" : "\n  ],\n");
        sb.append("  \"notes\": \"KEY rule is a proximity heuristic (LOW/MEDIUM confidence) -- ")
          .append("constant-fed array argument, not a proven hardcoded key; RNG rule counts ")
          .append("constructions only (invoke-direct Random.<init>) so SecureRandom users stay clean.\",\n");
        sb.append("  \"honesty\": \"findings mirror DriverPostProcessPipeline findings.jsonl line shape; ")
          .append("class/evidence are additive trailing keys\"\n");
        sb.append("}\n");
        String path = outDir + (outDir.endsWith("/") ? "" : "/") + "dalvik_bug_patterns.json";
        try {
            ReportWriter.writeAtomically(path, sb);
        } catch (Exception ex) {
            println("[DalvikPatterns] ERROR writing sidecar: " + ex);
        }
    }

    /** Minimal JSON string quoting (same rules as the other pipeline scripts). */
    private static String json(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Extract a top-level string field from a flat findings.jsonl line. */
    private static String jsonField(String line, String field) {
        int i = line.indexOf("\"" + field + "\"");
        if (i < 0) return null;
        int colon = line.indexOf(':', i + field.length() + 2);
        if (colon < 0) return null;
        int q1 = line.indexOf('"', colon + 1);
        if (q1 < 0) return null;
        int q2 = line.indexOf('"', q1 + 1);
        if (q2 < 0) return null;
        return line.substring(q1 + 1, q2);
    }
}
