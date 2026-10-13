import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;

public class DumpDalvik extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("FORMAT=" + currentProgram.getExecutableFormat());
        println("LANGUAGE=" + currentProgram.getLanguageID());
        println("IMAGEBASE=0x" + Long.toHexString(currentProgram.getImageBase().getOffset()));
        println("PTRSIZE=" + currentProgram.getDefaultPointerSize());
        println("=== FUNCTIONS ===");
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            println("FUNC " + f.getEntryPoint() + " name=[" + f.getName()
                + "] sig=[" + f.getSignature(true) + "] ext=" + f.isExternal()
                + " size=" + f.getBody().getNumAddresses());
        }
        println("=== SYMBOLS with Random/Trust/Key/Spec/AES ===");
        SymbolIterator si = currentProgram.getSymbolTable().getAllSymbols(true);
        while (si.hasNext()) {
            Symbol s = si.next();
            String n = s.getName();
            if (n.contains("Random") || n.contains("Trust") || n.contains("Spec")
                || n.contains("AES") || n.contains("array")) {
                println("SYM " + s.getAddress() + " [" + n + "] type=" + s.getSymbolType());
            }
        }
        println("=== INSTRUCTIONS (non-stub functions) ===");
        it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            if (f.isExternal()) continue;
            println("--- FUNC " + f.getName() + " @" + f.getEntryPoint());
            InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
            while (ii.hasNext()) {
                Instruction in = ii.next();
                StringBuilder sb = new StringBuilder();
                sb.append("INS ").append(in.getAddress()).append(" ")
                  .append(in.getMnemonicString());
                for (int i = 0; i < in.getNumOperands(); i++) {
                    sb.append(" |op").append(i).append("=[").append(in.getDefaultOperandRepresentation(i))
                      .append("]");
                    for (Object o : in.getOpObjects(i)) {
                        sb.append(" <").append(o.getClass().getSimpleName()).append(":").append(o).append(">");
                    }
                }
                for (Reference r : in.getReferencesFrom()) {
                    sb.append(" REF->").append(r.getToAddress()).append("/").append(r.getReferenceType());
                }
                println(sb.toString());
                PcodeOp[] pc = in.getPcode();
                if (pc != null) {
                    for (PcodeOp p : pc) {
                        if (p == null) continue;
                        println("    P " + p.getMnemonic() + " " + p.getSeqnum().getOrder() + " " + p);
                    }
                }
            }
        }
        println("=== MEMORY BLOCKS ===");
        for (ghidra.program.model.mem.MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            println("BLK " + b.getName() + " " + b.getStart() + "-" + b.getEnd()
                + " exec=" + b.isExecute() + " init=" + b.isInitialized());
        }
    }
}
