import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class DumpDalvik2 extends GhidraScript {
    @Override
    public void run() throws Exception {
        long[] targets = {0xe0000068L, 0xe0000070L, 0xe0000074L, 0xe0000044L, 0xe0000048L};
        for (long t : targets) {
            Address a = toAddr(t);
            println("TGT " + a);
            Symbol[] syms = currentProgram.getSymbolTable().getSymbols(a);
            for (Symbol s : syms) {
                println("  TGT-SYM [" + s.getName() + "] parent=[" + s.getParentNamespace().getName(true)
                    + "] type=" + s.getSymbolType());
            }
            Function fn = currentProgram.getFunctionManager().getFunctionAt(a);
            println("  TGT-FUNC " + (fn == null ? "null" : fn.getName()
                + " ext=" + fn.isExternal()
                + " parent=[" + (fn.getParentNamespace() == null ? "?" : fn.getParentNamespace().getName(true)) + "]"
                + (fn.isThunk() ? " THUNK-> " + fn.getThunkedFunction(true).getName()
                   + " in [" + fn.getThunkedFunction(true).getParentNamespace().getName(true) + "]" : "")));
            for (Symbol s : syms) {
                ExternalLocation el = currentProgram.getExternalManager().getExternalLocation(s);
                println("  TGT-EXTLOC " + (el == null ? "null" : el.getLabel() + " lib=" + el.getLibraryName()
                    + " addr=" + el.getAddress()));
            }
        }
        println("=== FUNCTION NAMESPACES ===");
        FunctionIterator it = currentProgram.getFunctionManager().getFunctions(true);
        while (it.hasNext()) {
            Function f = it.next();
            println("NS " + f.getEntryPoint() + " [" + f.getName() + "] path=["
                + f.getParentNamespace().getName(true) + "]");
        }
        println("=== TRIVIAL BODIES ===");
        for (String n : new String[]{"checkServerTrusted", "checkClientTrusted"}) {
            FunctionIterator i2 = currentProgram.getFunctionManager().getFunctions(true);
            while (i2.hasNext()) {
                Function f = i2.next();
                if (!f.getName().equals(n) || f.isExternal()) continue;
                int cnt = 0;
                StringBuilder sb = new StringBuilder();
                InstructionIterator ii = currentProgram.getListing().getInstructions(f.getBody(), true);
                while (ii.hasNext()) {
                    Instruction in = ii.next();
                    cnt++;
                    sb.append(in.getMnemonicString()).append(" ");
                }
                println("TRIVIAL " + n + " insns=" + cnt + " [" + sb + "]");
            }
        }
    }
}
