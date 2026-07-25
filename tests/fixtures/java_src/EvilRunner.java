// Compilation dependency + fixture for MethodRefAttack.java: the
// actual Runtime.exec() call lives here, reached only via a method
// reference (EvilRunner::detonate) from MethodRefAttack, not through
// any invoke in MethodRefAttack's own bytecode.
public class EvilRunner {
    public static void detonate() {
        try {
            Runtime.getRuntime().exec("calc.exe");
        } catch (Exception e) {
            // ignored
        }
    }
}
