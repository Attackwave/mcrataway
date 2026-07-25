// Fixture: process execution reached only via reflection, with the
// target class name hidden in a byte array. Regression fixture for
// the bug where the scanner correctly reconstructed the hidden
// strings ("java.lang.Runtime", "getRuntime", "exec", "calc.exe") but
// rated them INFO, which VerdictAggregator does not count at all —
// so the file came back CLEAN despite the reconstructor doing exactly
// the right thing. See detectors' analyze_reconstructed_strings and
// VerdictAggregator._static_override.
public class ReflectiveExec {
    public void run() throws Exception {
        byte[] classNameBytes = new byte[]{
            106, 97, 118, 97, 46, 108, 97, 110, 103, 46, 82, 117, 110,
            116, 105, 109, 101
        };
        Class<?> runtimeClass = Class.forName(new String(classNameBytes));
        Object runtimeInstance = runtimeClass.getMethod("getRuntime").invoke(null);
        runtimeClass.getMethod("exec", String.class).invoke(runtimeInstance, "calc.exe");
    }
}
