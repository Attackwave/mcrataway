// Fixture: direct process execution + native library load + hidden
// exfiltration URL. Compiled with real javac so the resulting .class
// contains genuine invoke* bytecode instructions (ProcessBuilder.<init>,
// ProcessBuilder.start, Runtime.getRuntime, Runtime.exec,
// System.loadLibrary) — unlike the older synthetic fixtures in
// generator.py, which only emitted ldc + return and never exercised
// the invoke-resolution path detectors D01/D03/D06/D07/D10 rely on.
public class DirectExec {
    public void spawnViaProcessBuilder() throws Exception {
        ProcessBuilder pb = new ProcessBuilder("cmd.exe", "/c", "whoami");
        pb.start();
    }

    public void spawnViaRuntime() throws Exception {
        Runtime.getRuntime().exec("calc.exe");
    }

    public void loadNative() {
        System.loadLibrary("payload");
    }

    public String hiddenUrl() {
        // new byte[]{...} -> new String(...) pattern (fractureiser
        // Stage-0 style string hiding) — real javac bytecode for this
        // produces newarray + repeated (bipush,bipush,bastore) triples
        // that the string_reconstructor module is meant to decode.
        byte[] bs = new byte[]{
            104, 116, 116, 112, 115, 58, 47, 47, 101, 118, 105, 108,
            46, 99, 111, 109, 47, 99, 111, 108, 108, 101, 99, 116
        };
        return new String(bs);
    }
}
