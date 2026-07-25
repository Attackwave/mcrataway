// Fixture: entirely benign mod that only trips the OLD, overly broad
// heuristics — an LWJGL native library reference and a "Startup"
// screen label. Regression fixture for the false-positive bug where
// D05/D07 flagged this as MALICIOUS purely from these substrings. A
// correctly tuned scanner must return CLEAN for this class.
public class BenignLwjglMod {
    public static final String STARTUP_SCREEN_LABEL = "gui.startup.loading";
    public static final String NATIVE_LIB_HINT = "natives/lwjgl64.dll";

    public String getStartupMessage() {
        return STARTUP_SCREEN_LABEL;
    }

    public void render() {
        // no-op: stands in for a rendering call
    }
}
