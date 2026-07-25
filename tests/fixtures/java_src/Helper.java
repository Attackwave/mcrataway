// Compilation dependency for WeedhackCipher.java's Helper.load(...)
// call — not itself a test fixture of interest (it produces its own
// javac_fixtures/Helper.jar as a side effect of the build, which is
// simply unused by the test suite).
public class Helper {
    public static String load(int[] d1, int[] d2, int k1, int k2) {
        return "";
    }
}
