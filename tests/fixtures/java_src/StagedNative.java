// Fixture: the DLL-staging pattern D07 exists for — extract a bundled
// native into a temp file, mark it for deletion on exit, then load it by
// absolute path. Here the class demonstrably stages what it loads, so
// System.load stays a HIGH finding. Compare NativeLoad, where the same
// call loads a library the mod ships without staging anything.
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;

public class StagedNative {
    public void extractAndLoad() throws Exception {
        File tmp = File.createTempFile("native", ".so");
        tmp.deleteOnExit();
        try (InputStream in = StagedNative.class.getResourceAsStream("/native.so");
             FileOutputStream out = new FileOutputStream(tmp)) {
            out.write(in.readAllBytes());
        }
        System.load(tmp.getAbsolutePath());
    }
}
