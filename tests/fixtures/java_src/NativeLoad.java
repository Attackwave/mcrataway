// Fixture: a mod loading the native library it ships, the way voicechat,
// Distant Horizons or any mod with its own audio/graphics native does.
// System.load with an absolute path stages nothing, so it must not be a
// HIGH finding on its own — otherwise every native-using mod pairs it
// with any other capability into a MALICIOUS verdict. Compare
// StagedNative, where the same call follows a temp-file extraction.
public class NativeLoad {
    public void load(String dir) {
        System.load(dir + "/libvoicechat.so");
    }
}
