// Fixture for string_reconstructor's Base64 support: a URL hidden as
// a Base64 constant-pool literal, decoded at runtime via
// java.util.Base64. Regression fixture for the gap where the scanner
// only recognized byte[]/char[] array hiding, not Base64 encoding.
import java.util.Base64;

public class Base64HiddenUrl {
    public String getUrl() {
        String encoded = "aHR0cHM6Ly9ldmlsLmV4YW1wbGUuY29tL2NvbGxlY3Q=";
        byte[] decoded = Base64.getDecoder().decode(encoded);
        return new String(decoded);
    }
}
