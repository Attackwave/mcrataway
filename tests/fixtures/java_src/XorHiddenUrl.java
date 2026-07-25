// Fixture for the generic repeating-key XOR cipher detector: a URL is
// hidden as a XOR-encrypted byte array, with the plaintext key itself
// present as a plain string constant ("k3y!") elsewhere in the class
// — the pattern _extract_generic_xor_strings brute-forces against.
public class XorHiddenUrl {
    public String getUrl() {
        String key = "k3y!";
        byte[] cipher = new byte[]{
            3, 71, 13, 81, 24, 9, 86, 14, 14, 69, 16, 77, 69, 86, 1, 64,
            6, 67, 21, 68, 69, 80, 22, 76, 68, 86, 1, 71, 2, 95
        };
        byte[] keyBytes = key.getBytes();
        byte[] out = new byte[cipher.length];
        for (int i = 0; i < cipher.length; i++) {
            out[i] = (byte) (cipher[i] ^ keyBytes[i % keyBytes.length]);
        }
        return new String(out);
    }
}
