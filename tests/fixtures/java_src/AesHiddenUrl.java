// Fixture for string_reconstructor's AES-with-embedded-key support:
// a URL hidden as an AES-encrypted constant-pool byte array, decrypted
// at runtime via javax.crypto.Cipher with a key embedded as a byte
// array literal in the same method. This is the defining
// characteristic of this malware class — the key is right there in the
// same class, because the mod needs to decrypt the string at runtime
// without any external dependency.
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AesHiddenUrl {
    public String getUrl() throws Exception {
        byte[] keyBytes = new byte[]{
            0x4e, 0x65, 0x76, 0x65, 0x72, 0x47, 0x6f, 0x6e,
            0x6e, 0x61, 0x47, 0x69, 0x76, 0x65, 0x59, 0x6f
        };
        byte[] encrypted = new byte[]{
            0x46, (byte)0xb9, (byte)0xf2, (byte)0xde, 0x3b, (byte)0x8b,
            0x15, 0x39, (byte)0xfe, (byte)0xd0, (byte)0xa0, (byte)0xe3,
            (byte)0xdc, (byte)0xb3, 0x60, 0x13, (byte)0x89, 0x0c,
            (byte)0xe6, 0x6f, 0x7c, 0x6d, (byte)0xc5, 0x2c, 0x60,
            (byte)0x88, 0x48, 0x09, (byte)0xbd, (byte)0xcc, 0x63,
            (byte)0xcf
        };
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(keyBytes, "AES"));
        byte[] decrypted = cipher.doFinal(encrypted);
        return new String(decrypted);
    }
}
