// False-positive regression fixture for the generic XOR detector: an
// ordinary byte array with no relation to any XOR cipher (just magic
// number bytes) must not trip _extract_generic_xor_strings.
public class BenignByteArray {
    public byte[] getMagicBytes() {
        return new byte[]{(byte)0xCA, (byte)0xFE, (byte)0xBA, (byte)0xBE, 0, 1, 2, 3};
    }
}
