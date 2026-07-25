// Fixture for string_reconstructor's weedhack/Majanito XOR-cipher
// support: exercises the Helper.load(int[], int[], int, int) call
// pattern that decode_xor_cipher decodes, but which nothing in the
// codebase ever extracted from bytecode before (decode_xor_cipher
// existed, correctly implemented, and was simply never called).
public class WeedhackCipher {
    public String getUrl() {
        int[] d1 = new int[]{10, 20, 30};
        int[] d2 = new int[]{40, 50};
        return Helper.load(d1, d2, 7, 3);
    }
}
