import java.beans.XMLDecoder;
import java.io.InputStream;
import java.lang.invoke.MethodHandles;

/**
 * Synthetic fixture for the two invoke-based entry points that the
 * hand-assembled fixtures cannot reach (they only ever emit ldc_w +
 * return): XMLDecoder's object graph deserialization (D06) and
 * defining a class straight from a byte array through a Lookup (D03).
 */
public class UnsafeLookup {
    public static Object decode(InputStream in) {
        return new XMLDecoder(in).readObject();
    }

    public static Class<?> define(byte[] bytecode) throws IllegalAccessException {
        return MethodHandles.lookup().defineClass(bytecode);
    }
}
