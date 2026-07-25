// Fixture for string_reconstructor's char[] support: a URL hidden as
// individual char array elements, mirroring the well-known byte[]
// hiding pattern but using char instead of byte.
public class CharArrayHiddenUrl {
    public String getUrl() {
        char[] cs = new char[]{
            'h', 't', 't', 'p', 's', ':', '/', '/', 'e', 'v', 'i', 'l', '.', 'c', 'o', 'm'
        };
        return new String(cs);
    }
}
