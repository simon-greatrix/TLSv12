package tlsv12.util;

public final class Strings {
    public static String fromUTF8ByteArray(byte[] bytes) {
        int i = 0;
        int length = 0;

        while( i < bytes.length ) {
            length++;
            if( (bytes[i] & 0xf0) == 0xf0 ) {
                // surrogate pair
                length++;
                i += 4;
            } else if( (bytes[i] & 0xe0) == 0xe0 ) {
                i += 3;
            } else if( (bytes[i] & 0xc0) == 0xc0 ) {
                i += 2;
            } else {
                i += 1;
            }
        }

        char[] cs = new char[length];

        i = 0;
        length = 0;

        while( i < bytes.length ) {
            char ch;

            if( (bytes[i] & 0xf0) == 0xf0 ) {
                int codePoint = ((bytes[i] & 0x03) << 18)
                        | ((bytes[i + 1] & 0x3F) << 12)
                        | ((bytes[i + 2] & 0x3F) << 6) | (bytes[i + 3] & 0x3F);
                int U = codePoint - 0x10000;
                char W1 = (char) (0xD800 | (U >> 10));
                char W2 = (char) (0xDC00 | (U & 0x3FF));
                cs[length++] = W1;
                ch = W2;
                i += 4;
            } else if( (bytes[i] & 0xe0) == 0xe0 ) {
                ch = (char) (((bytes[i] & 0x0f) << 12)
                        | ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f));
                i += 3;
            } else if( (bytes[i] & 0xd0) == 0xd0 ) {
                ch = (char) (((bytes[i] & 0x1f) << 6) | (bytes[i + 1] & 0x3f));
                i += 2;
            } else if( (bytes[i] & 0xc0) == 0xc0 ) {
                ch = (char) (((bytes[i] & 0x1f) << 6) | (bytes[i + 1] & 0x3f));
                i += 2;
            } else {
                ch = (char) (bytes[i] & 0xff);
                i += 1;
            }

            cs[length++] = ch;
        }

        return new String(cs);
    }


    /**
     * A locale independent version of toUpperCase.
     * 
     * @param string
     *            input to be converted
     * @return a US Ascii uppercase version
     */
    public static String toUpperCase(String string) {
        boolean changed = false;
        char[] chars = string.toCharArray();

        for(int i = 0;i != chars.length;i++) {
            char ch = chars[i];
            if( 'a' <= ch && 'z' >= ch ) {
                changed = true;
                chars[i] = (char) (ch - 'a' + 'A');
            }
        }

        if( changed ) {
            return new String(chars);
        }

        return string;
    }


    /**
     * A locale independent version of toLowerCase.
     * 
     * @param string
     *            input to be converted
     * @return a US ASCII lowercase version
     */
    public static String toLowerCase(String string) {
        boolean changed = false;
        char[] chars = string.toCharArray();

        for(int i = 0;i != chars.length;i++) {
            char ch = chars[i];
            if( 'A' <= ch && 'Z' >= ch ) {
                changed = true;
                chars[i] = (char) (ch - 'A' + 'a');
            }
        }

        if( changed ) {
            return new String(chars);
        }

        return string;
    }


    /**
     * Convert an array of 8 bit characters into a string.
     *
     * @param bytes
     *            8 bit characters.
     * @return resulting String.
     */
    public static String fromByteArray(byte[] bytes) {
        return new String(asCharArray(bytes));
    }


    /**
     * Do a simple conversion of an array of 8 bit characters into a string.
     *
     * @param bytes
     *            8 bit characters.
     * @return resulting String.
     */
    public static char[] asCharArray(byte[] bytes) {
        char[] chars = new char[bytes.length];

        for(int i = 0;i != chars.length;i++) {
            chars[i] = (char) (bytes[i] & 0xff);
        }

        return chars;
    }
}
