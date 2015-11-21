package tlsv12.util;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * BigInteger utilities.
 */
public final class BigIntegers {
    /**
     * Return the passed in value as an unsigned byte array.
     *
     * @param value
     *            value to be converted.
     * @return a byte array without a leading zero byte if present in the signed
     *         encoding.
     */
    public static byte[] asUnsignedByteArray(int length, BigInteger value) {
        byte[] bytes = value.toByteArray();
        if( bytes.length == length ) {
            return bytes;
        }

        int start = bytes[0] == 0 ? 1 : 0;
        int count = bytes.length - start;

        if( count > length ) {
            throw new IllegalArgumentException(
                    "standard length exceeded for value");
        }

        byte[] tmp = new byte[length];
        System.arraycopy(bytes, start, tmp, tmp.length - count, count);
        return tmp;
    }
}
