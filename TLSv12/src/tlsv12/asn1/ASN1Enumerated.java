package tlsv12.asn1;

import tlsv12.util.Arrays;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Class representing the ASN.1 ENUMERATED type.
 */
public class ASN1Enumerated extends ASN1Primitive {
    byte[] bytes;


    /**
     * Constructor from encoded BigInteger.
     *
     * @param bytes
     *            the value of this enumerated as an encoded BigInteger
     *            (signed).
     */
    public ASN1Enumerated(byte[] bytes) {
        this.bytes = bytes;
    }


    boolean isConstructed() {
        return false;
    }


    int encodedLength() {
        return 1 + StreamUtil.calculateBodyLength(bytes.length) + bytes.length;
    }


    void encode(ASN1OutputStream out) throws IOException {
        out.writeEncoded(BERTags.ENUMERATED, bytes);
    }


    boolean asn1Equals(ASN1Primitive o) {
        if( !(o instanceof ASN1Enumerated) ) {
            return false;
        }

        ASN1Enumerated other = (ASN1Enumerated) o;

        return Arrays.areEqual(this.bytes, other.bytes);
    }


    public int hashCode() {
        return Arrays.hashCode(bytes);
    }

    private static ASN1Enumerated[] cache = new ASN1Enumerated[12];


    static ASN1Enumerated fromOctetString(byte[] enc) {
        if( enc.length > 1 ) {
            return new ASN1Enumerated(Arrays.clone(enc));
        }

        if( enc.length == 0 ) {
            throw new IllegalArgumentException("ENUMERATED has zero length");
        }
        int value = enc[0] & 0xff;

        if( value >= cache.length ) {
            return new ASN1Enumerated(Arrays.clone(enc));
        }

        ASN1Enumerated possibleMatch = cache[value];

        if( possibleMatch == null ) {
            possibleMatch = cache[value] = new ASN1Enumerated(Arrays.clone(enc));
        }

        return possibleMatch;
    }
}
