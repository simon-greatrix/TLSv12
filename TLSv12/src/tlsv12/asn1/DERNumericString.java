package tlsv12.asn1;

import tlsv12.util.Arrays;
import tlsv12.util.Strings;

import java.io.IOException;

/**
 * DER NumericString object - this is an ascii string of characters
 * {0,1,2,3,4,5,6,7,8,9, }.
 */
public class DERNumericString extends ASN1Primitive implements ASN1String {
    private byte[] string;


    /**
     * basic constructor - with bytes.
     */
    DERNumericString(byte[] string) {
        this.string = string;
    }


    public String getString() {
        return Strings.fromByteArray(string);
    }


    public String toString() {
        return getString();
    }


    boolean isConstructed() {
        return false;
    }


    int encodedLength() {
        return 1 + StreamUtil.calculateBodyLength(string.length)
                + string.length;
    }


    void encode(ASN1OutputStream out) throws IOException {
        out.writeEncoded(BERTags.NUMERIC_STRING, string);
    }


    public int hashCode() {
        return Arrays.hashCode(string);
    }


    boolean asn1Equals(ASN1Primitive o) {
        if( !(o instanceof DERNumericString) ) {
            return false;
        }

        DERNumericString s = (DERNumericString) o;

        return Arrays.areEqual(string, s.string);
    }

}
