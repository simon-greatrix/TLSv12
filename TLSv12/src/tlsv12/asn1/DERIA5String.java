package tlsv12.asn1;

import tlsv12.util.Arrays;
import tlsv12.util.Strings;

import java.io.IOException;

/**
 * DER IA5String object - this is an ascii string.
 */
public class DERIA5String extends ASN1Primitive implements ASN1String {
    private byte[] string;


    /**
     * basic constructor - with bytes.
     * 
     * @param string
     *            the byte encoding of the characters making up the string.
     */
    DERIA5String(byte[] string) {
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
        out.writeEncoded(BERTags.IA5_STRING, string);
    }


    public int hashCode() {
        return Arrays.hashCode(string);
    }


    boolean asn1Equals(ASN1Primitive o) {
        if( !(o instanceof DERIA5String) ) {
            return false;
        }

        DERIA5String s = (DERIA5String) o;

        return Arrays.areEqual(string, s.string);
    }

}
