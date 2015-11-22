package tlsv12.asn1;

import tlsv12.util.Arrays;
import tlsv12.util.Strings;

import java.io.IOException;

public class DERGeneralString extends ASN1Primitive implements ASN1String {
    private byte[] string;


    DERGeneralString(byte[] string) {
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
        out.writeEncoded(BERTags.GENERAL_STRING, string);
    }


    public int hashCode() {
        return Arrays.hashCode(string);
    }


    boolean asn1Equals(ASN1Primitive o) {
        if( !(o instanceof DERGeneralString) ) {
            return false;
        }
        DERGeneralString s = (DERGeneralString) o;

        return Arrays.areEqual(string, s.string);
    }
}
