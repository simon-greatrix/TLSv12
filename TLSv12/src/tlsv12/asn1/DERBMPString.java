package tlsv12.asn1;

import tlsv12.util.Arrays;

import java.io.IOException;

/**
 * DER BMPString object.
 */
public class DERBMPString extends ASN1Primitive implements ASN1String {
    private char[] string;


    DERBMPString(char[] string) {
        this.string = string;
    }


    public String getString() {
        return new String(string);
    }


    public String toString() {
        return getString();
    }


    public int hashCode() {
        return Arrays.hashCode(string);
    }


    protected boolean asn1Equals(ASN1Primitive o) {
        if( !(o instanceof DERBMPString) ) {
            return false;
        }

        DERBMPString s = (DERBMPString) o;

        return Arrays.areEqual(string, s.string);
    }


    boolean isConstructed() {
        return false;
    }


    int encodedLength() {
        return 1 + StreamUtil.calculateBodyLength(string.length * 2)
                + (string.length * 2);
    }


    void encode(ASN1OutputStream out) throws IOException {
        out.write(BERTags.BMP_STRING);
        out.writeLength(string.length * 2);

        for(int i = 0;i != string.length;i++) {
            char c = string[i];

            out.write((byte) (c >> 8));
            out.write((byte) c);
        }
    }
}
