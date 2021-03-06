package tlsv12.asn1;

import tlsv12.util.Arrays;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * DER UniversalString object.
 */
public class DERUniversalString extends ASN1Primitive implements ASN1String {
    private static final char[] table = { '0', '1', '2', '3', '4', '5', '6',
            '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

    private byte[] string;


    /**
     * basic constructor - byte encoded string.
     */
    public DERUniversalString(byte[] string) {
        this.string = string;
    }


    public String getString() {
        StringBuffer buf = new StringBuffer("#");
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream aOut = new ASN1OutputStream(bOut);

        try {
            aOut.writeObject(this);
        } catch (IOException e) {
            throw new RuntimeException("internal error encoding BitString");
        }

        byte[] string = bOut.toByteArray();

        for(int i = 0;i != string.length;i++) {
            buf.append(table[(string[i] >>> 4) & 0xf]);
            buf.append(table[string[i] & 0xf]);
        }

        return buf.toString();
    }


    public String toString() {
        return getString();
    }


    public byte[] getOctets() {
        return string;
    }


    boolean isConstructed() {
        return false;
    }


    int encodedLength() {
        return 1 + StreamUtil.calculateBodyLength(string.length)
                + string.length;
    }


    void encode(ASN1OutputStream out) throws IOException {
        out.writeEncoded(BERTags.UNIVERSAL_STRING, this.getOctets());
    }


    boolean asn1Equals(ASN1Primitive o) {
        if( !(o instanceof DERUniversalString) ) {
            return false;
        }

        return Arrays.areEqual(string, ((DERUniversalString) o).string);
    }


    public int hashCode() {
        return Arrays.hashCode(string);
    }
}
