package tlsv12.asn1;

import tlsv12.util.Arrays;
import tlsv12.util.Strings;

import java.io.IOException;

/**
 * DER PrintableString object.
 */
public class DERPrintableString
    extends ASN1Primitive
    implements ASN1String
{
    private byte[]  string;

    

    

    /**
     * basic constructor - byte encoded string.
     */
    DERPrintableString(
        byte[]   string)
    {
        this.string = string;
    }

    

    

    public String getString()
    {
        return Strings.fromByteArray(string);
    }

    

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(string.length) + string.length;
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.writeEncoded(BERTags.PRINTABLE_STRING, string);
    }

    public int hashCode()
    {
        return Arrays.hashCode(string);
    }

    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof DERPrintableString))
        {
            return false;
        }

        DERPrintableString  s = (DERPrintableString)o;

        return Arrays.areEqual(string, s.string);
    }

    public String toString()
    {
        return getString();
    }

    
}
