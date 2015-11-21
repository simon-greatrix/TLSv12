package tlsv12.asn1;

import tlsv12.util.Arrays;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Base class for an application specific object
 */
public class DERApplicationSpecific 
    extends ASN1Primitive
{
    private final boolean   isConstructed;
    private final int       tag;
    private final byte[]    octets;

    DERApplicationSpecific(
        boolean isConstructed,
        int     tag,
        byte[]  octets)
    {
        this.isConstructed = isConstructed;
        this.tag = tag;
        this.octets = octets;
    }

    

    

    

    public DERApplicationSpecific(int tagNo, ASN1EncodableVector vec)
    {
        this.tag = tagNo;
        this.isConstructed = true;
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();

        for (int i = 0; i != vec.size(); i++)
        {
            try
            {
                bOut.write(((ASN1Object)vec.get(i)).getEncodedDER());
            }
            catch (IOException e)
            {
                throw new ASN1ParsingException("malformed object: " + e, e);
            }
        }
        this.octets = bOut.toByteArray();
    }

    

    public boolean isConstructed()
    {
        return isConstructed;
    }
    
    int encodedLength()
        throws IOException
    {
        return StreamUtil.calculateTagLength(tag) + StreamUtil.calculateBodyLength(octets.length) + octets.length;
    }

    /* (non-Javadoc)
     * @see org.bouncycastle.asn1.ASN1Primitive#encode(org.bouncycastle.asn1.DEROutputStream)
     */
    void encode(ASN1OutputStream out) throws IOException
    {
        int classBits = BERTags.APPLICATION;
        if (isConstructed)
        {
            classBits |= BERTags.CONSTRUCTED;
        }

        out.writeEncoded(classBits, tag, octets);
    }
    
    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof DERApplicationSpecific))
        {
            return false;
        }

        DERApplicationSpecific other = (DERApplicationSpecific)o;

        return isConstructed == other.isConstructed
            && tag == other.tag
            && Arrays.areEqual(octets, other.octets);
    }

    public int hashCode()
    {
        return (isConstructed ? 1 : 0) ^ tag ^ Arrays.hashCode(octets);
    }
}
