package tlsv12.asn1;

import java.io.IOException;
import java.util.Enumeration;

/**
 * A DER encoded set object
 */
public class DERSet
    extends ASN1Set
{
    private int bodyLength = -1;

    /**
     * create an empty set
     */
    public DERSet()
    {
    }

    

    

    DERSet(
        ASN1EncodableVector v,
        boolean                  doSort)
    {
        super(v, doSort);
    }

    private int getBodyLength()
        throws IOException
    {
        if (bodyLength < 0)
        {
            int length = 0;

            for (Enumeration e = this.getObjects(); e.hasMoreElements();)
            {
                Object    obj = e.nextElement();

                length += ((ASN1Encodable)obj).toASN1Primitive().toDERObject().encodedLength();
            }

            bodyLength = length;
        }

        return bodyLength;
    }

    int encodedLength()
        throws IOException
    {
        int length = getBodyLength();

        return 1 + StreamUtil.calculateBodyLength(length) + length;
    }

    @Override
    void encode(ASN1OutputStream out) throws IOException {
        // TODO Auto-generated method stub
        
    }
}
