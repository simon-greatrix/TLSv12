package tlsv12.asn1;

import java.io.IOException;
import java.util.Enumeration;

public class BERSet
    extends ASN1Set
{
    /**
     * create an empty sequence
     */
    public BERSet()
    {
    }

    

    /**
     * @param v - a vector of objects making up the set.
     */
    public BERSet(
        ASN1EncodableVector v)
    {
        super(v, false);
    }

    

    int encodedLength()
        throws IOException
    {
        int length = 0;
        for (Enumeration e = getObjects(); e.hasMoreElements();)
        {
            length += ((ASN1Encodable)e.nextElement()).toASN1Primitive().encodedLength();
        }

        return 2 + length + 2;
    }

    /*
     */
    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.write(BERTags.SET | BERTags.CONSTRUCTED);
        out.write(0x80);

        Enumeration e = getObjects();
        while (e.hasMoreElements())
        {
            out.writeObject((ASN1Encodable)e.nextElement());
        }

        out.write(0x00);
        out.write(0x00);
    }
}
