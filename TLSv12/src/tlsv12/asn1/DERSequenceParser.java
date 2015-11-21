package tlsv12.asn1;

import java.io.IOException;

public class DERSequenceParser
    implements ASN1SequenceParser
{
    private ASN1StreamParser _parser;

    DERSequenceParser(ASN1StreamParser parser)
    {
        this._parser = parser;
    }

    

    public ASN1Primitive getLoadedObject()
        throws IOException
    {
         return new DERSequence(_parser.readVector());
    }

    public ASN1Primitive toASN1Primitive()
    {
        try
        {
            return getLoadedObject();
        }
        catch (IOException e)
        {
            throw new IllegalStateException(e.getMessage());
        }
    }
}
