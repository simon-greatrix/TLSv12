package tlsv12.asn1;

import java.io.IOException;

public class BERSetParser
    implements ASN1SetParser
{
    private ASN1StreamParser _parser;

    BERSetParser(ASN1StreamParser parser)
    {
        this._parser = parser;
    }

    

    public ASN1Primitive getLoadedObject()
        throws IOException
    {
        return new BERSet(_parser.readVector());
    }

    public ASN1Primitive toASN1Primitive()
    {
        try
        {
            return getLoadedObject();
        }
        catch (IOException e)
        {
            throw new ASN1ParsingException(e.getMessage(), e);
        }
    }
}
