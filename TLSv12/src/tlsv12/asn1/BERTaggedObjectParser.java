package tlsv12.asn1;

import java.io.IOException;

public class BERTaggedObjectParser implements ASN1TaggedObjectParser {
    private boolean _constructed;

    private int _tagNumber;

    private ASN1StreamParser _parser;


    BERTaggedObjectParser(boolean constructed, int tagNumber,
            ASN1StreamParser parser) {
        _constructed = constructed;
        _tagNumber = tagNumber;
        _parser = parser;
    }


    public int getTagNo() {
        return _tagNumber;
    }


    public ASN1Primitive getLoadedObject() throws IOException {
        return _parser.readTaggedObject(_constructed, _tagNumber);
    }


    public ASN1Primitive toASN1Primitive() {
        try {
            return this.getLoadedObject();
        } catch (IOException e) {
            throw new ASN1ParsingException(e.getMessage());
        }
    }
}
