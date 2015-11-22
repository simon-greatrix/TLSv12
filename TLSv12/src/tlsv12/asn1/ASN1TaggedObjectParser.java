package tlsv12.asn1;

public interface ASN1TaggedObjectParser extends ASN1Encodable,
        InMemoryRepresentable {
    public int getTagNo();

}
