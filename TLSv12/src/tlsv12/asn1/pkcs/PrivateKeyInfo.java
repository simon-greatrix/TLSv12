package tlsv12.asn1.pkcs;

import tlsv12.asn1.*;
import tlsv12.asn1.x509.AlgorithmIdentifier;

import java.io.IOException;

public class PrivateKeyInfo extends ASN1Object {
    private ASN1OctetString privKey;

    private AlgorithmIdentifier algId;

    private ASN1Set attributes;


    public PrivateKeyInfo(AlgorithmIdentifier algId, ASN1Encodable privateKey)
            throws IOException {
        this(algId, privateKey, null);
    }


    public PrivateKeyInfo(AlgorithmIdentifier algId, ASN1Encodable privateKey,
            ASN1Set attributes) throws IOException {
        this.privKey = new DEROctetString(
                privateKey.toASN1Primitive().getEncodedDER());
        this.algId = algId;
        this.attributes = attributes;
    }


    /**
     * write out an RSA private key with its associated information as described
     * in PKCS8.
     * 
     * <pre>
     *      PrivateKeyInfo ::= SEQUENCE {
     *                              version Version,
     *                              privateKeyAlgorithm AlgorithmIdentifier {{PrivateKeyAlgorithms}},
     *                              privateKey PrivateKey,
     *                              attributes [0] IMPLICIT Attributes OPTIONAL 
     *                          }
     *      Version ::= INTEGER {v1(0)} (v1,...)
     * 
     *      PrivateKey ::= OCTET STRING
     * 
     *      Attributes ::= SET OF Attribute
     * </pre>
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(0));
        v.add(algId);
        v.add(privKey);

        if( attributes != null ) {
            v.add(new DERTaggedObject(false, 0, attributes));
        }

        return new DERSequence(v);
    }
}
