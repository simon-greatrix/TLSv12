package tlsv12.asn1.x509;

import tlsv12.asn1.*;

import java.util.Enumeration;

/**
 * The object that contains the public key stored in a certficate.
 * <p>
 * The getEncoded() method in the public keys in the JCE produces a DER encoded
 * one of these.
 */
public class SubjectPublicKeyInfo extends ASN1Object {
    private AlgorithmIdentifier algId;

    private DERBitString keyData;


    public static SubjectPublicKeyInfo getInstance(Object obj) {
        if( obj instanceof SubjectPublicKeyInfo ) {
            return (SubjectPublicKeyInfo) obj;
        } else if( obj != null ) {
            return new SubjectPublicKeyInfo(ASN1Sequence.getInstance(obj));
        }

        return null;
    }


    public SubjectPublicKeyInfo(AlgorithmIdentifier algId, byte[] publicKey) {
        this.keyData = new DERBitString(publicKey);
        this.algId = algId;
    }


    public SubjectPublicKeyInfo(ASN1Sequence seq) {
        if( seq.size() != 2 ) {
            throw new IllegalArgumentException("Bad sequence size: "
                    + seq.size());
        }

        Enumeration e = seq.getObjects();

        this.algId = AlgorithmIdentifier.getInstance(e.nextElement());
        this.keyData = DERBitString.getInstance(e.nextElement());
    }


    /**
     * for when the public key is raw bits.
     *
     * @return the public key as the raw bit string...
     */
    public DERBitString getPublicKeyData() {
        return keyData;
    }


    /**
     * Produce an object suitable for an ASN1OutputStream.
     * 
     * <pre>
     * SubjectPublicKeyInfo ::= SEQUENCE {
     *                          algorithm AlgorithmIdentifier,
     *                          publicKey BIT STRING }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(algId);
        v.add(keyData);

        return new DERSequence(v);
    }
}
