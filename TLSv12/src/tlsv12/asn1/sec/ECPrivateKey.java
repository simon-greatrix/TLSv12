package tlsv12.asn1.sec;

import tlsv12.asn1.*;
import tlsv12.util.BigIntegers;

import java.math.BigInteger;

/**
 * the elliptic curve private key object from SEC 1
 */
public class ECPrivateKey extends ASN1Object {
    private ASN1Sequence seq;


    public ECPrivateKey(int orderBitLength, BigInteger key,
            ASN1Encodable parameters) {
        this(orderBitLength, key, null, parameters);
    }


    public ECPrivateKey(int orderBitLength, BigInteger key,
            DERBitString publicKey, ASN1Encodable parameters) {
        byte[] bytes = BigIntegers.asUnsignedByteArray(
                (orderBitLength + 7) / 8, key);

        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(1));
        v.add(new DEROctetString(bytes));

        if( parameters != null ) {
            v.add(new DERTaggedObject(true, 0, parameters));
        }

        if( publicKey != null ) {
            v.add(new DERTaggedObject(true, 1, publicKey));
        }

        seq = new DERSequence(v);
    }


    /**
     * ECPrivateKey ::= SEQUENCE { version INTEGER { ecPrivkeyVer1(1) }
     * (ecPrivkeyVer1), privateKey OCTET STRING, parameters [0] Parameters
     * OPTIONAL, publicKey [1] BIT STRING OPTIONAL }
     */
    public ASN1Primitive toASN1Primitive() {
        return seq;
    }
}
