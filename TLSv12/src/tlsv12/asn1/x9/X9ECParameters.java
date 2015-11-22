package tlsv12.asn1.x9;

import tlsv12.asn1.*;
import tlsv12.math.ec.ECAlgorithms;
import tlsv12.math.ec.ECCurve;
import tlsv12.math.ec.ECPoint;
import tlsv12.math.field.PolynomialExtensionField;

import java.math.BigInteger;

/**
 * ASN.1 def for Elliptic-Curve ECParameters structure. See X9.62, for further
 * details.
 */
public class X9ECParameters extends ASN1Object implements X9ObjectIdentifiers {

    private X9FieldID fieldID;

    private ECCurve curve;

    private ECPoint g;

    private BigInteger n;

    private BigInteger h;

    private byte[] seed;


    public X9ECParameters(ECCurve curve, ECPoint g, BigInteger n, BigInteger h,
            byte[] seed) {
        this.curve = curve;
        this.g = g.normalize();
        this.n = n;
        this.h = h;
        this.seed = seed;

        if( ECAlgorithms.isFpCurve(curve) ) {
            this.fieldID = new X9FieldID(curve.getField().getCharacteristic());
        } else if( ECAlgorithms.isF2mCurve(curve) ) {
            PolynomialExtensionField field = (PolynomialExtensionField) curve.getField();
            int[] exponents = field.getMinimalPolynomial().getExponentsPresent();
            if( exponents.length == 3 ) {
                this.fieldID = new X9FieldID(exponents[2], exponents[1]);
            } else if( exponents.length == 5 ) {
                this.fieldID = new X9FieldID(exponents[4], exponents[1],
                        exponents[2], exponents[3]);
            } else {
                throw new IllegalArgumentException(
                        "Only trinomial and pentomial curves are supported");
            }
        } else {
            throw new IllegalArgumentException(
                    "'curve' is of an unsupported type");
        }
    }


    /**
     * Produce an object suitable for an ASN1OutputStream.
     * 
     * <pre>
     *  ECParameters ::= SEQUENCE {
     *      version         INTEGER { ecpVer1(1) } (ecpVer1),
     *      fieldID         FieldID {{FieldTypes}},
     *      curve           X9Curve,
     *      base            X9ECPoint,
     *      order           INTEGER,
     *      cofactor        INTEGER OPTIONAL
     *  }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector v = new ASN1EncodableVector();

        v.add(new ASN1Integer(1));
        v.add(fieldID);
        v.add(new X9Curve(curve, seed));
        v.add(new X9ECPoint(g));
        v.add(new ASN1Integer(n));

        if( h != null ) {
            v.add(new ASN1Integer(h));
        }

        return new DERSequence(v);
    }
}
