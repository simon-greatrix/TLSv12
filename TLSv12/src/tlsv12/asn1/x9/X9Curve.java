package tlsv12.asn1.x9;

import tlsv12.math.ec.ECAlgorithms;
import tlsv12.math.ec.ECCurve;

import tlsv12.asn1.*;

/**
 * ASN.1 def for Elliptic-Curve Curve structure. See
 * X9.62, for further details.
 */
public class X9Curve
    extends ASN1Object
    implements X9ObjectIdentifiers
{
    private ECCurve     curve;
    private byte[]      seed;
    private ASN1ObjectIdentifier fieldIdentifier = null;

    

    public X9Curve(
        ECCurve     curve,
        byte[]      seed)
    {
        this.curve = curve;
        this.seed = seed;
        setFieldIdentifier();
    }

    private void setFieldIdentifier()
    {
        if (ECAlgorithms.isFpCurve(curve))
        {
            fieldIdentifier = prime_field;
        }
        else if (ECAlgorithms.isF2mCurve(curve))
        {
            fieldIdentifier = characteristic_two_field;
        }
        else
        {
            throw new IllegalArgumentException("This type of ECCurve is not implemented");
        }
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  Curve ::= SEQUENCE {
     *      a               FieldElement,
     *      b               FieldElement,
     *      seed            BIT STRING      OPTIONAL
     *  }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        ASN1EncodableVector v = new ASN1EncodableVector();

        if (fieldIdentifier.equals(prime_field)) 
        { 
            v.add(new X9FieldElement(curve.getA()).toASN1Primitive());
            v.add(new X9FieldElement(curve.getB()).toASN1Primitive());
        } 
        else if (fieldIdentifier.equals(characteristic_two_field)) 
        {
            v.add(new X9FieldElement(curve.getA()).toASN1Primitive());
            v.add(new X9FieldElement(curve.getB()).toASN1Primitive());
        }

        if (seed != null)
        {
            v.add(new DERBitString(seed));
        }

        return new DERSequence(v);
    }
}
