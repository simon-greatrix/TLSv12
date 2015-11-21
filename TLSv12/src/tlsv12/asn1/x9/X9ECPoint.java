package tlsv12.asn1.x9;

import tlsv12.math.ec.ECPoint;

import tlsv12.asn1.ASN1Object;
import tlsv12.asn1.ASN1Primitive;
import tlsv12.asn1.DEROctetString;

/**
 * class for describing an ECPoint as a DER object.
 */
public class X9ECPoint
    extends ASN1Object
{
    ECPoint p;

    public X9ECPoint(
        ECPoint p)
    {
        this.p = p.normalize();
    }

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     *  ECPoint ::= OCTET STRING
     * </pre>
     * <p>
     * Octet string produced using ECPoint.getEncoded().
     */
    public ASN1Primitive toASN1Primitive()
    {
        return new DEROctetString(p.getEncoded());
    }
}
