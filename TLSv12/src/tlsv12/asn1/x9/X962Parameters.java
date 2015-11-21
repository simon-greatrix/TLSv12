package tlsv12.asn1.x9;

import tlsv12.asn1.*;

public class X962Parameters
    extends ASN1Object
    implements ASN1Choice
{
    private ASN1Primitive           params = null;

    public X962Parameters(
        X9ECParameters      ecParameters)
    {
        this.params = ecParameters.toASN1Primitive();
    }

    

    /**
     * Produce an object suitable for an ASN1OutputStream.
     * <pre>
     * Parameters ::= CHOICE {
     *    ecParameters ECParameters,
     *    namedCurve   CURVES.&amp;id({CurveNames}),
     *    implicitlyCA NULL
     * }
     * </pre>
     */
    public ASN1Primitive toASN1Primitive()
    {
        return (ASN1Primitive)params;
    }
}
