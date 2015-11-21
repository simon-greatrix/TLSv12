package tlsv12.asn1.x500;

import tlsv12.asn1.x500.style.BCStyle;

import tlsv12.asn1.*;

import java.util.Enumeration;

/**
 * <pre>
 *     Name ::= CHOICE {
 *                       RDNSequence }
 *
 *     RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
 *
 *     RelativeDistinguishedName ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
 *
 *     AttributeTypeAndValue ::= SEQUENCE {
 *                                   type  OBJECT IDENTIFIER,
 *                                   value ANY }
 * </pre>
 */
public class X500Name
    extends ASN1Object
    implements ASN1Choice
{
    private static BCStyle    defaultStyle = BCStyle.INSTANCE;

    private boolean                 isHashCodeCalculated;
    private int                     hashCodeValue;

    private BCStyle style;
    private RDN[] rdns;

    

    

    /**
     * Constructor from ASN1Sequence
     *
     * the principal will be a list of constructed sets, each containing an (OID, String) pair.
     */
    private X500Name(
        ASN1Sequence  seq)
    {
        this(defaultStyle, seq);
    }

    private X500Name(
        BCStyle style,
        ASN1Sequence  seq)
    {
        this.style = style;
        this.rdns = new RDN[seq.size()];

        int index = 0;

        for (Enumeration e = seq.getObjects(); e.hasMoreElements();)
        {
            rdns[index++] = RDN.getInstance(e.nextElement());
        }
    }

    

    /**
     * return an array of RDNs in structure order.
     *
     * @return an array of RDN objects.
     */
    public RDN[] getRDNs()
    {
        RDN[] tmp = new RDN[this.rdns.length];

        System.arraycopy(rdns, 0, tmp, 0, tmp.length);

        return tmp;
    }

    public ASN1Primitive toASN1Primitive()
    {
        return new DERSequence(rdns);
    }

    public int hashCode()
    {
        if (isHashCodeCalculated)
        {
            return hashCodeValue;
        }

        isHashCodeCalculated = true;

        hashCodeValue = style.calculateHashCode(this);

        return hashCodeValue;
    }

    /**
     * test for equality - note: case is ignored.
     */
    public boolean equals(Object obj)
    {
        if (obj == this)
        {
            return true;
        }

        if (!(obj instanceof X500Name || obj instanceof ASN1Sequence))
        {
            return false;
        }
        
        ASN1Primitive derO = ((ASN1Encodable)obj).toASN1Primitive();

        if (this.toASN1Primitive().equals(derO))
        {
            return true;
        }

        try
        {
            return style.areEqual(this, new X500Name(ASN1Sequence.getInstance(((ASN1Encodable)obj).toASN1Primitive())));
        }
        catch (Exception e)
        {
            return false;
        }
    }
    
    public String toString()
    {
        return style.toString(this);
    }
}
