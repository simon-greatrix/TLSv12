package tlsv12.asn1;

import java.util.Vector;

/**
 * Mutable class for building ASN.1 constructed objects.
 */
public class ASN1EncodableVector
{
    Vector v = new Vector();

    /**
     * Base constructor.
     */
    public ASN1EncodableVector()
    {
    }

    /**
     * Add an encodable to the vector.
     *
     * @param obj the encodable to add.
     */
    public void add(ASN1Encodable obj)
    {
        v.addElement(obj);
    }

    

    /**
     * Return the object at position i in this vector.
     *
     * @param i the index of the object of interest.
     * @return the object at position i.
     */
    public ASN1Encodable get(int i)
    {
        return (ASN1Encodable)v.elementAt(i);
    }

    /**
     * Return the size of the vector.
     *
     * @return the object count in the vector.
     */
    public int size()
    {
        return v.size();
    }
}
