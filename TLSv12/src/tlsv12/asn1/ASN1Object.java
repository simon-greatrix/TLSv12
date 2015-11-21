package tlsv12.asn1;

import tlsv12.util.Encodable;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Base class for defining an ASN.1 object.
 */
public abstract class ASN1Object implements ASN1Encodable, Encodable {
    /**
     * Return the default BER or DER encoding for this object.
     *
     * @return BER/DER byte encoded object.
     * @throws java.io.IOException
     *             on encoding error.
     */
    public byte[] getEncoded() throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream aOut = new ASN1OutputStream(bOut);

        aOut.writeObject(this);

        return bOut.toByteArray();
    }


    public byte[] getEncodedDER() throws IOException {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        DEROutputStream dOut = new DEROutputStream(bOut);

        dOut.writeObject(this);

        return bOut.toByteArray();
    }


    public int hashCode() {
        return this.toASN1Primitive().hashCode();
    }


    public boolean equals(Object o) {
        if( this == o ) {
            return true;
        }

        if( !(o instanceof ASN1Encodable) ) {
            return false;
        }

        ASN1Encodable other = (ASN1Encodable) o;

        return this.toASN1Primitive().equals(other.toASN1Primitive());
    }


    /**
     * Method providing a primitive representation of this object suitable for
     * encoding.
     * 
     * @return a primitive representation of this object.
     */
    public abstract ASN1Primitive toASN1Primitive();
}
