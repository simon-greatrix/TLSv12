package tlsv12.asn1;

import tlsv12.util.Arrays;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Class representing the ASN.1 INTEGER type.
 */
public class ASN1Integer
    extends ASN1Primitive
{
    byte[] bytes;

    

    

    public ASN1Integer(
        long value)
    {
        bytes = BigInteger.valueOf(value).toByteArray();
    }

    public ASN1Integer(
        BigInteger value)
    {
        bytes = value.toByteArray();
    }

    

    ASN1Integer(byte[] bytes, boolean clone)
    {
        this.bytes = (clone) ? Arrays.clone(bytes) : bytes;
    }

    public BigInteger getValue()
    {
        return new BigInteger(bytes);
    }

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(bytes.length) + bytes.length;
    }

    void encode(
        ASN1OutputStream out)
        throws IOException
    {
        out.writeEncoded(BERTags.INTEGER, bytes);
    }

    public int hashCode()
    {
        int value = 0;

        for (int i = 0; i != bytes.length; i++)
        {
            value ^= (bytes[i] & 0xff) << (i % 4);
        }

        return value;
    }

    boolean asn1Equals(
        ASN1Primitive o)
    {
        if (!(o instanceof ASN1Integer))
        {
            return false;
        }

        ASN1Integer other = (ASN1Integer)o;

        return Arrays.areEqual(bytes, other.bytes);
    }

    public String toString()
    {
        return getValue().toString();
    }

}
