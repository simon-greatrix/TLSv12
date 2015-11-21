package tlsv12.asn1;

import tlsv12.util.Arrays;
import tlsv12.util.io.Streams;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

public class DERBitString
    extends ASN1Primitive
    implements ASN1String
{
    private static final char[]  table = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };
    
    protected byte[]      data;
    protected int         padBits;

    

    

    /**
     * return a Bit String from the passed in object
     *
     * @param obj a DERBitString or an object that can be converted into one.
     * @exception IllegalArgumentException if the object cannot be converted.
     * @return a DERBitString instance, or null.
     */
    public static DERBitString getInstance(
        Object  obj)
    {
        if (obj == null || obj instanceof DERBitString)
        {
            return (DERBitString)obj;
        }

        throw new IllegalArgumentException("illegal object in getInstance: " + obj.getClass().getName());
    }

    
    
    

    /**
     * @param data the octets making up the bit string.
     * @param padBits the number of extra bits at the end of the string.
     */
    public DERBitString(
        byte[]  data,
        int     padBits)
    {
        this.data = data;
        this.padBits = padBits;
    }

    public DERBitString(
        byte[]  data)
    {
        this(data, 0);
    }

    

    public byte[] getBytes()
    {
        return data;
    }

    public int getPadBits()
    {
        return padBits;
    }


    

    boolean isConstructed()
    {
        return false;
    }

    int encodedLength()
    {
        return 1 + StreamUtil.calculateBodyLength(data.length + 1) + data.length + 1;
    }

    void encode(
        ASN1OutputStream  out)
        throws IOException
    {
        byte[]  bytes = new byte[getBytes().length + 1];

        bytes[0] = (byte)getPadBits();
        System.arraycopy(getBytes(), 0, bytes, 1, bytes.length - 1);

        out.writeEncoded(BERTags.BIT_STRING, bytes);
    }

    public int hashCode()
    {
        return padBits ^ Arrays.hashCode(data);
    }

    protected boolean asn1Equals(
        ASN1Primitive  o)
    {
        if (!(o instanceof DERBitString))
        {
            return false;
        }

        DERBitString other = (DERBitString)o;

        return this.padBits == other.padBits
            && Arrays.areEqual(this.data, other.data);
    }

    public String getString()
    {
        StringBuffer          buf = new StringBuffer("#");
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        ASN1OutputStream      aOut = new ASN1OutputStream(bOut);
        
        try
        {
            aOut.writeObject(this);
        }
        catch (IOException e)
        {
           throw new RuntimeException("internal error encoding BitString");
        }
        
        byte[]    string = bOut.toByteArray();
        
        for (int i = 0; i != string.length; i++)
        {
            buf.append(table[(string[i] >>> 4) & 0xf]);
            buf.append(table[string[i] & 0xf]);
        }
        
        return buf.toString();
    }

    public String toString()
    {
        return getString();
    }

    

    static DERBitString fromInputStream(int length, InputStream stream)
        throws IOException
    {
        if (length < 1)
        {
            throw new IllegalArgumentException("truncated BIT STRING detected");
        }

        int padBits = stream.read();
        byte[] data = new byte[length - 1];

        if (data.length != 0)
        {
            if (Streams.readFully(stream, data) != data.length)
            {
                throw new EOFException("EOF encountered in middle of BIT STRING");
            }
        }

        return new DERBitString(data, padBits);
    }
}
