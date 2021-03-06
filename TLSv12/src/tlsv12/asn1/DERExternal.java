package tlsv12.asn1;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

/**
 * Class representing the DER-type External
 */
public class DERExternal extends ASN1Primitive {
    private ASN1ObjectIdentifier directReference;

    private ASN1Integer indirectReference;

    private ASN1Primitive dataValueDescriptor;

    private int encoding;

    private ASN1Primitive externalContent;


    public DERExternal(ASN1EncodableVector vector) {
        int offset = 0;

        ASN1Primitive enc = getObjFromVector(vector, offset);
        if( enc instanceof ASN1ObjectIdentifier ) {
            directReference = (ASN1ObjectIdentifier) enc;
            offset++;
            enc = getObjFromVector(vector, offset);
        }
        if( enc instanceof ASN1Integer ) {
            indirectReference = (ASN1Integer) enc;
            offset++;
            enc = getObjFromVector(vector, offset);
        }
        if( !(enc instanceof DERTaggedObject) ) {
            dataValueDescriptor = (ASN1Primitive) enc;
            offset++;
            enc = getObjFromVector(vector, offset);
        }

        if( vector.size() != offset + 1 ) {
            throw new IllegalArgumentException("input vector too large");
        }

        if( !(enc instanceof DERTaggedObject) ) {
            throw new IllegalArgumentException(
                    "No tagged object found in vector. Structure doesn't seem to be of type External");
        }
        DERTaggedObject obj = (DERTaggedObject) enc;
        setEncoding(obj.getTagNo());
        externalContent = obj.getObject();
    }


    private ASN1Primitive getObjFromVector(ASN1EncodableVector v, int index) {
        if( v.size() <= index ) {
            throw new IllegalArgumentException(
                    "too few objects in input vector");
        }

        return v.get(index).toASN1Primitive();
    }


    /*
     * (non-Javadoc)
     * 
     * @see java.lang.Object#hashCode()
     */
    public int hashCode() {
        int ret = 0;
        if( directReference != null ) {
            ret = directReference.hashCode();
        }
        if( indirectReference != null ) {
            ret ^= indirectReference.hashCode();
        }
        if( dataValueDescriptor != null ) {
            ret ^= dataValueDescriptor.hashCode();
        }
        ret ^= externalContent.hashCode();
        return ret;
    }


    boolean isConstructed() {
        return true;
    }


    int encodedLength() throws IOException {
        return this.getEncoded().length;
    }


    /*
     * (non-Javadoc)
     * 
     * @see org.bouncycastle.asn1.ASN1Primitive#encode(org.bouncycastle.asn1.
     * DEROutputStream)
     */
    void encode(ASN1OutputStream out) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        if( directReference != null ) {
            baos.write(directReference.getEncodedDER());
        }
        if( indirectReference != null ) {
            baos.write(indirectReference.getEncodedDER());
        }
        if( dataValueDescriptor != null ) {
            baos.write(dataValueDescriptor.getEncodedDER());
        }
        DERTaggedObject obj = new DERTaggedObject(true, encoding,
                externalContent);
        baos.write(obj.getEncodedDER());
        out.writeEncoded(BERTags.CONSTRUCTED, BERTags.EXTERNAL,
                baos.toByteArray());
    }


    /*
     * (non-Javadoc)
     * 
     * @see
     * org.bouncycastle.asn1.ASN1Primitive#asn1Equals(org.bouncycastle.asn1.
     * ASN1Primitive)
     */
    boolean asn1Equals(ASN1Primitive o) {
        if( !(o instanceof DERExternal) ) {
            return false;
        }
        if( this == o ) {
            return true;
        }
        DERExternal other = (DERExternal) o;
        if( directReference != null ) {
            if( other.directReference == null
                    || !other.directReference.equals(directReference) ) {
                return false;
            }
        }
        if( indirectReference != null ) {
            if( other.indirectReference == null
                    || !other.indirectReference.equals(indirectReference) ) {
                return false;
            }
        }
        if( dataValueDescriptor != null ) {
            if( other.dataValueDescriptor == null
                    || !other.dataValueDescriptor.equals(dataValueDescriptor) ) {
                return false;
            }
        }
        return externalContent.equals(other.externalContent);
    }


    /**
     * Sets the encoding of the content. Valid values are
     * <ul>
     * <li><code>0</code> single-ASN1-type</li>
     * <li><code>1</code> OCTET STRING</li>
     * <li><code>2</code> BIT STRING</li>
     * </ul>
     * 
     * @param encoding
     *            The encoding
     */
    private void setEncoding(int encoding) {
        if( encoding < 0 || encoding > 2 ) {
            throw new IllegalArgumentException("invalid encoding value: "
                    + encoding);
        }
        this.encoding = encoding;
    }
}
