package tlsv12.asn1;

import java.io.IOException;

/**
 * A NULL object - use DERNull.INSTANCE for populating structures.
 */
public abstract class ASN1Null extends ASN1Primitive {

    public int hashCode() {
        return -1;
    }


    boolean asn1Equals(ASN1Primitive o) {
        if( !(o instanceof ASN1Null) ) {
            return false;
        }

        return true;
    }


    abstract void encode(ASN1OutputStream out) throws IOException;


    public String toString() {
        return "NULL";
    }
}
