package tlsv12.asn1.x500;

import tlsv12.asn1.ASN1Object;
import tlsv12.asn1.ASN1Primitive;
import tlsv12.asn1.ASN1Set;

public class RDN extends ASN1Object {
    private ASN1Set values;


    private RDN(ASN1Set values) {
        this.values = values;
    }


    public static RDN getInstance(Object obj) {
        if( obj instanceof RDN ) {
            return (RDN) obj;
        } else if( obj != null ) {
            return new RDN(ASN1Set.getInstance(obj));
        }

        return null;
    }


    public boolean isMultiValued() {
        return this.values.size() > 1;
    }


    public AttributeTypeAndValue getFirst() {
        if( this.values.size() == 0 ) {
            return null;
        }

        return AttributeTypeAndValue.getInstance(this.values.getObjectAt(0));
    }


    public AttributeTypeAndValue[] getTypesAndValues() {
        AttributeTypeAndValue[] tmp = new AttributeTypeAndValue[values.size()];

        for(int i = 0;i != tmp.length;i++) {
            tmp[i] = AttributeTypeAndValue.getInstance(values.getObjectAt(i));
        }

        return tmp;
    }


    /**
     * <pre>
     * RelativeDistinguishedName ::=
     *                     SET OF AttributeTypeAndValue
     * 
     * AttributeTypeAndValue ::= SEQUENCE {
     *        type     AttributeType,
     *        value    AttributeValue }
     * </pre>
     * 
     * @return this object as an ASN1Primitive type
     */
    public ASN1Primitive toASN1Primitive() {
        return values;
    }
}
