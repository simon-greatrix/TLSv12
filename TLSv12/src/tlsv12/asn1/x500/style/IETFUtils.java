package tlsv12.asn1.x500.style;

import tlsv12.asn1.*;
import tlsv12.asn1.x500.AttributeTypeAndValue;
import tlsv12.asn1.x500.RDN;
import tlsv12.util.Strings;
import tlsv12.util.encoders.Hex;

import java.io.IOException;
import java.util.Hashtable;

public class IETFUtils {
    public static void appendRDN(StringBuffer buf, RDN rdn, Hashtable oidSymbols) {
        if( rdn.isMultiValued() ) {
            AttributeTypeAndValue[] atv = rdn.getTypesAndValues();
            boolean firstAtv = true;

            for(int j = 0;j != atv.length;j++) {
                if( firstAtv ) {
                    firstAtv = false;
                } else {
                    buf.append('+');
                }

                IETFUtils.appendTypeAndValue(buf, atv[j], oidSymbols);
            }
        } else {
            if( rdn.getFirst() != null ) {
                IETFUtils.appendTypeAndValue(buf, rdn.getFirst(), oidSymbols);
            }
        }
    }


    public static void appendTypeAndValue(StringBuffer buf,
            AttributeTypeAndValue typeAndValue, Hashtable oidSymbols) {
        String sym = (String) oidSymbols.get(typeAndValue.getType());

        if( sym != null ) {
            buf.append(sym);
        } else {
            buf.append(typeAndValue.getType().getId());
        }

        buf.append('=');

        buf.append(valueToString(typeAndValue.getValue()));
    }


    public static String valueToString(ASN1Encodable value) {
        StringBuffer vBuf = new StringBuffer();

        if( value instanceof ASN1String
                && !(value instanceof DERUniversalString) ) {
            String v = ((ASN1String) value).getString();
            if( v.length() > 0 && v.charAt(0) == '#' ) {
                vBuf.append("\\" + v);
            } else {
                vBuf.append(v);
            }
        } else {
            try {
                vBuf.append("#"
                        + bytesToString(Hex.encode(value.toASN1Primitive().getEncodedDER())));
            } catch (IOException e) {
                throw new IllegalArgumentException(
                        "Other value has no encoded form");
            }
        }

        int end = vBuf.length();
        int index = 0;

        if( vBuf.length() >= 2 && vBuf.charAt(0) == '\\'
                && vBuf.charAt(1) == '#' ) {
            index += 2;
        }

        while( index != end ) {
            if( (vBuf.charAt(index) == ',') || (vBuf.charAt(index) == '"')
                    || (vBuf.charAt(index) == '\\')
                    || (vBuf.charAt(index) == '+')
                    || (vBuf.charAt(index) == '=')
                    || (vBuf.charAt(index) == '<')
                    || (vBuf.charAt(index) == '>')
                    || (vBuf.charAt(index) == ';') ) {
                vBuf.insert(index, "\\");
                index++;
                end++;
            }

            index++;
        }

        int start = 0;
        if( vBuf.length() > 0 ) {
            while( vBuf.length() > start && vBuf.charAt(start) == ' ' ) {
                vBuf.insert(start, "\\");
                start += 2;
            }
        }

        int endBuf = vBuf.length() - 1;

        while( endBuf >= 0 && vBuf.charAt(endBuf) == ' ' ) {
            vBuf.insert(endBuf, '\\');
            endBuf--;
        }

        return vBuf.toString();
    }


    private static String bytesToString(byte[] data) {
        char[] cs = new char[data.length];

        for(int i = 0;i != cs.length;i++) {
            cs[i] = (char) (data[i] & 0xff);
        }

        return new String(cs);
    }


    public static String canonicalize(String s) {
        String value = Strings.toLowerCase(s);

        if( value.length() > 0 && value.charAt(0) == '#' ) {
            ASN1Primitive obj = decodeObject(value);

            if( obj instanceof ASN1String ) {
                value = Strings.toLowerCase(((ASN1String) obj).getString());
            }
        }

        if( value.length() > 1 ) {
            int start = 0;
            while( start + 1 < value.length() && value.charAt(start) == '\\'
                    && value.charAt(start + 1) == ' ' ) {
                start += 2;
            }

            int end = value.length() - 1;
            while( end - 1 > 0 && value.charAt(end - 1) == '\\'
                    && value.charAt(end) == ' ' ) {
                end -= 2;
            }

            if( start > 0 || end < value.length() - 1 ) {
                value = value.substring(start, end + 1);
            }
        }

        value = stripInternalSpaces(value);

        return value;
    }


    private static ASN1Primitive decodeObject(String oValue) {
        try {
            return ASN1Primitive.fromByteArray(Hex.decode(oValue.substring(1)));
        } catch (IOException e) {
            throw new IllegalStateException("unknown encoding in name: " + e);
        }
    }


    public static String stripInternalSpaces(String str) {
        StringBuffer res = new StringBuffer();

        if( str.length() != 0 ) {
            char c1 = str.charAt(0);

            res.append(c1);

            for(int k = 1;k < str.length();k++) {
                char c2 = str.charAt(k);
                if( !(c1 == ' ' && c2 == ' ') ) {
                    res.append(c2);
                }
                c1 = c2;
            }
        }

        return res.toString();
    }


    public static boolean rDNAreEqual(RDN rdn1, RDN rdn2) {
        if( rdn1.isMultiValued() ) {
            if( rdn2.isMultiValued() ) {
                AttributeTypeAndValue[] atvs1 = rdn1.getTypesAndValues();
                AttributeTypeAndValue[] atvs2 = rdn2.getTypesAndValues();

                if( atvs1.length != atvs2.length ) {
                    return false;
                }

                for(int i = 0;i != atvs1.length;i++) {
                    if( !atvAreEqual(atvs1[i], atvs2[i]) ) {
                        return false;
                    }
                }
            } else {
                return false;
            }
        } else {
            if( !rdn2.isMultiValued() ) {
                return atvAreEqual(rdn1.getFirst(), rdn2.getFirst());
            }
            return false;
        }

        return true;
    }


    private static boolean atvAreEqual(AttributeTypeAndValue atv1,
            AttributeTypeAndValue atv2) {
        if( atv1 == atv2 ) {
            return true;
        }

        if( atv1 == null ) {
            return false;
        }

        if( atv2 == null ) {
            return false;
        }

        ASN1ObjectIdentifier o1 = atv1.getType();
        ASN1ObjectIdentifier o2 = atv2.getType();

        if( !o1.equals(o2) ) {
            return false;
        }

        String v1 = IETFUtils.canonicalize(IETFUtils.valueToString(atv1.getValue()));
        String v2 = IETFUtils.canonicalize(IETFUtils.valueToString(atv2.getValue()));

        if( !v1.equals(v2) ) {
            return false;
        }

        return true;
    }
}
