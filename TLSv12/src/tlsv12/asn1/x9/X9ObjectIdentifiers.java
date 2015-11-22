package tlsv12.asn1.x9;

import tlsv12.asn1.ASN1ObjectIdentifier;

/**
 *
 * X9.62
 * 
 * <pre>
 * ansi-X9-62 OBJECT IDENTIFIER ::= { iso(1) member-body(2)
 *                                    us(840) ansi-x962(10045) }
 * </pre>
 */
public interface X9ObjectIdentifiers {
    /** Base OID: 1.2.840.10045 */
    static final ASN1ObjectIdentifier ansi_X9_62 = new ASN1ObjectIdentifier(
            "1.2.840.10045");

    /** OID: 1.2.840.10045.1 */
    static final ASN1ObjectIdentifier id_fieldType = ansi_X9_62.branch("1");

    /** OID: 1.2.840.10045.1.1 */
    static final ASN1ObjectIdentifier prime_field = id_fieldType.branch("1");

    /** OID: 1.2.840.10045.1.2 */
    static final ASN1ObjectIdentifier characteristic_two_field = id_fieldType.branch("2");

    /** OID: 1.2.840.10045.1.2.3.2 */
    static final ASN1ObjectIdentifier tpBasis = characteristic_two_field.branch("3.2");

    /** OID: 1.2.840.10045.1.2.3.3 */
    static final ASN1ObjectIdentifier ppBasis = characteristic_two_field.branch("3.3");

    /** OID: 1.2.840.10045.2 */
    static final ASN1ObjectIdentifier id_publicKeyType = ansi_X9_62.branch("2");

    /** OID: 1.2.840.10045.2.1 */
    static final ASN1ObjectIdentifier id_ecPublicKey = id_publicKeyType.branch("1");

}
