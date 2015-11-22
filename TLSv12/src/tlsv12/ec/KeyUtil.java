package tlsv12.ec;

import tlsv12.asn1.x509.SubjectPublicKeyInfo;

public class KeyUtil {

    public static byte[] getEncodedSubjectPublicKeyInfo(
            SubjectPublicKeyInfo info) {
        try {
            return info.getEncodedDER();
        } catch (Exception e) {
            return null;
        }
    }
}
