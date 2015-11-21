package tlsv12.ec;

import tlsv12.util.Strings;
import tlsv12.crypto.agreement.ECDHBasicAgreement;
import tlsv12.crypto.params.ECDomainParameters;
import tlsv12.crypto.params.ECPrivateKeyParameters;
import tlsv12.crypto.params.ECPublicKeyParameters;
import tlsv12.asn1.x9.X9IntegerConverter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * Diffie-Hellman key agreement using elliptic curve keys, ala IEEE P1363 both
 * the simple one, and the simple one with cofactors are supported.
 *
 * Also, MQV key agreement per SEC-1
 */
public class KeyAgreementSpi {
    private static final X9IntegerConverter converter = new X9IntegerConverter();

    private String kaAlgorithm;

    private BigInteger result;

    private ECDomainParameters parameters;

    private ECDHBasicAgreement agreement;


    private byte[] bigIntToBytes(BigInteger r) {
        return converter.integerToBytes(r,
                converter.getByteLength(parameters.getCurve()));
    }


    public KeyAgreementSpi() {
        this.kaAlgorithm = "ECDH";
        this.agreement = new ECDHBasicAgreement();
    }


    protected Key engineDoPhase(java.security.interfaces.ECPublicKey key,
            boolean lastPhase) throws IllegalStateException {
        if( parameters == null ) {
            throw new IllegalStateException(kaAlgorithm + " not initialised.");
        }

        if( !lastPhase ) {
            throw new IllegalStateException(kaAlgorithm
                    + " can only be between two parties.");
        }

        ECPublicKeyParameters pubKey = ECUtil.generatePublicKeyParameter(key);

        result = agreement.calculateAgreement(pubKey);

        return null;
    }


    


    protected SecretKey engineGenerateSecret(String algorithm) throws NoSuchAlgorithmException {
        byte[] secret = bigIntToBytes(result);
        Strings.toUpperCase(algorithm);
        

        // TODO

        return new SecretKeySpec(secret, algorithm);
    }


    protected void engineInit(java.security.interfaces.ECPrivateKey key) {

        ECPrivateKeyParameters privKey = (ECPrivateKeyParameters) ECUtil.generatePrivateKeyParameter(key);
        this.parameters = privKey.getParameters();

        agreement.init(privKey);
    }

}
