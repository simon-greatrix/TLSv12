package tlsv12.crypto.generators;

import tlsv12.crypto.AsymmetricCipherKeyPair;
import tlsv12.crypto.params.ECDomainParameters;
import tlsv12.crypto.params.ECKeyGenerationParameters;
import tlsv12.crypto.params.ECPrivateKeyParameters;
import tlsv12.crypto.params.ECPublicKeyParameters;
import tlsv12.math.ec.*;

import java.math.BigInteger;
import java.security.SecureRandom;

public class ECKeyPairGenerator implements ECConstants {
    ECDomainParameters params;

    SecureRandom random;


    public void init(ECKeyGenerationParameters param) {
        ECKeyGenerationParameters ecP = (ECKeyGenerationParameters) param;

        this.random = ecP.getRandom();
        this.params = ecP.getDomainParameters();

        if( this.random == null ) {
            this.random = new SecureRandom();
        }
    }


    /**
     * Given the domain parameters this routine generates an EC key pair in
     * accordance with X9.62 section 5.2.1 pages 26, 27.
     */
    public AsymmetricCipherKeyPair generateKeyPair() {
        BigInteger n = params.getN();
        int nBitLength = n.bitLength();
        int minWeight = nBitLength >>> 2;

        BigInteger d;
        for(;;) {
            d = new BigInteger(nBitLength, random);

            if( d.compareTo(TWO) < 0 || (d.compareTo(n) >= 0) ) {
                continue;
            }

            /*
             * Require a minimum weight of the NAF representation, since
             * low-weight primes may be weak against a version of the
             * number-field-sieve for the discrete-logarithm-problem.
             * 
             * See "The number field sieve for integers of low weight", Oliver
             * Schirokauer.
             */
            if( WNafUtil.getNafWeight(d) < minWeight ) {
                continue;
            }

            break;
        }

        ECPoint Q = createBasePointMultiplier().multiply(params.getG(), d);

        return new AsymmetricCipherKeyPair(
                new ECPublicKeyParameters(Q, params),
                new ECPrivateKeyParameters(d, params));
    }


    protected ECMultiplier createBasePointMultiplier() {
        return new FixedPointCombMultiplier();
    }
}
