package tlsv12.ec;

import tlsv12.math.ec.ECCurve;
import tlsv12.math.ec.ECPoint;

import tlsv12.util.Integers;
import tlsv12.crypto.AsymmetricCipherKeyPair;
import tlsv12.crypto.generators.ECKeyPairGenerator;
import tlsv12.crypto.params.ECDomainParameters;
import tlsv12.crypto.params.ECKeyGenerationParameters;
import tlsv12.crypto.params.ECPrivateKeyParameters;
import tlsv12.crypto.params.ECPublicKeyParameters;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Hashtable;

public abstract class KeyPairGeneratorSpi  {
    public KeyPairGeneratorSpi(String algorithmName) {
    }

    public static class EC extends KeyPairGeneratorSpi {
        ECKeyGenerationParameters param;

        ECKeyPairGenerator engine = new ECKeyPairGenerator();

        java.security.spec.ECParameterSpec ecParams = null;

        int strength = 239;

        boolean initialised = false;

        String algorithm;

        static private Hashtable ecParameters;

        static {
            ecParameters = new Hashtable();

            ecParameters.put(Integers.valueOf(192), new ECGenParameterSpec(
                    "prime192v1")); // a.k.a P-192
            ecParameters.put(Integers.valueOf(239), new ECGenParameterSpec(
                    "prime239v1"));
            ecParameters.put(Integers.valueOf(256), new ECGenParameterSpec(
                    "prime256v1")); // a.k.a P-256

            ecParameters.put(Integers.valueOf(224), new ECGenParameterSpec(
                    "P-224"));
            ecParameters.put(Integers.valueOf(384), new ECGenParameterSpec(
                    "P-384"));
            ecParameters.put(Integers.valueOf(521), new ECGenParameterSpec(
                    "P-521"));
        }


        public EC() {
            super("EC");
            this.algorithm = "EC";
        }


        public EC(String algorithm) {
            super(algorithm);
            this.algorithm = algorithm;
        }


        public void initialize(int strength, SecureRandom random) {
            this.strength = strength;

            ECGenParameterSpec ecParams = (ECGenParameterSpec) ecParameters.get(Integers.valueOf(strength));
            if( ecParams == null ) {
                throw new InvalidParameterException("unknown key size.");
            }

            try {
                initialize(ecParams, random);
            } catch (InvalidAlgorithmParameterException e) {
                throw new InvalidParameterException(
                        "key size not configurable.");
            }
        }


        public void initialize(AlgorithmParameterSpec params,
                SecureRandom random) throws InvalidAlgorithmParameterException {
            if( params == null ) {
                throw new InvalidAlgorithmParameterException(
                        "null parameter passed but no implicitCA set");
            }
            this.ecParams = (java.security.spec.ECParameterSpec) params;
            this.param = createKeyGenParamsJCE(
                    (java.security.spec.ECParameterSpec) params, random);

            engine.init(param);
            initialised = true;
        }


        public KeyPair generateKeyPair() {
            if( !initialised ) {
                initialize(strength, new SecureRandom());
            }

            AsymmetricCipherKeyPair pair = engine.generateKeyPair();
            ECPublicKeyParameters pub = pair.getPublic();
            ECPrivateKeyParameters priv = pair.getPrivate();

                java.security.spec.ECParameterSpec p = (java.security.spec.ECParameterSpec) ecParams;

                BCECPublicKey pubKey = new BCECPublicKey(algorithm, pub, p);

                return new KeyPair(pubKey, new BCECPrivateKey(algorithm, priv,
                        pubKey, p));
        }


        protected ECKeyGenerationParameters createKeyGenParamsJCE(
                java.security.spec.ECParameterSpec p, SecureRandom r) {
            ECCurve curve = EC5Util.convertCurve(p.getCurve());
            ECPoint g = EC5Util.convertPoint(curve, p.getGenerator());
            BigInteger n = p.getOrder();
            BigInteger h = BigInteger.valueOf(p.getCofactor());
            ECDomainParameters dp = new ECDomainParameters(curve, g, n, h);
            return new ECKeyGenerationParameters(dp, r);
        }
    }

    public static class ECDH extends EC {
        public ECDH() {
            super("ECDH");
        }
    }

}