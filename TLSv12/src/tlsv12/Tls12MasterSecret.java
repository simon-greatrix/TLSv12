package tlsv12;

import javax.crypto.SecretKey;

import java.security.DigestException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;

public class Tls12MasterSecret {

    static int checkVersion(int version) {
        if( (version < 0) || (version > 255) ) {
            throw new IllegalArgumentException(
                    "Version must be between 0 and 255");
        }
        return version;
    }

    /**
     * Parameters for SSL/TLS master secret generation. This class encapsulates
     * the information necessary to calculate a SSL/TLS master secret from the
     * premaster secret and other parameters. It is used to initialize
     * KeyGenerators of the type "TlsMasterSecret".
     *
     * <p>
     * Instances of this class are immutable.
     */
    public static class Spec {

        private final SecretKey premasterSecret;

        private final int majorVersion, minorVersion;

        private final byte[] clientRandom, serverRandom;

        private final String prfHashAlg;

        private final int prfHashLength;

        private final int prfBlockSize;


        /**
         * Constructs a new TlsMasterSecretParameterSpec.
         *
         * <p>
         * The <code>getAlgorithm()</code> method of
         * <code>premasterSecret</code> should return
         * <code>"TlsRsaPremasterSecret"</code> if the key exchange algorithm
         * was RSA and <code>"TlsPremasterSecret"</code> otherwise.
         *
         * @param premasterSecret
         *            the premaster secret
         * @param majorVersion
         *            the major number of the protocol version
         * @param minorVersion
         *            the minor number of the protocol version
         * @param clientRandom
         *            the client's random value
         * @param serverRandom
         *            the server's random value
         * @param prfHashAlg
         *            the name of the TLS PRF hash algorithm to use. Used only
         *            for TLS 1.2+. TLS1.1 and earlier use a fixed PRF.
         * @param prfHashLength
         *            the output length of the TLS PRF hash algorithm. Used only
         *            for TLS 1.2+.
         * @param prfBlockSize
         *            the input block size of the TLS PRF hash algorithm. Used
         *            only for TLS 1.2+.
         *
         * @throws NullPointerException
         *             if premasterSecret, clientRandom, or serverRandom are
         *             null
         * @throws IllegalArgumentException
         *             if minorVersion or majorVersion are negative or larger
         *             than 255
         */
        public Spec(SecretKey premasterSecret, int majorVersion,
                int minorVersion, byte[] clientRandom, byte[] serverRandom,
                String prfHashAlg, int prfHashLength, int prfBlockSize) {
            if( premasterSecret == null ) {
                throw new NullPointerException(
                        "premasterSecret must not be null");
            }
            this.premasterSecret = premasterSecret;
            this.majorVersion = checkVersion(majorVersion);
            this.minorVersion = checkVersion(minorVersion);
            this.clientRandom = clientRandom.clone();
            this.serverRandom = serverRandom.clone();
            this.prfHashAlg = prfHashAlg;
            this.prfHashLength = prfHashLength;
            this.prfBlockSize = prfBlockSize;
        }


        /**
         * Returns the premaster secret.
         *
         * @return the premaster secret.
         */
        public SecretKey getPremasterSecret() {
            return premasterSecret;
        }


        /**
         * Returns the major version number.
         *
         * @return the major version number.
         */
        public int getMajorVersion() {
            return majorVersion;
        }


        /**
         * Returns the minor version number.
         *
         * @return the minor version number.
         */
        public int getMinorVersion() {
            return minorVersion;
        }


        /**
         * Returns a copy of the client's random value.
         *
         * @return a copy of the client's random value.
         */
        public byte[] getClientRandom() {
            return clientRandom.clone();
        }


        /**
         * Returns a copy of the server's random value.
         *
         * @return a copy of the server's random value.
         */
        public byte[] getServerRandom() {
            return serverRandom.clone();
        }


        /**
         * Obtains the PRF hash algorithm to use in the PRF calculation.
         *
         * @return the hash algorithm.
         */
        public String getPRFHashAlg() {
            return prfHashAlg;
        }


        /**
         * Obtains the length of the PRF hash algorithm.
         *
         * @return the hash algorithm length.
         */
        public int getPRFHashLength() {
            return prfHashLength;
        }


        /**
         * Obtains the block size of the PRF hash algorithm.
         *
         * @return the hash algorithm block size.
         */
        public int getPRFBlockSize() {
            return prfBlockSize;
        }
    }

    private Spec spec;

    private int protocolVersion;


    public Tls12MasterSecret(Spec params)
            throws InvalidAlgorithmParameterException {
        this.spec = params;
        if( "RAW".equals(spec.getPremasterSecret().getFormat()) == false ) {
            throw new InvalidAlgorithmParameterException(
                    "Key format must be RAW");
        }
        protocolVersion = (spec.getMajorVersion() << 8)
                | spec.getMinorVersion();
        if( (protocolVersion < 0x0300) || (protocolVersion > 0x0303) ) {
            throw new InvalidAlgorithmParameterException(
                    "Only SSL 3.0, TLS 1.0/1.1/1.2 supported");
        }
    }


    public TlsMasterSecretKey generateKey() throws NoSuchAlgorithmException,
            DigestException {
        if( spec == null ) {
            throw new IllegalStateException(
                    "TlsMasterSecretGenerator must be initialized");
        }
        SecretKey premasterKey = spec.getPremasterSecret();
        byte[] premaster = premasterKey.getEncoded();

        int premasterMajor, premasterMinor;
        if( premasterKey.getAlgorithm().equals("TlsRsaPremasterSecret") ) {
            // RSA
            premasterMajor = premaster[0] & 0xff;
            premasterMinor = premaster[1] & 0xff;
        } else {
            // DH, KRB5, others
            premasterMajor = -1;
            premasterMinor = -1;
        }

        byte[] master;
        byte[] clientRandom = spec.getClientRandom();
        byte[] serverRandom = spec.getServerRandom();

        if( protocolVersion >= 0x0301 ) {
            byte[] seed = Tls12Material.concat(clientRandom, serverRandom);
            master = Tls12Prf.doTLS12PRF(premaster,
                    Tls12Prf.LABEL_MASTER_SECRET, seed, 48,
                    spec.getPRFHashAlg(), spec.getPRFHashLength(),
                    spec.getPRFBlockSize());
        } else {
            throw new IllegalStateException("Invalid protocol version: "
                    + Integer.toHexString(protocolVersion));
        }

        return new TlsMasterSecretKey(master, premasterMajor, premasterMinor);
    }

    public static final class TlsMasterSecretKey implements SecretKey {
        private static final long serialVersionUID = 1l;

        private byte[] key;

        TlsMasterSecretKey(byte[] key, int majorVersion, int minorVersion) {
            this.key = key;
        }


        public String getAlgorithm() {
            return "TlsMasterSecret";
        }


        public String getFormat() {
            return "RAW";
        }


        public byte[] getEncoded() {
            return key.clone();
        }

    }

}
