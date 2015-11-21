package tlsv12;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;

/**
 * KeyGenerator implementation for the SSL/TLS master secret derivation.
 *
 */
public final class Tls12Material {

    public static class KeyMaterial implements SecretKey {

        static final long serialVersionUID = 812912859129525028L;

        private final SecretKey clientMacKey, serverMacKey;

        private final SecretKey clientCipherKey, serverCipherKey;

        private final IvParameterSpec clientIv, serverIv;


        /**
         * Constructs a new TlsKeymaterialSpec from the client and server MAC
         * keys. This call is equivalent to
         * <code>new TlsKeymaterialSpec(clientMacKey, serverMacKey,
         * null, null, null, null)</code>.
         *
         * @param clientMacKey
         *            the client MAC key
         * @param serverMacKey
         *            the server MAC key
         * @throws NullPointerException
         *             if clientMacKey or serverMacKey is null
         */
        public KeyMaterial(SecretKey clientMacKey, SecretKey serverMacKey) {
            this(clientMacKey, serverMacKey, null, null, null, null);
        }


        /**
         * Constructs a new TlsKeymaterialSpec from the client and server MAC
         * keys, client and server cipher keys, and client and server
         * initialization vectors.
         *
         * @param clientMacKey
         *            the client MAC key
         * @param serverMacKey
         *            the server MAC key
         * @param clientCipherKey
         *            the client cipher key (or null)
         * @param clientIv
         *            the client initialization vector (or null)
         * @param serverCipherKey
         *            the server cipher key (or null)
         * @param serverIv
         *            the server initialization vector (or null)
         *
         * @throws NullPointerException
         *             if clientMacKey or serverMacKey is null
         */
        public KeyMaterial(SecretKey clientMacKey, SecretKey serverMacKey,
                SecretKey clientCipherKey, IvParameterSpec clientIv,
                SecretKey serverCipherKey, IvParameterSpec serverIv) {
            if( (clientMacKey == null) || (serverMacKey == null) ) {
                throw new NullPointerException("MAC keys must not be null");
            }
            this.clientMacKey = clientMacKey;
            this.serverMacKey = serverMacKey;
            this.clientCipherKey = clientCipherKey;
            this.serverCipherKey = serverCipherKey;
            this.clientIv = clientIv;
            this.serverIv = serverIv;
        }


        /**
         * Returns <code>TlsKeyMaterial</code>.
         *
         * @return <code>TlsKeyMaterial</code>.
         */
        public String getAlgorithm() {
            return "TlsKeyMaterial";
        }


        /**
         * Returns <code>null</code> because keys of this type have no encoding.
         *
         * @return <code>null</code> because keys of this type have no encoding.
         */
        public String getFormat() {
            return null;
        }


        /**
         * Returns <code>null</code> because keys of this type have no encoding.
         *
         * @return <code>null</code> because keys of this type have no encoding.
         */
        public byte[] getEncoded() {
            return null;
        }


        /**
         * Returns the client MAC key.
         *
         * @return the client MAC key.
         */
        public SecretKey getClientMacKey() {
            return clientMacKey;
        }


        /**
         * Return the server MAC key.
         *
         * @return the server MAC key.
         */
        public SecretKey getServerMacKey() {
            return serverMacKey;
        }


        /**
         * Return the client cipher key (or null).
         *
         * @return the client cipher key (or null).
         */
        public SecretKey getClientCipherKey() {
            return clientCipherKey;
        }


        /**
         * Return the client initialization vector (or null).
         *
         * @return the client initialization vector (or null).
         */
        public IvParameterSpec getClientIv() {
            return clientIv;
        }


        /**
         * Return the server cipher key (or null).
         *
         * @return the server cipher key (or null).
         */
        public SecretKey getServerCipherKey() {
            return serverCipherKey;
        }


        /**
         * Return the server initialization vector (or null).
         *
         * @return the server initialization vector (or null).
         */
        public IvParameterSpec getServerIv() {
            return serverIv;
        }

    }

    public static class Spec {
        private final SecretKey masterSecret;

        private final int majorVersion, minorVersion;

        private final byte[] clientRandom, serverRandom;

        private final String cipherAlgorithm;

        private final int cipherKeyLength, ivLength, macKeyLength;

        private final int expandedCipherKeyLength; // == 0 for domestic
                                                   // ciphersuites

        private final String prfHashAlg;

        private final int prfHashLength;

        private final int prfBlockSize;


        /**
         * Constructs a new spec.
         *
         * @param masterSecret
         *            the master secret
         * @param majorVersion
         *            the major number of the protocol version
         * @param minorVersion
         *            the minor number of the protocol version
         * @param clientRandom
         *            the client's random value
         * @param serverRandom
         *            the server's random value
         * @param cipherAlgorithm
         *            the algorithm name of the cipher keys to be generated
         * @param cipherKeyLength
         *            if 0, no cipher keys will be generated; otherwise, the
         *            length in bytes of cipher keys to be generated for
         *            domestic cipher suites; for cipher suites defined as
         *            exportable, the number of key material bytes to be
         *            generated;
         * @param expandedCipherKeyLength
         *            0 for domestic cipher suites; for exportable cipher suites
         *            the length in bytes of the key to be generated.
         * @param ivLength
         *            the length in bytes of the initialization vector to be
         *            generated, or 0 if no initialization vector is required
         * @param macKeyLength
         *            the length in bytes of the MAC key to be generated
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
         *             if masterSecret, clientRandom, serverRandom, or
         *             cipherAlgorithm are null
         * @throws IllegalArgumentException
         *             if the algorithm of masterSecret is not TlsMasterSecret,
         *             or if majorVersion or minorVersion are negative or larger
         *             than 255; or if cipherKeyLength, expandedKeyLength,
         *             ivLength, or macKeyLength are negative
         */
        public Spec(SecretKey masterSecret, int majorVersion, int minorVersion,
                byte[] clientRandom, byte[] serverRandom,
                String cipherAlgorithm, int cipherKeyLength,
                int expandedCipherKeyLength, int ivLength, int macKeyLength,
                String prfHashAlg, int prfHashLength, int prfBlockSize) {
            if( masterSecret.getAlgorithm().equals("TlsMasterSecret") == false ) {
                throw new IllegalArgumentException("Not a TLS master secret");
            }
            if( cipherAlgorithm == null ) {
                throw new NullPointerException();
            }
            this.masterSecret = masterSecret;
            this.majorVersion = Tls12MasterSecret.checkVersion(majorVersion);
            this.minorVersion = Tls12MasterSecret.checkVersion(minorVersion);
            this.clientRandom = clientRandom.clone();
            this.serverRandom = serverRandom.clone();
            this.cipherAlgorithm = cipherAlgorithm;
            this.cipherKeyLength = checkSign(cipherKeyLength);
            this.expandedCipherKeyLength = checkSign(expandedCipherKeyLength);
            this.ivLength = checkSign(ivLength);
            this.macKeyLength = checkSign(macKeyLength);
            this.prfHashAlg = prfHashAlg;
            this.prfHashLength = prfHashLength;
            this.prfBlockSize = prfBlockSize;
        }


        private static int checkSign(int k) {
            if( k < 0 ) {
                throw new IllegalArgumentException("Value must not be negative");
            }
            return k;
        }


        /**
         * Returns the master secret.
         *
         * @return the master secret.
         */
        public SecretKey getMasterSecret() {
            return masterSecret;
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
         * Returns the cipher algorithm.
         *
         * @return the cipher algorithm.
         */
        public String getCipherAlgorithm() {
            return cipherAlgorithm;
        }


        /**
         * Returns the length in bytes of the encryption key to be generated.
         *
         * @return the length in bytes of the encryption key to be generated.
         */
        public int getCipherKeyLength() {
            return cipherKeyLength;
        }


        /**
         * Returns the length in bytes of the expanded encryption key to be
         * generated. Returns zero if the expanded encryption key is not
         * supposed to be generated.
         *
         * @return the length in bytes of the expanded encryption key to be
         *         generated.
         */
        public int getExpandedCipherKeyLength() {
            // TLS v1.1 disables the exportable weak cipher suites.
            if( majorVersion >= 0x03 && minorVersion >= 0x02 ) {
                return 0;
            }
            return expandedCipherKeyLength;
        }


        /**
         * Returns the length in bytes of the initialization vector to be
         * generated. Returns zero if the initialization vector is not supposed
         * to be generated.
         *
         * @return the length in bytes of the initialization vector to be
         *         generated.
         */
        public int getIvLength() {
            // TLS v1.1 or later uses an explicit IV to protect against
            // the CBC attacks.
            if( majorVersion >= 0x03 && minorVersion >= 0x02 ) {
                return 0;
            }

            return ivLength;
        }


        /**
         * Returns the length in bytes of the MAC key to be generated.
         *
         * @return the length in bytes of the MAC key to be generated.
         */
        public int getMacKeyLength() {
            return macKeyLength;
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
         * @return the hash algorithm block size
         */
        public int getPRFBlockSize() {
            return prfBlockSize;
        }
    }


    static byte[] concat(byte[] b1, byte[] b2) {
        int n1 = b1.length;
        int n2 = b2.length;
        byte[] b = new byte[n1 + n2];
        System.arraycopy(b1, 0, b, 0, n1);
        System.arraycopy(b2, 0, b, n1, n2);
        return b;
    }

    private Spec spec;

    private int protocolVersion;


    public Tls12Material(Spec params) throws InvalidAlgorithmParameterException {
        this.spec = params;
        if( "RAW".equals(spec.getMasterSecret().getFormat()) == false ) {
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


    public KeyMaterial generateKey() throws GeneralSecurityException {
        if( spec == null ) {
            throw new IllegalStateException(
                    "TlsKeyMaterialGenerator must be initialized");
        }

        byte[] masterSecret = spec.getMasterSecret().getEncoded();

        byte[] clientRandom = spec.getClientRandom();
        byte[] serverRandom = spec.getServerRandom();

        SecretKey clientMacKey = null;
        SecretKey serverMacKey = null;
        SecretKey clientCipherKey = null;
        SecretKey serverCipherKey = null;
        IvParameterSpec clientIv = null;
        IvParameterSpec serverIv = null;

        int macLength = spec.getMacKeyLength();
        int expandedKeyLength = spec.getExpandedCipherKeyLength();
        boolean isExportable = (expandedKeyLength != 0);
        int keyLength = spec.getCipherKeyLength();
        int ivLength = spec.getIvLength();

        int keyBlockLen = macLength + keyLength + (isExportable ? 0 : ivLength);
        keyBlockLen <<= 1;
        byte[] keyBlock = new byte[keyBlockLen];

        // generate key block
        if( protocolVersion >= 0x0303 ) {
            // TLS 1.2
            byte[] seed = concat(serverRandom, clientRandom);
            keyBlock = Tls12Prf.doTLS12PRF(masterSecret,
                    Tls12Prf.LABEL_KEY_EXPANSION, seed, keyBlockLen,
                    spec.getPRFHashAlg(), spec.getPRFHashLength(),
                    spec.getPRFBlockSize());
        } else {
            throw new GeneralSecurityException(
                    "Only TLS1.2 or higher supported, not "
                            + Integer.toHexString(protocolVersion));
        }

        // partition keyblock into individual secrets

        int ofs = 0;
        byte[] tmp = new byte[macLength];

        // mac keys
        System.arraycopy(keyBlock, ofs, tmp, 0, macLength);
        ofs += macLength;
        clientMacKey = new SecretKeySpec(tmp, "Mac");

        System.arraycopy(keyBlock, ofs, tmp, 0, macLength);
        ofs += macLength;
        serverMacKey = new SecretKeySpec(tmp, "Mac");

        if( keyLength == 0 ) { // SSL_RSA_WITH_NULL_* ciphersuites
            return new KeyMaterial(clientMacKey, serverMacKey);
        }

        String alg = spec.getCipherAlgorithm();

        // cipher keys
        byte[] clientKeyBytes = new byte[keyLength];
        System.arraycopy(keyBlock, ofs, clientKeyBytes, 0, keyLength);
        ofs += keyLength;

        byte[] serverKeyBytes = new byte[keyLength];
        System.arraycopy(keyBlock, ofs, serverKeyBytes, 0, keyLength);
        ofs += keyLength;

        if( isExportable == false ) {
            // cipher keys
            clientCipherKey = new SecretKeySpec(clientKeyBytes, alg);
            serverCipherKey = new SecretKeySpec(serverKeyBytes, alg);

            // IV keys if needed.
            if( ivLength != 0 ) {
                tmp = new byte[ivLength];

                System.arraycopy(keyBlock, ofs, tmp, 0, ivLength);
                ofs += ivLength;
                clientIv = new IvParameterSpec(tmp);

                System.arraycopy(keyBlock, ofs, tmp, 0, ivLength);
                ofs += ivLength;
                serverIv = new IvParameterSpec(tmp);
            }
        } else {
            // if exportable suites, calculate the alternate
            // cipher key expansion and IV generation
            if( protocolVersion >= 0x0302 ) {
                // TLS 1.1+
                throw new RuntimeException(
                        "Internal Error:  TLS 1.1+ should not be negotiating"
                                + "exportable ciphersuites");
            }
        }

        return new KeyMaterial(clientMacKey, serverMacKey, clientCipherKey,
                clientIv, serverCipherKey, serverIv);
    }

}