package tlsv12;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.security.*;
import java.util.Arrays;

/**
 * KeyGenerator implementation for the TLS PRF function.
 * <p>
 * This class duplicates the HMAC functionality (RFC 2104) with performance
 * optimizations (e.g. XOR'ing keys with padding doesn't need to be redone for
 * each HMAC operation).
 *
 */
class Tls12Prf {

    public static class Spec {
        private final SecretKey secret;

        private final String label;

        private final byte[] seed;

        private final int outputLength;

        private final String prfHashAlg;

        private final int prfHashLength;

        private final int prfBlockSize;


        /**
         * Constructs a new TlsPrfParameterSpec.
         *
         * @param secret
         *            the secret to use in the calculation (or null)
         * @param label
         *            the label to use in the calculation
         * @param seed
         *            the random seed to use in the calculation
         * @param outputLength
         *            the length in bytes of the output key to be produced
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
         *             if label or seed is null
         * @throws IllegalArgumentException
         *             if outputLength is negative
         */
        public Spec(SecretKey secret, String label, byte[] seed,
                int outputLength, String prfHashAlg, int prfHashLength,
                int prfBlockSize) {
            if( (label == null) || (seed == null) ) {
                throw new NullPointerException(
                        "label and seed must not be null");
            }
            if( outputLength <= 0 ) {
                throw new IllegalArgumentException(
                        "outputLength must be positive");
            }
            this.secret = secret;
            this.label = label;
            this.seed = seed.clone();
            this.outputLength = outputLength;
            this.prfHashAlg = prfHashAlg;
            this.prfHashLength = prfHashLength;
            this.prfBlockSize = prfBlockSize;
        }


        /**
         * Returns the secret to use in the PRF calculation, or null if there is
         * no secret.
         *
         * @return the secret to use in the PRF calculation, or null if there is
         *         no secret.
         */
        public SecretKey getSecret() {
            return secret;
        }


        /**
         * Returns the label to use in the PRF calcuation.
         *
         * @return the label to use in the PRF calcuation.
         */
        public String getLabel() {
            return label;
        }


        /**
         * Returns a copy of the seed to use in the PRF calcuation.
         *
         * @return a copy of the seed to use in the PRF calcuation.
         */
        public byte[] getSeed() {
            return seed.clone();
        }


        /**
         * Returns the length in bytes of the output key to be produced.
         *
         * @return the length in bytes of the output key to be produced.
         */
        public int getOutputLength() {
            return outputLength;
        }


        /**
         * Obtains the PRF hash algorithm to use in the PRF calculation.
         *
         * @return the hash algorithm, or null if no algorithm was specified.
         */
        public String getPRFHashAlg() {
            return prfHashAlg;
        }


        /**
         * Obtains the length of PRF hash algorithm.
         *
         * It would have been preferred to use MessageDigest.getDigestLength(),
         * but the API does not require implementations to support the method.
         *
         * @return the hash algorithm length.
         */
        public int getPRFHashLength() {
            return prfHashLength;
        }


        /**
         * Obtains the length of PRF hash algorithm.
         *
         * @return the hash algorithm length.
         */
        public int getPRFBlockSize() {
            return prfBlockSize;
        }
    }

    // magic constants and utility functions, also used by other files
    // in this package

    private final static byte[] B0 = new byte[0];

    final static byte[] LABEL_MASTER_SECRET = // "master secret"
    { 109, 97, 115, 116, 101, 114, 32, 115, 101, 99, 114, 101, 116 };

    final static byte[] LABEL_KEY_EXPANSION = // "key expansion"
    { 107, 101, 121, 32, 101, 120, 112, 97, 110, 115, 105, 111, 110 };

    /*
     * TLS HMAC "inner" and "outer" padding. This isn't a function of the digest
     * algorithm.
     */
    private static final byte[] HMAC_ipad64 = genPad((byte) 0x36, 64);

    private static final byte[] HMAC_ipad128 = genPad((byte) 0x36, 128);

    private static final byte[] HMAC_opad64 = genPad((byte) 0x5c, 64);

    private static final byte[] HMAC_opad128 = genPad((byte) 0x5c, 128);


    private static byte[] genPad(byte b, int count) {
        byte[] padding = new byte[count];
        Arrays.fill(padding, b);
        return padding;
    }

    private Spec spec;


    public Tls12Prf(Spec params) throws InvalidAlgorithmParameterException {
        this.spec = params;
        SecretKey key = spec.getSecret();
        if( (key != null) && (!"RAW".equals(key.getFormat())) ) {
            throw new InvalidAlgorithmParameterException(
                    "Key encoding format must be RAW");
        }
    }


    public SecretKey generateKey() {
        if( spec == null ) {
            throw new IllegalStateException(
                    "TlsPrfGenerator must be initialized");
        }
        SecretKey key = spec.getSecret();
        byte[] secret = (key == null) ? null : key.getEncoded();
        try {
            byte[] labelBytes = spec.getLabel().getBytes("UTF8");
            int n = spec.getOutputLength();
            byte[] prfBytes = doTLS12PRF(secret, labelBytes, spec.getSeed(), n,
                    spec.getPRFHashAlg(), spec.getPRFHashLength(),
                    spec.getPRFBlockSize());
            return new SecretKeySpec(prfBytes, "TlsPrf");
        } catch (GeneralSecurityException e) {
            throw new ProviderException("Could not generate PRF", e);
        } catch (java.io.UnsupportedEncodingException e) {
            throw new ProviderException("Could not generate PRF", e);
        }
    }


    static byte[] doTLS12PRF(byte[] secret, byte[] labelBytes, byte[] seed,
            int outputLength, String prfHash, int prfHashLength,
            int prfBlockSize) throws NoSuchAlgorithmException, DigestException {
        if( prfHash == null ) {
            throw new NoSuchAlgorithmException("Unspecified PRF algorithm");
        }
        MessageDigest prfMD = MessageDigest.getInstance(prfHash);
        return doTLS12PRF(secret, labelBytes, seed, outputLength, prfMD,
                prfHashLength, prfBlockSize);
    }


    private static byte[] doTLS12PRF(byte[] secret, byte[] labelBytes,
            byte[] seed, int outputLength, MessageDigest mdPRF, int mdPRFLen,
            int mdPRFBlockSize) throws DigestException {

        if( secret == null ) {
            secret = B0;
        }

        // If we have a long secret, digest it first.
        if( secret.length > mdPRFBlockSize ) {
            secret = mdPRF.digest(secret);
        }

        byte[] output = new byte[outputLength];
        byte[] ipad;
        byte[] opad;

        switch (mdPRFBlockSize) {
        case 64:
            ipad = HMAC_ipad64.clone();
            opad = HMAC_opad64.clone();
            break;
        case 128:
            ipad = HMAC_ipad128.clone();
            opad = HMAC_opad128.clone();
            break;
        default:
            throw new DigestException("Unexpected block size.");
        }

        // P_HASH(Secret, label + seed)
        expand(mdPRF, mdPRFLen, secret, 0, secret.length, labelBytes, seed,
                output, ipad, opad);

        return output;
    }


    /*
     * @param digest the MessageDigest to produce the HMAC
     * 
     * @param hmacSize the HMAC size
     * 
     * @param secret the secret
     * 
     * @param secOff the offset into the secret
     * 
     * @param secLen the secret length
     * 
     * @param label the label
     * 
     * @param seed the seed
     * 
     * @param output the output array
     */
    private static void expand(MessageDigest digest, int hmacSize,
            byte[] secret, int secOff, int secLen, byte[] label, byte[] seed,
            byte[] output, byte[] pad1, byte[] pad2) throws DigestException {
        /*
         * modify the padding used, by XORing the key into our copy of that
         * padding. That's to avoid doing that for each HMAC computation.
         */
        for(int i = 0;i < secLen;i++) {
            pad1[i] ^= secret[i + secOff];
            pad2[i] ^= secret[i + secOff];
        }

        byte[] tmp = new byte[hmacSize];
        byte[] aBytes = null;

        /*
         * compute:
         * 
         * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
         * HMAC_hash(secret, A(2) + seed) + HMAC_hash(secret, A(3) + seed) + ...
         * A() is defined as:
         * 
         * A(0) = seed A(i) = HMAC_hash(secret, A(i-1))
         */
        int remaining = output.length;
        int ofs = 0;
        while( remaining > 0 ) {
            /*
             * compute A() ...
             */
            // inner digest
            digest.update(pad1);
            if( aBytes == null ) {
                digest.update(label);
                digest.update(seed);
            } else {
                digest.update(aBytes);
            }
            digest.digest(tmp, 0, hmacSize);

            // outer digest
            digest.update(pad2);
            digest.update(tmp);
            if( aBytes == null ) {
                aBytes = new byte[hmacSize];
            }
            digest.digest(aBytes, 0, hmacSize);

            /*
             * compute HMAC_hash() ...
             */
            // inner digest
            digest.update(pad1);
            digest.update(aBytes);
            digest.update(label);
            digest.update(seed);
            digest.digest(tmp, 0, hmacSize);

            // outer digest
            digest.update(pad2);
            digest.update(tmp);
            digest.digest(tmp, 0, hmacSize);

            int k = Math.min(hmacSize, remaining);
            for(int i = 0;i < k;i++) {
                output[ofs++] ^= tmp[i];
            }
            remaining -= k;
        }
    }
}
