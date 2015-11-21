package tlsv12.crypto;

import tlsv12.crypto.params.ECPrivateKeyParameters;
import tlsv12.crypto.params.ECPublicKeyParameters;

/**
 * a holding class for public/private parameter pairs.
 */
public class AsymmetricCipherKeyPair
{
    private ECPublicKeyParameters    publicParam;
    private ECPrivateKeyParameters    privateParam;

    /**
     * basic constructor.
     *
     * @param publicParam a public key parameters object.
     * @param privateParam the corresponding private key parameters.
     */
    public AsymmetricCipherKeyPair(
            ECPublicKeyParameters    publicParam,
            ECPrivateKeyParameters    privateParam)
    {
        this.publicParam = publicParam;
        this.privateParam = privateParam;
    }

    

    /**
     * return the public key parameters.
     *
     * @return the public key parameters.
     */
    public ECPublicKeyParameters getPublic()
    {
        return publicParam;
    }

    /**
     * return the private key parameters.
     *
     * @return the private key parameters.
     */
    public ECPrivateKeyParameters getPrivate()
    {
        return privateParam;
    }
}
