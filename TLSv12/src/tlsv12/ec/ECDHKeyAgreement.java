package tlsv12.ec;

import javax.crypto.SecretKey;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;

public class ECDHKeyAgreement extends KeyAgreementSpi {

    public ECDHKeyAgreement(ECPrivateKey privateKey) throws InvalidKeyException {
        engineInit(privateKey);
    }


    public void doPhase(ECPublicKey peerPublicKey) throws GeneralSecurityException {
        engineDoPhase(peerPublicKey, true);
    }


    public SecretKey generateSecret(String string) throws NoSuchAlgorithmException {
        return engineGenerateSecret(string);
    }

}
