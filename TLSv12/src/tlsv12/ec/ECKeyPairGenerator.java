package tlsv12.ec;

import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.security.spec.ECParameterSpec;

public class ECKeyPairGenerator extends KeyPairGeneratorSpi.ECDH {

    public void initialize(ECParameterSpec params, SecureRandom random) throws InvalidAlgorithmParameterException {
        super.initialize(params, random);
    }

}
