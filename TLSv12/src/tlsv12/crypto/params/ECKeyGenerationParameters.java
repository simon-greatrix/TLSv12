package tlsv12.crypto.params;

import tlsv12.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

public class ECKeyGenerationParameters extends KeyGenerationParameters {
    private ECDomainParameters domainParams;


    public ECKeyGenerationParameters(ECDomainParameters domainParams,
            SecureRandom random) {
        super(random, domainParams.getN().bitLength());

        this.domainParams = domainParams;
    }


    public ECDomainParameters getDomainParameters() {
        return domainParams;
    }
}
