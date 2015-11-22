package tlsv12.crypto.params;

import java.math.BigInteger;

public class ECPrivateKeyParameters extends ECKeyParameters {
    BigInteger d;


    public ECPrivateKeyParameters(BigInteger d, ECDomainParameters params) {
        super(params);
        this.d = d;
    }


    public BigInteger getD() {
        return d;
    }
}
