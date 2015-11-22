package tlsv12.crypto.params;

import tlsv12.math.ec.ECPoint;

public class ECPublicKeyParameters extends ECKeyParameters {
    ECPoint Q;


    public ECPublicKeyParameters(ECPoint Q, ECDomainParameters params) {
        super(params);
        this.Q = Q.normalize();
    }


    public ECPoint getQ() {
        return Q;
    }
}
