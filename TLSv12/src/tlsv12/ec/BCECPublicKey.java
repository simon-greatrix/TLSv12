package tlsv12.ec;

import tlsv12.asn1.ASN1OctetString;
import tlsv12.asn1.x509.AlgorithmIdentifier;
import tlsv12.asn1.x509.SubjectPublicKeyInfo;
import tlsv12.asn1.x9.X962Parameters;
import tlsv12.asn1.x9.X9ECParameters;
import tlsv12.asn1.x9.X9ECPoint;
import tlsv12.asn1.x9.X9ObjectIdentifiers;
import tlsv12.crypto.params.ECDomainParameters;
import tlsv12.crypto.params.ECPublicKeyParameters;
import tlsv12.math.ec.ECCurve;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public class BCECPublicKey implements ECPublicKey {
    static final long serialVersionUID = 2422789860422731812L;

    private String algorithm = "EC";

    private transient tlsv12.math.ec.ECPoint q;

    private transient ECParameterSpec ecSpec;


    public BCECPublicKey(String algorithm, ECPublicKeyParameters params,
            ECParameterSpec spec) {
        ECDomainParameters dp = params.getParameters();

        this.algorithm = algorithm;
        this.q = params.getQ();

        if( spec == null ) {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(),
                    dp.getSeed());

            this.ecSpec = createSpec(ellipticCurve, dp);
        } else {
            this.ecSpec = spec;
        }
    }


    private ECParameterSpec createSpec(EllipticCurve ellipticCurve,
            ECDomainParameters dp) {
        return new ECParameterSpec(ellipticCurve, new ECPoint(
                dp.getG().getAffineXCoord().toBigInteger(),
                dp.getG().getAffineYCoord().toBigInteger()), dp.getN(),
                dp.getH().intValue());
    }


    public String getAlgorithm() {
        return algorithm;
    }


    public String getFormat() {
        return "X.509";
    }


    public byte[] getEncoded() {
        X962Parameters params;
        SubjectPublicKeyInfo info;

        ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());

        X9ECParameters ecP = new X9ECParameters(curve, EC5Util.convertPoint(
                curve, ecSpec.getGenerator()), ecSpec.getOrder(),
                BigInteger.valueOf(ecSpec.getCofactor()),
                ecSpec.getCurve().getSeed());

        params = new X962Parameters(ecP);

        curve = this.engineGetQ().getCurve();
        ASN1OctetString p = (ASN1OctetString) new X9ECPoint(curve.createPoint(
                this.getQ().getAffineXCoord().toBigInteger(),
                this.getQ().getAffineYCoord().toBigInteger(), false)).toASN1Primitive();

        info = new SubjectPublicKeyInfo(new AlgorithmIdentifier(
                X9ObjectIdentifiers.id_ecPublicKey, params), p.getOctets());

        return KeyUtil.getEncodedSubjectPublicKeyInfo(info);
    }


    public ECParameterSpec getParams() {
        return ecSpec;
    }


    public ECPoint getW() {
        return new ECPoint(q.getAffineXCoord().toBigInteger(),
                q.getAffineYCoord().toBigInteger());
    }


    public tlsv12.math.ec.ECPoint getQ() {
        if( ecSpec == null ) {
            return q.getDetachedPoint();
        }

        return q;
    }


    public tlsv12.math.ec.ECPoint engineGetQ() {
        return q;
    }


    tlsv12.ec.ECParameterSpec engineGetSpec() {
        return EC5Util.convertSpec(ecSpec);
    }


    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = System.getProperty("line.separator");

        buf.append("EC Public Key").append(nl);
        buf.append("            X: ").append(
                this.q.getAffineXCoord().toBigInteger().toString(16)).append(nl);
        buf.append("            Y: ").append(
                this.q.getAffineYCoord().toBigInteger().toString(16)).append(nl);

        return buf.toString();

    }


    public boolean equals(Object o) {
        if( !(o instanceof BCECPublicKey) ) {
            return false;
        }

        BCECPublicKey other = (BCECPublicKey) o;

        return engineGetQ().equals(other.engineGetQ())
                && (engineGetSpec().equals(other.engineGetSpec()));
    }


    public int hashCode() {
        return engineGetQ().hashCode() ^ engineGetSpec().hashCode();
    }


    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
