package tlsv12.ec;

import tlsv12.asn1.ASN1Primitive;
import tlsv12.asn1.DERBitString;
import tlsv12.asn1.pkcs.PrivateKeyInfo;
import tlsv12.asn1.x509.AlgorithmIdentifier;
import tlsv12.asn1.x509.SubjectPublicKeyInfo;
import tlsv12.asn1.x9.X962Parameters;
import tlsv12.asn1.x9.X9ECParameters;
import tlsv12.asn1.x9.X9ObjectIdentifiers;
import tlsv12.crypto.params.ECDomainParameters;
import tlsv12.crypto.params.ECPrivateKeyParameters;
import tlsv12.math.ec.ECCurve;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public class BCECPrivateKey implements ECPrivateKey {
    static final long serialVersionUID = 994553197664784084L;

    private String algorithm = "EC";

    private transient BigInteger d;

    private transient ECParameterSpec ecSpec;

    private transient DERBitString publicKey;


    protected BCECPrivateKey() {}


    public BCECPrivateKey(String algorithm, ECPrivateKeyParameters params,
            BCECPublicKey pubKey, ECParameterSpec spec) {
        ECDomainParameters dp = params.getParameters();

        this.algorithm = algorithm;
        this.d = params.getD();

        if( spec == null ) {
            EllipticCurve ellipticCurve = EC5Util.convertCurve(dp.getCurve(),
                    dp.getSeed());

            this.ecSpec = new ECParameterSpec(ellipticCurve, new ECPoint(
                    dp.getG().getAffineXCoord().toBigInteger(),
                    dp.getG().getAffineYCoord().toBigInteger()), dp.getN(),
                    dp.getH().intValue());
        } else {
            this.ecSpec = spec;
        }

        publicKey = getPublicKeyDetails(pubKey);
    }


    public String getAlgorithm() {
        return algorithm;
    }


    /**
     * return the encoding format we produce in getEncoded().
     *
     * @return the string "PKCS#8"
     */
    public String getFormat() {
        return "PKCS#8";
    }


    /**
     * Return a PKCS8 representation of the key. The sequence returned
     * represents a full PrivateKeyInfo object.
     *
     * @return a PKCS8 representation of the key.
     */
    public byte[] getEncoded() {

        ECCurve curve = EC5Util.convertCurve(ecSpec.getCurve());

        X9ECParameters ecP = new X9ECParameters(curve, EC5Util.convertPoint(
                curve, ecSpec.getGenerator()), ecSpec.getOrder(),
                BigInteger.valueOf(ecSpec.getCofactor()),
                ecSpec.getCurve().getSeed());

        X962Parameters params = new X962Parameters(ecP);
        int orderBitLength = ECUtil.getOrderBitLength(ecSpec.getOrder(),
                this.getS());

        PrivateKeyInfo info;
        tlsv12.asn1.sec.ECPrivateKey keyStructure;

        if( publicKey != null ) {
            keyStructure = new tlsv12.asn1.sec.ECPrivateKey(orderBitLength,
                    this.getS(), publicKey, params);
        } else {
            keyStructure = new tlsv12.asn1.sec.ECPrivateKey(orderBitLength,
                    this.getS(), params);
        }

        try {
            info = new PrivateKeyInfo(new AlgorithmIdentifier(
                    X9ObjectIdentifiers.id_ecPublicKey, params), keyStructure);

            return info.getEncodedDER();
        } catch (IOException e) {
            return null;
        }
    }


    public ECParameterSpec getParams() {
        return ecSpec;
    }


    tlsv12.ec.ECParameterSpec engineGetSpec() {
        return EC5Util.convertSpec(ecSpec);
    }


    public BigInteger getS() {
        return d;
    }


    public BigInteger getD() {
        return d;
    }


    public boolean equals(Object o) {
        if( !(o instanceof BCECPrivateKey) ) {
            return false;
        }

        BCECPrivateKey other = (BCECPrivateKey) o;

        return getD().equals(other.getD())
                && (engineGetSpec().equals(other.engineGetSpec()));
    }


    public int hashCode() {
        return getD().hashCode() ^ engineGetSpec().hashCode();
    }


    public String toString() {
        StringBuffer buf = new StringBuffer();
        String nl = System.getProperty("line.separator");

        buf.append("EC Private Key").append(nl);
        buf.append("             S: ").append(this.d.toString(16)).append(nl);

        return buf.toString();

    }


    private DERBitString getPublicKeyDetails(BCECPublicKey pub) {
        try {
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(ASN1Primitive.fromByteArray(pub.getEncoded()));

            return info.getPublicKeyData();
        } catch (IOException e) { // should never happen
            return null;
        }
    }


    private void writeObject(ObjectOutputStream out) throws IOException {
        out.defaultWriteObject();

        out.writeObject(this.getEncoded());
    }
}
