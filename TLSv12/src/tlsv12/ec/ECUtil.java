package tlsv12.ec;

import tlsv12.crypto.params.ECDomainParameters;
import tlsv12.crypto.params.ECPrivateKeyParameters;
import tlsv12.crypto.params.ECPublicKeyParameters;

import java.math.BigInteger;

/**
 * utility class for converting jce/jca ECDSA, ECDH, and ECDHC objects into
 * their org.bouncycastle.crypto counterparts.
 */
public class ECUtil {
    /**
     * Returns a sorted array of middle terms of the reduction polynomial.
     * 
     * @param k
     *            The unsorted array of middle terms of the reduction polynomial
     *            of length 1 or 3.
     * @return the sorted array of middle terms of the reduction polynomial.
     *         This array always has length 3.
     */
    static int[] convertMidTerms(int[] k) {
        int[] res = new int[3];

        if( k.length == 1 ) {
            res[0] = k[0];
        } else {
            if( k.length != 3 ) {
                throw new IllegalArgumentException(
                        "Only Trinomials and pentanomials supported");
            }

            if( k[0] < k[1] && k[0] < k[2] ) {
                res[0] = k[0];
                if( k[1] < k[2] ) {
                    res[1] = k[1];
                    res[2] = k[2];
                } else {
                    res[1] = k[2];
                    res[2] = k[1];
                }
            } else if( k[1] < k[2] ) {
                res[0] = k[1];
                if( k[0] < k[2] ) {
                    res[1] = k[0];
                    res[2] = k[2];
                } else {
                    res[1] = k[2];
                    res[2] = k[0];
                }
            } else {
                res[0] = k[2];
                if( k[0] < k[1] ) {
                    res[1] = k[0];
                    res[2] = k[1];
                } else {
                    res[1] = k[1];
                    res[2] = k[0];
                }
            }
        }

        return res;
    }


    public static ECPublicKeyParameters generatePublicKeyParameter(
            java.security.interfaces.ECPublicKey pubKey) {

        ECParameterSpec s = EC5Util.convertSpec(pubKey.getParams());
        return new ECPublicKeyParameters(EC5Util.convertPoint(
                pubKey.getParams(), pubKey.getW()), new ECDomainParameters(
                s.getCurve(), s.getG(), s.getN(), s.getH(), s.getSeed()));
    }


    public static ECPrivateKeyParameters generatePrivateKeyParameter(
            java.security.interfaces.ECPrivateKey privKey) {
        ECParameterSpec s = EC5Util.convertSpec(privKey.getParams());
        return new ECPrivateKeyParameters(privKey.getS(),
                new ECDomainParameters(s.getCurve(), s.getG(), s.getN(),
                        s.getH(), s.getSeed()));
    }


    public static int getOrderBitLength(BigInteger order,
            BigInteger privateValue) {
        if( order == null ) // implicitly CA
        {
            return privateValue.bitLength(); // a guess but better than an
                                             // exception!
        } else {
            return order.bitLength();
        }
    }

}
