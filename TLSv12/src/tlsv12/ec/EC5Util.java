package tlsv12.ec;

import tlsv12.math.ec.ECAlgorithms;
import tlsv12.math.ec.ECCurve;

import java.math.BigInteger;
import java.security.spec.*;

public class EC5Util {

    public static EllipticCurve convertCurve(ECCurve curve, byte[] seed) {
        // TODO: the Sun EC implementation doesn't currently handle the seed
        // properly
        // so at the moment it's set to null. Should probably look at making
        // this configurable
        if( ECAlgorithms.isFpCurve(curve) ) {
            return new EllipticCurve(new ECFieldFp(
                    curve.getField().getCharacteristic()),
                    curve.getA().toBigInteger(), curve.getB().toBigInteger(),
                    null);
        } else {
            ECCurve.F2m curveF2m = (ECCurve.F2m) curve;
            int ks[];

            if( curveF2m.isTrinomial() ) {
                ks = new int[] { curveF2m.getK1() };

                return new EllipticCurve(new ECFieldF2m(curveF2m.getM(), ks),
                        curve.getA().toBigInteger(),
                        curve.getB().toBigInteger(), null);
            } else {
                ks = new int[] { curveF2m.getK3(), curveF2m.getK2(),
                        curveF2m.getK1() };

                return new EllipticCurve(new ECFieldF2m(curveF2m.getM(), ks),
                        curve.getA().toBigInteger(),
                        curve.getB().toBigInteger(), null);
            }
        }
    }


    public static ECCurve convertCurve(EllipticCurve ec) {
        ECField field = ec.getField();
        BigInteger a = ec.getA();
        BigInteger b = ec.getB();

        if( field instanceof ECFieldFp ) {
            ECCurve.Fp curve = new ECCurve.Fp(((ECFieldFp) field).getP(), a, b);
            return curve;
        } else {
            ECFieldF2m fieldF2m = (ECFieldF2m) field;
            int m = fieldF2m.getM();
            int ks[] = ECUtil.convertMidTerms(fieldF2m.getMidTermsOfReductionPolynomial());
            return new ECCurve.F2m(m, ks[0], ks[1], ks[2], a, b);
        }
    }


    public static tlsv12.ec.ECParameterSpec convertSpec(
            java.security.spec.ECParameterSpec ecSpec) {
        ECCurve curve = convertCurve(ecSpec.getCurve());

        return new tlsv12.ec.ECParameterSpec(curve, convertPoint(curve,
                ecSpec.getGenerator()), ecSpec.getOrder(),
                BigInteger.valueOf(ecSpec.getCofactor()),
                ecSpec.getCurve().getSeed());
    }


    public static tlsv12.math.ec.ECPoint convertPoint(
            java.security.spec.ECParameterSpec ecSpec, ECPoint point) {
        return convertPoint(convertCurve(ecSpec.getCurve()), point);
    }


    public static tlsv12.math.ec.ECPoint convertPoint(ECCurve curve,
            ECPoint point) {
        return curve.createPoint(point.getAffineX(), point.getAffineY(), false);
    }
}
