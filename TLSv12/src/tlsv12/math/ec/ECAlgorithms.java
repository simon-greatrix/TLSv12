package tlsv12.math.ec;

import tlsv12.math.field.FiniteField;
import tlsv12.math.field.PolynomialExtensionField;

import java.math.BigInteger;

public class ECAlgorithms {
    public static boolean isF2mCurve(ECCurve c) {
        FiniteField field = c.getField();
        return field.getDimension() > 1
                && field.getCharacteristic().equals(ECConstants.TWO)
                && field instanceof PolynomialExtensionField;
    }


    public static boolean isFpCurve(ECCurve c) {
        return c.getField().getDimension() == 1;
    }


    public static void montgomeryTrick(ECFieldElement[] zs, int off, int len,
            ECFieldElement scale) {
        /*
         * Uses the "Montgomery Trick" to invert many field elements, with only
         * a single actual field inversion. See e.g. the paper:
         * "Fast Multi-scalar Multiplication Methods on Elliptic Curves with Precomputation Strategy Using Montgomery Trick"
         * by Katsuyuki Okeya, Kouichi Sakurai.
         */

        ECFieldElement[] c = new ECFieldElement[len];
        c[0] = zs[off];

        int i = 0;
        while( ++i < len ) {
            c[i] = c[i - 1].multiply(zs[off + i]);
        }

        --i;

        if( scale != null ) {
            c[i] = c[i].multiply(scale);
        }

        ECFieldElement u = c[i].invert();

        while( i > 0 ) {
            int j = off + i--;
            ECFieldElement tmp = zs[j];
            zs[j] = c[i].multiply(u);
            u = u.multiply(tmp);
        }

        zs[off] = u;
    }


    /**
     * Simple shift-and-add multiplication. Serves as reference implementation
     * to verify (possibly faster) implementations, and for very small scalars.
     * 
     * @param p
     *            The point to multiply.
     * @param k
     *            The multiplier.
     * @return The result of the point multiplication <code>kP</code>.
     */
    public static ECPoint referenceMultiply(ECPoint p, BigInteger k) {
        BigInteger x = k.abs();
        ECPoint q = p.getCurve().getInfinity();
        int t = x.bitLength();
        if( t > 0 ) {
            if( x.testBit(0) ) {
                q = p;
            }
            for(int i = 1;i < t;i++) {
                p = p.twice();
                if( x.testBit(i) ) {
                    q = q.add(p);
                }
            }
        }
        return k.signum() < 0 ? q.negate() : q;
    }


    public static ECPoint validatePoint(ECPoint p) {
        if( !p.isValid() ) {
            throw new IllegalArgumentException("Invalid point");
        }

        return p;
    }


    static ECPoint implShamirsTrickWNaf(ECPoint P, BigInteger k, ECPoint Q,
            BigInteger l) {
        boolean negK = k.signum() < 0, negL = l.signum() < 0;

        k = k.abs();
        l = l.abs();

        int widthP = Math.max(2,
                Math.min(16, WNafUtil.getWindowSize(k.bitLength())));
        int widthQ = Math.max(2,
                Math.min(16, WNafUtil.getWindowSize(l.bitLength())));

        WNafPreCompInfo infoP = WNafUtil.precompute(P, widthP, true);
        WNafPreCompInfo infoQ = WNafUtil.precompute(Q, widthQ, true);

        ECPoint[] preCompP = negK ? infoP.getPreCompNeg() : infoP.getPreComp();
        ECPoint[] preCompQ = negL ? infoQ.getPreCompNeg() : infoQ.getPreComp();
        ECPoint[] preCompNegP = negK ? infoP.getPreComp()
                : infoP.getPreCompNeg();
        ECPoint[] preCompNegQ = negL ? infoQ.getPreComp()
                : infoQ.getPreCompNeg();

        byte[] wnafP = WNafUtil.generateWindowNaf(widthP, k);
        byte[] wnafQ = WNafUtil.generateWindowNaf(widthQ, l);

        return implShamirsTrickWNaf(preCompP, preCompNegP, wnafP, preCompQ,
                preCompNegQ, wnafQ);
    }


    static ECPoint implShamirsTrickWNaf(ECPoint P, BigInteger k,
            ECPointMap pointMapQ, BigInteger l) {
        boolean negK = k.signum() < 0, negL = l.signum() < 0;

        k = k.abs();
        l = l.abs();

        int width = Math.max(
                2,
                Math.min(
                        16,
                        WNafUtil.getWindowSize(Math.max(k.bitLength(),
                                l.bitLength()))));

        ECPoint Q = WNafUtil.mapPointWithPrecomp(P, width, true, pointMapQ);
        WNafPreCompInfo infoP = WNafUtil.getWNafPreCompInfo(P);
        WNafPreCompInfo infoQ = WNafUtil.getWNafPreCompInfo(Q);

        ECPoint[] preCompP = negK ? infoP.getPreCompNeg() : infoP.getPreComp();
        ECPoint[] preCompQ = negL ? infoQ.getPreCompNeg() : infoQ.getPreComp();
        ECPoint[] preCompNegP = negK ? infoP.getPreComp()
                : infoP.getPreCompNeg();
        ECPoint[] preCompNegQ = negL ? infoQ.getPreComp()
                : infoQ.getPreCompNeg();

        byte[] wnafP = WNafUtil.generateWindowNaf(width, k);
        byte[] wnafQ = WNafUtil.generateWindowNaf(width, l);

        return implShamirsTrickWNaf(preCompP, preCompNegP, wnafP, preCompQ,
                preCompNegQ, wnafQ);
    }


    private static ECPoint implShamirsTrickWNaf(ECPoint[] preCompP,
            ECPoint[] preCompNegP, byte[] wnafP, ECPoint[] preCompQ,
            ECPoint[] preCompNegQ, byte[] wnafQ) {
        int len = Math.max(wnafP.length, wnafQ.length);

        ECCurve curve = preCompP[0].getCurve();
        ECPoint infinity = curve.getInfinity();

        ECPoint R = infinity;
        int zeroes = 0;

        for(int i = len - 1;i >= 0;--i) {
            int wiP = i < wnafP.length ? wnafP[i] : 0;
            int wiQ = i < wnafQ.length ? wnafQ[i] : 0;

            if( (wiP | wiQ) == 0 ) {
                ++zeroes;
                continue;
            }

            ECPoint r = infinity;
            if( wiP != 0 ) {
                int nP = Math.abs(wiP);
                ECPoint[] tableP = wiP < 0 ? preCompNegP : preCompP;
                r = r.add(tableP[nP >>> 1]);
            }
            if( wiQ != 0 ) {
                int nQ = Math.abs(wiQ);
                ECPoint[] tableQ = wiQ < 0 ? preCompNegQ : preCompQ;
                r = r.add(tableQ[nQ >>> 1]);
            }

            if( zeroes > 0 ) {
                R = R.timesPow2(zeroes);
                zeroes = 0;
            }

            R = R.twicePlus(r);
        }

        if( zeroes > 0 ) {
            R = R.timesPow2(zeroes);
        }

        return R;
    }
}
