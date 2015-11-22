package tlsv12.math.raw;

import java.math.BigInteger;

public abstract class Nat {
    private static final long M = 0xFFFFFFFFL;


    public static int add(int len, int[] x, int[] y, int[] z) {
        long c = 0;
        for(int i = 0;i < len;++i) {
            c += (x[i] & M) + (y[i] & M);
            z[i] = (int) c;
            c >>>= 32;
        }
        return (int) c;
    }


    public static int addTo(int len, int[] x, int[] z) {
        long c = 0;
        for(int i = 0;i < len;++i) {
            c += (x[i] & M) + (z[i] & M);
            z[i] = (int) c;
            c >>>= 32;
        }
        return (int) c;
    }


    public static int[] copy(int len, int[] x) {
        int[] z = new int[len];
        System.arraycopy(x, 0, z, 0, len);
        return z;
    }


    public static int[] create(int len) {
        return new int[len];
    }


    public static int[] fromBigInteger(int bits, BigInteger x) {
        if( x.signum() < 0 || x.bitLength() > bits ) {
            throw new IllegalArgumentException();
        }

        int len = (bits + 31) >> 5;
        int[] z = create(len);
        int i = 0;
        while( x.signum() != 0 ) {
            z[i++] = x.intValue();
            x = x.shiftRight(32);
        }
        return z;
    }


    public static boolean gte(int len, int[] x, int[] y) {
        for(int i = len - 1;i >= 0;--i) {
            int x_i = x[i] ^ Integer.MIN_VALUE;
            int y_i = y[i] ^ Integer.MIN_VALUE;
            if( x_i < y_i ) return false;
            if( x_i > y_i ) return true;
        }
        return true;
    }


    public static boolean isOne(int len, int[] x) {
        if( x[0] != 1 ) {
            return false;
        }
        for(int i = 1;i < len;++i) {
            if( x[i] != 0 ) {
                return false;
            }
        }
        return true;
    }


    public static boolean isZero(int len, int[] x) {
        for(int i = 0;i < len;++i) {
            if( x[i] != 0 ) {
                return false;
            }
        }
        return true;
    }


    public static int shiftDownBit(int len, int[] z, int c) {
        int i = len;
        while( --i >= 0 ) {
            int next = z[i];
            z[i] = (next >>> 1) | (c << 31);
            c = next;
        }
        return c << 31;
    }


    public static int shiftDownBits(int len, int[] z, int bits, int c) {
        // assert bits > 0 && bits < 32;
        int i = len;
        while( --i >= 0 ) {
            int next = z[i];
            z[i] = (next >>> bits) | (c << -bits);
            c = next;
        }
        return c << -bits;
    }


    public static int shiftDownWord(int len, int[] z, int c) {
        int i = len;
        while( --i >= 0 ) {
            int next = z[i];
            z[i] = c;
            c = next;
        }
        return c;
    }


    public static int subFrom(int len, int[] x, int[] z) {
        long c = 0;
        for(int i = 0;i < len;++i) {
            c += (z[i] & M) - (x[i] & M);
            z[i] = (int) c;
            c >>= 32;
        }
        return (int) c;
    }


    public static BigInteger toBigInteger(int len, int[] x) {
        byte[] bs = new byte[len << 2];
        for(int i = 0;i < len;++i) {
            int x_i = x[i];
            if( x_i != 0 ) {
                intToBigEndian(x_i, bs, (len - 1 - i) << 2);
            }
        }
        return new BigInteger(1, bs);
    }


    public static void intToBigEndian(int n, byte[] bs, int off) {
        bs[off] = (byte) (n >>> 24);
        bs[++off] = (byte) (n >>> 16);
        bs[++off] = (byte) (n >>> 8);
        bs[++off] = (byte) (n);
    }

}
