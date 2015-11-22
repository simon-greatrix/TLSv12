package tlsv12.ec;

import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

public class ECKeyFactory {

    public static class ECPublicKeyImpl implements ECPublicKey {

        private static final long serialVersionUID = -2462037275160462289L;

        private ECPoint w;

        private ECParameterSpec params;


        /**
         * Construct a key from its components. Used by the ECKeyFactory and
         * SunPKCS11.
         */
        public ECPublicKeyImpl(ECPoint w, ECParameterSpec params)
                throws InvalidKeyException {
            this.w = w;
            this.params = params;
        }


        // see JCA doc
        public String getAlgorithm() {
            return "EC";
        }


        // see JCA doc
        public ECPoint getW() {
            return w;
        }


        // see JCA doc
        public ECParameterSpec getParams() {
            return params;
        }


        // return a string representation of this key for debugging
        public String toString() {
            return "EC public key, "
                    + params.getCurve().getField().getFieldSize()
                    + " bits\n  public x coord: " + w.getAffineX()
                    + "\n  public y coord: " + w.getAffineY()
                    + "\n  parameters: " + params;
        }


        @Override
        public String getFormat() {
            return "X.509";
        }


        @Override
        public byte[] getEncoded() {
            throw new UnsupportedOperationException();
        }
    }


    public ECPublicKey generatePublic(ECPublicKeySpec spec) throws GeneralSecurityException {
        return new ECPublicKeyImpl(spec.getW(), spec.getParams());
    }
}
