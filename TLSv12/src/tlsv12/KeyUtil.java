package tlsv12;

/*
 * Copyright (c) 2012, 2014, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 * 
 * This code is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License version 2 only, as published by
 * the Free Software Foundation. Oracle designates this particular file as
 * subject to the "Classpath" exception as provided by Oracle in the LICENSE
 * file that accompanied this code.
 * 
 * This code is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU General Public License version 2 for more
 * details (a copy is included in the LICENSE file that accompanied this code).
 * 
 * You should have received a copy of the GNU General Public License version 2
 * along with this work; if not, write to the Free Software Foundation, Inc., 51
 * Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 * 
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA or
 * visit www.oracle.com if you need additional information or have any
 * questions.
 */

import javax.crypto.interfaces.DHKey;
import javax.crypto.spec.DHPublicKeySpec;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.interfaces.DSAKey;
import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;
import java.security.spec.KeySpec;

/**
 * A utility class to get key length, valiate keys, etc.
 */
public final class KeyUtil {

    /**
     * Returns the key size of the given key object in bits.
     *
     * @param key
     *            the key object, cannot be null
     * @return the key size of the given key object in bits, or -1 if the key
     *         size is not accessible
     */
    public static final int getKeySize(PrivateKey key) {
        int size = -1;

        // try to parse the length from key specification
        if( key instanceof RSAKey ) {
            RSAKey pubk = (RSAKey) key;
            size = pubk.getModulus().bitLength();
        } else if( key instanceof ECKey ) {
            ECKey pubk = (ECKey) key;
            size = pubk.getParams().getOrder().bitLength();
        } else if( key instanceof DSAKey ) {
            DSAKey pubk = (DSAKey) key;
            size = pubk.getParams().getP().bitLength();
        } else if( key instanceof DHKey ) {
            DHKey pubk = (DHKey) key;
            size = pubk.getParams().getP().bitLength();
        } // Otherwise, it may be a unextractable key of PKCS#11, or
          // a key we are not able to handle.

        return size;
    }


    /**
     * Returns whether the key spec is valid or not.
     * <P>
     * Note that this method is only apply to DHPublicKeySpec at present.
     *
     * @param keySpec
     *            the key spec object, cannot be null
     *
     * @throws NullPointerException
     *             if {@code keySpec} is null
     * @throws InvalidKeyException
     *             if {@code keySpec} is invalid
     */
    public static final void validate(KeySpec keySpec) throws InvalidKeyException {
        if( keySpec == null ) {
            throw new NullPointerException(
                    "The key spec to be validated cannot be null");
        }

        if( keySpec instanceof DHPublicKeySpec ) {
            validateDHPublicKey((DHPublicKeySpec) keySpec);
        }
    }


    private static void validateDHPublicKey(DHPublicKeySpec publicKeySpec) throws InvalidKeyException {
        validateDHPublicKey(publicKeySpec.getP(), publicKeySpec.getG(),
                publicKeySpec.getY());
    }


    private static void validateDHPublicKey(BigInteger p, BigInteger g,
            BigInteger y) throws InvalidKeyException {

        // For better interoperability, the interval is limited to [2, p-2].
        BigInteger leftOpen = BigInteger.ONE;
        BigInteger rightOpen = p.subtract(BigInteger.ONE);
        if( y.compareTo(leftOpen) <= 0 ) {
            throw new InvalidKeyException(
                    "Diffie-Hellman public key is too small");
        }
        if( y.compareTo(rightOpen) >= 0 ) {
            throw new InvalidKeyException(
                    "Diffie-Hellman public key is too large");
        }

        // y^q mod p == 1?
        // Unable to perform this check as q is unknown in this circumstance.

        // p is expected to be prime. However, it is too expensive to check
        // that p is prime. Instead, in order to mitigate the impact of
        // non-prime values, we check that y is not a factor of p.
        BigInteger r = p.remainder(y);
        if( r.equals(BigInteger.ZERO) ) {
            throw new InvalidKeyException("Invalid Diffie-Hellman parameters");
        }
    }

}
