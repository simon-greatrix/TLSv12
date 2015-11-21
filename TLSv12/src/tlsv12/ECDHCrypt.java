/*
 * Copyright (c) 2006, 2015, Oracle and/or its affiliates. All rights reserved.
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

package tlsv12;

import tlsv12.ec.ECDHKeyAgreement;
import tlsv12.ec.ECKeyFactory;
import tlsv12.ec.ECKeyPairGenerator;
import tlsv12.ec.ECUtils;

import javax.crypto.SecretKey;
import javax.net.ssl.SSLHandshakeException;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;

/**
 * Helper class for the ECDH key exchange. It generates the appropriate
 * ephemeral keys as necessary and performs the actual shared secret derivation.
 *
 */
final class ECDHCrypt {

    // our private key
    private ECPrivateKey privateKey;

    // our public key
    private ECPublicKey publicKey;


    // Called by ServerHandshaker for static ECDH
    ECDHCrypt(ECPrivateKey privateKey, ECPublicKey publicKey) {
        this.privateKey = privateKey;
        this.publicKey = publicKey;
    }


    // Called by ServerHandshaker for ephemeral ECDH
    ECDHCrypt(String oid, SecureRandom random) {
        try {
            ECKeyPairGenerator kpg = new ECKeyPairGenerator();
            ECParameterSpec params = ECUtils.getECParameterSpec(oid);
            kpg.initialize(params, random);
            KeyPair kp = kpg.generateKeyPair();
            privateKey = (ECPrivateKey) kp.getPrivate();
            publicKey = (ECPublicKey) kp.getPublic();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Could not generate DH keypair", e);
        }
    }


    // Called by ClientHandshaker with params it received from the server
    ECDHCrypt(ECParameterSpec params, SecureRandom random) {
        try {
            ECKeyPairGenerator kpg = new ECKeyPairGenerator();
            kpg.initialize(params, random);
            KeyPair kp = kpg.generateKeyPair();
            privateKey = (ECPrivateKey) kp.getPrivate();
            publicKey = (ECPublicKey) kp.getPublic();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("Could not generate DH keypair", e);
        }
    }


    /**
     * Gets the public key of this end of the key exchange.
     */
    ECPublicKey getPublicKey() {
        return publicKey;
    }


    // called by ClientHandshaker with either the server's static or
    // ephemeral public key
    SecretKey getAgreedSecret(PublicKey peerPublicKey) throws SSLHandshakeException {

        try {
            ECDHKeyAgreement ka = new ECDHKeyAgreement(privateKey);
            ka.doPhase((ECPublicKey) peerPublicKey);
            return ka.generateSecret("TlsPremasterSecret");
        } catch (GeneralSecurityException e) {
            throw (SSLHandshakeException) new SSLHandshakeException(
                    "Could not generate secret").initCause(e);
        }
    }


    // called by ServerHandshaker
    SecretKey getAgreedSecret(byte[] encodedPoint) throws SSLHandshakeException {

        try {
            ECParameterSpec params = publicKey.getParams();
            ECPoint point = ECUtils.decodePoint(encodedPoint, params.getCurve());
            ECKeyFactory kf = new ECKeyFactory();
            ECPublicKeySpec spec = new ECPublicKeySpec(point, params);
            PublicKey peerPublicKey = kf.generatePublic(spec);
            return getAgreedSecret(peerPublicKey);
        } catch (GeneralSecurityException e) {
            throw (SSLHandshakeException) new SSLHandshakeException(
                    "Could not generate secret").initCause(e);
        } catch (java.io.IOException e) {
            throw (SSLHandshakeException) new SSLHandshakeException(
                    "Could not generate secret").initCause(e);
        }
    }

}
