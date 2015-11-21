/*
 * Copyright (c) 1999, 2011, Oracle and/or its affiliates. All rights reserved.
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

import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * The TLSv1.2 provider.
 *
 * The RSA implementation has been removed from JSSE, but we still need to
 * register the same algorithms for compatibility. We just point to the RSA
 * implementation in the SunRsaSign provider. This works because all classes are
 * in the bootclasspath and therefore loaded by the same classloader.
 *
 * SunJSSE now supports an experimental FIPS compliant mode when used with an
 * appropriate FIPS certified crypto provider. In FIPS mode, we: . allow only
 * TLS 1.0 or later . allow only FIPS approved ciphersuites . perform all crypto
 * in the FIPS crypto provider
 *
 * It is currently not possible to use both FIPS compliant SunJSSE and standard
 * JSSE at the same time because of the various static data structures we use.
 *
 * However, we do want to allow FIPS mode to be enabled at runtime and without
 * editing the java.security file. That means we need to allow
 * Security.removeProvider("SunJSSE") to work, which creates an instance of this
 * class in non-FIPS mode. That is why we delay the selection of the mode as
 * long as possible. This is until we open an SSL/TLS connection and the data
 * structures need to be initialized or until SunJSSE is initialized in FIPS
 * mode.
 *
 */
public class Tls12Provider extends java.security.Provider {

    private static final long serialVersionUID = 3231825739635378733L;


    // standard constructor
    public Tls12Provider() {
        super("TLSv1.2", 1.0d, "TLSv1.2 provider");
        registerAlgorithms();
    }


    private void registerAlgorithms() {
        AccessController.doPrivileged(new PrivilegedAction<Object>() {
            public Object run() {
                doRegister();
                return null;
            }
        });
    }


    void doRegister() {
        put("Alg.Alias.SSLContext.TLS", "TLSv1.2");
        put("SSLContext.TLSv1.2", "tls12.SSLContextImpl$TLS12Context");
    }
}
