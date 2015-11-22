# TLSv12
TLS 1.2 for Java 1.6

## The stand alone version

The "standalone" branch provides everything needed to run most TLSv1.2 connections with Java 1.6 where the server. The connection is limited to the following cipher suites:

+ TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
+ TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
+ TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
+ TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
+ TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
+ TLS_DHE_DSS_WITH_AES_256_CBC_SHA256
+ TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
+ TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
+ TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
+ TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
+ TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
+ TLS_DHE_DSS_WITH_AES_128_CBC_SHA256

This list was chosen to meet the following requirements:

+ AES-128 or AES-256 as the cipher suite
+ SHA-256 or better
+ Ephemeral keys or Elliptic Curve used for key agreement
+ Cryptographic primitives supported by Java 1.6

Notably missing from the above list are ciphers using Galois Counter Mode, as Sun's cryptographic provider does not support them.

The stand alone TLS library is derived from the OpenJDK v8 release, augmented with the Bouncy Castle Elliptic Curve crypotgraphic primitives.


** How to use

    System.out.println("Fetching from Google");
    HttpsURLConnection conn = Tls12Context.getConnection("https://www.google.com");
    InputStream in = conn.getInputStream();
    int r;
    while( (r = in.read()) != -1 ) {
        System.out.print((char) r);
    }
    in.close();
    conn.disconnect();
    System.out.println();

or

    SSLContext sslContext = new Tls12Context();
    sslContext.init(null,null,null);
    SSLSocketFactory factory = sslContext.getSSLSocketFactory();
    
