package tlsv12;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import java.io.IOException;
import java.net.URL;
import java.security.KeyManagementException;

public class Tls12Context extends SSLContext {
    /** A default instance of this context */
    public static final Tls12Context INSTANCE;

    /** A default socket factory using the default instance */
    public static final SSLSocketFactory SOCKET_FACTORY;

    static {
        Tls12Context c = new Tls12Context();
        try {
            c.init(null, null, null);
        } catch (KeyManagementException e) {
            throw new Error("Default key manager failed", e);
        }
        INSTANCE = c;
        SOCKET_FACTORY = c.getSocketFactory();
    }


    /**
     * Open an HTTPS connection to the specified URL.
     * 
     * @param url
     *            the URL to connect to
     * @return a connection, or null if the URL is not HTTPS
     * @throws IOException
     */
    public static HttpsURLConnection getConnection(String url) throws IOException {
        if( url == null ) return null;
        return getConnection(new URL(url));
    }


    /**
     * Open an HTTPS connection to the specified URL.
     * 
     * @param url
     *            the URL to connect to
     * @return a connection, or null if the URL is not HTTPS
     * @throws IOException
     */
    public static HttpsURLConnection getConnection(URL url) throws IOException {
        if( url == null ) return null;
        if( !"https".equals(url.getProtocol()) ) return null;
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(SOCKET_FACTORY);
        return conn;
    }


    public Tls12Context() {
        super(new SSLContextImpl.TLS12Context(), new Tls12Provider(), "TLSv1.2");
    }
}
