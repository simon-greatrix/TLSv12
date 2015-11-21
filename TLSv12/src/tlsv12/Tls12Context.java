package tlsv12;

import javax.net.ssl.SSLContext;

public class Tls12Context extends SSLContext {

    public Tls12Context() {
        super(new SSLContextImpl.TLS12Context(), new Tls12Provider(), "TLSv1.2");
    }
}
