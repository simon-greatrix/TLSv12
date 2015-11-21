package tlsv12;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import java.io.InputStream;
import java.net.URL;

public class TheBigMainApplication {

    public static void main(String[] args) throws Exception {

        SSLContext sslCtxt = new Tls12Context();
        sslCtxt.init(null, null, null);
        SSLSocketFactory fact = sslCtxt.getSocketFactory();
        URL url = new URL("https://www.google.com");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(fact);
        InputStream in = conn.getInputStream();
        int r;
        while( (r = in.read()) != -1 ) {
            System.out.print((char) r);
        }
        in.close();
        conn.disconnect();
    }

}
