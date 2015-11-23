package tlsv12;

import javax.net.ssl.HttpsURLConnection;

import java.io.IOException;
import java.io.InputStream;

public class Example {

    static void fetchPage(HttpsURLConnection conn) {
        try {
            InputStream in = conn.getInputStream();
            int r;
            while( (r = in.read()) != -1 ) {
                System.out.print((char) r);
            }
            in.close();
            conn.disconnect();
            System.out.println();
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }


    public static void main(String[] args) throws IOException {
         System.setProperty("javax.net.debug", "ssl");
/*
        System.out.println("Fetching from Google");
        HttpsURLConnection conn = Tls12Context.getConnection("https://www.google.com");
        fetchPage(conn);

        System.out.println("Fetching from Facebook");
        conn = Tls12Context.getConnection("https://www.facebook.com");
        fetchPage(conn);

        System.out.println("Fetching from Cybersource");
        conn = Tls12Context.getConnection("https://www.cybersource.com");
        fetchPage(conn);
*/
        System.out.println("Fetching from Harte Hanks");
        HttpsURLConnection conn = Tls12Context.getConnection("https://belk2-uat.hostedtax.thomsonreuters.com");
        fetchPage(conn);
    }

}
