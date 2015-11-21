package tlsv12;

import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.util.TreeSet;

public class ProviderList {

    public static void main(String[] args) {
        Provider[] provs = Security.getProviders();
        TreeSet<String> services = new TreeSet<String>();
        for(Provider p:provs) {
            for(Service s:p.getServices()) {
                services.add(s.toString());
            }
        }
        for(String s:services) {
            System.out.println(s);
        }
    }

}
