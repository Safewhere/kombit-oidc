package kombit.oidc.security;
import jakarta.annotation.PostConstruct;
import org.springframework.context.annotation.Configuration;

//import javax.net.ssl.*;
//import java.security.SecureRandom;
//import java.security.cert.X509Certificate;

@Configuration
public class InsecureSslConfig {
//    @PostConstruct
//  public void disableSslValidationForDevOnly() throws Exception {
//    TrustManager[] trustAll = new TrustManager[]{
//        new X509TrustManager() {
//          public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
//          public void checkClientTrusted(X509Certificate[] certs, String authType) {}
//          public void checkServerTrusted(X509Certificate[] certs, String authType) {}
//        }
//    };
//    SSLContext sc = SSLContext.getInstance("TLS");
//    sc.init(null, trustAll, new SecureRandom());
//    SSLContext.setDefault(sc);
//
//    HttpsURLConnection.setDefaultHostnameVerifier((h,s)->true);
//
//  }
}
