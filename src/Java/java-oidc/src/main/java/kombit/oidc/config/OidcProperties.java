package kombit.oidc.config;

import jakarta.validation.constraints.*;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.client.SimpleClientHttpRequestFactory;

import javax.net.ssl.*;
import java.security.cert.X509Certificate;

import jakarta.annotation.PostConstruct;
import java.util.Map;

@Validated
@ConfigurationProperties(prefix = "config.oidc")
public class OidcProperties {

    @NotBlank
    private String registrationId;

    @NotBlank
    private String issuerUri;

    private String authorizationEndpoint;
    private String tokenEndpoint;
    private String endSessionEndpoint;
    private String revokeEndpoint;

    @NotBlank
    private String clientId;

    @NotBlank
    private String clientSecret;

    @org.jetbrains.annotations.NotNull
    private TokenAuthMethod tokenAuthMethod = TokenAuthMethod.CLIENT_SECRET_POST;

    private boolean usePkce = true;
    private AuthorizationMethod authorizationEndpointMethod = AuthorizationMethod.POST;

    @NotNull private String redirectUri;

    @NotBlank
    private String scope;

    private String jwtSigningKeystorePath;
    private String jwtSigningKeystorePassword;
    private String idTokenKeystorePath;
    private String idTokenKeystorePassword;

    public enum TokenAuthMethod {
        CLIENT_SECRET_POST,
        CLIENT_SECRET_BASIC,
        PRIVATE_KEY_JWT
    }
    public enum AuthorizationMethod {
        POST,
        GET
    }

    public String getRegistrationId() { return registrationId; }
    public void setRegistrationId(String registrationId) { this.registrationId = registrationId; }

    public String getIssuerUri() { return issuerUri; }
    public void setIssuerUri(String issuerUri) { this.issuerUri = issuerUri; }

    @PostConstruct
    public void loadOidcMetadata() {
        if (issuerUri == null || issuerUri.isEmpty()) {
            return;
        }

        try {
            String metadataUrl = issuerUri + "/.well-known/openid-configuration";
            
            // Create RestTemplate with SSL verification disabled for development
            RestTemplate restTemplate = createInsecureRestTemplate();
            
            @SuppressWarnings("unchecked")
            Map<String, Object> metadata = restTemplate.getForObject(metadataUrl, Map.class);

            if (metadata != null) {
                authorizationEndpoint = (String) metadata.get("authorization_endpoint");
                tokenEndpoint = (String) metadata.get("token_endpoint");
                endSessionEndpoint = (String) metadata.get("end_session_endpoint");
                revokeEndpoint = (String) metadata.get("revocation_endpoint");
            }
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load OIDC metadata from " + issuerUri, e);
        }
    }

    private RestTemplate createInsecureRestTemplate() {
        try {
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) { }
                    public void checkServerTrusted(X509Certificate[] certs, String authType) { }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());
            
            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());
            HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

            return new RestTemplate();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create insecure RestTemplate", e);
        }
    }

    public String getAuthorizationEndpoint() { 
        if (authorizationEndpoint == null) loadOidcMetadata();
        return authorizationEndpoint; 
    }

    public String getTokenEndpoint() { 
        if (tokenEndpoint == null) loadOidcMetadata();
        return tokenEndpoint; 
    }

    public String getEndSessionEndpoint() { 
        if (endSessionEndpoint == null) loadOidcMetadata();
        return endSessionEndpoint; 
    }

    public String getRevokeEndpoint() { 
        if (revokeEndpoint == null) loadOidcMetadata();
        return revokeEndpoint; 
    }

    public String getClientId() { return clientId; }
    public void setClientId(String clientId) { this.clientId = clientId; }

    public String getClientSecret() { return clientSecret; }
    public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

    public @org.jetbrains.annotations.NotNull TokenAuthMethod getTokenAuthMethod() { return tokenAuthMethod; }
    public void setTokenAuthMethod(@org.jetbrains.annotations.NotNull TokenAuthMethod tokenAuthMethod) { this.tokenAuthMethod = tokenAuthMethod; }

    public boolean isUsePkce() { return usePkce; }
    public void setUsePkce(boolean usePkce) { this.usePkce = usePkce; }

    public @org.jetbrains.annotations.NotNull AuthorizationMethod getAuthorizationEndpointMethod() { return authorizationEndpointMethod; }
    public void setAuthorizationEndpointMethod(@org.jetbrains.annotations.NotNull AuthorizationMethod authorizationEndpointMethod) { this.authorizationEndpointMethod = authorizationEndpointMethod; }

    public String getRedirectUri() { return redirectUri; }
    public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }

    public String getScope() { return scope; }
    public void setScope(String scope) { this.scope = scope; }

    public String getJwtSigningKeystorePath() { return jwtSigningKeystorePath; }
    public void setJwtSigningKeystorePath(String jwtSigningKeystorePath) { this.jwtSigningKeystorePath = jwtSigningKeystorePath; }

    public String getJwtSigningKeystorePassword() { return jwtSigningKeystorePassword; }
    public void setJwtSigningKeystorePassword(String jwtSigningKeystorePassword) { this.jwtSigningKeystorePassword = jwtSigningKeystorePassword; }

    public String getIdTokenKeystorePath() { return idTokenKeystorePath; }
    public void setIdTokenKeystorePath(String idTokenKeystorePath) { this.idTokenKeystorePath = idTokenKeystorePath; }

    public String getIdTokenKeystorePassword() { return idTokenKeystorePassword; }
    public void setIdTokenKeystorePassword(String idTokenKeystorePassword) { this.idTokenKeystorePassword = idTokenKeystorePassword; }

}
