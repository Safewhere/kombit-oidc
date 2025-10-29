package kombit.oidc.config;

import jakarta.validation.constraints.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "config.oidc")
public class OidcProperties {

    @Autowired(required = false)
    private ClientRegistrationRepository clientRegistrationRepository;

    private ClientRegistration getOidcRegistration() {
        if (clientRegistrationRepository == null)
            throw new IllegalStateException("ClientRegistrationRepository is not initialized.");

        ClientRegistration reg = clientRegistrationRepository.findByRegistrationId("oidc");
        if (reg == null)
            throw new IllegalStateException("OIDC registration not found in ClientRegistrationRepository.");

        return reg;
    }

    @NotBlank
    private String registrationId;

    @NotBlank private String clientId;
    @NotBlank private String clientSecret;

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

    public String getAuthorizationEndpoint() { return getOidcRegistration().getProviderDetails().getAuthorizationUri(); }

    public String getTokenEndpoint() { return getOidcRegistration().getProviderDetails().getTokenUri(); }

    public String getEndSessionEndpoint() {
        Object val = getOidcRegistration().getProviderDetails()
            .getConfigurationMetadata()
            .get("end_session_endpoint");
        return val != null ? val.toString() : "";
    }

    public String getRevokeEndpoint() {
        Object val = getOidcRegistration().getProviderDetails()
            .getConfigurationMetadata()
            .get("revocation_endpoint");
        return val != null ? val.toString() : "";
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
