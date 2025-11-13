package kombit.oidc.config;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

@Service
public class OidcClientConfig {

    private final OidcProperties p;
    private static final SecureRandom RNG = new SecureRandom();

    public OidcClientConfig(OidcProperties properties) {
        this.p = Objects.requireNonNull(properties, "OidcProperties must not be null");
    }


    public String authorizationEndpoint() { return p.getAuthorizationEndpoint(); }
    public String tokenEndpoint()         { return p.getTokenEndpoint(); }
    public String endSessionEndpoint()    { return p.getEndSessionEndpoint(); }
    public String revokeEndpoint()        { return p.getRevokeEndpoint(); }
    public String clientId()              { return p.getClientId(); }
    public String clientSecret()          { return p.getClientSecret(); }
    public OidcProperties.TokenAuthMethod tokenAuthMethod() { return p.getTokenAuthMethod(); }
    public boolean usePkce()              { return p.isUsePkce(); }
    public String redirectUri()           { return p.getRedirectUri(); }
    public String scope()                 { return p.getScope(); }
    public String jwtSigningKeystorePath(){ return p.getJwtSigningKeystorePath(); }
    public String jwtSigningKeystorePassword(){ return p.getJwtSigningKeystorePassword(); }
    public String idTokenKeystorePath()   { return p.getIdTokenKeystorePath(); }
    public String idTokenKeystorePassword(){ return p.getIdTokenKeystorePassword(); }
    public OidcProperties.AuthorizationMethod authorizationEndpointMethod() { return p.getAuthorizationEndpointMethod();}

    public String buildAuthorizeUrl(
            String state,
            String nonce,
            Optional<String> acrValues,
            Optional<Integer> maxAgeSec,
            Optional<String> codeChallenge
    ) {
        UriComponentsBuilder b = UriComponentsBuilder.fromUriString(p.getAuthorizationEndpoint())
                .queryParam("response_type", "code")
                .queryParam("client_id", p.getClientId())
                .queryParam("scope", p.getScope())
                .queryParam("redirect_uri", p.getRedirectUri().toString())
                .queryParam("state", state)
                .queryParam("nonce", nonce);

        acrValues.filter(s -> !s.isBlank()).ifPresent(v -> b.queryParam("acr_values", v));
        maxAgeSec.filter(v -> v > 0).ifPresent(v -> b.queryParam("max_age", v));

        if (p.isUsePkce() && codeChallenge.isPresent()) {
            b.queryParam("code_challenge_method", "S256")
                    .queryParam("code_challenge", codeChallenge.get());
        }

        return b.build(true).toUriString();
    }


    public MultiValueMap<String, String> buildAuthorizeForm(
            String state,
            String nonce,
            Optional<String> acrValues,
            Optional<Integer> maxAgeSec,
            Optional<String> codeChallenge
    ) {
        LinkedMultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("response_type", "code");
        form.add("client_id", p.getClientId());
        form.add("scope", p.getScope());
        form.add("redirect_uri", p.getRedirectUri().toString());
        form.add("state", state);
        form.add("nonce", nonce);

        acrValues.filter(s -> !s.isBlank()).ifPresent(v -> form.add("acr_values", v));
        maxAgeSec.filter(v -> v > 0).ifPresent(v -> form.add("max_age", String.valueOf(v)));

        if (p.isUsePkce() && codeChallenge.isPresent()) {
            form.add("code_challenge_method", "S256");
            form.add("code_challenge", codeChallenge.get());
        }
        return form;
    }

    public String buildEndSessionUrl(
            String idTokenHint,
            Optional<URI> postLogoutRedirectUri
    ) {
        UriComponentsBuilder b = UriComponentsBuilder.fromUriString(p.getEndSessionEndpoint())
                .queryParam("id_token_hint", idTokenHint);

        postLogoutRedirectUri.ifPresent(uri -> b.queryParam("post_logout_redirect_uri", uri.toString()));
        return b.build(true).toUriString();
    }

    public MultiValueMap<String, String> tokenForm_authorizationCode(
            String code,
            Optional<String> codeVerifier
    ) {
        LinkedMultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", p.getRedirectUri().toString());

        if (p.isUsePkce()) {
            form.add("code_verifier", codeVerifier.orElseThrow(
                    () -> new IllegalArgumentException("code_verifier is required when PKCE is enabled")
            ));
        }

        switch (p.getTokenAuthMethod()) {
            case CLIENT_SECRET_POST -> {
                form.add("client_id", p.getClientId());
                form.add("client_secret", p.getClientSecret());
            }
            case PRIVATE_KEY_JWT -> {
                // form.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
                // form.add("client_assertion", signedAssertion);
                form.add("client_id", p.getClientId());
            }
            case CLIENT_SECRET_BASIC -> {

            }
        }
        return form;
    }

    public MultiValueMap<String, String> tokenForm_refreshToken(String refreshToken) {
        LinkedMultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "refresh_token");
        form.add("refresh_token", refreshToken);

        switch (p.getTokenAuthMethod()) {
            case CLIENT_SECRET_POST -> {
                form.add("client_id", p.getClientId());
                form.add("client_secret", p.getClientSecret());
            }
            case PRIVATE_KEY_JWT -> {
                // form.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
                // form.add("client_assertion", signedAssertion);
                form.add("client_id", p.getClientId());
            }
            case CLIENT_SECRET_BASIC -> {
                // dùng Basic Auth header
            }
        }
        return form;
    }

    public HttpHeaders tokenHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        if (p.getTokenAuthMethod() == OidcProperties.TokenAuthMethod.CLIENT_SECRET_BASIC) {
            headers.set(HttpHeaders.AUTHORIZATION, basicAuth(p.getClientId(), p.getClientSecret()));
        }
        return headers;
    }

    public MultiValueMap<String, String> revokeForm(String token, String tokenTypeHint) {
        LinkedMultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("token", token);
        if (tokenTypeHint != null && !tokenTypeHint.isBlank()) {
            form.add("token_type_hint", tokenTypeHint); // access_token|refresh_token
        }

        if (p.getTokenAuthMethod() == OidcProperties.TokenAuthMethod.CLIENT_SECRET_POST) {
            form.add("client_id", p.getClientId());
            form.add("client_secret", p.getClientSecret());
        } else if (p.getTokenAuthMethod() == OidcProperties.TokenAuthMethod.PRIVATE_KEY_JWT) {
            // form.add("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            // form.add("client_assertion", signedAssertion);
            form.add("client_id", p.getClientId());
        }
        return form;
    }

    public HttpHeaders revokeHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        if (p.getTokenAuthMethod() == OidcProperties.TokenAuthMethod.CLIENT_SECRET_BASIC) {
            headers.set(HttpHeaders.AUTHORIZATION, basicAuth(p.getClientId(), p.getClientSecret()));
        }
        return headers;
    }


    public static String basicAuth(String clientId, String clientSecret) {
        String pair = clientId + ":" + clientSecret;
        String b64 = Base64.getEncoder().encodeToString(pair.getBytes(StandardCharsets.UTF_8));
        return "Basic " + b64;
    }

    public static String generateCodeVerifier() {
        byte[] buf = new byte[32];
        RNG.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    public static String codeChallengeS256(String codeVerifier) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(codeVerifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot compute code_challenge", e);
        }
    }

    public static String randomUrlSafe(int bytes) {
        byte[] buf = new byte[bytes];
        RNG.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }

    public Map<String, Object> asInfo() {
        return Map.of(
                "authorizationEndpoint", p.getAuthorizationEndpoint(),
                "authorizationEndpointMethod", p.getAuthorizationEndpointMethod(),
                "tokenEndpoint", p.getTokenEndpoint(),
                "endSessionEndpoint", p.getEndSessionEndpoint(),
                "revokeEndpoint", p.getRevokeEndpoint(),
                "clientId", p.getClientId(),
                "tokenAuthMethod", p.getTokenAuthMethod().name(),
                "usePkce", p.isUsePkce(),
                "redirectUri", p.getRedirectUri(),
                "scope", p.getScope()
        );
    }
}
