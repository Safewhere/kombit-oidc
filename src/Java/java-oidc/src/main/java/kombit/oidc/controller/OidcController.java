package kombit.oidc.controller;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import kombit.oidc.config.OidcClientConfig;
import kombit.oidc.config.OidcProperties;
import kombit.oidc.service.OpenIdCryptoService;
import kombit.oidc.util.TokenBundle;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;


import org.springframework.web.reactive.function.BodyInserters;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Controller
public class OidcController {

    private final WebClient webClient = WebClient.builder().build();
    private final OidcClientConfig cfg;
    public OidcController(OidcClientConfig cfg) {
        this.cfg = cfg;
    }

    @Autowired
    private OpenIdCryptoService openIdCryptoService;

    @GetMapping("/oidc/start")
    public void start(HttpServletRequest req, HttpServletResponse res, HttpSession session) throws Exception {

        String acrValues = Optional.ofNullable(req.getParameter("acr_values")).orElse("");
        String maxAgeStr = Optional.ofNullable(req.getParameter("max_age")).orElse("");
        
        // Sinh state & nonce
        String state = UUID.randomUUID().toString().replace("-", "");
        String nonce = UUID.randomUUID().toString().replace("-", "");

        String codeVerifier  = OidcClientConfig.generateCodeVerifier();
        String codeChallenge = OidcClientConfig.codeChallengeS256(codeVerifier);

        session.setAttribute("oidc_state", state);
        session.setAttribute("oidc_nonce", nonce);
        session.setAttribute("oidc_code_verifier", codeVerifier);

        Optional<String> acrOpt = acrValues.isBlank() ? Optional.empty() : Optional.of(acrValues);
        Optional<Integer> maxAgeOpt = Optional.empty();
        if (!maxAgeStr.isBlank()) {
            try { maxAgeOpt = Optional.of(Integer.parseInt(maxAgeStr)); } catch (NumberFormatException ignored) {}
        }
        Optional<String> codeChallengeOpt = Optional.ofNullable(codeChallenge);

        String url = cfg.buildAuthorizeUrl(state,nonce,acrOpt,maxAgeOpt,codeChallengeOpt);
        res.sendRedirect(url);
    }

    @GetMapping("/oidc/callback")
    public String callback(HttpServletRequest req, HttpSession session, Map<String, Object> model) throws Exception {
        String code  = req.getParameter("code");
        String state = req.getParameter("state");

        String stateSaved = (String) session.getAttribute("oidc_state");
        String codeVerifier = (String) session.getAttribute("oidc_code_verifier");

        if (code == null || state == null || stateSaved == null || !stateSaved.equals(state)) {
            model.put("error", "Invalid state or missing code.");
            return "redirect:/home";
        }
        if (codeVerifier == null) {
            model.put("error", "Missing code_verifier in session (PKCE).");
            return "redirect:/home";
        }

        Map<String, Object> token = exchangeAuthCodeForToken(code, codeVerifier);

        String accessToken = (String) token.get("access_token");
        String idToken     = (String) token.getOrDefault("id_token", "");
        String refresh     = (String) token.getOrDefault("refresh_token", "");

        idToken = openIdCryptoService.decryptIfNeeded(idToken);

        Map<String, Object> idClaims = parseIdToken(idToken);
        session.setAttribute("access_token", accessToken);
        session.setAttribute("id_token", idToken);
        session.setAttribute("refresh_token", refresh);
        session.setAttribute("idClaims", idClaims);

        TokenBundle tokens = new TokenBundle(accessToken, refresh, idToken);
        session.setAttribute("TOKENS", tokens);

        return "redirect:/home";
    }

    private Map<String, Object> exchangeAuthCodeForToken(String code, String codeVerifier) throws Exception {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", cfg.redirectUri());
        form.add("client_id", cfg.clientId());

        if (cfg.usePkce() && codeVerifier != null && !codeVerifier.isBlank()) {
            form.add("code_verifier", codeVerifier);
        }

        cfg.tokenAuthMethod();
        if (cfg.tokenAuthMethod() == OidcProperties.TokenAuthMethod.PRIVATE_KEY_JWT){
            String clientAssertion = buildClientAssertion(cfg.clientId(), cfg.tokenEndpoint(),
                    cfg.jwtSigningKeystorePath(), cfg.jwtSigningKeystorePassword());
            form.add("client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            form.add("client_assertion", clientAssertion);
        } else {
            form.add("client_secret", cfg.clientSecret());
        }

        return webClient.post()
                .uri(cfg.tokenEndpoint())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .body(BodyInserters.fromFormData(form))
                .retrieve()
                .bodyToMono(Map.class)
                .block();
    }
    private String buildClientAssertion(String clientId,
                                        String tokenEndpoint,
                                        String p12Path,
                                        String p12Password) throws Exception {
        java.security.KeyStore ks = java.security.KeyStore.getInstance("PKCS12");
        try (var fis = new java.io.FileInputStream(p12Path)) {
            ks.load(fis, p12Password.toCharArray());
        }
        String alias = firstKeyAlias(ks);
        java.security.PrivateKey privateKey =
                (java.security.PrivateKey) ks.getKey(alias, p12Password.toCharArray());
        java.security.cert.X509Certificate cert =
                (java.security.cert.X509Certificate) ks.getCertificate(alias);

        var thumb = com.nimbusds.jose.util.X509CertUtils.computeSHA256Thumbprint(cert);
        var header = new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                .type(com.nimbusds.jose.JOSEObjectType.JWT)
                .x509CertSHA256Thumbprint(new com.nimbusds.jose.util.Base64URL(thumb.toString()))
                .build();

        var now = java.time.Instant.now();
        var claims = new com.nimbusds.jwt.JWTClaimsSet.Builder()
                .issuer(clientId).subject(clientId).audience(tokenEndpoint)
                .jwtID(java.util.UUID.randomUUID().toString())
                .issueTime(java.util.Date.from(now))
                .expirationTime(java.util.Date.from(now.plusSeconds(300)))
                .build();

        var jwt = new com.nimbusds.jwt.SignedJWT(header, claims);
        jwt.sign(new com.nimbusds.jose.crypto.RSASSASigner(privateKey));
        return jwt.serialize();
    }
    private Map<String, Object> parseIdToken(String idToken) throws Exception {
        if (idToken == null) return Map.of();

        long dots = idToken.chars().filter(ch -> ch == '.').count();

        if (dots == 4) { // JWE (encrypted)
            KeyStore ks = KeyStore.getInstance("PKCS12");
            try (var fis = new java.io.FileInputStream(cfg.idTokenKeystorePath())) {
                ks.load(fis, cfg.idTokenKeystorePassword().toCharArray());
            }
            String alias = ks.aliases().nextElement();
            PrivateKey decryptKey = (PrivateKey) ks.getKey(alias, cfg.idTokenKeystorePassword().toCharArray());

            EncryptedJWT jwe = EncryptedJWT.parse(idToken);
            jwe.decrypt(new com.nimbusds.jose.crypto.RSADecrypter(decryptKey));

            // nested JWS?
            SignedJWT nested = jwe.getPayload().toSignedJWT();
            Map<String, Object> claims;

            if (nested != null) {
                claims = nested.getJWTClaimsSet().getClaims();
            } else {
                claims = jwe.getJWTClaimsSet().getClaims();
            }
            return claims;
        } else { // JWS (signed only)
            SignedJWT jws = SignedJWT.parse(idToken);
            return jws.getJWTClaimsSet().getClaims();
        }
    }
    private static String firstKeyAlias(java.security.KeyStore ks) throws Exception {
        java.util.Enumeration<String> e = ks.aliases();
        while (e.hasMoreElements()) {
            String a = e.nextElement();
            if (ks.isKeyEntry(a)) return a;
        }
        throw new IllegalStateException("No private key entry found in the keystore");
    }
}
