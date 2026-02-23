package kombit.oidc.controller;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import kombit.oidc.config.OidcClientConfig;
import kombit.oidc.config.OidcProperties;
import kombit.oidc.service.OpenIdCryptoService;
import kombit.oidc.util.TokenBundle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Controller;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;
import reactor.netty.http.client.HttpClient;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;

import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;


import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.util.HtmlUtils;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Controller
public class OidcController {
    
    private static final Logger log = LoggerFactory.getLogger(OidcController.class);

    private final WebClient webClient;
    private final OidcClientConfig cfg;
    
    public OidcController(OidcClientConfig cfg) {
        this.cfg = cfg;
        
        // Create WebClient with SSL verification disabled for development
        try {
            // Build SSL context outside the lambda since build() throws checked exception
            var sslContext = SslContextBuilder.forClient()
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();
            
            HttpClient httpClient = HttpClient.create()
                .secure(sslSpec -> sslSpec.sslContext(sslContext));
            
            this.webClient = WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .build();
        } catch (Exception e) {
            throw new RuntimeException("Failed to create WebClient with insecure SSL", e);
        }
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

        if (cfg.authorizationEndpointMethod() == OidcProperties.AuthorizationMethod.POST) {
            // POST: write a self-submitting HTML form so the browser POSTs to the authorization endpoint
            MultiValueMap<String, String> form = cfg.buildAuthorizeForm(state, nonce, acrOpt, maxAgeOpt, codeChallengeOpt);

            res.setContentType("text/html;charset=UTF-8");
            StringBuilder html = new StringBuilder();
            html.append("<!DOCTYPE html><html><body onload=\"document.forms[0].submit()\">\n");
            html.append("<form method=\"POST\" action=\"").append(HtmlUtils.htmlEscape(cfg.authorizationEndpoint())).append("\">\n");
            for (Map.Entry<String, List<String>> entry : form.entrySet()) {
                for (String value : entry.getValue()) {
                    html.append("  <input type=\"hidden\" name=\"")
                        .append(HtmlUtils.htmlEscape(entry.getKey()))
                        .append("\" value=\"")
                        .append(HtmlUtils.htmlEscape(value))
                        .append("\"/>\n");
                }
            }
            html.append("  <noscript><button type=\"submit\">Continue</button></noscript>\n");
            html.append("</form></body></html>");
            res.getWriter().write(html.toString());
        } else {
            // GET: standard redirect
            String url = cfg.buildAuthorizeUrl(state, nonce, acrOpt, maxAgeOpt, codeChallengeOpt);
            res.sendRedirect(url);
        }
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

        if (cfg.usePkce() && codeVerifier != null && !codeVerifier.isBlank()) {
            form.add("code_verifier", codeVerifier);
        }

        cfg.tokenAuthMethod();
        log.info("Using authentication method: {}", cfg.tokenAuthMethod());
        
        if (cfg.tokenAuthMethod() == OidcProperties.TokenAuthMethod.PRIVATE_KEY_JWT){
            String clientAssertion = buildClientAssertion(cfg.clientId(), cfg.tokenEndpoint(),
                    cfg.jwtAssertionSigningCertPath(), cfg.jwtAssertionSigningCertPassword());
            form.add("client_assertion_type",
                    "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            form.add("client_assertion", clientAssertion);
            log.info("Added client_assertion to request (private_key_jwt authentication)");
        } else {
            form.add("client_id", cfg.clientId());
            form.add("client_secret", cfg.clientSecret());
            log.info("Added client_id and client_secret to request ({} authentication)", cfg.tokenAuthMethod());
        }

        log.info("Exchanging code for token at: {}", cfg.tokenEndpoint());
        log.info("Complete form parameters: {}", form.toSingleValueMap().keySet());
        log.info("Request parameters: grant_type=authorization_code, redirect_uri={}, has_code={}, has_code_verifier={}", 
            cfg.redirectUri(), code != null, codeVerifier != null);

        try {
            Map response = webClient.post()
                    .uri(cfg.tokenEndpoint())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .accept(MediaType.APPLICATION_JSON)
                    .body(BodyInserters.fromFormData(form))
                    .retrieve()
                    .bodyToMono(Map.class)
                    .block();
            
            log.info("Token exchange successful!");
            return response;
            
        } catch (WebClientResponseException e) {
            log.error("Token exchange failed with status: {}", e.getStatusCode());
            log.error("Error response body: {}", e.getResponseBodyAsString());
            log.error("Response headers: {}", e.getHeaders());
            throw e;
        } catch (Exception e) {
            log.error("Exception during token exchange: {}", e.getMessage(), e);
            throw e;
        }
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

        // Calculate SHA-1 hash of the certificate (same as C# GetCertHash())
        java.security.MessageDigest sha1 = java.security.MessageDigest.getInstance("SHA-1");
        byte[] certHash = sha1.digest(cert.getEncoded());
        String kid = com.nimbusds.jose.util.Base64URL.encode(certHash).toString();
        
        // Calculate SHA-256 thumbprint for x5t#S256
        var thumb = com.nimbusds.jose.util.X509CertUtils.computeSHA256Thumbprint(cert);
        var thumbBase64 = new com.nimbusds.jose.util.Base64URL(thumb.toString());
        
        var header = new com.nimbusds.jose.JWSHeader.Builder(com.nimbusds.jose.JWSAlgorithm.RS256)
                .type(com.nimbusds.jose.JOSEObjectType.JWT)
                .keyID(kid)
                .x509CertSHA256Thumbprint(thumbBase64)
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
            try (var fis = new java.io.FileInputStream(cfg.idTokenDecryptionCertPath())) {
                ks.load(fis, cfg.idTokenDecryptionCertPassword().toCharArray());
            }
            String alias = ks.aliases().nextElement();
            PrivateKey decryptKey = (PrivateKey) ks.getKey(alias, cfg.idTokenDecryptionCertPassword().toCharArray());

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
