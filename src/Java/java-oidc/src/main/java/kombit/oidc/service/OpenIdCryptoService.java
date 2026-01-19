package kombit.oidc.service;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.*;
import com.nimbusds.jose.util.JSONObjectUtils;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import kombit.oidc.config.OidcClientConfig;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;

import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Instant;

@Component
public class OpenIdCryptoService {

    private RSAPublicKey jwtVerifyPublicKey;
    private RSAPrivateKey idTokenDecryptKey;
    private final OidcClientConfig cfg;
    public OpenIdCryptoService(OidcClientConfig cfg) {
        this.cfg = cfg;
    }

    @PostConstruct
    public void init() throws Exception {
        // Skip initialization if keystore paths are not configured
        if (cfg.jwtAssertionSigningCertPath() == null || cfg.jwtAssertionSigningCertPath().isEmpty()) {
            return;
        }
        if (cfg.idTokenDecryptionCertPath() == null || cfg.idTokenDecryptionCertPath().isEmpty()) {
            return;
        }

        KeyStore verifyKs = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(cfg.jwtAssertionSigningCertPath())) {
            verifyKs.load(fis, cfg.jwtAssertionSigningCertPassword().toCharArray());
        }
        String certAlias = firstCertificateAlias(verifyKs);
        if (certAlias == null) {
            throw new KeyStoreException("No certificate alias found in jwtSigning keystore.");
        }
        Certificate verifyCert = verifyKs.getCertificate(certAlias);
        if (verifyCert == null || !(verifyCert.getPublicKey() instanceof RSAPublicKey)) {
            throw new IllegalStateException("Cannot load RSA public key for JWS verification.");
        }
        jwtVerifyPublicKey = (RSAPublicKey) verifyCert.getPublicKey();


        KeyStore decryptKs = KeyStore.getInstance("PKCS12");
        try (FileInputStream fis = new FileInputStream(cfg.idTokenDecryptionCertPath())) {
            decryptKs.load(fis, cfg.idTokenDecryptionCertPassword().toCharArray());
        }
        String keyAlias = firstPrivateKeyAlias(decryptKs);
        if (keyAlias == null) {
            throw new KeyStoreException("No private key alias found in idToken keystore.");
        }
        Key pkey = decryptKs.getKey(keyAlias, cfg.idTokenDecryptionCertPassword().toCharArray());
        if (!(pkey instanceof RSAPrivateKey)) {
            throw new IllegalStateException("Private key is not RSA; unsupported for RSA_* JWE.");
        }
        idTokenDecryptKey = (RSAPrivateKey) pkey;
    }


    private String firstCertificateAlias(KeyStore ks) throws Exception {
        var en = ks.aliases();
        while (en.hasMoreElements()) {
            String a = en.nextElement();
            if (ks.getCertificate(a) != null) return a;
        }
        return null;
    }


    private String firstPrivateKeyAlias(KeyStore ks) throws Exception {
        var en = ks.aliases();
        while (en.hasMoreElements()) {
            String a = en.nextElement();
            if (ks.isKeyEntry(a)) return a;
        }
        return null;
    }


    private String getHeaderJson(String token) {
        if (token == null || token.isBlank()) return null;
        String[] parts = token.split("\\.");
        if (parts.length < 2) return null;
        try {
            byte[] raw = java.util.Base64.getUrlDecoder().decode(parts[0]);
            return new String(raw, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return null;
        }
    }


    public String decryptIfNeeded(String idToken) throws Exception {
        if (idToken == null || idToken.isBlank()) {
            throw new IllegalArgumentException("id_token is null or empty");
        }

        String[] parts = idToken.split("\\.");
        if (parts.length < 1 || parts[0] == null) {
            throw new IllegalArgumentException("Invalid id_token format — missing header part");
        }

        String headerJson;
        try {
            headerJson = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            throw new JOSEException("Invalid base64url header in id_token", e);
        }

        boolean isEncrypted = false;
        String contentEncAlg = null;
        String keyMgmtAlg = null;
        try {
            var headerMap = JSONObjectUtils.parse(headerJson);
            Object enc = headerMap.get("enc");
            Object alg = headerMap.get("alg");
            if (enc != null && !enc.toString().isBlank()) {
                isEncrypted = true;
                contentEncAlg = enc.toString();
            }
            if (alg != null) keyMgmtAlg = alg.toString();
        } catch (Exception ex) {
            throw new JOSEException("Invalid JWT header JSON", ex);
        }

        if (!isEncrypted) {
            return idToken;
        }

        if (idTokenDecryptKey == null) {
            throw new IllegalStateException("Id token is encrypted but no RSA private key is configured.");
        }

        JWEObject jwe = JWEObject.parse(idToken);

        JWEAlgorithm alg = jwe.getHeader().getAlgorithm();
        if (!(JWEAlgorithm.RSA_OAEP_256.equals(alg)
                || JWEAlgorithm.RSA_OAEP.equals(alg)
                || JWEAlgorithm.RSA1_5.equals(alg))) {
            throw new JOSEException("Unsupported JWE alg: " + alg + " (supported: RSA_OAEP_256, RSA_OAEP, RSA1_5)");
        }

        jwe.decrypt(new RSADecrypter(idTokenDecryptKey));

        String inner = jwe.getPayload() != null ? jwe.getPayload().toString() : null;
        if (inner == null || inner.isBlank()) {
            throw new JOSEException("Decryption succeeded but inner payload is empty.");
        }

        return inner;
    }

    public boolean verifyIfJws(String token) throws Exception {
        try {
            SignedJWT jws = SignedJWT.parse(token);
            var verifier = new RSASSAVerifier(jwtVerifyPublicKey);
            return jws.verify(verifier);
        } catch (ParseException e) {
            return false;         }
    }

    public JWTClaimsSet getClaimsIfValidJws(String token, String expectedIssuer, String expectedAudience) throws Exception {
        SignedJWT jws = SignedJWT.parse(token);
        var verifier = new RSASSAVerifier(jwtVerifyPublicKey);
        if (!jws.verify(verifier)) throw new JOSEException("Invalid JWS signature");

        JWTClaimsSet claims = jws.getJWTClaimsSet();

        if (expectedIssuer != null && !expectedIssuer.equals(claims.getIssuer()))
            throw new JOSEException("Invalid issuer");
        if (expectedAudience != null && (claims.getAudience() == null || !claims.getAudience().contains(expectedAudience)))
            throw new JOSEException("Invalid audience");
        if (claims.getExpirationTime() != null && claims.getExpirationTime().toInstant().isBefore(Instant.now()))
            throw new JOSEException("Token expired");

        return claims;
    }
}
