package kombit.oidc.controller;

import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpSession;
import kombit.oidc.util.JwtHelper;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import kombit.oidc.config.OidcClientConfig;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Map;

@Controller
public class HomeController {

    private final OidcClientConfig cfg;
    public HomeController(OidcClientConfig cfg) {
        this.cfg = cfg;
    }

    @GetMapping("/home")
    public String home(Model model, HttpSession session) throws Exception {
        String idToken     = (String) session.getAttribute("id_token");
        String accessToken = (String) session.getAttribute("access_token");

        if (idToken == null || accessToken == null) {
            return "redirect:/";
        }

        var idInfo  = JwtHelper.getJwtInfo(idToken);
        var accInfo = JwtHelper.getJwtInfo(accessToken);

        model.addAttribute("idToken", idToken);
        model.addAttribute("accessToken", accessToken);

        model.addAttribute("idTokenHeader",   idInfo != null ? idInfo.headerJson()   : "");
        model.addAttribute("idTokenPayload",  idInfo != null ? idInfo.payloadJson()  : "");
        model.addAttribute("accessTokenHeader",  accInfo != null ? accInfo.headerJson()  : "");
        model.addAttribute("accessTokenPayload", accInfo != null ? accInfo.payloadJson() : "");

        // Claims
        model.addAttribute("idClaims", parseIdToken(idToken));

        return "home";
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

            SignedJWT nested = jwe.getPayload().toSignedJWT();
            if (nested != null) {
                return nested.getJWTClaimsSet().getClaims();
            } else {
                return jwe.getJWTClaimsSet().getClaims();
            }
        } else { // JWS (signed only)
            SignedJWT jws = SignedJWT.parse(idToken);
            return jws.getJWTClaimsSet().getClaims();
        }
    }
}
