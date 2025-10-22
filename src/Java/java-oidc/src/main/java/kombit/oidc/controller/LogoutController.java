package kombit.oidc.controller;

import kombit.oidc.config.OidcClientConfig;
import kombit.oidc.util.JwtHelper;
import kombit.oidc.service.OAuthRevocationService;
import kombit.oidc.util.TokenBundle;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.util.UriComponentsBuilder;

@Controller
public class LogoutController {

    private final OAuthRevocationService revocationService;
    private final OidcClientConfig cfg;

    public LogoutController(
            OAuthRevocationService revocationService, OidcClientConfig cfg) {
        this.revocationService = revocationService;
        this.cfg = cfg;
    }

    @PostMapping("/app/logout")
    public String logoutPost(HttpServletRequest req, HttpSession session) {
        return doLogout(req, session);
    }

    @GetMapping("/app/logout")
    public String logoutGet(HttpServletRequest req, HttpSession session) {
        return doLogout(req, session);
    }

    @GetMapping("/logout/callback")
    public String afterLogout() {
        return "redirect:/";
    }

    private String doLogout(HttpServletRequest req, HttpSession session) {
        TokenBundle tokens = (TokenBundle) session.getAttribute("TOKENS");
        //try { revocationService.revokeTokens(tokens); } catch (Exception ignore) {}
        session.invalidate();
        String postLogout = UriComponentsBuilder.fromHttpUrl(JwtHelper.getBaseUrl(req))
                .path("/logout/callback").toUriString();
        String url = cfg.endSessionEndpoint()
                + (cfg.endSessionEndpoint().contains("?") ? "&" : "?")
                + (tokens != null && tokens.getIdToken() != null && !tokens.getIdToken().isBlank()
                ? "id_token_hint=" + urlEncode(tokens.getIdToken()) + "&" : "")
                + "post_logout_redirect_uri=" + urlEncode(postLogout);
        return "redirect:" + url;
    }

    private static String urlEncode(String s) {
        try { return java.net.URLEncoder.encode(s, java.nio.charset.StandardCharsets.UTF_8); }
        catch (Exception e) { return ""; }
    }
}
