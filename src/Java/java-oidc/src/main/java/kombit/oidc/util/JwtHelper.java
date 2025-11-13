package kombit.oidc.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class JwtHelper {
    public record JwtInfo(String headerJson, String payloadJson) {}
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static JwtInfo getJwtInfo(String token) {
        if (token == null || token.isBlank()) return null;

        String[] parts = token.split("\\.");
        if (parts.length < 2) return null;

        String header = decodeBase64UrlToString(parts[0]);
        String payload = decodeBase64UrlToString(parts[1]);
        if (header == null || payload == null) return null;

        return new JwtInfo(prettyJson(header), prettyJson(payload));
    }

    public static String decodeBase64UrlToString(String input) {
        if (input == null || input.isBlank()) return null;
        try {
            byte[] bytes = Base64.getUrlDecoder().decode(input);
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException ex) {
            String s = input.replace('-', '+').replace('_', '/');
            int mod = s.length() % 4;
            if (mod == 2) s += "==";
            else if (mod == 3) s += "=";
            else if (mod != 0) return null;

            try {
                byte[] bytes = Base64.getDecoder().decode(s);
                return new String(bytes, StandardCharsets.UTF_8);
            } catch (IllegalArgumentException e) {
                return null;
            }
        }
    }
    public static String prettyJson(String json) {
        if (json == null || json.isBlank()) return "";
        try {
            Object tree = MAPPER.readValue(json, Object.class);
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(tree);
        } catch (JsonProcessingException e) {
            return json;
        }
    }
    public static String getBaseUrl(HttpServletRequest req) {
        String scheme = req.getHeader("X-Forwarded-Proto");
        if (scheme == null || scheme.isBlank()) scheme = req.getScheme();  // http/https
        String host = req.getHeader("X-Forwarded-Host");
        if (host == null || host.isBlank()) host = req.getServerName();

        int port = req.getServerPort();
        String forwardedPort = req.getHeader("X-Forwarded-Port");
        if (forwardedPort != null && !forwardedPort.isBlank()) {
            try { port = Integer.parseInt(forwardedPort); } catch (NumberFormatException ignored) {}
        }

        boolean defaultPort = ("http".equalsIgnoreCase(scheme) && port == 80)
                || ("https".equalsIgnoreCase(scheme) && port == 443);

        return scheme + "://" + host + (defaultPort ? "" : ":" + port);
    }
}
