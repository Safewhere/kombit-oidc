package kombit.oidc.service;
import kombit.oidc.config.OidcClientConfig;
import kombit.oidc.util.TokenBundle;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.util.retry.Retry;

import java.time.Duration;
@Service
public class OAuthRevocationService {
    private final WebClient client;
    private final OidcClientConfig cfg;


    public OAuthRevocationService(OidcClientConfig cfg) {
        this.cfg = cfg;
        this.client = WebClient.builder()
                .defaultHeaders(h -> h.setBasicAuth(cfg.clientId(), cfg.clientSecret()))
                .build();
    }

    public void revokeTokens(TokenBundle tokens) {
        if (tokens == null) return;

        if (tokens.getRefreshToken() != null && !tokens.getRefreshToken().isBlank()) {
            revokeSingle(tokens.getRefreshToken(), "refresh_token", "refresh_token");
        }

        if (tokens.getAccessToken() != null && !tokens.getAccessToken().isBlank()) {
            revokeSingle(tokens.getAccessToken(), "access_token", "access_token");
        }
    }

    private void revokeSingle(String token, String tokenTypeHint, String logName) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("token", token);
        form.add("token_type_hint", tokenTypeHint);

        client.post()
                .uri(cfg.revokeEndpoint())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .bodyValue(form)
                .exchangeToMono(resp -> {
                    if (resp.statusCode().is2xxSuccessful()) {
                        return resp.releaseBody().then(Mono.empty());
                    } else {
                        return resp.createException().flatMap(ex -> {
                            System.err.println("Revoke " + logName + " failed: " + ex.getMessage());
                            return Mono.empty();
                        });
                    }
                })
                .retryWhen(Retry.fixedDelay(1, Duration.ofMillis(200)))
                .block(Duration.ofSeconds(5));
    }
}
