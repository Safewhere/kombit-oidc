package kombit.oidc.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.SecurityFilterChain;
import jakarta.servlet.http.HttpServletRequest;

@Configuration
@EnableConfigurationProperties(SecurityConfig.OidcProps.class)
public class SecurityConfig {

  @ConfigurationProperties(prefix = "app.oidc")
  public static class OidcProps {
        private String acrValues;
        private int maxAge;
  }

  @Bean
    public OidcProps oidcProps() {
      return new OidcProps();
  }

@Bean
SecurityFilterChain security(HttpSecurity http,
                             ClientRegistrationRepository repo,
                             OidcProps oidcProps) throws Exception {
  var logoutHandler = new OidcClientInitiatedLogoutSuccessHandler(repo);
  logoutHandler.setPostLogoutRedirectUri("{baseUrl}/");

  http
    .authorizeHttpRequests(a -> a.anyRequest().permitAll())
    .oauth2Login(o -> o
      .authorizationEndpoint(ep -> ep.authorizationRequestResolver(authorizationRequestResolver(repo, oidcProps)))
      .defaultSuccessUrl("/", true)
    )
    .logout(l -> l.logoutSuccessHandler(logoutHandler));

  return http.build();
}

  @Bean
  OAuth2AuthorizationRequestResolver authorizationRequestResolver(
      ClientRegistrationRepository repo, OidcProps oidcProps) {

    var defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(repo, "/oauth2/authorization");

    return new OAuth2AuthorizationRequestResolver() {
      @Override public OAuth2AuthorizationRequest resolve(HttpServletRequest req) {
        return customize(defaultResolver.resolve(req), req);
      }
      @Override public OAuth2AuthorizationRequest resolve(HttpServletRequest req, String id) {
        return customize(defaultResolver.resolve(req, id), req);
      }
      private OAuth2AuthorizationRequest customize(OAuth2AuthorizationRequest orig, HttpServletRequest req) {
        if (orig == null) return null;
        var extras = new java.util.HashMap<>(orig.getAdditionalParameters());

        String acr = firstNonBlank(req.getParameter("acr_values"), oidcProps.acrValues);
        if (acr != null && !acr.isBlank()) extras.put("acr_values", acr);

        String max = req.getParameter("max_age");
        if (max == null || max.isBlank()) {
          if (oidcProps.maxAge > 0) max = Integer.toString(oidcProps.maxAge);
        }
        if (max != null) {
          try { if (Integer.parseInt(max) > 0) extras.put("max_age", max); } catch (NumberFormatException ignore) {}
        }

        String loginHint = req.getParameter("login_hint");
        if (loginHint != null && !loginHint.isBlank()) extras.put("login_hint", loginHint);

        return OAuth2AuthorizationRequest.from(orig).additionalParameters(extras).build();
      }
      private String firstNonBlank(String a, String b) { return (a != null && !a.isBlank()) ? a : ((b != null && !b.isBlank()) ? b : null); }
    };
  }
}
