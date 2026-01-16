package kombit.oidc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;

@Configuration
public class ClientRegistrationConfig {

    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(OidcProperties props) {
        ClientRegistration registration = ClientRegistration.withRegistrationId(props.getRegistrationId())
                .clientId(props.getClientId())
                .clientSecret(props.getClientSecret())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
                .scope(props.getScope().split(","))
                .authorizationUri(props.getAuthorizationEndpoint())
                .tokenUri(props.getTokenEndpoint())
                .issuerUri(props.getIssuerUri())
                .build();

        return new InMemoryClientRegistrationRepository(registration);
    }
}
