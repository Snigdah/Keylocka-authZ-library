package leads.authz.core.config;

import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.authorization.client.Configuration;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;

import java.util.Map;

@org.springframework.context.annotation.Configuration
public class AuthzClientAutoConfig {

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.credentials.secret}")
    private String clientSecret;

    @Bean
    public AuthzClient authzClient() {
        Configuration configuration = new Configuration(
                authServerUrl,
                realm,
                clientId,
                Map.of("secret", clientSecret),
                null
        );

        return AuthzClient.create(configuration);
    }
}
