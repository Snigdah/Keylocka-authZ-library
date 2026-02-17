package leads.authz.core.config;

import leads.authz.core.security.KeycloakAuthzChecker;
import leads.authz.core.security.KeycloakRoleConverter;
import org.keycloak.authorization.client.AuthzClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;

@Configuration
@EnableMethodSecurity
public class SecurityAutoConfig {

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());
        return converter;
    }

}
