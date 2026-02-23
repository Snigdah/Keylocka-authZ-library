package leads.authz.core.config;

import leads.authz.core.filter.PolicyAuthorizationFilter;
import leads.authz.core.security.KeycloakAuthzChecker;
import leads.authz.core.security.KeycloakRoleConverter;
import leads.authz.core.security.SecurityProperties;
import org.keycloak.authorization.client.AuthzClient;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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

    @Bean
    public PolicyAuthorizationFilter policyAuthorizationFilter(
            KeycloakAuthzChecker checker,
            AuthorizationMappingConfig mappingConfig,
            @Qualifier("appSecurityProperties")
            SecurityProperties props) {

        return new PolicyAuthorizationFilter(checker, mappingConfig, props);
    }

    @Bean
    @ConditionalOnProperty(name = "app.security.mode", havingValue = "POLICY")
    @ConditionalOnMissingBean(AuthzClient.class)
    public AuthzClient authzClient() {
        return AuthzClient.create();
    }

}
