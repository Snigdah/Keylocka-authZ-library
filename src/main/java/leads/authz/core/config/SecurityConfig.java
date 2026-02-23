package leads.authz.core.config;

import leads.authz.core.filter.PolicyAuthorizationFilter;
import leads.authz.core.security.SecurityMode;
import leads.authz.core.security.SecurityProperties;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

    private final SecurityProperties props;
    private final PolicyAuthorizationFilter policyFilter;

    public SecurityConfig(
            @Qualifier("appSecurityProperties") SecurityProperties props,
            PolicyAuthorizationFilter policyFilter) {
        this.props = props;
        this.policyFilter = policyFilter;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthenticationConverter converter) throws Exception {

        if (props.getMode() == SecurityMode.NONE) {
            http
                    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    .csrf(AbstractHttpConfigurer::disable)
                    .securityMatcher("/**");
            return http.build();
        }

        http.authorizeHttpRequests(auth -> {
            // Register permit-all entries with optional method filtering
            for (SecurityProperties.PermitAllEntry entry : props.getPermitAll()) {
                if (entry.isAllMethods()) {
                    // No methods specified → permit all HTTP methods for this path
                    auth.requestMatchers(entry.getPath()).permitAll();
                } else {
                    // Methods specified → permit only those methods for this path
                    for (String method : entry.getMethods()) {
                        auth.requestMatchers(HttpMethod.valueOf(method.toUpperCase()), entry.getPath()).permitAll();
                    }
                }
            }
            auth.anyRequest().authenticated();
        });

        http.csrf(AbstractHttpConfigurer::disable);

        http.oauth2ResourceServer(oauth2 ->
                oauth2.jwt(jwt -> jwt.jwtAuthenticationConverter(converter))
        );

        if (props.getMode() == SecurityMode.POLICY) {
            http.addFilterAfter(policyFilter, BearerTokenAuthenticationFilter.class);
        }

        return http.build();
    }
}