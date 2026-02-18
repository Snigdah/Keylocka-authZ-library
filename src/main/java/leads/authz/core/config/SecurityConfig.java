package leads.authz.core.config;

import leads.authz.core.security.SecurityMode;
import leads.authz.core.security.SecurityProperties;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableConfigurationProperties(SecurityProperties.class)
public class SecurityConfig {

    private final SecurityProperties props;

    public SecurityConfig(
            @Qualifier("appSecurityProperties")  SecurityProperties props) {
        this.props = props;
    }

    @Bean
    @Order(1)
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthenticationConverter converter) throws Exception {


        System.out.println(">>> Security mode: " + props.getMode()); // confirm this prints

        if (props.getMode() == SecurityMode.NONE) {
            http
                    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    .csrf(AbstractHttpConfigurer::disable)
                    .securityMatcher("/**"); // match all paths

            return http.build();
        }

        http.authorizeHttpRequests(auth -> {
            if (!props.getPermitAll().isEmpty()) {
                auth.requestMatchers(
                        props.getPermitAll().toArray(new String[0])
                ).permitAll();
            }

            auth.anyRequest().authenticated();
        });

        http.csrf(AbstractHttpConfigurer::disable);

        http.oauth2ResourceServer(oauth2 ->
                oauth2.jwt(jwt ->
                        jwt.jwtAuthenticationConverter(converter)
                )
        );

        return http.build();
    }
}
