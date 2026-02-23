package leads.authz.core.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import leads.authz.core.config.AuthorizationMappingConfig;
import leads.authz.core.security.KeycloakAuthzChecker;
import leads.authz.core.security.SecurityMode;
import leads.authz.core.security.SecurityProperties;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class PolicyAuthorizationFilter extends OncePerRequestFilter {

    private final KeycloakAuthzChecker checker;
    private final AuthorizationMappingConfig mappingConfig;
    private final SecurityProperties props;
    private final AntPathMatcher matcher = new AntPathMatcher();

    public PolicyAuthorizationFilter(
            KeycloakAuthzChecker checker,
            AuthorizationMappingConfig mappingConfig,
            @Qualifier("appSecurityProperties")
            SecurityProperties props) {

        this.checker = checker;
        this.mappingConfig = mappingConfig;
        this.props = props;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        if (props.getMode() != SecurityMode.POLICY) {
            filterChain.doFilter(request, response);
            return;
        }

        if (mappingConfig.getMappings() == null) {
            filterChain.doFilter(request, response);
            return;
        }

        String path = request.getRequestURI();
        String method = request.getMethod();

        var mapping = mappingConfig.getMappings().stream()
                .filter(m ->
                        matcher.match(m.getPath(), path)
                                && method.equalsIgnoreCase(m.getMethod()))
                .findFirst()
                .orElse(null);

        if (mapping == null) {
            filterChain.doFilter(request, response);
            return;
        }

        var auth = SecurityContextHolder.getContext().getAuthentication();

        if (!(auth instanceof JwtAuthenticationToken jwtAuth)) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }

        String token = jwtAuth.getToken().getTokenValue();

        boolean allowed = false;

        for (String scope : mapping.getScopes().split(",")) {
            if (checker.hasPermission(
                    token,
                    mapping.getResource(),
                    scope.trim())) {
                allowed = true;
                break;
            }
        }

        if (!allowed) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        filterChain.doFilter(request, response);
    }
}
