package leads.authz.core.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import leads.authz.core.security.KeycloakAuthzChecker;
import leads.authz.core.security.SecurityMode;
import leads.authz.core.security.SecurityProperties;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.util.AntPathMatcher;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class AuthorizationInterceptor implements HandlerInterceptor {

    private final KeycloakAuthzChecker checker;
    private final SecurityProperties props;
    private final AntPathMatcher pathMatcher = new AntPathMatcher();

    public AuthorizationInterceptor(
            KeycloakAuthzChecker checker,
            @Qualifier("appSecurityProperties") SecurityProperties props) {
        this.checker = checker;
        this.props = props;
    }

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws Exception {

        SecurityMode mode = props.getMode();

        // Skip when security disabled or using PreAuthorize only
        if (mode == SecurityMode.NONE ||
                mode == SecurityMode.PREAUTHORIZE) {
            return true;
        }

        // Skip permit-all endpoints
        if (isPermitAll(request)) {
            return true;
        }

        // Skip non-controller handlers
        if (!(handler instanceof HandlerMethod hm)) {
            return true;
        }

        Authentication auth =
                SecurityContextHolder.getContext().getAuthentication();

        if (!(auth.getPrincipal() instanceof Jwt jwt)) {
            response.sendError(401);
            return false;
        }

        String methodName = hm.getMethod().getName();
        String scope = request.getMethod();

        boolean permitted =
                checker.hasPermission(
                        jwt.getTokenValue(),
                        methodName,
                        scope);

        if (!permitted && mode == SecurityMode.MIXED) {
            request.setAttribute("AUTHZ_FAILED", true);
            return true;
        }

        if (!permitted) {
            response.sendError(403);
            return false;
        }

        request.setAttribute("AUTHZ_PASSED", true);
        return true;
    }

    /**
     * Checks whether the request path matches permit-all configuration.
     */
    private boolean isPermitAll(HttpServletRequest request) {
        String path = request.getRequestURI();

        return props.getPermitAll() != null &&
                props.getPermitAll()
                        .stream()
                        .anyMatch(p -> pathMatcher.match(p, path));
    }
}
