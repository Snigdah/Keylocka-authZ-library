package leads.authz.core.interceptor;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import leads.authz.core.security.KeycloakAuthzChecker;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerInterceptor;

@Component
public class AuthorizationInterceptor implements HandlerInterceptor {

    private final KeycloakAuthzChecker checker;

    public AuthorizationInterceptor(KeycloakAuthzChecker checker) {
        this.checker = checker;
    }

    @Override
    public boolean preHandle(HttpServletRequest request,
                             HttpServletResponse response,
                             Object handler) throws Exception {

        if (!(handler instanceof HandlerMethod hm))
            return true;

        String resource = hm.getMethod().getName();
        String scope = request.getMethod();

        Jwt jwt = (Jwt) SecurityContextHolder
                .getContext()
                .getAuthentication()
                .getPrincipal();

        boolean permitted =
                checker.hasPermission(jwt.getTokenValue(),
                        resource,
                        scope);

        if (!permitted) {
            response.sendError(403, "Permission denied");
            return false;
        }

        return true;
    }
}

