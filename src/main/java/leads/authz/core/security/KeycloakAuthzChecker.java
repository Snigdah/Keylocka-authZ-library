package leads.authz.core.security;

import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

@Component("kcAuth")
public class KeycloakAuthzChecker {

    private final AuthzClient authzClient;
    private final SecurityProperties props;

    public KeycloakAuthzChecker(AuthzClient authzClient,
                                @Qualifier("appSecurityProperties")
                                SecurityProperties props) {
        this.authzClient = authzClient;
        this.props = props;
        System.out.println(">>> KeycloakAuthzChecker loaded");
    }

    public boolean hasPermission(String token,
                                 String resource,
                                 String scope) {

        // DEV MODE → Always allow
        if (props.getMode() == SecurityMode.NONE) {
            return true;
        }

        // If no token but security enabled → deny
        if (token == null || token.isBlank()) {
            return false;
        }

        try {
            AuthorizationRequest request = new AuthorizationRequest();
            request.addPermission(resource, scope);
            request.setSubjectToken(token);

            AccessTokenResponse rpt =
                    authzClient.authorization(token).authorize(request);

            return rpt != null && rpt.getToken() != null;

        } catch (Exception e) {
            return false;
        }
    }
}
