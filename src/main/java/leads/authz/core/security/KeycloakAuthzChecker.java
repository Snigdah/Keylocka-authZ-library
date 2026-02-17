package leads.authz.core.security;

import org.keycloak.authorization.client.AuthzClient;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.idm.authorization.AuthorizationRequest;
import org.springframework.stereotype.Component;

@Component("kcAuth")
public class KeycloakAuthzChecker {

    private final AuthzClient authzClient;

    public KeycloakAuthzChecker(AuthzClient authzClient) {
        this.authzClient = authzClient;
        System.out.println(">>> KeycloakAuthzChecker loaded");
    }

    public boolean hasPermission(String token,
                                 String resource,
                                 String scope) {
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
