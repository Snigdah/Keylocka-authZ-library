package leads.authz.core.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import leads.authz.core.model.ClientTokenCache;
import leads.authz.core.utils.HttpUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Service
public class ClientTokenService {

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.credentials.secret:}")
    private String clientSecret; // optional

    @Value("${keycloak.cache-time:3600}") // seconds
    private long cacheTime;

    private final ObjectMapper mapper = new ObjectMapper();

    private ClientTokenCache cache;

    @PostConstruct
    public void init() {
        refreshToken();
    }

    private synchronized void refreshToken() {
        try {
            String tokenUrl = authServerUrl + "/realms/" + realm + "/protocol/openid-connect/token";
            Map<String, String> formParams = new HashMap<>();
            formParams.put("grant_type", "client_credentials");
            formParams.put("client_id", clientId);
            if (!clientSecret.isEmpty()) {
                formParams.put("client_secret", clientSecret);
            }

            String response = HttpUtils.postForm(tokenUrl, formParams);
            JsonNode jsonNode = mapper.readTree(response);
            String accessToken = jsonNode.get("access_token").asText();
            Instant expireAt = Instant.now().plusSeconds(cacheTime);

            cache = new ClientTokenCache(accessToken, expireAt);
        } catch (IOException e) {
            throw new RuntimeException("Failed to fetch client token", e);
        }
    }

    public synchronized String getClientToken() {
        if (cache == null || cache.isExpired()) {
            refreshToken();
        }
        return cache.getToken();
    }

    public synchronized String getNewClientToken() {
        refreshToken();
        return cache.getToken();
    }
}
