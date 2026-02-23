package leads.authz.core.model;

import java.time.Instant;

public class ClientTokenCache {
    private String token;
    private Instant expireAt;

    public ClientTokenCache(String token, Instant expireAt) {
        this.token = token;
        this.expireAt = expireAt;
    }

    public String getToken() {
        return token;
    }

    public Instant getExpireAt() {
        return expireAt;
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expireAt);
    }
}