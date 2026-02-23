package leads.authz.core.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
@ConfigurationProperties(prefix = "authorization")
public class AuthorizationMappingConfig {
    private List<Mapping> mappings;

    public List<Mapping> getMappings() {
        return mappings;
    }

    public void setMappings(List<Mapping> mappings) {
        this.mappings = mappings;
    }

    public static class Mapping {
        private String path;
        private String method;
        private String resource;
        private String scopes;

        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }

        public String getMethod() { return method; }
        public void setMethod(String method) { this.method = method; }

        public String getResource() { return resource; }
        public void setResource(String resource) { this.resource = resource; }

        public String getScopes() { return scopes; }
        public void setScopes(String scopes) { this.scopes = scopes; }
    }
}
