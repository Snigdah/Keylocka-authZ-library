package leads.authz.core.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component("appSecurityProperties")
@ConfigurationProperties(prefix = "app.security")
@Primary
public class SecurityProperties {

    private SecurityMode mode = SecurityMode.INTERCEPTOR;
    private List<PermitAllEntry> permitAll = new ArrayList<>();

    public SecurityMode getMode() { return mode; }
    public void setMode(SecurityMode mode) { this.mode = mode; }
    public List<PermitAllEntry> getPermitAll() { return permitAll; }
    public void setPermitAll(List<PermitAllEntry> permitAll) { this.permitAll = permitAll; }

    public static class PermitAllEntry {
        private String path;
        private List<String> methods = new ArrayList<>(); // empty = all methods

        public String getPath() { return path; }
        public void setPath(String path) { this.path = path; }
        public List<String> getMethods() { return methods; }
        public void setMethods(List<String> methods) { this.methods = methods; }

        public boolean isAllMethods() {
            return methods == null || methods.isEmpty();
        }
    }

}