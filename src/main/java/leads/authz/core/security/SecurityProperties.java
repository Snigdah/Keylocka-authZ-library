package leads.authz.core.security;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component("appSecurityProperties")
@ConfigurationProperties(prefix = "app.security")
@Primary
public class SecurityProperties {

    private SecurityMode mode = SecurityMode.INTERCEPTOR;

    private List<String> permitAll = new ArrayList<>();

    public SecurityMode getMode() {
        return mode;
    }

    public void setMode(SecurityMode mode) {
        this.mode = mode;
    }

    public List<String> getPermitAll() {
        return permitAll;
    }

    public void setPermitAll(List<String> permitAll) {
        this.permitAll = permitAll;
    }
}