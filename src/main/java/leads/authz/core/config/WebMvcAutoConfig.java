package leads.authz.core.config;

import leads.authz.core.interceptor.AuthorizationInterceptor;
import leads.authz.core.security.SecurityMode;
import leads.authz.core.security.SecurityProperties;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.*;

@Configuration
public class WebMvcAutoConfig implements WebMvcConfigurer {

    private final AuthorizationInterceptor interceptor;
    private final SecurityProperties props;

    public WebMvcAutoConfig(
            AuthorizationInterceptor interceptor,
            @Qualifier("appSecurityProperties") SecurityProperties props) {
        this.interceptor = interceptor;
        this.props = props;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {

        System.out.println(">>> Interceptor mode: " + props.getMode());

        if (props.getMode() == SecurityMode.INTERCEPTOR
                || props.getMode() == SecurityMode.MIXED) {

            registry.addInterceptor(interceptor);
            System.out.println(">>> AuthorizationInterceptor REGISTERED");

        } else {
            System.out.println(">>> AuthorizationInterceptor SKIPPED");
        }
    }
}
