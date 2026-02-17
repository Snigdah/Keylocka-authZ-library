package leads.authz.core.config;

import leads.authz.core.interceptor.AuthorizationInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.*;

@Configuration
public class WebMvcAutoConfig implements WebMvcConfigurer {

    private final AuthorizationInterceptor interceptor;

    public WebMvcAutoConfig(AuthorizationInterceptor interceptor) {
        this.interceptor = interceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(interceptor);
    }
}
