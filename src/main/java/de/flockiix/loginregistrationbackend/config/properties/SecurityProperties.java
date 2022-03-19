package de.flockiix.loginregistrationbackend.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "application.security")
public class SecurityProperties {
    private Long loginAttempts;
    private Long requestLimit;

    public Long getLoginAttempts() {
        return loginAttempts;
    }

    public void setLoginAttempts(Long loginAttempts) {
        this.loginAttempts = loginAttempts;
    }

    public Long getRequestLimit() {
        return requestLimit;
    }

    public void setRequestLimit(Long requestLimit) {
        this.requestLimit = requestLimit;
    }
}
