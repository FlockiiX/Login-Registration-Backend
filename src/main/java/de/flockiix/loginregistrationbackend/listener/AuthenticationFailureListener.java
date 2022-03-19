package de.flockiix.loginregistrationbackend.listener;

import de.flockiix.loginregistrationbackend.cache.LoginAttemptCache;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationFailureListener {
    private final LoginAttemptCache loginAttemptCache;

    public AuthenticationFailureListener(LoginAttemptCache loginAttemptCache) {
        this.loginAttemptCache = loginAttemptCache;
    }

    @EventListener
    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
        Object principal = event.getAuthentication().getPrincipal();
        if (principal instanceof String email)
            loginAttemptCache.loginFailed(email);
    }
}
