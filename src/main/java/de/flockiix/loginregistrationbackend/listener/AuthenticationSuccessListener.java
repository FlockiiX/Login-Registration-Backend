package de.flockiix.loginregistrationbackend.listener;

import de.flockiix.loginregistrationbackend.cache.LoginAttemptCache;
import de.flockiix.loginregistrationbackend.model.UserPrincipal;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationSuccessListener {
    private final LoginAttemptCache loginAttemptCache;

    public AuthenticationSuccessListener(LoginAttemptCache loginAttemptCache) {
        this.loginAttemptCache = loginAttemptCache;
    }

    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        Object principal = event.getAuthentication().getPrincipal();
        if (principal instanceof UserPrincipal user)
            loginAttemptCache.loginSucceeded(user.getUsername());
    }
}
