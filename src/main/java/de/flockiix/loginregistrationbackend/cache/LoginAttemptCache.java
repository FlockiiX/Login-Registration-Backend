package de.flockiix.loginregistrationbackend.cache;

import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import de.flockiix.loginregistrationbackend.config.properties.SecurityProperties;
import de.flockiix.loginregistrationbackend.constant.EmailConstant;
import de.flockiix.loginregistrationbackend.exception.EmailSendFailedException;
import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.service.EmailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

@Service
public class LoginAttemptCache {
    private static final Logger LOGGER = LoggerFactory.getLogger(LoginAttemptCache.class);
    private final LoadingCache<String, Integer> attemptCache;
    private final EmailService emailService;
    private final SecurityProperties securityProperties;

    public LoginAttemptCache(EmailService emailService, SecurityProperties securityProperties) {
        this.attemptCache = CacheBuilder.newBuilder()
                .expireAfterWrite(1, TimeUnit.DAYS)
                .build(new CacheLoader<>() {
                    public Integer load(String key) {
                        return 0;
                    }
                });
        this.emailService = emailService;
        this.securityProperties = securityProperties;
    }

    /**
     * Deletes the login attempts if the user's login succeeded.
     *
     * @param email the email from the user
     */
    public void loginSucceeded(String email) {
        attemptCache.invalidate(email);
    }

    /**
     * Adds a login attempt if the user's login was not successful.
     *
     * @param email the email from the user
     */
    public void loginFailed(String email) {
        int attempts = getLoginAttempts(email);
        attemptCache.put(email, ++attempts);
    }

    /**
     * Checks if the user is blocked due to multiple suspicious login attempts.
     *
     * @param email the email from the user
     * @return {@code true} if the user is blocked and {@code false} otherwise
     */
    public boolean isBlocked(String email) {
        try {
            return attemptCache.get(email) >= securityProperties.getLoginAttempts();
        } catch (ExecutionException exception) {
            return false;
        }
    }

    /**
     * Gets the number of login attempts of the user.
     *
     * @param email the email from the user
     * @return the number of login attempts
     */
    public int getLoginAttempts(String email) {
        try {
            return attemptCache.get(email);
        } catch (ExecutionException exception) {
            return 0;
        }
    }

    /**
     * Validates a login attempt and sends an email to the user if there is something suspicious.
     *
     * @param user the user
     */
    public void validateLoginAttempt(User user) {
        if (user.isNotLocked()) {
            if (isBlocked(user.getEmail())) {
                if (user.isNotLocked())
                    sendEmail(user.getEmail(), "User Management Security", EmailConstant.buildAccountLockedEmail(user.getFirstName()));
                user.setNotLocked(false);
            } else {
                user.setNotLocked(true);
            }
            if (getLoginAttempts(user.getEmail()) == 3)
                sendEmail(user.getEmail(), "Safety warning", EmailConstant.buildSafetyWarningEmail(user.getFirstName()));
        }
    }


    /**
     * Sends an email to the given user.
     *
     * @param email   the email from the user
     * @param subject the email subject
     * @param content the email content
     */
    private void sendEmail(String email, String subject, String content) {
        try {
            emailService.sendEmail(email, subject, content);
        } catch (EmailSendFailedException exception) {
            LOGGER.error("Email send failed", exception);
        }
    }
}
