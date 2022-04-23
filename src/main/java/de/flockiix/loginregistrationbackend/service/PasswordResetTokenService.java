package de.flockiix.loginregistrationbackend.service;

import de.flockiix.loginregistrationbackend.model.PasswordResetToken;
import de.flockiix.loginregistrationbackend.model.User;

import java.util.Optional;

public interface PasswordResetTokenService {
    PasswordResetToken createPasswordResetTokenForUser(User user);

    Optional<PasswordResetToken> getPasswordResetTokenByToken(String token);

    void setPasswordResetTokenConfirmedAt(String token);

    boolean isAllowedToRequestPasswordResetToken(String email);
}
