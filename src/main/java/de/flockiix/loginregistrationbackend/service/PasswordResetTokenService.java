package de.flockiix.loginregistrationbackend.service;

import de.flockiix.loginregistrationbackend.model.PasswordResetToken;

import java.util.Optional;

public interface PasswordResetTokenService {
    void savePasswordResetToken(PasswordResetToken passwordResetToken);

    Optional<PasswordResetToken> getPasswordResetTokenByToken(String token);

    void setPasswordResetTokenConfirmedAt(String token);
}
