package de.flockiix.loginregistrationbackend.service;

import de.flockiix.loginregistrationbackend.model.ConfirmationToken;

import java.util.Optional;

public interface ConfirmationTokenService {
    void saveConfirmationToken(ConfirmationToken confirmationToken);

    Optional<ConfirmationToken> getConfirmationTokenByToken(String token);

    void setConfirmationTokenConfirmedAt(String token);
}
