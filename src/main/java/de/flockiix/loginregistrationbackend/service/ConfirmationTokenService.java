package de.flockiix.loginregistrationbackend.service;

import de.flockiix.loginregistrationbackend.model.ConfirmationToken;
import de.flockiix.loginregistrationbackend.model.User;

import java.util.Optional;

public interface ConfirmationTokenService {
    ConfirmationToken createConfirmationTokenForUser(User user);

    Optional<ConfirmationToken> getConfirmationTokenByToken(String token);

    void setConfirmationTokenConfirmedAt(String token);
}
