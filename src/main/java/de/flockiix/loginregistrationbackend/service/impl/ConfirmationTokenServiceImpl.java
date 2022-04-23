package de.flockiix.loginregistrationbackend.service.impl;

import de.flockiix.loginregistrationbackend.exception.TokenNotFoundException;
import de.flockiix.loginregistrationbackend.model.ConfirmationToken;
import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.repository.ConfirmationTokenRepository;
import de.flockiix.loginregistrationbackend.service.ConfirmationTokenService;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
public class ConfirmationTokenServiceImpl implements ConfirmationTokenService {
    private final ConfirmationTokenRepository confirmationTokenRepository;

    public ConfirmationTokenServiceImpl(ConfirmationTokenRepository confirmationTokenRepository) {
        this.confirmationTokenRepository = confirmationTokenRepository;
    }

    @Override
    public ConfirmationToken createConfirmationTokenForUser(User user) {
        return confirmationTokenRepository.save(new ConfirmationToken(
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                user
        ));
    }

    @Override
    public Optional<ConfirmationToken> getConfirmationTokenByToken(String token) {
        return confirmationTokenRepository.findConfirmationTokenByToken(token);
    }

    @Override
    public void setConfirmationTokenConfirmedAt(String token) {
        ConfirmationToken confirmationToken = confirmationTokenRepository
                .findConfirmationTokenByToken(token)
                .orElseThrow(() -> new TokenNotFoundException("Token not found"));
        confirmationToken.setConfirmedAt(LocalDateTime.now());
    }
}
