package de.flockiix.loginregistrationbackend.service.impl;

import de.flockiix.loginregistrationbackend.exception.TokenNotFoundException;
import de.flockiix.loginregistrationbackend.model.PasswordResetToken;
import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.repository.PasswordResetTokenRepository;
import de.flockiix.loginregistrationbackend.service.PasswordResetTokenService;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Service
public class PasswordResetTokenServiceImpl implements PasswordResetTokenService {
    private final PasswordResetTokenRepository passwordResetTokenRepository;

    public PasswordResetTokenServiceImpl(PasswordResetTokenRepository passwordResetTokenRepository) {
        this.passwordResetTokenRepository = passwordResetTokenRepository;
    }

    @Override
    public PasswordResetToken createPasswordResetTokenForUser(User user) {
        return passwordResetTokenRepository.save(new PasswordResetToken(
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                user
        ));
    }

    @Override
    public Optional<PasswordResetToken> getPasswordResetTokenByToken(String token) {
        return passwordResetTokenRepository.findPasswordResetTokenByToken(token);
    }

    @Override
    public void setPasswordResetTokenConfirmedAt(String token) {
        PasswordResetToken passwordResetToken = passwordResetTokenRepository
                .findPasswordResetTokenByToken(token)
                .orElseThrow(() -> new TokenNotFoundException("Token not found"));
        passwordResetToken.setConfirmedAt(LocalDateTime.now());
    }

    @Override
    public boolean isAllowedToRequestPasswordResetToken(String email) {
        List<PasswordResetToken> resetTokenList = passwordResetTokenRepository.findPasswordResetTokensByUserEmail(email);
        if (resetTokenList.isEmpty())
            return true;

        return resetTokenList.get(0).getCreatedAt().isBefore(LocalDateTime.now().minusDays(7));
    }
}
