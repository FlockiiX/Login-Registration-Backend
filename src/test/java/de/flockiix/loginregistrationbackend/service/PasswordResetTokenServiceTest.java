package de.flockiix.loginregistrationbackend.service;

import de.flockiix.loginregistrationbackend.model.PasswordResetToken;
import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.repository.PasswordResetTokenRepository;
import de.flockiix.loginregistrationbackend.service.impl.PasswordResetTokenServiceImpl;
import de.flockiix.loginregistrationbackend.util.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class PasswordResetTokenServiceTest {
    private PasswordResetTokenService passwordResetTokenService;

    @Mock
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        passwordResetTokenService = new PasswordResetTokenServiceImpl(passwordResetTokenRepository);
    }

    @Test
    void createPasswordResetTokenForUser() {
        User user = TestUtils.getUser();
        passwordResetTokenService.createPasswordResetTokenForUser(user);
        ArgumentCaptor<PasswordResetToken> argumentCaptor = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(passwordResetTokenRepository).save(argumentCaptor.capture());
        PasswordResetToken capturedToken = argumentCaptor.getValue();
        assertThat(capturedToken.getUser()).isEqualTo(user);
    }

    @Test
    void getPasswordResetTokenByToken() {
        PasswordResetToken passwordResetToken = new PasswordResetToken(LocalDateTime.now(), LocalDateTime.now(), TestUtils.getUser());
        given(passwordResetTokenRepository.findPasswordResetTokenByToken(passwordResetToken.getToken())).willReturn(Optional.of(passwordResetToken));
        Optional<PasswordResetToken> actual = passwordResetTokenService.getPasswordResetTokenByToken(passwordResetToken.getToken());
        assertThat(actual.get()).isEqualTo(passwordResetToken);
    }

    @Test
    void isAllowedToRequestPasswordResetToken() {
        User user = TestUtils.getUser();
        given(passwordResetTokenRepository.findPasswordResetTokensByUserEmail(user.getEmail())).willReturn(null);
        assertThat(passwordResetTokenService.isAllowedToRequestPasswordResetToken(user.getEmail())).isTrue();
    }
}