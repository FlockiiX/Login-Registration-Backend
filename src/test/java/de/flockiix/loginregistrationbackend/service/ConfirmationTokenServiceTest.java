package de.flockiix.loginregistrationbackend.service;

import de.flockiix.loginregistrationbackend.model.ConfirmationToken;
import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.repository.ConfirmationTokenRepository;
import de.flockiix.loginregistrationbackend.service.impl.ConfirmationTokenServiceImpl;
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
class ConfirmationTokenServiceTest {
    private ConfirmationTokenService confirmationTokenService;

    @Mock
    private ConfirmationTokenRepository confirmationTokenRepository;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        confirmationTokenService = new ConfirmationTokenServiceImpl(confirmationTokenRepository);
    }

    @Test
    void createConfirmationTokenForUser() {
        User user = TestUtils.getUser();
        confirmationTokenService.createConfirmationTokenForUser(user);
        ArgumentCaptor<ConfirmationToken> argumentCaptor = ArgumentCaptor.forClass(ConfirmationToken.class);
        verify(confirmationTokenRepository).save(argumentCaptor.capture());
        ConfirmationToken capturedToken = argumentCaptor.getValue();
        assertThat(capturedToken.getUser()).isEqualTo(user);
    }

    @Test
    void getConfirmationTokenByToken() {
        ConfirmationToken confirmationToken = new ConfirmationToken(LocalDateTime.now(), LocalDateTime.now(), TestUtils.getUser());
        given(confirmationTokenRepository.findConfirmationTokenByToken(confirmationToken.getToken())).willReturn(Optional.of(confirmationToken));
        Optional<ConfirmationToken> actual = confirmationTokenService.getConfirmationTokenByToken(confirmationToken.getToken());
        assertThat(actual.get()).isEqualTo(confirmationToken);
    }
}