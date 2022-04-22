package de.flockiix.loginregistrationbackend.repository;

import de.flockiix.loginregistrationbackend.model.ConfirmationToken;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.time.LocalDateTime;

import static de.flockiix.loginregistrationbackend.util.TestUtils.getUser;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@DataJpaTest
class ConfirmationTokenRepositoryTest {

    private final ConfirmationTokenRepository confirmationTokenRepository;
    private final UserRepository userRepository;

    @Autowired
    ConfirmationTokenRepositoryTest(ConfirmationTokenRepository confirmationTokenRepository, UserRepository userRepository) {
        this.confirmationTokenRepository = confirmationTokenRepository;
        this.userRepository = userRepository;
    }

    @Test
    void findConfirmationTokenByToken() {
        var user = userRepository.save(getUser());
        var confirmationToken = new ConfirmationToken(
                LocalDateTime.now(),
                LocalDateTime.now(),
                user
        );

        var expected = confirmationTokenRepository.save(confirmationToken);

        var actual = confirmationTokenRepository.findConfirmationTokenByToken(expected.getToken());
        assertThat(actual.isPresent()).isTrue();
    }
}