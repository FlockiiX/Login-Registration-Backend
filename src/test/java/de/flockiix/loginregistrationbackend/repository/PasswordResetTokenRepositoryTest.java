package de.flockiix.loginregistrationbackend.repository;

import de.flockiix.loginregistrationbackend.model.PasswordResetToken;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.time.LocalDateTime;

import static de.flockiix.loginregistrationbackend.util.TestUtils.getUser;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@DataJpaTest
class PasswordResetTokenRepositoryTest {
    private final PasswordResetTokenRepository resetTokenRepository;
    private final UserRepository userRepository;

    @Autowired
    PasswordResetTokenRepositoryTest(PasswordResetTokenRepository resetTokenRepository, UserRepository userRepository) {
        this.resetTokenRepository = resetTokenRepository;
        this.userRepository = userRepository;
    }

    @Test
    void findPasswordResetTokenByToken() {
        var user = userRepository.save(getUser());
        var resetToken = new PasswordResetToken(
                LocalDateTime.now(),
                LocalDateTime.now(),
                user
        );
        var expected = resetTokenRepository.save(resetToken);

        var actual = resetTokenRepository.findPasswordResetTokenByToken(expected.getToken());
        assertThat(actual.isPresent()).isTrue();
    }

    @Test
    void findPasswordResetTokenByUserEmail() {
        var user = userRepository.save(getUser());
        var expected = resetTokenRepository.save(new PasswordResetToken(
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                user
        ));

        for (int i = 0; i < 5; i++) {
            var passwordResetToken = new PasswordResetToken(
                    LocalDateTime.now().plusMinutes(1),
                    LocalDateTime.now().plusMinutes(15),
                    user
            );

            resetTokenRepository.save(passwordResetToken);
        }

        var actual = resetTokenRepository.findPasswordResetTokensByUserEmail(user.getEmail()).get(0);
        assertThat(actual).isEqualTo(expected);

    }
}