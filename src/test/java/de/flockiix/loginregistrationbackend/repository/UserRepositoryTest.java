package de.flockiix.loginregistrationbackend.repository;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import static de.flockiix.loginregistrationbackend.util.TestUtils.faker;
import static de.flockiix.loginregistrationbackend.util.TestUtils.getUser;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@DataJpaTest
class UserRepositoryTest {
    private final UserRepository userRepository;

    @Autowired
    UserRepositoryTest(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Test
    void findUserByEmail() {
        var email = faker.internet().safeEmailAddress();
        var expected = userRepository.save(getUser());
        expected.setEmail(email);

        var actual = userRepository.findUserByEmail(email);
        assertThat(actual.isPresent()).isTrue();
    }

    @Test
    void findUserByDisplayName() {
        var displayName = faker.name().username();
        var expected = userRepository.save(getUser());
        expected.setDisplayName(displayName);

        var actual = userRepository.findUserByDisplayName(displayName);
        assertThat(actual.isPresent()).isTrue();
    }
}