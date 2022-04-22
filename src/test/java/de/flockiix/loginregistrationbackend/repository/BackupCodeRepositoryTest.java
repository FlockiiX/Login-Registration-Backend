package de.flockiix.loginregistrationbackend.repository;

import de.flockiix.loginregistrationbackend.model.BackupCode;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;

import java.util.ArrayList;
import java.util.List;

import static de.flockiix.loginregistrationbackend.util.TestUtils.getUser;
import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

@DataJpaTest
class BackupCodeRepositoryTest {

    private final BackupCodeRepository backupCodeRepository;
    private final UserRepository userRepository;

    @Autowired
    BackupCodeRepositoryTest(BackupCodeRepository backupCodeRepository, UserRepository userRepository) {
        this.backupCodeRepository = backupCodeRepository;
        this.userRepository = userRepository;
    }

    @Test
    void findBackupCodesByUser() {
        var user = userRepository.save(getUser());

        List<BackupCode> expected = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            var backupCode = new BackupCode(
                    "SomeBackupCode#" + i,
                    user
            );

            expected.add(backupCode);
            backupCodeRepository.save(backupCode);
        }

        var actual = backupCodeRepository.findBackupCodesByUser(user);
        assertThat(actual).isEqualTo(expected);
    }
}