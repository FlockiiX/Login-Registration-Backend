package de.flockiix.loginregistrationbackend.service;

import de.flockiix.loginregistrationbackend.model.BackupCode;
import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.repository.BackupCodeRepository;
import de.flockiix.loginregistrationbackend.service.impl.BackupCodeServiceImpl;
import de.flockiix.loginregistrationbackend.util.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class BackupCodeServiceTest {
    private BackupCodeService backupCodeService;

    @Mock
    private BackupCodeRepository backupCodeRepository;
    @Mock
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        backupCodeService = new BackupCodeServiceImpl(backupCodeRepository, bCryptPasswordEncoder);
    }

    @Test
    void getBackupCodesByUser() {
        User user = TestUtils.getUser();
        List<BackupCode> backupCodes = List.of(new BackupCode("123456", user), new BackupCode("111111", user), new BackupCode("654321", user), new BackupCode("1234", user));
        given(backupCodeRepository.findBackupCodesByUser(user)).willReturn(backupCodes);
        List<BackupCode> actual = backupCodeService.getBackupCodesByUser(user);
        assertThat(actual).isEqualTo(backupCodes);
    }

    @Test
    void deleteBackupCodesFromUser() {
        User user = TestUtils.getUser();
        List<BackupCode> backupCodes = List.of(new BackupCode("123456", user), new BackupCode("111111", user), new BackupCode("654321", user), new BackupCode("1234", user));
        given(backupCodeRepository.findBackupCodesByUser(user)).willReturn(backupCodes);
        backupCodeService.deleteBackupCodesFromUser(user);
        verify(backupCodeRepository).deleteAll(backupCodes);
    }
}