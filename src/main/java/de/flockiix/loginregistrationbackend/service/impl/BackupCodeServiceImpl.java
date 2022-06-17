package de.flockiix.loginregistrationbackend.service.impl;

import de.flockiix.loginregistrationbackend.model.BackupCode;
import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.repository.BackupCodeRepository;
import de.flockiix.loginregistrationbackend.service.BackupCodeService;
import org.apache.commons.lang3.RandomStringUtils;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
public class BackupCodeServiceImpl implements BackupCodeService {
    private final BackupCodeRepository backupCodeRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;

    public BackupCodeServiceImpl(BackupCodeRepository backupCodeRepository, BCryptPasswordEncoder bCryptPasswordEncoder) {
        this.backupCodeRepository = backupCodeRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
    }

    @Override
    public List<BackupCode> getBackupCodesByUser(User user) {
        return backupCodeRepository.findBackupCodesByUser(user);
    }

    @Override
    public List<String> createBackupCodes(User user) {
        List<String> backupCodes = createBackupCodes();
        for (String backupCode : backupCodes) {
            String encoded = bCryptPasswordEncoder.encode(backupCode);
            backupCodeRepository.save(new BackupCode(encoded, user));
        }

        return backupCodes;
    }

    private List<String> createBackupCodes() {
        List<String> backupCodes = new ArrayList<>();
        while (backupCodes.size() < 8) {
            String backupCode = RandomStringUtils.randomAlphanumeric(8);
            backupCodes.add(backupCode);
        }

        return backupCodes;
    }

    @Override
    public void deleteBackupCodesFromUser(User user) {
        List<BackupCode> backupCodes = backupCodeRepository.findBackupCodesByUser(user);
        backupCodeRepository.deleteAll(backupCodes);
    }

    @Override
    public void setBackupCodeUsed(BackupCode backupCode) {
        backupCode.setUsed(true);
        backupCodeRepository.save(backupCode);
    }
}
