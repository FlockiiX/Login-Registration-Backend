package de.flockiix.loginregistrationbackend.service;

import de.flockiix.loginregistrationbackend.model.BackupCode;
import de.flockiix.loginregistrationbackend.model.User;

import java.util.List;

public interface BackupCodeService {
    List<BackupCode> getBackupCodesByUser(User user);

    List<String> createBackupCodes(User user);

    void deleteBackupCodesFromUser(User user);

    void setBackupCodeUsed(BackupCode backupCode);
}
