package de.flockiix.loginregistrationbackend.repository;

import de.flockiix.loginregistrationbackend.model.BackupCode;
import de.flockiix.loginregistrationbackend.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;
import java.util.List;

@Repository
public interface BackupCodeRepository extends JpaRepository<BackupCode, Long> {
    @Query("SELECT bc FROM BackupCode bc WHERE bc.user = ?1")
    List<BackupCode> findBackupCodesByUser(User user);

    @Transactional
    @Modifying
    @Query("UPDATE BackupCode bc SET bc.isUsed = true WHERE bc.code = ?1")
    void setBackupCodeUsed(String code);
}
