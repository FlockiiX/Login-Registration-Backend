package de.flockiix.loginregistrationbackend.repository;

import de.flockiix.loginregistrationbackend.model.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;
import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    @Query("SELECT prt FROM PasswordResetToken prt WHERE prt.token = ?1")
    Optional<PasswordResetToken> findPasswordResetTokenByToken(String token);

    @Transactional
    @Modifying
    @Query("UPDATE PasswordResetToken prt SET prt.confirmedAt = ?2 WHERE prt.token = ?1")
    void updateConfirmedAt(String token, LocalDateTime confirmedAt);
}
