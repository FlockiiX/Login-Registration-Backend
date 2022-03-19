package de.flockiix.loginregistrationbackend.repository;

import de.flockiix.loginregistrationbackend.model.ConfirmationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;
import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface ConfirmationTokenRepository extends JpaRepository<ConfirmationToken, Long> {
    @Query("SELECT ct FROM ConfirmationToken ct WHERE ct.token = ?1")
    Optional<ConfirmationToken> findConfirmationTokenByToken(String token);

    @Transactional
    @Modifying
    @Query("UPDATE ConfirmationToken ct SET ct.confirmedAt = ?2 WHERE ct.token = ?1")
    void updateConfirmedAt(String token, LocalDateTime confirmedAt);
}
