package de.flockiix.loginregistrationbackend.repository;

import de.flockiix.loginregistrationbackend.model.ConfirmationToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ConfirmationTokenRepository extends JpaRepository<ConfirmationToken, Long> {
    @Query("SELECT ct FROM ConfirmationToken ct WHERE ct.token = ?1")
    Optional<ConfirmationToken> findConfirmationTokenByToken(String token);
}
