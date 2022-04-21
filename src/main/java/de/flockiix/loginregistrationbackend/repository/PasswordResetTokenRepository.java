package de.flockiix.loginregistrationbackend.repository;

import de.flockiix.loginregistrationbackend.model.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {
    @Query("SELECT prt FROM PasswordResetToken prt WHERE prt.token = ?1")
    Optional<PasswordResetToken> findPasswordResetTokenByToken(String token);

    @Query(value = "SELECT prt FROM PasswordResetToken prt WHERE prt.user.email = ?1 ORDER BY prt.createdAt ASC")
    List<PasswordResetToken> findPasswordResetTokensByUserEmail(String email);
}
