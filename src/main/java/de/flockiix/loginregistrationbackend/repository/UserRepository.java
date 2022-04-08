package de.flockiix.loginregistrationbackend.repository;

import de.flockiix.loginregistrationbackend.enumeration.Role;
import de.flockiix.loginregistrationbackend.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import javax.transaction.Transactional;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    @Query("SELECT u FROM User u WHERE u.email = ?1")
    Optional<User> findUserByEmail(String email);

    @Query("SELECT u FROM User u WHERE u.displayName = ?1")
    Optional<User> findUserByDisplayName(String displayName);

    @Transactional
    @Modifying
    @Query("UPDATE User u SET u.isActive = TRUE, u.isEmailVerified = TRUE, u.role = ?2 WHERE u.email = ?1")
    void enableUser(String email, Role role);

    @Transactional
    @Modifying
    @Query("UPDATE User u SET u.password = ?2 WHERE u.email = ?1")
    void updatePassword(String email, String password);

    @Transactional
    @Modifying
    @Query("UPDATE User u SET u.isUsing2FA = ?2 WHERE u.email = ?1")
    void update2FA(String email, boolean using2FA);
}
