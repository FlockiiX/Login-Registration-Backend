package de.flockiix.loginregistrationbackend.service;

import de.flockiix.loginregistrationbackend.dto.PasswordDto;
import de.flockiix.loginregistrationbackend.model.User;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.Optional;

public interface UserService {
    User login(String email, String password, HttpServletRequest request);

    void register(String firstName, String lastName, String displayName, String email, String password);

    void confirmToken(String token);

    List<User> getUsers();

    Optional<User> findUserByEmail(String email);

    void deleteUser(String email);

    void createPasswordResetToken(String email);

    void resetUserPassword(String token, String password);

    void updateUserPassword(PasswordDto passwordDto, String token);

    void updateUserPassword(User user, String password, String token);

    String updateUser2FA(boolean use2FA, String token);

    void incrementRefreshTokenCount(User user);

    void logout();
}
