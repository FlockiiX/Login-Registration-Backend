package de.flockiix.loginregistrationbackend.service.impl;

import com.auth0.jwt.exceptions.TokenExpiredException;
import de.flockiix.loginregistrationbackend.constant.EmailConstant;
import de.flockiix.loginregistrationbackend.dto.PasswordDto;
import de.flockiix.loginregistrationbackend.enumeration.Role;
import de.flockiix.loginregistrationbackend.exception.*;
import de.flockiix.loginregistrationbackend.google2fa.CustomWebAuthenticationDetailsSource;
import de.flockiix.loginregistrationbackend.model.ConfirmationToken;
import de.flockiix.loginregistrationbackend.model.PasswordResetToken;
import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.repository.UserRepository;
import de.flockiix.loginregistrationbackend.service.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import javax.servlet.http.HttpServletRequest;
import javax.transaction.Transactional;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.Date;
import java.util.List;
import java.util.Optional;

import static de.flockiix.loginregistrationbackend.constant.JwtConstant.ISSUER;

@Service
@Transactional
public class UserServiceImpl implements UserService {
    private final UserRepository userRepository;
    private final BCryptPasswordEncoder bCryptPasswordEncoder;
    private final ConfirmationTokenService confirmationTokenService;
    private final PasswordResetTokenService passwordResetTokenService;
    private final EmailService emailService;
    private final BackupCodeService backupCodeService;
    private final AuthenticationManager authenticationManager;
    private final DeviceMetadataService deviceMetadataService;

    public UserServiceImpl(UserRepository userRepository, BCryptPasswordEncoder bCryptPasswordEncoder, ConfirmationTokenService confirmationTokenService, PasswordResetTokenService passwordResetTokenService, EmailService emailService, BackupCodeService backupCodeService, AuthenticationManager authenticationManager, DeviceMetadataService deviceMetadataService) {
        this.userRepository = userRepository;
        this.bCryptPasswordEncoder = bCryptPasswordEncoder;
        this.confirmationTokenService = confirmationTokenService;
        this.passwordResetTokenService = passwordResetTokenService;
        this.emailService = emailService;
        this.backupCodeService = backupCodeService;
        this.authenticationManager = authenticationManager;
        this.deviceMetadataService = deviceMetadataService;
    }

    @Override
    public User login(String email, String password, HttpServletRequest request) {
        User user = userRepository
                .findUserByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("Wrong email or password"));

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(email, password + user.getSecret());
        token.setDetails(
                new CustomWebAuthenticationDetailsSource().buildDetails(request)
        );
        authenticationManager.authenticate(token);
        deviceMetadataService.verifyDevice(user, request);
        return user;
    }

    @Override
    public void register(String firstName, String lastName, String displayName, String email, String password) {
        boolean emailExists = findUserByEmail(email).isPresent();
        if (emailExists)
            throw new EmailExistException("Email already exists");

        User user = new User(
                firstName,
                lastName,
                displayName,
                email,
                password,
                new Date(),
                Role.UNVERIFIED,
                false,
                true
        );

        String encodedPassword = bCryptPasswordEncoder.encode(password + user.getSecret());
        user.setPassword(encodedPassword);
        userRepository.save(user);
        sendConfirmationToken(user);
    }

    private void sendConfirmationToken(User user) {
        ConfirmationToken confirmationToken = new ConfirmationToken(
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                user
        );

        confirmationTokenService.saveConfirmationToken(confirmationToken);
        String link = ServletUriComponentsBuilder.fromCurrentContextPath().toUriString() + "/api/v1/user/confirm?token=" + confirmationToken.getToken();
        emailService.sendEmail(user.getEmail(), "Confirm your account", EmailConstant.buildConfirmEmail(user.getFirstName(), link));
    }

    @Override
    public void confirmToken(String token) {
        ConfirmationToken confirmationToken = confirmationTokenService
                .getConfirmationTokenByToken(token)
                .orElseThrow(() -> new TokenNotFoundException("Confirmation token cannot be found"));

        if (confirmationToken.getConfirmedAt() != null)
            throw new TokenAlreadyConfirmedException("Confirmation token already confirmed");

        LocalDateTime expiredAt = confirmationToken.getExpiresAt();
        if (expiredAt.isBefore(LocalDateTime.now()))
            throw new TokenExpiredException("Confirmation token expired");

        User user = confirmationToken.getUser();
        confirmationTokenService.setConfirmationTokenConfirmedAt(token);
        userRepository.enableUser(user.getEmail(), Role.USER);
        emailService.sendEmail(user.getEmail(), "Welcome", EmailConstant.buildWelcomeEmail(user.getFirstName()));
    }

    @Override
    public List<User> getUsers() {
        return userRepository.findAll();
    }

    @Override
    public Optional<User> findUserByDisplayName(String displayName) {
        return userRepository.findUserByDisplayName(displayName);
    }

    @Override
    public Optional<User> findUserByEmail(String email) {
        return userRepository.findUserByEmail(email);
    }

    @Override
    public void deleteUser(String email) {
        User user = userRepository
                .findUserByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User with email " + email + " cannot be found"));

        userRepository.delete(user);
    }

    @Override
    public void createPasswordResetToken(String email) {
        User user = userRepository
                .findUserByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User with email " + email + " cannot be found"));

        PasswordResetToken passwordResetToken = new PasswordResetToken(
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                user
        );

        passwordResetTokenService.savePasswordResetToken(passwordResetToken);
        String link = ServletUriComponentsBuilder.fromCurrentContextPath().toUriString() + "/api/v1/user/resetPassword?token=" + passwordResetToken.getToken();
        emailService.sendEmail(user.getEmail(), "Reset your password", EmailConstant.buildResetPasswordEmail(user.getFirstName(), link));
    }

    @Override
    public void resetUserPassword(String token, String password) {
        if (password == null)
            throw new InvalidPasswordException("Password cant be null");

        PasswordResetToken passwordResetToken = passwordResetTokenService
                .getPasswordResetTokenByToken(token)
                .orElseThrow(() -> new TokenNotFoundException("Password reset token cannot be found"));

        if (passwordResetToken.getConfirmedAt() != null)
            throw new TokenAlreadyConfirmedException("Password reset token already confirmed");

        if (passwordResetToken.getExpiresAt().isBefore(LocalDateTime.now()))
            throw new TokenExpiredException("Password reset token expired");

        User user = passwordResetToken.getUser();
        if (user == null)
            throw new UserNotFoundException("User not found");

        passwordResetTokenService.setPasswordResetTokenConfirmedAt(token);
        updateUserPassword(user, password, null);
    }

    @Override
    public void updateUserPassword(PasswordDto passwordDto, String token) {
        String email = SecurityContextHolder
                .getContext()
                .getAuthentication()
                .getPrincipal()
                .toString();
        User user = userRepository
                .findUserByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("User not found"));
        if (!isValidOldPassword(user, passwordDto.getOldPassword()))
            throw new InvalidPasswordException("Invalid old password");

        updateUserPassword(user, passwordDto.getNewPassword(), token);
    }

    @Override
    public void updateUserPassword(User user, String password, String token) {
        String encodedPassword = bCryptPasswordEncoder.encode(password + user.getSecret());
        userRepository.updatePassword(user.getEmail(), encodedPassword);
        incrementRefreshTokenCount(user);
    }

    private boolean isValidOldPassword(User user, String oldPassword) {
        return bCryptPasswordEncoder.matches(oldPassword + user.getSecret(), user.getPassword());
    }

    @Override
    public String generateUserQRUrl(User user) {
        return "https://chart.googleapis.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=" + URLEncoder.encode(String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s", ISSUER, user.getEmail(), user.getSecret(), ISSUER), StandardCharsets.UTF_8);
    }

    @Override
    public User updateUser2FA(boolean use2FA, String token) {
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        User user = findUserByEmail(currentAuth.getPrincipal().toString())
                .orElseThrow(() -> new InvalidAuthenticationException("Invalid authentication"));
        userRepository.update2FA(user.getEmail(), use2FA);
        Authentication auth = new UsernamePasswordAuthenticationToken(user, user.getPassword(), currentAuth.getAuthorities());
        SecurityContextHolder.getContext().setAuthentication(auth);
        if (use2FA) {
            List<String> backupCodes = backupCodeService.createBackupCodes(user);
            emailService.sendEmail(user.getEmail(), "2 FA Activated", EmailConstant.build2FAActivatedEmail(user.getFirstName(), backupCodes));
        } else {
            backupCodeService.deleteBackupCodesFromUser(user);
        }

        incrementRefreshTokenCount(user);
        return user;
    }

    @Override
    public void incrementRefreshTokenCount(User user) {
        int refreshTokenCount = user.getRefreshTokenCount();
        user.setRefreshTokenCount(++refreshTokenCount);
        userRepository.save(user);
    }

    @Override
    public void logout() {
        Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
        User user = findUserByEmail(currentAuth.getPrincipal().toString())
                .orElseThrow(() -> new InvalidAuthenticationException("Invalid authentication"));
        incrementRefreshTokenCount(user);
    }
}
