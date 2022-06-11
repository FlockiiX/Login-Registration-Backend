package de.flockiix.loginregistrationbackend.service;

import de.flockiix.loginregistrationbackend.constant.EmailConstant;
import de.flockiix.loginregistrationbackend.dto.PasswordDto;
import de.flockiix.loginregistrationbackend.model.ConfirmationToken;
import de.flockiix.loginregistrationbackend.model.PasswordResetToken;
import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.repository.UserRepository;
import de.flockiix.loginregistrationbackend.service.impl.UserServiceImpl;
import de.flockiix.loginregistrationbackend.util.TestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {
    private UserService userService;

    @Mock
    private UserRepository userRepository;
    @Mock
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Mock
    private ConfirmationTokenService confirmationTokenService;
    @Mock
    private PasswordResetTokenService passwordResetTokenService;
    @Mock
    private EmailService emailService;
    @Mock
    private BackupCodeService backupCodeService;
    @Mock
    private AuthenticationManager authenticationManager;
    @Mock
    private DeviceMetadataService deviceMetadataService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        userService = new UserServiceImpl(userRepository, bCryptPasswordEncoder, confirmationTokenService, passwordResetTokenService, emailService, backupCodeService, authenticationManager, deviceMetadataService);
    }

    @Test
    void login() {
        MockHttpServletRequest mockRequest = new MockHttpServletRequest();
        mockRequest.setServerName("http://localhost:8080");
        mockRequest.setContextPath("/api/v1/auth/login");
        mockRequest.addHeader("X-Forwarded-For", TestUtils.faker.internet().publicIpV4Address());
        mockRequest.addHeader("User-Agent", TestUtils.faker.internet().userAgentAny());
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(mockRequest));
        User user = TestUtils.getVerifiedUser(TestUtils.getUserPayload());
        given(userRepository.findUserByEmail(user.getEmail())).willReturn(Optional.of(user));
        userService.login(user.getEmail(), user.getPassword());
    }

    @Test
    void register() {
        MockHttpServletRequest mockRequest = new MockHttpServletRequest();
        mockRequest.setServerName("http://localhost:8080");
        mockRequest.setContextPath("/api/v1/auth/register");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(mockRequest));
        User user = TestUtils.getUser();
        given(userRepository.findUserByEmail(user.getEmail())).willReturn(Optional.empty());
        given(confirmationTokenService.createConfirmationTokenForUser(Mockito.any())).willReturn(new ConfirmationToken(
                LocalDateTime.now(), LocalDateTime.now().plusMinutes(15), user
        ));
        userService.register(
                user.getFirstName(),
                user.getLastName(),
                user.getDisplayName(),
                user.getEmail(),
                user.getPassword()
        );

        ArgumentCaptor<User> argumentCaptor = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(argumentCaptor.capture());
        User capturedUser = argumentCaptor.getValue();
        assertThat(capturedUser.getEmail()).isEqualTo(user.getEmail());
        verify(emailService).sendEmail(Mockito.any(), Mockito.any(), Mockito.any());
    }

    @Test
    void confirmToken() {
        String token = "1234";
        User user = TestUtils.getUser();
        given(confirmationTokenService.getConfirmationTokenByToken(token)).willReturn(Optional.of(new ConfirmationToken(
                LocalDateTime.now().minusMinutes(5),
                LocalDateTime.now().plusMinutes(5),
                user
        )));
        userService.confirmToken(token);
        verify(confirmationTokenService).setConfirmationTokenConfirmedAt(token);
        verify(emailService).sendEmail(user.getEmail(), "Welcome", EmailConstant.buildWelcomeEmail(user.getFirstName()));
    }

    @Test
    void getUsers() {
        List<User> users = List.of(TestUtils.getUser(), TestUtils.getUser(), TestUtils.getUser());
        given(userRepository.findAll()).willReturn(users);
        List<User> actual = userService.getUsers();
        assertThat(actual).isEqualTo(users);
    }

    @Test
    void findUserByEmail() {
        String email = "test@example.com";
        User user = TestUtils.getVerifiedUser(TestUtils.getUserPayload());
        user.setEmail(email);
        given(userRepository.findUserByEmail(email)).willReturn(Optional.of(user));
        Optional<User> actual = userService.findUserByEmail(email);
        assertThat(actual.get()).isEqualTo(user);
    }

    @Test
    void deleteUser() {
        User user = TestUtils.getUser();
        given(userRepository.findUserByEmail(user.getEmail())).willReturn(Optional.of(user));
        userService.deleteUser(user.getEmail());
        verify(userRepository).delete(user);
    }

    @Test
    void createPasswordResetToken() {
        MockHttpServletRequest mockRequest = new MockHttpServletRequest();
        mockRequest.setServerName("http://localhost:8080");
        mockRequest.setContextPath("/api/v1/user/resetPassword");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(mockRequest));
        User user = TestUtils.getUser();
        given(userRepository.findUserByEmail(user.getEmail())).willReturn(Optional.of(user));
        given(passwordResetTokenService.isAllowedToRequestPasswordResetToken(user.getEmail())).willReturn(true);
        given(passwordResetTokenService.createPasswordResetTokenForUser(user)).willReturn(
                new PasswordResetToken(
                        LocalDateTime.now().minusMinutes(5),
                        LocalDateTime.now().plusMinutes(5),
                        user
                )
        );
        userService.createPasswordResetToken(user.getEmail());
        verify(emailService).sendEmail(Mockito.any(), Mockito.any(), Mockito.any());
    }

    @Test
    void resetUserPassword() {
        User user = TestUtils.getUser();
        String token = "1234";
        String newPassword = TestUtils.getStrongPassword();
        given(passwordResetTokenService.getPasswordResetTokenByToken(token)).willReturn(
                Optional.of(new PasswordResetToken(
                        LocalDateTime.now().minusMinutes(5),
                        LocalDateTime.now().plusMinutes(5),
                        user
                ))
        );
        userService.resetUserPassword(token, newPassword);
        verify(passwordResetTokenService).setPasswordResetTokenConfirmedAt(token);
    }

    @Test
    void updateUserPassword() {
        String oldPassword = TestUtils.getStrongPassword();
        String newPassword = TestUtils.getStrongPassword();
        User user = TestUtils.getUser();
        user.setPassword(oldPassword);
        PasswordDto passwordDto = new PasswordDto(oldPassword, newPassword);
        SecurityContextHolder
                .getContext()
                .setAuthentication(new UsernamePasswordAuthenticationToken(user.getEmail(), null));
        given(userRepository.findUserByEmail(user.getEmail())).willReturn(Optional.of(user));
        given(bCryptPasswordEncoder.matches(Mockito.any(), Mockito.any())).willReturn(true);
        userService.updateUserPassword(passwordDto);
    }

    @Test
    void updateUser2FA() {
        User user = TestUtils.getUser();
        List<String> backupCodes = List.of("1234", "4321");
        SecurityContextHolder
                .getContext()
                .setAuthentication(new UsernamePasswordAuthenticationToken(user.getEmail(), null));
        given(userRepository.findUserByEmail(user.getEmail())).willReturn(Optional.of(user));
        given(backupCodeService.createBackupCodes(user)).willReturn(backupCodes);
        userService.updateUser2FA(true);
        verify(emailService).sendEmail(user.getEmail(), "2 FA Activated", EmailConstant.build2FAActivatedEmail(user.getFirstName(), backupCodes));
    }
}