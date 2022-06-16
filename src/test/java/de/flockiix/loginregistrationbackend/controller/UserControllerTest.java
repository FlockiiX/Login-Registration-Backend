package de.flockiix.loginregistrationbackend.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.flockiix.loginregistrationbackend.dto.PasswordDto;
import de.flockiix.loginregistrationbackend.enumeration.Role;
import de.flockiix.loginregistrationbackend.exception.EmailSendFailedException;
import de.flockiix.loginregistrationbackend.jwt.JwtTokenProvider;
import de.flockiix.loginregistrationbackend.model.ConfirmationToken;
import de.flockiix.loginregistrationbackend.model.PasswordResetToken;
import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.repository.*;
import de.flockiix.loginregistrationbackend.service.EmailService;
import de.flockiix.loginregistrationbackend.util.TestUtils;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

import static de.flockiix.loginregistrationbackend.util.TestUtils.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestPropertySource(locations = "classpath:application-test.yml")
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private EmailService emailService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private ConfirmationTokenRepository confirmationTokenRepository;
    @Autowired
    private PasswordResetTokenRepository passwordResetTokenRepository;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Autowired
    private BackupCodeRepository backupCodeRepository;
    @Autowired
    private DeviceMetadataRepository deviceMetadataRepository;

    @BeforeAll
    void beforeAll() throws EmailSendFailedException {
        emailService.sendEmail("test@test.com", "test", "test");
    }

    @Test
    void register() throws Exception {
        var userPayload = getUserPayload();
        mockMvc.perform(
                        post("/api/v1/user/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(userPayload))
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isOk());

        var actual = userRepository.findUserByEmail(userPayload.getEmail());
        assertThat(actual.isPresent()).isTrue();
    }

    @Test
    void registerWithInvalidEmail() throws Exception {
        var userPayload = getUserPayload();
        userPayload.setEmail("foo");
        mockMvc.perform(
                        post("/api/v1/user/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(userPayload))
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    void registerWithWeakPassword() throws Exception {
        var userPayload = getUserPayload();
        userPayload.setPassword("foo");
        mockMvc.perform(
                        post("/api/v1/user/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(userPayload))
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    void registerWithRegisteredEmail() throws Exception {
        var userPayload = getUserPayload();
        userRepository.save(getVerifiedUser(userPayload));

        mockMvc.perform(
                        post("/api/v1/user/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(userPayload))
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    void confirm() throws Exception {
        var user = userRepository.save(getUser());
        var confirmationToken = confirmationTokenRepository.save(new ConfirmationToken(
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                user
        ));

        mockMvc.perform(
                        get("/api/v1/user/confirm?token=" + confirmationToken.getToken())
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isOk());

        var actualUser = userRepository.findUserByEmail(user.getEmail());
        assertThat(actualUser.isPresent()).isTrue();
        assertThat(actualUser.get().isActive()).isTrue();
        assertThat(actualUser.get().isEmailVerified()).isTrue();
        assertThat(actualUser.get().getRole()).isEqualTo(Role.USER);

        var actualToken = confirmationTokenRepository.findConfirmationTokenByToken(confirmationToken.getToken());
        assertThat(actualToken.isPresent()).isTrue();
        assertThat(actualToken.get().getConfirmedAt()).isNotNull();
    }

    @Test
    void confirmWithInvalidCode() throws Exception {
        mockMvc.perform(
                        get("/api/v1/user/confirm?token=foo")
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    void confirmAlreadyConfirmedAccount() throws Exception {
        var user = userRepository.save(getVerifiedUser(getUserPayload()));
        var confirmationToken = confirmationTokenRepository.save(new ConfirmationToken(
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                LocalDateTime.now(),
                user
        ));

        mockMvc.perform(
                        get("/api/v1/user/confirm?token=" + confirmationToken.getToken())
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    void confirmWithExpiredToken() throws Exception {
        var user = userRepository.save(getUser());
        var confirmationToken = confirmationTokenRepository.save(new ConfirmationToken(
                LocalDateTime.now(),
                LocalDateTime.now(),
                user
        ));

        mockMvc.perform(
                        get("/api/v1/user/confirm?token=" + confirmationToken.getToken())
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isBadRequest());

        var actualUser = userRepository.findUserByEmail(user.getEmail());
        assertThat(actualUser.isPresent()).isTrue();
        assertThat(actualUser.get().isActive()).isFalse();
        assertThat(actualUser.get().isEmailVerified()).isFalse();
        assertThat(actualUser.get().getRole()).isEqualTo(Role.UNVERIFIED);
    }

    @Test
    void resetPasswordRequest() throws Exception {
        var user = userRepository.save(getVerifiedUser(getUserPayload()));
        mockMvc.perform(
                        get("/api/v1/user/resetPassword?email=" + user.getEmail())
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isOk());
    }

    @Test
    void resetPasswordRequestWithInvalidEmail() throws Exception {
        mockMvc.perform(
                        get("/api/v1/user/resetPassword?email=foo")
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    void resetPasswordRequestWithAlreadyRequestedEmail() throws Exception {
        var user = userRepository.save(getVerifiedUser(getUserPayload()));
        passwordResetTokenRepository.save(new PasswordResetToken(
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                user
        ));

        mockMvc.perform(
                        get("/api/v1/user/resetPassword?email=" + user.getEmail())
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    void resetPassword() throws Exception {
        var user = userRepository.save(getVerifiedUser(getUserPayload()));
        var passwordResetToken = passwordResetTokenRepository.save(new PasswordResetToken(
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                user
        ));

        var newPassword = getStrongPassword();
        mockMvc.perform(
                        post("/api/v1/user/resetPassword?token=" + passwordResetToken.getToken())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(new PasswordDto(null, newPassword)))
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isOk());

        var actualToken = passwordResetTokenRepository.findPasswordResetTokenByToken(passwordResetToken.getToken());
        assertThat(actualToken.isPresent()).isTrue();
        assertThat(actualToken.get().getConfirmedAt()).isNotNull();

        var actualUser = userRepository.findUserByEmail(user.getEmail());
        assertThat(actualUser.isPresent()).isTrue();
        assertThat(bCryptPasswordEncoder.matches(newPassword + actualUser.get().getSecret(), actualUser.get().getPassword())).isTrue();
    }

    @Test
    void resetPasswordWithWeakPassword() throws Exception {
        var user = userRepository.save(getVerifiedUser(getUserPayload()));
        var passwordResetToken = passwordResetTokenRepository.save(new PasswordResetToken(
                LocalDateTime.now(),
                LocalDateTime.now().plusMinutes(15),
                user
        ));

        var newPassword = "password";
        mockMvc.perform(
                        post("/api/v1/user/resetPassword?token=" + passwordResetToken.getToken())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(new PasswordDto(null, newPassword)))
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    void resetPasswordWithExpiredToken() throws Exception {
        var user = userRepository.save(getVerifiedUser(getUserPayload()));
        var passwordResetToken = passwordResetTokenRepository.save(new PasswordResetToken(
                LocalDateTime.now(),
                LocalDateTime.now(),
                user
        ));

        var newPassword = getStrongPassword();
        mockMvc.perform(
                        post("/api/v1/user/resetPassword?token=" + passwordResetToken.getToken())
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(new PasswordDto(null, newPassword)))
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    void updatePassword() throws Exception {
        var userPayload = getUserPayload();
        var newPassword = getStrongPassword();
        var user = getVerifiedUser(userPayload);
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword() + user.getSecret()));
        userRepository.save(user);
        var accessToken = jwtTokenProvider.generateJwtAccessToken(user);
        mockMvc.perform(
                        post("/api/v1/user/updatePassword")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(new PasswordDto(userPayload.getPassword(), newPassword)))
                                .headers(getFakeHeaders())
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                )
                .andDo(print())
                .andExpect(status().isOk());

        var actual = userRepository.findUserByEmail(user.getEmail());
        assertThat(actual.isPresent()).isTrue();
        assertThat(bCryptPasswordEncoder.matches(newPassword + actual.get().getSecret(), actual.get().getPassword())).isTrue();
    }

    @Test
    void updatePasswordWithWeakPassword() throws Exception {
        var userPayload = getUserPayload();
        var newPassword = "password";
        var user = getVerifiedUser(userPayload);
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword() + user.getSecret()));
        userRepository.save(user);
        var accessToken = jwtTokenProvider.generateJwtAccessToken(user);
        mockMvc.perform(
                        post("/api/v1/user/updatePassword")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(new PasswordDto(userPayload.getPassword(), newPassword)))
                                .headers(getFakeHeaders())
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    void updatePasswordWithWrongOldPassword() throws Exception {
        var userPayload = getUserPayload();
        var newPassword = getStrongPassword();
        var user = getVerifiedUser(userPayload);
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword() + user.getSecret()));
        userRepository.save(user);
        var accessToken = jwtTokenProvider.generateJwtAccessToken(user);
        mockMvc.perform(
                        post("/api/v1/user/updatePassword")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(new PasswordDto("password", newPassword)))
                                .headers(getFakeHeaders())
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    void update2FA() throws Exception {
        var user = userRepository.save(getVerifiedUser(getUserPayload()));
        var accessToken = jwtTokenProvider.generateJwtAccessToken(user);
        mockMvc.perform(
                        post("/api/v1/user/update2FA?use2FA=true")
                                .headers(getFakeHeaders())
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                )
                .andDo(print())
                .andExpect(status().isOk());

        var actual = userRepository.findUserByEmail(user.getEmail());
        assertThat(actual.isPresent()).isTrue();
        assertThat(actual.get().isUsing2FA()).isTrue();

        var backupCodes = backupCodeRepository.findBackupCodesByUser(actual.get());
        assertThat(backupCodes.size()).isEqualTo(8);
    }

    @Test
    void update2FAToSameState() throws Exception {
        var user = getVerifiedUser(getUserPayload());
        user.setUsing2FA(true);
        userRepository.save(user);
        var accessToken = jwtTokenProvider.generateJwtAccessToken(user);
        mockMvc.perform(
                        post("/api/v1/user/update2FA?use2FA=true")
                                .headers(getFakeHeaders())
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    void getUsers() throws Exception {
        confirmationTokenRepository.deleteAll();
        backupCodeRepository.deleteAll();
        passwordResetTokenRepository.deleteAll();
        deviceMetadataRepository.deleteAll();
        userRepository.deleteAll();
        List<User> expected = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            expected.add(userRepository.save(TestUtils.getVerifiedUser(TestUtils.getUserPayload())));
        }

        var user = getVerifiedUser(getUserPayload());
        user.setRole(Role.SUPER_USER);
        userRepository.save(user);
        expected.add(user);
        var accessToken = jwtTokenProvider.generateJwtAccessToken(user);
        String actual = mockMvc.perform(
                        get("/api/v1/user/list")
                                .headers(getFakeHeaders())
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                )
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertThat(actual).contains(objectMapper.writeValueAsString(expected));
    }

    @Test
    void findUser() throws Exception {
        var expected = userRepository.save(getVerifiedUser(getUserPayload()));
        var user = getVerifiedUser(getUserPayload());
        user.setRole(Role.SUPER_USER);
        userRepository.save(user);
        var accessToken = jwtTokenProvider.generateJwtAccessToken(user);
        String actual = mockMvc.perform(
                        get("/api/v1/user/find?email=" + expected.getEmail())
                                .headers(getFakeHeaders())
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                )
                .andDo(print())
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString();

        assertThat(actual).isEqualTo(objectMapper.writeValueAsString(expected));
    }

    @Test
    void findUserWithWrongEmail() throws Exception {
        var user = getVerifiedUser(getUserPayload());
        user.setRole(Role.SUPER_USER);
        userRepository.save(user);
        var accessToken = jwtTokenProvider.generateJwtAccessToken(user);
        mockMvc.perform(
                        get("/api/v1/user/find?email=foo")
                                .headers(getFakeHeaders())
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    void deleteUser() throws Exception {
        var expected = userRepository.save(getVerifiedUser(getUserPayload()));
        var user = getVerifiedUser(getUserPayload());
        user.setRole(Role.SUPER_USER);
        userRepository.save(user);
        var accessToken = jwtTokenProvider.generateJwtAccessToken(user);
        mockMvc.perform(
                        delete("/api/v1/user/delete?email=" + expected.getEmail())
                                .headers(getFakeHeaders())
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                )
                .andDo(print())
                .andExpect(status().isOk());

        var actual = userRepository.findUserByEmail(expected.getEmail());
        assertThat(actual.isPresent()).isFalse();
    }

    @Test
    void deleteUserWithWrongEmail() throws Exception {
        var user = getVerifiedUser(getUserPayload());
        user.setRole(Role.SUPER_USER);
        userRepository.save(user);
        var accessToken = jwtTokenProvider.generateJwtAccessToken(user);
        mockMvc.perform(
                        delete("/api/v1/user/delete?email=foo")
                                .headers(getFakeHeaders())
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }
}