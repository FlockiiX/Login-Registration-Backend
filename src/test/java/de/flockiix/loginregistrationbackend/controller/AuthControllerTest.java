package de.flockiix.loginregistrationbackend.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import de.flockiix.loginregistrationbackend.config.properties.SecurityProperties;
import de.flockiix.loginregistrationbackend.exception.EmailSendFailedException;
import de.flockiix.loginregistrationbackend.jwt.JwtTokenProvider;
import de.flockiix.loginregistrationbackend.repository.DeviceMetadataRepository;
import de.flockiix.loginregistrationbackend.repository.UserRepository;
import de.flockiix.loginregistrationbackend.service.EmailService;
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
import org.springframework.test.web.servlet.ResultActions;

import javax.servlet.http.Cookie;

import java.util.Objects;

import static de.flockiix.loginregistrationbackend.util.TestUtils.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
@TestPropertySource(locations = "classpath:application-test.yml")
class AuthControllerTest {
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private EmailService emailService;
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;
    @Autowired
    private DeviceMetadataRepository deviceMetadataRepository;
    @Autowired
    private SecurityProperties securityProperties;

    @BeforeAll
    void beforeAll() throws EmailSendFailedException {
        emailService.sendEmail("test@test.com", "test", "test");
    }

    @Test
    void login() throws Exception {
        var userPayload = getUserPayload();
        var user = getVerifiedUser(userPayload);
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword() + user.getSecret()));
        userRepository.save(user);
        ResultActions resultActions = mockMvc.perform(
                        post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(userPayload))
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isOk());

        String accessToken = resultActions.andReturn().getResponse().getHeader("Jwt-Access-Token");
        String refreshToken = resultActions.andReturn().getResponse().getHeader("Set-Cookie");
        assertThat(accessToken).isNotNull();
        assertThat(refreshToken).isNotNull();
    }

    @Test
    void loginWithInvalidEmail() throws Exception {
        var userPayload = getUserPayload();
        var user = getVerifiedUser(userPayload);
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword() + user.getSecret()));
        userRepository.save(user);
        userPayload.setEmail(faker.internet().safeEmailAddress());
        mockMvc.perform(
                        post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(userPayload))
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    void loginWithInvalidPassword() throws Exception {
        var userPayload = getUserPayload();
        var user = getVerifiedUser(userPayload);
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword() + user.getSecret()));
        userRepository.save(user);
        userPayload.setPassword(getStrongPassword());
        mockMvc.perform(
                        post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(userPayload))
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    void loginWithoutConfirmedAccount() throws Exception {
        var userPayload = getUserPayload();
        var user = getUnverifiedUser(userPayload);
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword() + user.getSecret()));
        userRepository.save(user);
        mockMvc.perform(
                        post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(userPayload))
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    void loginFromSameDevice() throws Exception {
        var headers = getFakeHeaders();
        var userPayload = getUserPayload();
        var user = getVerifiedUser(userPayload);
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword() + user.getSecret()));
        userRepository.save(user);
        mockMvc.perform(
                        post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(userPayload))
                                .headers(headers)
                )
                .andDo(print())
                .andExpect(status().isOk());
        assertThat(deviceMetadataRepository.findDeviceMetadataByUser(user).size()).isEqualTo(1);

        mockMvc.perform(
                        post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(userPayload))
                                .headers(headers)
                )
                .andDo(print())
                .andExpect(status().isOk());
        assertThat(deviceMetadataRepository.findDeviceMetadataByUser(user).size()).isEqualTo(1);
    }

    @Test
    void loginFromDifferentDevice() throws Exception {
        var userPayload = getUserPayload();
        var user = getVerifiedUser(userPayload);
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword() + user.getSecret()));
        userRepository.save(user);
        mockMvc.perform(
                        post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(userPayload))
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isOk());
        assertThat(deviceMetadataRepository.findDeviceMetadataByUser(user).size()).isEqualTo(1);

        mockMvc.perform(
                        post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(userPayload))
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isOk());
        assertThat(deviceMetadataRepository.findDeviceMetadataByUser(user).size()).isEqualTo(2);
    }

    @Test
    void bruteForce() throws Exception {
        var userPayload = getUserPayload();
        var user = getVerifiedUser(userPayload);
        user.setPassword(bCryptPasswordEncoder.encode(user.getPassword() + user.getSecret()));
        userRepository.save(user);
        userPayload.setPassword("password");
        for (int i = 0; i < securityProperties.getLoginAttempts(); i++) {
            mockMvc.perform(
                            post("/api/v1/auth/login")
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(objectMapper.writeValueAsString(userPayload))
                                    .headers(getFakeHeaders())
                    )
                    .andDo(print())
                    .andExpect(status().isBadRequest());
        }

        mockMvc.perform(
                        post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(userPayload))
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isUnauthorized());

        var actual = userRepository.findUserByEmail(userPayload.getEmail());
        assertThat(actual.isPresent()).isTrue();
        assertThat(actual.get().isActive()).isFalse();
    }

    @Test
    void logout() throws Exception {
        var user = userRepository.save(getVerifiedUser(getUserPayload()));
        var accessToken = jwtTokenProvider.generateJwtAccessToken(user);
        var refreshToken = jwtTokenProvider.generateJwtRefreshToken(user);
        mockMvc.perform(
                        get("/api/v1/auth/logout")
                                .headers(getFakeHeaders())
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                )
                .andDo(print())
                .andExpect(status().isOk());

        var actual = userRepository.findUserByEmail(user.getEmail());
        assertThat(actual.isPresent()).isTrue();
        assertThat(actual.get().getRefreshTokenCount()).isEqualTo(1);
        assertThat(jwtTokenProvider.getRefreshTokenCountFromToken(refreshToken)).isNotEqualTo(actual.get().getRefreshTokenCount());
    }

    @Test
    void refreshToken() throws Exception {
        var user = userRepository.save(getVerifiedUser(getUserPayload()));
        var accessToken = jwtTokenProvider.generateJwtAccessToken(user);
        var refreshToken = jwtTokenProvider.generateJwtRefreshToken(user);
        ResultActions resultActions = mockMvc.perform(
                        get("/api/v1/auth/refresh")
                                .headers(getFakeHeaders())
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken)
                                .cookie(new Cookie("refresh-token", refreshToken))
                )
                .andDo(print())
                .andExpect(status().isOk());

        var actualAccessToken = resultActions.andReturn().getResponse().getHeader("Jwt-Access-Token");
        var actualRefreshToken = Objects.requireNonNull(resultActions.andReturn().getResponse().getCookie("refresh-token")).getValue();
        assertThat(accessToken).isNotEqualTo(actualAccessToken);
        assertThat(refreshToken).isEqualTo(actualRefreshToken);
    }

    @Test
    void refreshTokenWithoutRefreshToken() throws Exception {
        mockMvc.perform(
                        get("/api/v1/auth/refresh")
                                .headers(getFakeHeaders())
                )
                .andDo(print())
                .andExpect(status().isBadRequest());
    }
}