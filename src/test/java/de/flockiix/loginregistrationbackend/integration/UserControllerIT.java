package de.flockiix.loginregistrationbackend.integration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.javafaker.Faker;
import de.flockiix.loginregistrationbackend.dto.PasswordDto;
import de.flockiix.loginregistrationbackend.enumeration.Role;
import de.flockiix.loginregistrationbackend.exception.EmailSendFailedException;
import de.flockiix.loginregistrationbackend.payload.UserPayload;
import de.flockiix.loginregistrationbackend.repository.DeviceMetadataRepository;
import de.flockiix.loginregistrationbackend.repository.UserRepository;
import de.flockiix.loginregistrationbackend.service.EmailService;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Locale;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class UserControllerIT {
    private final Faker faker = new Faker(new Locale("de"));
    @Autowired
    private MockMvc mockMvc;
    @Autowired
    private ObjectMapper objectMapper;
    @Autowired
    private EmailService emailService;
    @Autowired
    private DeviceMetadataRepository deviceMetadataRepository;
    @Autowired
    private UserRepository userRepository;

    @BeforeAll
    void beforeAll() throws EmailSendFailedException {
        emailService.sendEmail("test@test.com", "test", "test");
    }

    @Test
    void register() throws Exception {
        register(getUserPayload(), status().isOk());
    }

    @Test
    void registerWithSameEmail() throws Exception {
        UserPayload userPayload = getUserPayload();
        register(userPayload, status().isOk());
        register(userPayload, status().isBadRequest());
    }

    @Test
    void registerWithWeakPassword() throws Exception {
        UserPayload weakPasswordUserPayload = getUserPayload().setPassword("password");
        register(weakPasswordUserPayload, status().isBadRequest());
    }

    @Test
    void registerWithInvalidEmail() throws Exception {
        UserPayload invalidEmailUserPayload = getUserPayload().setEmail("email");
        register(invalidEmailUserPayload, status().isBadRequest());
    }

    @Test
    void login() throws Exception {
        UserPayload userPayload = getUserPayload();
        register(userPayload, status().isOk());
        userRepository.enableUser(userPayload.getEmail(), Role.USER);
        login(userPayload, status().isOk(), getHeaders());
    }

    @Test
    void loginWithoutConfirmedAccount() throws Exception {
        UserPayload userPayload = getUserPayload();
        register(userPayload, status().isOk());
        login(userPayload, status().isUnauthorized(), getHeaders());
    }

    @Test
    void loginWithWrongPassword() throws Exception {
        UserPayload userPayload = getUserPayload();
        register(userPayload, status().isOk());
        userRepository.enableUser(userPayload.getEmail(), Role.USER);
        login(userPayload.setPassword("password"), status().isBadRequest(), getHeaders());
    }

    @Test
    void loginWithWrongEmail() throws Exception {
        UserPayload userPayload = getUserPayload();
        register(userPayload, status().isOk());
        userRepository.enableUser(userPayload.getEmail(), Role.USER);
        login(userPayload.setEmail("email"), status().isBadRequest(), getHeaders());
    }

    @Test
    void loginFromSameDevice() throws Exception {
        UserPayload userPayload = getUserPayload();
        register(userPayload, status().isOk());
        userRepository.enableUser(userPayload.getEmail(), Role.USER);
        HttpHeaders headers = getHeaders();
        login(userPayload, status().isOk(), headers);

        login(userPayload, status().isOk(), headers);
        int devices = deviceMetadataRepository.findDeviceMetadataByUser(userRepository.findUserByEmail(userPayload.getEmail()).get()).size();
        Assertions.assertThat(devices).isEqualTo(1);
    }

    @Test
    void loginFromNewDevice() throws Exception {
        UserPayload userPayload = getUserPayload();
        register(userPayload, status().isOk());
        userRepository.enableUser(userPayload.getEmail(), Role.USER);
        login(userPayload, status().isOk(), getHeaders());

        login(userPayload, status().isOk(), getHeaders());
        int devices = deviceMetadataRepository.findDeviceMetadataByUser(userRepository.findUserByEmail(userPayload.getEmail()).get()).size();
        Assertions.assertThat(devices).isEqualTo(2);
    }

    @Test
    void loginAndUpdatePassword() throws Exception {
        UserPayload userPayload = getUserPayload();
        register(userPayload, status().isOk());
        userRepository.enableUser(userPayload.getEmail(), Role.USER);
        ResultActions resultActions = login(userPayload, status().isOk(), getHeaders());
        String token = resultActions.andReturn().getResponse().getHeader("Jwt-Access-Token");
        mockMvc.perform(
                        post("/api/v1/user/updatePassword")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(new PasswordDto(userPayload.getPassword(), getStrongPassword())))
                                .headers(getHeaders())
                                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                ).andDo(print())
                .andExpect(status().isOk());
    }

    private void register(UserPayload userPayload, ResultMatcher resultMatcher) throws Exception {
        mockMvc.perform(
                        post("/api/v1/user/register")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(userPayload))
                                .headers(getHeaders())
                )
                .andDo(print())
                .andExpect(resultMatcher);
    }

    private ResultActions login(UserPayload userPayload, ResultMatcher resultMatcher, HttpHeaders headers) throws Exception {
        return mockMvc.perform(
                        post("/api/v1/auth/login")
                                .contentType(MediaType.APPLICATION_JSON)
                                .content(objectMapper.writeValueAsString(userPayload))
                                .headers(headers)
                )
                .andDo(print())
                .andExpect(resultMatcher);
    }

    private UserPayload getUserPayload() {
        return new UserPayload(
                faker.name().firstName(),
                faker.name().lastName(),
                faker.name().username(),
                faker.internet().safeEmailAddress(),
                getStrongPassword()
        );
    }

    private HttpHeaders getHeaders() {
        MultiValueMap<String, String> header = new LinkedMultiValueMap<>();
        header.add("X-Forwarded-For", faker.internet().ipV4Address());
        header.add("user-agent", faker.internet().userAgentAny());
        return new HttpHeaders(header);
    }

    private String getStrongPassword() {
        return faker.internet().password(12, 30, true, true, true) + "123@!aA";
    }
}
