package de.flockiix.loginregistrationbackend.util;

import com.github.javafaker.Faker;
import de.flockiix.loginregistrationbackend.enumeration.Role;
import de.flockiix.loginregistrationbackend.model.User;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.Date;

@Component
public class TestUtils {
    public static final Faker faker = new Faker();

    public static User getUser() {
        return new User(
                faker.name().firstName(),
                faker.name().lastName(),
                faker.name().username(),
                faker.internet().safeEmailAddress(),
                getStrongPassword(),
                new Date(),
                Role.UNVERIFIED,
                false,
                false
        );
    }

    public static User getUnverifiedUser(UserPayload userPayload) {
        return new User(
                userPayload.getFirstName(),
                userPayload.getLastName(),
                userPayload.getDisplayName(),
                userPayload.getEmail(),
                userPayload.getPassword(),
                new Date(),
                Role.UNVERIFIED,
                false,
                false
        );
    }

    public static User getVerifiedUser(UserPayload userPayload) {
        return new User(
                userPayload.getFirstName(),
                userPayload.getLastName(),
                userPayload.getDisplayName(),
                userPayload.getEmail(),
                userPayload.getPassword(),
                new Date(),
                Role.USER,
                true,
                true
        );
    }

    public static UserPayload getUserPayload() {
        return new UserPayload(
                faker.name().firstName(),
                faker.name().lastName(),
                faker.name().username(),
                faker.internet().safeEmailAddress(),
                getStrongPassword()
        );
    }

    public static HttpHeaders getFakeHeaders() {
        MultiValueMap<String, String> header = new LinkedMultiValueMap<>();
        header.add("X-Forwarded-For", faker.internet().publicIpV4Address());
        header.add("user-agent", faker.internet().userAgentAny());
        return new HttpHeaders(header);
    }

    public static String getStrongPassword() {
        return faker.internet().password(12, 30, true, true, true) + "123@!aA";
    }
}