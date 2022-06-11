package de.flockiix.loginregistrationbackend.controller;

import de.flockiix.loginregistrationbackend.advice.ControllerAdvice;
import de.flockiix.loginregistrationbackend.config.properties.JwtProperties;
import de.flockiix.loginregistrationbackend.constant.JwtConstant;
import de.flockiix.loginregistrationbackend.exception.InvalidRefreshTokenException;
import de.flockiix.loginregistrationbackend.jwt.JwtTokenProvider;
import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.service.UserService;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.concurrent.TimeUnit;

import static org.springframework.http.HttpStatus.OK;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController extends ControllerAdvice {
    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;
    private final JwtProperties jwtProperties;

    public AuthController(UserService userService, JwtTokenProvider jwtTokenProvider, JwtProperties jwtProperties) {
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
        this.jwtProperties = jwtProperties;
    }

    @PostMapping("/login")
    public ResponseEntity<User> login(@RequestBody User user) {
        User loginUser = userService.login(user.getEmail(), user.getPassword());
        HttpHeaders jwtHeader = getJwtHeader(loginUser, jwtTokenProvider.generateJwtRefreshToken(loginUser));
        return new ResponseEntity<>(loginUser, jwtHeader, HttpStatus.OK);
    }

    @GetMapping("/logout")
    public ResponseEntity<?> logout() {
        userService.logout();
        return new ResponseEntity<>("Logged out", OK);
    }

    @GetMapping("/refresh")
    public ResponseEntity<?> refreshToken(@CookieValue(name = "refresh-token", defaultValue = "") String refreshToken) {
        if (refreshToken.isBlank())
            throw new InvalidRefreshTokenException("Invalid refresh token");

        String email = jwtTokenProvider.getSubject(refreshToken, false);
        User user = userService
                .findUserByEmail(email)
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token"));

        if (!jwtTokenProvider.isTokenValid(email, refreshToken, false) || jwtTokenProvider.getRefreshTokenCountFromToken(refreshToken) != user.getRefreshTokenCount())
            throw new InvalidRefreshTokenException("Invalid refresh token");

        HttpHeaders jwtHeader = getJwtHeader(user, refreshToken);
        return new ResponseEntity<>("Token refreshed", jwtHeader, HttpStatus.OK);
    }

    private HttpHeaders getJwtHeader(User user, String refreshToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.add(JwtConstant.JWT_TOKEN_HEADER, jwtTokenProvider.generateJwtAccessToken(user));
        headers.add(HttpHeaders.SET_COOKIE, getJwtRefreshTokenCookie(refreshToken).toString());
        return headers;
    }

    private ResponseCookie getJwtRefreshTokenCookie(String refreshToken) {
        return ResponseCookie.from("refresh-token", refreshToken)
                .httpOnly(true)
                .secure(true)
                .sameSite("strict")
                .maxAge(TimeUnit.DAYS.toSeconds(jwtProperties.getRefreshTokenExpiresIn()))
                .build();
    }
}
