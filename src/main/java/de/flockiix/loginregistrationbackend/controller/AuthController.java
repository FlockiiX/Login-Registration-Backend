package de.flockiix.loginregistrationbackend.controller;

import de.flockiix.loginregistrationbackend.advice.ControllerAdvice;
import de.flockiix.loginregistrationbackend.exception.InvalidRefreshTokenException;
import de.flockiix.loginregistrationbackend.jwt.JwtTokenProvider;
import de.flockiix.loginregistrationbackend.model.JwtAuthenticationResponse;
import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.payload.RefreshTokenRequest;
import de.flockiix.loginregistrationbackend.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import static org.springframework.http.HttpStatus.OK;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController extends ControllerAdvice {
    private final UserService userService;
    private final JwtTokenProvider jwtTokenProvider;

    public AuthController(UserService userService, JwtTokenProvider jwtTokenProvider) {
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody User user) {
        User loginUser = userService.login(user.getEmail(), user.getPassword());
        JwtAuthenticationResponse authenticationResponse = getJwtAuthenticationResponse(loginUser, jwtTokenProvider.generateJwtRefreshToken(loginUser));
        return new ResponseEntity<>(authenticationResponse, HttpStatus.OK);
    }

    @GetMapping("/logout")
    public ResponseEntity<?> logout() {
        userService.logout();
        return new ResponseEntity<>("Logged out", OK);
    }

    @GetMapping("/refresh")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        if (refreshTokenRequest == null || refreshTokenRequest.refreshToken().isBlank())
            throw new InvalidRefreshTokenException("Invalid refresh token");

        String refreshToken = refreshTokenRequest.refreshToken();
        String email = jwtTokenProvider.getSubject(refreshToken, false);
        User user = userService
                .findUserByEmail(email)
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token"));

        if (!jwtTokenProvider.isTokenValid(email, refreshToken, false) || jwtTokenProvider.getRefreshTokenCountFromToken(refreshToken) != user.getRefreshTokenCount())
            throw new InvalidRefreshTokenException("Invalid refresh token");

        JwtAuthenticationResponse authenticationResponse = getJwtAuthenticationResponse(user, refreshToken);
        return new ResponseEntity<>(authenticationResponse, HttpStatus.OK);
    }

    private JwtAuthenticationResponse getJwtAuthenticationResponse(User user, String refreshToken) {
        String accessToken = jwtTokenProvider.generateJwtAccessToken(user);
        return new JwtAuthenticationResponse(accessToken, refreshToken);
    }
}
