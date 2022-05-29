package de.flockiix.loginregistrationbackend.controller;

import de.flockiix.loginregistrationbackend.advice.ControllerAdvice;
import de.flockiix.loginregistrationbackend.config.properties.JwtProperties;
import de.flockiix.loginregistrationbackend.dto.PasswordDto;
import de.flockiix.loginregistrationbackend.exception.UserNotFoundException;
import de.flockiix.loginregistrationbackend.model.HttpResponse;
import de.flockiix.loginregistrationbackend.model.User;
import de.flockiix.loginregistrationbackend.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.List;

import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.http.HttpStatus.OK;

@RestController
@RequestMapping("/api/v1/user")
public class UserController extends ControllerAdvice {
    private final UserService userService;
    private final JwtProperties jwtProperties;

    public UserController(UserService userService, JwtProperties jwtProperties) {
        this.userService = userService;
        this.jwtProperties = jwtProperties;
    }

    @PostMapping("/register")
    public ResponseEntity<HttpResponse> register(@Valid @RequestBody User user) {
        userService.register(
                user.getFirstName(),
                user.getLastName(),
                user.getDisplayName(),
                user.getEmail(),
                user.getPassword()
        );

        return response(OK, "Confirm your email");
    }


    @GetMapping("/confirm")
    public ResponseEntity<HttpResponse> confirm(@RequestParam("token") String token) {
        userService.confirmToken(token);
        return response(OK, "Email confirmed");
    }

    @GetMapping("/resetPassword")
    public ResponseEntity<HttpResponse> resetPasswordRequest(@RequestParam("email") String email) {
        userService.createPasswordResetToken(email);
        return response(OK, "Success");
    }

    @PostMapping("/resetPassword")
    public ResponseEntity<HttpResponse> resetPassword(@RequestParam("token") String token, @Valid @RequestBody PasswordDto passwordDto) {
        userService.resetUserPassword(
                token,
                passwordDto.getNewPassword()
        );

        return response(OK, "Success");
    }

    @PostMapping("/updatePassword")
    @PreAuthorize("hasAuthority('verified')")
    public ResponseEntity<HttpResponse> updatePassword(@Valid @RequestBody PasswordDto passwordDto, HttpServletRequest request) {
        userService.updateUserPassword(
                passwordDto,
                getTokenFromRequest(request)
        );

        return response(OK, "Password changed");
    }

    @PostMapping("/update2FA")
    @PreAuthorize("hasAuthority('verified')")
    public ResponseEntity<HttpResponse> update2FA(@Valid @RequestParam("use2FA") boolean use2FA, HttpServletRequest request) {
        return response(OK, userService.updateUser2FA(
                use2FA,
                getTokenFromRequest(request)
        ));
    }

    @GetMapping("/list")
    @PreAuthorize("hasAuthority('user:read')")
    public ResponseEntity<List<User>> getUsers() {
        List<User> users = userService.getUsers();
        return new ResponseEntity<>(users, OK);
    }

    @GetMapping("/find")
    @PreAuthorize("hasAuthority('user:read')")
    public ResponseEntity<User> findUser(@RequestParam("email") String email) {
        User user = userService
                .findUserByEmail(email)
                .orElseThrow(() -> new UserNotFoundException(String.format("User with email %s cannot be found", email)));

        return new ResponseEntity<>(user, OK);
    }

    @DeleteMapping("/delete")
    @PreAuthorize("hasAuthority('user:delete')")
    public ResponseEntity<HttpResponse> deleteUser(@RequestParam("email") String email) {
        userService.deleteUser(email);
        return response(OK, "Entity deleted");
    }

    private String getTokenFromRequest(HttpServletRequest request) {
        String authorizationHeader = request.getHeader(AUTHORIZATION);
        return authorizationHeader.substring(jwtProperties.getPrefix().length() + 1);
    }

    private ResponseEntity<HttpResponse> response(HttpStatus httpStatus, String message) {
        return new ResponseEntity<>(new HttpResponse(httpStatus.value(), httpStatus, httpStatus.getReasonPhrase().toUpperCase(), message), httpStatus);
    }
}
