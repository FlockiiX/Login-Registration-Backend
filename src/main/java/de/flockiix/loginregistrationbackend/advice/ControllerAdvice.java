package de.flockiix.loginregistrationbackend.advice;

import com.auth0.jwt.exceptions.TokenExpiredException;
import de.flockiix.loginregistrationbackend.exception.*;
import de.flockiix.loginregistrationbackend.model.HttpResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.MissingServletRequestParameterException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;

import javax.persistence.NoResultException;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import static org.springframework.http.HttpStatus.*;

@RestControllerAdvice
public class ControllerAdvice {
    private static final Logger LOGGER = LoggerFactory.getLogger(ControllerAdvice.class);

    // CUSTOM EXCEPTIONS

    @ExceptionHandler(EmailNotVerifiedException.class)
    public ResponseEntity<HttpResponse> emailNotVerifiedException(EmailNotVerifiedException exception) {
        return createHttpResponse(UNAUTHORIZED, exception.getMessage());
    }

    @ExceptionHandler(DeviceVerificationException.class)
    public ResponseEntity<HttpResponse> deviceVerificationException(DeviceVerificationException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(DisplayNameExistException.class)
    public ResponseEntity<HttpResponse> displayNameExistException(DisplayNameExistException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(EmailExistException.class)
    public ResponseEntity<HttpResponse> emailExistException(EmailExistException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(EmailSendFailedException.class)
    public ResponseEntity<HttpResponse> emailSendFailedException(EmailSendFailedException exception) {
        return createHttpResponse(INTERNAL_SERVER_ERROR, exception.getMessage());
    }

    @ExceptionHandler(InvalidAuthenticationException.class)
    public ResponseEntity<HttpResponse> invalidAuthenticationException(InvalidAuthenticationException exception) {
        return createHttpResponse(UNAUTHORIZED, exception.getMessage());
    }

    @ExceptionHandler(InvalidPasswordException.class)
    public ResponseEntity<HttpResponse> invalidPasswordException(InvalidPasswordException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<HttpResponse> InvalidRefreshTokenException(InvalidRefreshTokenException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(TokenAlreadyConfirmedException.class)
    public ResponseEntity<HttpResponse> tokenAlreadyConfirmedException(TokenAlreadyConfirmedException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(TokenExistException.class)
    public ResponseEntity<HttpResponse> tokenExistException(TokenExistException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(TokenNotFoundException.class)
    public ResponseEntity<HttpResponse> tokenNotFoundException(TokenNotFoundException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<HttpResponse> userNotFoundException(UserNotFoundException exception) {
        return createHttpResponse(BAD_REQUEST, exception.getMessage());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<HttpResponse> methodArgumentNotValidException(MethodArgumentNotValidException exception) {
        List<String> errors = new ArrayList<>();
        exception.getBindingResult().getAllErrors().forEach((error) -> {
            String errorMessage = error.getDefaultMessage();
            errors.add(errorMessage);
        });
        return createHttpResponse(BAD_REQUEST, String.valueOf(errors));
    }

    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<HttpResponse> accountDisabledException() {
        return createHttpResponse(BAD_REQUEST, "Your account is disabled");
    }

    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<HttpResponse> badCredentialsException(BadCredentialsException exception) {
        return createHttpResponse(BAD_REQUEST, "Username / password incorrect. Please try again");
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<HttpResponse> accessDeniedException() {
        return createHttpResponse(FORBIDDEN, "You do not have enough permission");
    }

    @ExceptionHandler(LockedException.class)
    public ResponseEntity<HttpResponse> lockedException(LockedException exception) {
        return createHttpResponse(UNAUTHORIZED, exception.getMessage());
    }

    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<HttpResponse> tokenExpiredException(TokenExpiredException exception) {
        return createHttpResponse(UNAUTHORIZED, exception.getMessage());
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<HttpResponse> noHandlerFoundException() {
        return createHttpResponse(BAD_REQUEST, "There is no mapping for this URL");
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<HttpResponse> methodNotSupportedException(HttpRequestMethodNotSupportedException exception) {
        HttpMethod supportedMethod = Objects.requireNonNull(exception.getSupportedHttpMethods()).iterator().next();
        return createHttpResponse(METHOD_NOT_ALLOWED, String.format("This request method is not allowed on this endpoint. Please send a '%s' request", supportedMethod));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<HttpResponse> internalServerErrorException(Exception exception) {
        LOGGER.error(exception.getMessage());
        return createHttpResponse(INTERNAL_SERVER_ERROR, "An error occurred while processing the request");
    }

    @ExceptionHandler(MissingServletRequestParameterException.class)
    public ResponseEntity<HttpResponse> missingServletRequestParameterException(MissingServletRequestParameterException exception) {
        return createHttpResponse(BAD_REQUEST, "Missing: " + exception.getParameterName());
    }

    @ExceptionHandler(NoResultException.class)
    public ResponseEntity<HttpResponse> notFoundException(NoResultException exception) {
        LOGGER.error(exception.getMessage());
        return createHttpResponse(NOT_FOUND, exception.getMessage());
    }

    private ResponseEntity<HttpResponse> createHttpResponse(HttpStatus httpStatus, String message) {
        return new ResponseEntity<>(new HttpResponse(httpStatus.value(), httpStatus,
                httpStatus.getReasonPhrase().toUpperCase(), message), httpStatus);
    }
}
