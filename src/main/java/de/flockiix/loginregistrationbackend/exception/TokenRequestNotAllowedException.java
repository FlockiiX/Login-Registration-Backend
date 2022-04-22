package de.flockiix.loginregistrationbackend.exception;

public class TokenRequestNotAllowedException extends RuntimeException {
    public TokenRequestNotAllowedException(String message) {
        super(message);
    }
}
