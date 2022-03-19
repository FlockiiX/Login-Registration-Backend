package de.flockiix.loginregistrationbackend.exception;

public class TokenExistException extends RuntimeException {
    public TokenExistException(String message) {
        super(message);
    }
}
