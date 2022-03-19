package de.flockiix.loginregistrationbackend.exception;

public class DisplayNameExistException extends RuntimeException {
    public DisplayNameExistException(String message) {
        super(message);
    }
}
