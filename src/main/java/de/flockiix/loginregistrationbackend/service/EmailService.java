package de.flockiix.loginregistrationbackend.service;

public interface EmailService {
    void sendEmail(String receiver, String subject, String content);
}
