package de.flockiix.loginregistrationbackend.service.impl;

import de.flockiix.loginregistrationbackend.exception.EmailSendFailedException;
import de.flockiix.loginregistrationbackend.service.EmailService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import javax.mail.MessagingException;
import javax.mail.internet.MimeMessage;

@Service
public class EmailServiceImpl implements EmailService {
    private static final Logger LOGGER = LoggerFactory.getLogger(EmailServiceImpl.class);
    private final JavaMailSender mailSender;

    public EmailServiceImpl(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    @Override
    @Async
    public void sendEmail(String receiver, String subject, String content) {
        try {
            MimeMessage mimeMessage = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(mimeMessage, "utf-8");
            helper.setText(content, true);
            helper.setTo(receiver);
            helper.setSubject(subject);
            helper.setFrom("user-management@flockiix.de");
            mailSender.send(mimeMessage);
        } catch (MessagingException exception) {
            LOGGER.error("Failed to send email", exception);
            throw new EmailSendFailedException("Failed to send email");
        }
    }
}
