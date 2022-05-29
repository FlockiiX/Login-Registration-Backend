package de.flockiix.loginregistrationbackend.constant;

import java.util.List;

public class EmailConstant {
    public static String buildAccountLockedEmail(String firstName) {
        return String.format("Bad News %s!\n\nYour account has been locked.", firstName);
    }

    public static String buildConfirmEmail(String firstName, String link) {
        return String.format("Confirm your account, %s\n\n <a href=\"%s\">Confirm Account</a>", firstName, link);
    }

    public static String buildWelcomeEmail(String firstName) {
        return String.format("Welcome, %s", firstName);
    }

    public static String buildSafetyWarningEmail(String firstName) {
        return String.format("Bad news %s! We have detected suspicious login attempts on your account!", firstName);
    }

    public static String buildResetPasswordEmail(String firstName, String link) {
        return String.format("Reset your password, %s.\n\n <a href=\"%s\">Reset Password</a>", firstName, link);
    }

    public static String build2FAActivatedEmail(String firstName, List<String> backupCodes) {
        return String.format("Activated 2 fa, %s. Your codes: %s", firstName, backupCodes);
    }
}
