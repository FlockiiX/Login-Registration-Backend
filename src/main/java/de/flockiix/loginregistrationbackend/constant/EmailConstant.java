package de.flockiix.loginregistrationbackend.constant;

import java.util.List;

public class EmailConstant {
    public static String buildAccountLockedEmail(String firstName) {
        return "Bad News " + firstName + "!\n\nYour account has been locked.";
    }

    public static String buildConfirmEmail(String firstName, String link) {
        return "Confirm your account, " + firstName + "\n\n <a href=\"" + link + "\">Confirm Account</a>";
    }

    public static String buildWelcomeEmail(String firstName) {
        return "Welcome, " + firstName;
    }

    public static String buildSafetyWarningEmail(String firstName) {
        return "Bad news " + firstName + "! We have detected suspicious login attempts on your account!";
    }

    public static String buildResetPasswordEmail(String firstName, String link) {
        return "Reset your password, " + firstName + ".\n\n <a href=\"" + link + "\">Reset Password</a>";
    }

    public static String build2FAActivatedEmail(String firstName, List<String> backupCodes) {
        return "Activated 2 fa, " + firstName + ". Your codes: " + backupCodes;
    }
}
