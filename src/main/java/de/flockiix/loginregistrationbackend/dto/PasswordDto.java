package de.flockiix.loginregistrationbackend.dto;

import de.flockiix.loginregistrationbackend.validation.annotation.ValidPassword;

import javax.validation.constraints.NotBlank;

public class PasswordDto {
    private final String oldPassword;
    @ValidPassword
    @NotBlank(message = "Password is mandatory")
    private final String newPassword;

    public PasswordDto(String oldPassword, String newPassword) {
        this.oldPassword = oldPassword;
        this.newPassword = newPassword;
    }

    public String getOldPassword() {
        return oldPassword;
    }

    public String getNewPassword() {
        return newPassword;
    }
}
