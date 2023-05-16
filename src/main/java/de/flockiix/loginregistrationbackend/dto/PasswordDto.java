package de.flockiix.loginregistrationbackend.dto;

import de.flockiix.loginregistrationbackend.validation.annotation.ValidPassword;

import javax.validation.constraints.NotBlank;

public record PasswordDto(String oldPassword,
                          @ValidPassword @NotBlank(message = "Password is mandatory") String newPassword) {
    public PasswordDto(String oldPassword, String newPassword) {
        this.oldPassword = oldPassword;
        this.newPassword = newPassword;
    }

    @Override
    public String newPassword() {
        return newPassword;
    }
}
