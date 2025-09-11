package dev.slethware.montra.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Email should be valid")
    private String email;

    private String password;

    @Pattern(regexp = "^\\d{4}$", message = "PIN must be 4 digits")
    private String pin;


    public boolean isPasswordLogin() {
        return password != null && !password.trim().isEmpty();
    }

    public boolean isPinLogin() {
        return pin != null && !pin.trim().isEmpty();
    }

    public boolean hasValidCredentials() {
        return isPasswordLogin() || isPinLogin();
    }
}