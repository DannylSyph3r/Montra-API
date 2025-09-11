package dev.slethware.montra.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class SetupPinRequest {

    @NotBlank(message = "Email is required")
    @Email(message = "Email Address should be valid")
    private String email;

    @NotBlank(message = "PIN is required")
    @Pattern(regexp = "^\\d{4}$", message = "PIN must be 4 digits")
    private String pin;

    @NotBlank(message = "PIN confirmation is required")
    @Pattern(regexp = "^\\d{4}$", message = "PIN confirmation must be 4 digits")
    private String confirmPin;

    public boolean isPinMatching() {
        return pin != null && pin.equals(confirmPin);
    }
}
