package dev.slethware.montra.user.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ProfileUpdateRequest {

    @Email(message = "Email should be valid")
    private String email;

    @Size(min = 3, max = 30, message = "Username must be between 3 and 30 characters")
    private String username;

    @Past(message = "Date of birth must be in the past")
    private LocalDate dateOfBirth;

    private String profilePictureUrl;
}
