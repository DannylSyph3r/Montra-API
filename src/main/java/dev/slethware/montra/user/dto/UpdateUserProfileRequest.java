package dev.slethware.montra.user.dto;

import jakarta.validation.constraints.Past;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class UpdateUserProfileRequest {

    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    private String username;

    @Size(max = 1000, message = "Bio must not exceed 1000 characters")
    private String bio;

    @Past(message = "Date of birth must be in the past")
    private LocalDate dateOfBirth;

    private String profilePictureUrl;

    // Helper methods to check what fields are being updated
    public boolean isUsernameUpdate() {
        return username != null && !username.trim().isEmpty();
    }

    public boolean isBioUpdate() {
        return bio != null;
    }

    public boolean isDateOfBirthUpdate() {
        return dateOfBirth != null;
    }

    public boolean isProfilePictureUpdate() {
        return profilePictureUrl != null;
    }
}