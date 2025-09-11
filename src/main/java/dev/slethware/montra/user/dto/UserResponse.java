package dev.slethware.montra.user.dto;

import dev.slethware.montra.user.model.UserRole;
import dev.slethware.montra.user.model.UserStatus;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {

    private Long id;
    private String email;
    private String firstName;
    private String lastName;
    private String username;
    private UserRole role;
    private UserStatus status;
    private boolean emailVerified;
    private boolean accountSetupComplete;
    private boolean pinSet;
    private LocalDate dateOfBirth;
    private String profilePictureUrl;
    private List<String> authorities;
    private LocalDateTime createdOn;

    public String getFullName() {
        return firstName + " " + lastName;
    }
}
