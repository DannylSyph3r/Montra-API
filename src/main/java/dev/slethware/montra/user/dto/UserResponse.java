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
    private String bio;
    private UserRole role;
    private UserStatus status;
    private boolean emailVerified;
    private boolean accountSetupComplete;
    private boolean pinSet;
    private LocalDate dateOfBirth;
    private String profilePictureUrl;

    // Username management info
    private Boolean usernameCustomized;
    private LocalDateTime usernameLastChangedAt;
    private Integer usernameChangeCount;
    private Integer usernameChangesThisYear;

    private List<String> authorities;
    private LocalDateTime createdOn;

    public String getFullName() {
        return firstName + " " + lastName;
    }

    // Create a public version (for viewing other users) and obscuring sensitive info
    public static UserResponse createPublicResponse(UserResponse fullResponse) {
        return UserResponse.builder()
                .id(fullResponse.getId())
                .email(fullResponse.getEmail())
                .firstName(fullResponse.getFirstName())
                .lastName(fullResponse.getLastName())
                .username(fullResponse.getUsername())
                .bio(fullResponse.getBio())
                .role(fullResponse.getRole())
                .profilePictureUrl(fullResponse.getProfilePictureUrl())
                .createdOn(fullResponse.getCreatedOn())
                // Exclude sensitive username management fields
                .build();
    }

    // Helper method to set username (empty if same as email)
    public void setDisplayUsername(String actualUsername, String userEmail) {
        if (actualUsername != null && actualUsername.equals(userEmail)) {
            this.username = ""; // Show empty if username is same as email
        } else {
            this.username = actualUsername;
        }
    }
}