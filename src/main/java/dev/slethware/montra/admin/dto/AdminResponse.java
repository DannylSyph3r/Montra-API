package dev.slethware.montra.admin.dto;

import dev.slethware.montra.user.model.UserRole;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AdminResponse {

    private Long id;
    private String email;
    private String firstName;
    private String lastName;
    private UserRole role;
    private boolean emailVerified;
    private boolean enabled;
    private List<String> authorities;
    private LocalDateTime createdOn;
    private String invitedBy;

    public String getFullName() {
        return firstName + " " + lastName;
    }
}