package dev.slethware.montra.user.model;

import dev.slethware.montra.shared.audit.Auditable;
import jakarta.persistence.*;
import lombok.*;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;

@Data
@Entity
@Table(name = "users", indexes = {
        @Index(name = "email_idx", columnList = "email", unique = true),
        @Index(name = "username_case_insensitive_idx", columnList = "username"),
        @Index(name = "pin_hash_idx", columnList = "pinHash"),
        @Index(name = "username_customized_idx", columnList = "usernameCustomized")
})
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class User extends Auditable implements UserDetails {

    // Identity Fields
    @Column(nullable = false, length = 50)
    private String username;

    @Column(unique = true, nullable = false, length = 255)
    private String email;

    @Column(nullable = false, length = 100)
    private String firstName;

    @Column(nullable = false, length = 100)
    private String lastName;

    @Column(nullable = false)
    private String passwordHash;

    // Profile Fields
    @Column(columnDefinition = "TEXT")
    private String bio;

    @Column(columnDefinition = "TEXT")
    private String profilePictureUrl;

    private LocalDate dateOfBirth;

    // Username Management
    @Column(nullable = false)
    private Boolean usernameCustomized = false;

    private LocalDateTime usernameLastChangedAt;

    @Column(nullable = false)
    private Integer usernameChangeCount = 0;

    @Column(nullable = false)
    private Integer usernameChangesThisYear = 0;

    private LocalDate usernameYearResetDate;

    // PIN fields
    private String pinHash;
    private LocalDateTime pinSetAt;
    private Integer pinAttempts = 0;
    private LocalDateTime pinBlockedUntil;

    // Account Status
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserStatus status = UserStatus.PENDING_EMAIL_VERIFICATION;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private UserRole role = UserRole.USER;

    private Boolean emailVerified = false;
    private Boolean accountSetupComplete = false;

    // Security Flags
    private Boolean enabled = false;
    private Boolean accountNonExpired = true;
    private Boolean accountNonLocked = true;
    private Boolean credentialsNonExpired = true;
    private Boolean canResetPassword = false;

    // Authorities
    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_authorities",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "authority_id", referencedColumnName = "id")
    )
    private List<Authority> authorities;

    public void verifyEmail() {
        this.emailVerified = true;
        this.status = UserStatus.EMAIL_VERIFIED;
        this.enabled = true;
        this.accountNonLocked = true;
    }

    public void completeAccountSetup() {
        this.accountSetupComplete = true;
        this.status = UserStatus.ACCOUNT_SETUP_COMPLETE;
    }

    public void setupPin(String hashedPin) {
        this.pinHash = hashedPin;
        this.pinSetAt = LocalDateTime.now();
        this.pinAttempts = 0;
        this.pinBlockedUntil = null;
    }

    public boolean canAttemptPin() {
        return this.pinBlockedUntil == null || LocalDateTime.now().isAfter(this.pinBlockedUntil);
    }

    public void recordFailedPinAttempt() {
        this.pinAttempts++;
        if (this.pinAttempts >= 5) {
            this.pinBlockedUntil = LocalDateTime.now().plusHours(1);
        }
    }

    public void recordSuccessfulPinAttempt() {
        this.pinAttempts = 0;
        this.pinBlockedUntil = null;
    }

    public boolean isPinSet() {
        return this.pinHash != null && !this.pinHash.trim().isEmpty();
    }

    public void updateUsername(String newUsername) {
        this.username = newUsername;
        this.usernameCustomized = true;
        this.usernameLastChangedAt = LocalDateTime.now();
        this.usernameChangeCount++;
        this.usernameChangesThisYear++;
    }

    public String getFullName() {
        return this.firstName + " " + this.lastName;
    }

    public boolean isSuperAdmin() {
        return this.role == UserRole.SUPER_ADMIN;
    }

    public boolean isAdmin() {
        return this.role == UserRole.ADMIN || this.role == UserRole.SUPER_ADMIN;
    }

    public boolean isUser() {
        return this.role == UserRole.USER;
    }

    public boolean hasCustomizedUsername() {
        return this.usernameCustomized != null && this.usernameCustomized;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return passwordHash;
    }

    @Override
    public String getUsername() {
        return email; // Using email as username for login
    }

    @Override
    public boolean isAccountNonExpired() {
        return accountNonExpired != null ? accountNonExpired : true;
    }

    @Override
    public boolean isAccountNonLocked() {
        boolean locked = accountNonLocked != null ? accountNonLocked : true;
        return locked && canAttemptPin();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired != null ? credentialsNonExpired : true;
    }

    @Override
    public boolean isEnabled() {
        return enabled != null ? enabled : false;
    }
}