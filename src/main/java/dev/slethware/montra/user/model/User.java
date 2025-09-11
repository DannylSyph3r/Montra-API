package dev.slethware.montra.user.model;

import dev.slethware.montra.shared.audit.Auditable;
import dev.slethware.montra.shared.exception.BadRequestException;
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
        @Index(name = "username_idx", columnList = "username", unique = true),
        @Index(name = "pin_hash_idx", columnList = "pinHash")
})
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class User extends Auditable implements UserDetails {

    @Column(unique = true)
    private String username;

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String firstName;

    @Column(nullable = false)
    private String lastName;

    private String passwordHash;

    private String pinHash;

    private LocalDateTime pinSetAt;

    private int pinAttempts = 0;

    private LocalDateTime pinBlockedUntil;

    @Enumerated(EnumType.STRING)
    private UserStatus status = UserStatus.PENDING_EMAIL_VERIFICATION;

    @Enumerated(EnumType.STRING)
    private UserRole role = UserRole.USER;

    private LocalDate dateOfBirth;

    private String profilePictureUrl;

    private boolean emailVerified = false;

    private boolean accountSetupComplete = false;

    private boolean enabled = false;

    private boolean accountNonExpired = true;

    private boolean accountNonLocked = true;

    private boolean credentialsNonExpired = true;

    private boolean canResetPassword = false;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(
            name = "user_authorities",
            joinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id"),
            inverseJoinColumns = @JoinColumn(name = "authority_id", referencedColumnName = "id")
    )
    private List<Authority> authorities;

    // Business Logic Methods
    public void verifyEmail() {
        if (this.emailVerified) {
            throw new BadRequestException("Email is already verified");
        }
        this.emailVerified = true;
        this.status = UserStatus.EMAIL_VERIFIED;
        this.enabled = true;
        this.accountNonLocked = true;
    }

    public void setupPin(String hashedPin) {
        if (!this.emailVerified) {
            throw new BadRequestException("Email must be verified before setting up PIN");
        }
        this.pinHash = hashedPin;
        this.pinSetAt = LocalDateTime.now();
        this.pinAttempts = 0;
        this.pinBlockedUntil = null;
    }

    public void completeAccountSetup() {
        if (!this.emailVerified) {
            throw new BadRequestException("Email must be verified to complete setup");
        }
        if (this.username == null || this.username.trim().isEmpty()) {
            throw new BadRequestException("Username is required to complete setup");
        }
        this.accountSetupComplete = true;
        this.status = UserStatus.ACCOUNT_SETUP_COMPLETE;
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

    // UserDetails interface implementations
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
        return accountNonExpired;
    }

    @Override
    public boolean isAccountNonLocked() {
        return accountNonLocked && canAttemptPin();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }
}