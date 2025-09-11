package dev.slethware.montra.admin.model;

import dev.slethware.montra.shared.audit.Auditable;
import dev.slethware.montra.user.model.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "admin_invitations", indexes = {
        @Index(name = "invitation_email_idx", columnList = "email", unique = true)
})
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class AdminInvitation extends Auditable {

    @Column(unique = true, nullable = false)
    private String email;

    @Column(nullable = false)
    private String firstName;

    @Column(nullable = false)
    private String lastName;

    @Column(nullable = false)
    private String tempPassword;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "invited_by_user_id", nullable = false)
    private User invitedBy;

    private boolean accepted = false;

    private LocalDateTime acceptedAt;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "accepted_user_id")
    private User acceptedUser;

    private LocalDateTime expiryDate;

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(this.expiryDate);
    }

    public boolean isValid() {
        return !accepted && !isExpired();
    }

    public void accept(User user) {
        this.accepted = true;
        this.acceptedAt = LocalDateTime.now();
        this.acceptedUser = user;
    }
}
