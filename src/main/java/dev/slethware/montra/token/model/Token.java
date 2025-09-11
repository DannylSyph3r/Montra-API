package dev.slethware.montra.token.model;

import dev.slethware.montra.shared.audit.Auditable;
import dev.slethware.montra.user.model.User;
import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "tokens", indexes = {
        @Index(name = "token_idx", columnList = "token", unique = true),
        @Index(name = "token_user_type_idx", columnList = "user_id, tokenType")
})
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class Token extends Auditable {

    @Column(unique = true, nullable = false)
    private String token;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private TokenType tokenType;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(nullable = false)
    private LocalDateTime expiryDate;

    private boolean used = false;
    private boolean revoked = false;
    private String deviceInfo;
    private String ipAddress;

    public boolean isExpired() {
        return LocalDateTime.now().isAfter(this.expiryDate);
    }

    public boolean isValid() {
        if (tokenType == TokenType.REFRESH_TOKEN) {
            return !revoked && !isExpired();
        }
        return !used && !isExpired();
    }

    public boolean isRefreshToken() {
        return this.tokenType == TokenType.REFRESH_TOKEN;
    }

    public void markAsUsed() {
        this.used = true;
    }

    public void revoke() {
        this.revoked = true;
    }
}