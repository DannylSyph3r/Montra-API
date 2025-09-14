package dev.slethware.montra.audit.model;

import jakarta.persistence.*;
import lombok.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Data
@Entity
@Table(name = "audit_logs", indexes = {
        @Index(name = "audit_user_idx", columnList = "userEmail"),
        @Index(name = "audit_created_idx", columnList = "createdOn")
})
@Builder
@NoArgsConstructor
@AllArgsConstructor
@EntityListeners(AuditingEntityListener.class)
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdOn;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private AuditLogType auditLogType;

    @Column(nullable = false)
    private Long entityId;

    @Column(nullable = false)
    private String entityName;

    @Column(length = 1500)
    private String logDescription;

    @Column(nullable = false)
    private String userEmail;
}