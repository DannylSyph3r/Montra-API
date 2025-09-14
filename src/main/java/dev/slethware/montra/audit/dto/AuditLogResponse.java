package dev.slethware.montra.audit.dto;

import dev.slethware.montra.audit.model.AuditLogType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuditLogResponse {

    private Long id;
    private LocalDateTime createdOn;
    private AuditLogType auditLogType;
    private Long entityId;
    private String entityName;
    private String logDescription;
    private String userEmail;
}