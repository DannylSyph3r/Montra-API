package dev.slethware.montra.controllers;

import dev.slethware.montra.audit.AuditLogService;
import dev.slethware.montra.audit.dto.AuditLogResponse;
import dev.slethware.montra.audit.model.AuditLog;
import dev.slethware.montra.audit.model.AuditLogType;
import dev.slethware.montra.shared.ApiResponseWrapper;
import dev.slethware.montra.shared.util.ApiResponseUtil;
import dev.slethware.montra.user.model.User;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;

@RestController
@RequestMapping("/api/v1/audit")
@RequiredArgsConstructor
public class AuditLogController {

    private final AuditLogService auditLogService;

    @GetMapping
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<ApiResponseWrapper<Page<AuditLogResponse>>> getAuditLogs(
            @AuthenticationPrincipal User currentUser,
            @RequestParam(required = false) Long entityId,
            @RequestParam(required = false) String entityName,
            @RequestParam(required = false) AuditLogType auditLogType,
            @RequestParam(required = false) String userEmail,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime fromDate,
            @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime toDate,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "20") int size) {

        Page<AuditLog> auditLogs = auditLogService.getAuditLogs(
                currentUser, entityId, entityName, auditLogType,
                userEmail, fromDate, toDate, page, size
        );

        Page<AuditLogResponse> response = auditLogs.map(this::convertToResponse);
        return ResponseEntity.ok(ApiResponseUtil.successful("Audit logs retrieved successfully", response));
    }

    @DeleteMapping("/cleanup")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponseWrapper<Void>> cleanupOldAuditLogs(
            @RequestParam(defaultValue = "90") int daysToKeep) {

        auditLogService.cleanupOldAuditLogs(daysToKeep);
        return ResponseEntity.ok(ApiResponseUtil.successful("Audit logs cleanup completed", null));
    }

    private AuditLogResponse convertToResponse(AuditLog auditLog) {
        return AuditLogResponse.builder()
                .id(auditLog.getId())
                .createdOn(auditLog.getCreatedOn())
                .auditLogType(auditLog.getAuditLogType())
                .entityId(auditLog.getEntityId())
                .entityName(auditLog.getEntityName())
                .logDescription(auditLog.getLogDescription())
                .userEmail(auditLog.getUserEmail())
                .build();
    }
}