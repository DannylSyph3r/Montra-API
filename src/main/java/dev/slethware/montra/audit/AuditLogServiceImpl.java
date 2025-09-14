package dev.slethware.montra.audit;

import dev.slethware.montra.audit.model.AuditLog;
import dev.slethware.montra.audit.model.AuditLogType;
import dev.slethware.montra.user.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuditLogServiceImpl implements AuditLogService {

    private final AuditLogRepository auditLogRepository;

    @Async
    @Override
    public void log(Long entityId, String entityName, AuditLogType auditLogType, String logDescription, User user) {
        try {
            String userEmail = (user != null) ? user.getEmail() : "SYSTEM";

            AuditLog auditLog = AuditLog.builder()
                    .entityId(entityId).entityName(entityName)
                    .logDescription(logDescription).auditLogType(auditLogType)
                    .userEmail(userEmail).build();

            auditLogRepository.save(auditLog);
        } catch (Exception e) {
            log.error("Failed to create audit log: {}", e.getMessage());
        }
    }

    @Override
    public Page<AuditLog> getAuditLogs(User currentUser, Long entityId, String entityName,
                                       AuditLogType auditLogType, String userEmail,
                                       LocalDateTime fromDate, LocalDateTime toDate,
                                       int page, int size) {

        // Force regular users to only see their own logs
        if (!currentUser.isAdmin()) {
            userEmail = currentUser.getEmail();
        }

        PageRequest pageRequest = PageRequest.of(page, size, Sort.by("createdOn").descending());

        // Route to appropriate repository method based on filters
        if (userEmail != null && fromDate != null && toDate != null) {
            return auditLogRepository.findByUserEmailAndDateRange(userEmail, fromDate, toDate, pageRequest);
        }

        if (fromDate != null && toDate != null) {
            return auditLogRepository.findByDateRange(fromDate, toDate, pageRequest);
        }

        if (entityId != null && entityName != null) {
            return auditLogRepository.findByEntityIdAndEntityName(entityId, entityName, pageRequest);
        }

        if (auditLogType != null) {
            return auditLogRepository.findByAuditLogType(auditLogType, pageRequest);
        }

        if (userEmail != null) {
            return auditLogRepository.findByUserEmail(userEmail, pageRequest);
        }

        // Default: get all for admin, user's own for regular users
        if (currentUser.isAdmin()) {
            return auditLogRepository.findAll(pageRequest);
        } else {
            return auditLogRepository.findByUserEmail(currentUser.getEmail(), pageRequest);
        }
    }

    @Override
    public void cleanupOldAuditLogs(int daysToKeep) {
        LocalDateTime cutoffDate = LocalDateTime.now().minusDays(daysToKeep);
        auditLogRepository.deleteOldAuditLogs(cutoffDate);
    }
}