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
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuditLogServiceImpl implements AuditLogService {

    private final AuditLogRepository auditLogRepository;

    @Override
    @Async
    public void log(Long entityId, String entityName, AuditLogType auditLogType, String logDescription, User user) {
        String userEmail = (user != null) ? user.getEmail() : "SYSTEM";

        AuditLog auditLog = AuditLog.builder()
                .entityId(entityId)
                .entityName(entityName)
                .auditLogType(auditLogType)
                .logDescription(logDescription)
                .userEmail(userEmail)
                .build();

        auditLogRepository.save(auditLog);
        log.debug("Audit log created for entity {} with ID {}", entityName, entityId);
    }

    @Override
    @Transactional(readOnly = true)
    public Page<AuditLog> getAuditLogs(User currentUser, Long entityId, String entityName,
                                       AuditLogType auditLogType, String userEmail,
                                       LocalDateTime fromDate, LocalDateTime toDate,
                                       int page, int size) {

        PageRequest pageRequest = PageRequest.of(page, size, Sort.by("createdOn").descending());

        if (!currentUser.isAdmin()) {
            userEmail = currentUser.getEmail();
        }

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

        // Default: all logs for admin, user's own logs for regular users
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
        log.info("Cleaned up audit logs older than {} days", daysToKeep);
    }
}