package dev.slethware.montra.audit;

import dev.slethware.montra.audit.model.AuditLog;
import dev.slethware.montra.audit.model.AuditLogType;
import dev.slethware.montra.user.model.User;
import org.springframework.data.domain.Page;

import java.time.LocalDateTime;

public interface AuditLogService {

    void log(Long entityId, String entityName, AuditLogType auditLogType, String logDescription, User user);

    Page<AuditLog> getAuditLogs(User currentUser,
                                Long entityId,
                                String entityName,
                                AuditLogType auditLogType,
                                String userEmail,
                                LocalDateTime fromDate,
                                LocalDateTime toDate,
                                int page,
                                int size);

    void cleanupOldAuditLogs(int daysToKeep);
}