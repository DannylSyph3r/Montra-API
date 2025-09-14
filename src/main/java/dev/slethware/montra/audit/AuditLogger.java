package dev.slethware.montra.audit;

import dev.slethware.montra.audit.model.AuditLogType;
import dev.slethware.montra.user.model.User;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class AuditLogger {

    private static AuditLogService auditLogService;

    @Autowired
    public AuditLogger(AuditLogService auditLogService) {
        AuditLogger.auditLogService = auditLogService;
    }

    private static User getLoggedInUserOrSystem() {
        try {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            if (authentication != null && authentication.isAuthenticated() &&
                    authentication.getPrincipal() instanceof User) {
                return (User) authentication.getPrincipal();
            }
        } catch (Exception e) {
            log.debug("Could not get authenticated user for audit logging: {}", e.getMessage());
        }
        return null; // Service will handle null as SYSTEM
    }

    // Core CRUD logging methods
    public static void logCreate(Long entityId, String entityName) {
        var user = getLoggedInUserOrSystem();
        auditLogService.log(entityId, entityName, AuditLogType.CREATE, entityName + " was created.", user);
    }

    public static void logUpdate(Long entityId, String entityName, String narration) {
        var user = getLoggedInUserOrSystem();
        auditLogService.log(entityId, entityName, AuditLogType.UPDATE, narration, user);
    }

    public static void logDelete(Long entityId, String entityName) {
        var user = getLoggedInUserOrSystem();
        auditLogService.log(entityId, entityName, AuditLogType.DELETE, entityName + " was deleted.", user);
    }

    // Authentication logging methods
    public static void logLogin(Long userId, String email) {
        var user = getLoggedInUserOrSystem();
        auditLogService.log(userId, "User", AuditLogType.LOGIN, "User " + email + " logged in successfully.", user);
    }

    public static void logLogout(Long userId, String email) {
        var user = getLoggedInUserOrSystem();
        auditLogService.log(userId, "User", AuditLogType.LOGOUT, "User " + email + " logged out.", user);
    }

    // Security-related logging methods
    public static void logPasswordChange(Long userId, String email) {
        var user = getLoggedInUserOrSystem();
        auditLogService.log(userId, "User", AuditLogType.PASSWORD_CHANGE, "Password changed for user " + email + ".", user);
    }

    public static void logAuthorityChange(Long userId, String email, String description) {
        var user = getLoggedInUserOrSystem();
        auditLogService.log(userId, "User", AuditLogType.AUTHORITY_CHANGE, "Authority changed for user " + email + ": " + description, user);
    }
}