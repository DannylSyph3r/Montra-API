package dev.slethware.montra.audit;

import dev.slethware.montra.audit.model.AuditLog;
import dev.slethware.montra.audit.model.AuditLogType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;

@Repository
public interface AuditLogRepository extends JpaRepository<AuditLog, Long> {

    Page<AuditLog> findByUserEmail(String userEmail, Pageable pageable);

    Page<AuditLog> findByAuditLogType(AuditLogType auditLogType, Pageable pageable);

    Page<AuditLog> findByEntityIdAndEntityName(Long entityId, String entityName, Pageable pageable);

    @Query("SELECT a FROM AuditLog a WHERE a.createdOn BETWEEN :fromDate AND :toDate")
    Page<AuditLog> findByDateRange(@Param("fromDate") LocalDateTime fromDate,
                                   @Param("toDate") LocalDateTime toDate,
                                   Pageable pageable);

    @Query("SELECT a FROM AuditLog a WHERE a.userEmail = :userEmail AND a.createdOn BETWEEN :fromDate AND :toDate")
    Page<AuditLog> findByUserEmailAndDateRange(@Param("userEmail") String userEmail,
                                               @Param("fromDate") LocalDateTime fromDate,
                                               @Param("toDate") LocalDateTime toDate,
                                               Pageable pageable);

    @Modifying
    @Query("DELETE FROM AuditLog a WHERE a.createdOn < :cutoffDate")
    void deleteOldAuditLogs(@Param("cutoffDate") LocalDateTime cutoffDate);
}