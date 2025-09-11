package dev.slethware.montra.admin;

import dev.slethware.montra.admin.model.AdminInvitation;
import dev.slethware.montra.user.model.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface AdminInvitationRepository extends JpaRepository<AdminInvitation, Long> {

    Optional<AdminInvitation> findByEmail(String email);

    List<AdminInvitation> findByInvitedBy(User invitedBy);

    Page<AdminInvitation> findByAcceptedFalse(Pageable pageable);

    @Query("SELECT ai FROM AdminInvitation ai WHERE ai.accepted = false AND ai.expiryDate > :now")
    List<AdminInvitation> findValidPendingInvitations(@Param("now") LocalDateTime now);

    @Modifying
    @Query("DELETE FROM AdminInvitation ai WHERE ai.expiryDate < :now AND ai.accepted = false")
    void deleteExpiredInvitations(@Param("now") LocalDateTime now);

    boolean existsByEmail(String email);
}