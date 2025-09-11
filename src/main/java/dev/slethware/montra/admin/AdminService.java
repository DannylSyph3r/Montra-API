package dev.slethware.montra.admin;

import dev.slethware.montra.admin.dto.AdminInvitationRequest;
import dev.slethware.montra.admin.dto.AdminResponse;
import dev.slethware.montra.shared.response.ApiResponse;
import dev.slethware.montra.user.model.User;
import org.springframework.data.domain.Page;

import java.util.List;

public interface AdminService {

    ApiResponse<Void> inviteAdmin(AdminInvitationRequest request);

    ApiResponse<Void> acceptAdminInvitation(String email, String tempPassword);

    List<AdminResponse> getAllAdmins();

    Page<AdminResponse> getAdminsPaginated(int page, int size);

    AdminResponse getAdminById(Long id);

    ApiResponse<Void> updateAdminAuthorities(String email, List<String> authorities);

    ApiResponse<Void> deactivateAdmin(String email);

    ApiResponse<Void> reactivateAdmin(String email);

    void cleanupExpiredInvitations();
}