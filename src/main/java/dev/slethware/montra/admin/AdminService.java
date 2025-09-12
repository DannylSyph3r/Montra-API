package dev.slethware.montra.admin;

import dev.slethware.montra.admin.dto.AdminInvitationRequest;
import dev.slethware.montra.admin.dto.AdminResponse;
import dev.slethware.montra.shared.ApiResponseWrapper;
import org.springframework.data.domain.Page;

import java.util.List;

public interface AdminService {

    ApiResponseWrapper<Void> inviteAdmin(AdminInvitationRequest request);

    ApiResponseWrapper<Void> acceptAdminInvitation(String email, String tempPassword);

    List<AdminResponse> getAllAdmins();

    Page<AdminResponse> getAdminsPaginated(int page, int size);

    AdminResponse getAdminById(Long id);

    ApiResponseWrapper<Void> updateAdminAuthorities(String email, List<String> authorities);

    ApiResponseWrapper<Void> deactivateAdmin(String email);

    ApiResponseWrapper<Void> reactivateAdmin(String email);

    void cleanupExpiredInvitations();
}