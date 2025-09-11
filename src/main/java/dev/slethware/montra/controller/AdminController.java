package dev.slethware.montra.controller;

import dev.slethware.montra.admin.AdminService;
import dev.slethware.montra.admin.dto.AdminInvitationRequest;
import dev.slethware.montra.admin.dto.AdminResponse;
import dev.slethware.montra.shared.response.ApiResponse;
import dev.slethware.montra.shared.util.ApiResponseUtil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1/admin")
@RequiredArgsConstructor
public class AdminController {

    private final AdminService adminService;

    @PostMapping("/invite")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<Void>> inviteAdmin(@Valid @RequestBody AdminInvitationRequest request) {
        ApiResponse<Void> response = adminService.inviteAdmin(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/accept-invitation")
    public ResponseEntity<ApiResponse<Void>> acceptInvitation(
            @RequestParam String email,
            @RequestParam String tempPassword) {

        ApiResponse<Void> response = adminService.acceptAdminInvitation(email, tempPassword);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/list")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<List<AdminResponse>>> getAllAdmins() {
        List<AdminResponse> admins = adminService.getAllAdmins();
        return ResponseEntity.ok(ApiResponseUtil.successful("Admins retrieved successfully", admins));
    }

    @GetMapping
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<Page<AdminResponse>>> getAdminsPaginated(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Page<AdminResponse> admins = adminService.getAdminsPaginated(page, size);
        return ResponseEntity.ok(ApiResponseUtil.successful("Admins retrieved successfully", admins));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<AdminResponse>> getAdminById(@PathVariable Long id) {
        AdminResponse admin = adminService.getAdminById(id);
        return ResponseEntity.ok(ApiResponseUtil.successful("Admin retrieved successfully", admin));
    }

    @PutMapping("/{email}/authorities")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<Void>> updateAdminAuthorities(
            @PathVariable String email,
            @RequestBody List<String> authorities) {

        ApiResponse<Void> response = adminService.updateAdminAuthorities(email, authorities);
        return ResponseEntity.ok(response);
    }

    @PutMapping("/{email}/deactivate")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<Void>> deactivateAdmin(@PathVariable String email) {
        ApiResponse<Void> response = adminService.deactivateAdmin(email);
        return ResponseEntity.ok(response);
    }

    @PutMapping("/{email}/reactivate")
    @PreAuthorize("hasRole('SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<Void>> reactivateAdmin(@PathVariable String email) {
        ApiResponse<Void> response = adminService.reactivateAdmin(email);
        return ResponseEntity.ok(response);
    }
}