package dev.slethware.montra.admin;

import dev.slethware.montra.admin.dto.AdminInvitationRequest;
import dev.slethware.montra.admin.dto.AdminResponse;
import dev.slethware.montra.admin.model.AdminInvitation;
import dev.slethware.montra.email.EmailService;
import dev.slethware.montra.shared.exception.BadRequestException;
import dev.slethware.montra.shared.exception.ResourceNotFoundException;
import dev.slethware.montra.shared.ApiResponseWrapper;
import dev.slethware.montra.shared.util.ApiResponseUtil;
import dev.slethware.montra.user.AuthorityRepository;
import dev.slethware.montra.user.UserRepository;
import dev.slethware.montra.user.UserService;
import dev.slethware.montra.user.model.Authority;
import dev.slethware.montra.user.model.User;
import dev.slethware.montra.user.model.UserRole;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AdminServiceImpl implements AdminService {

    private final AdminInvitationRepository adminInvitationRepository;
    private final UserRepository userRepository;
    private final AuthorityRepository authorityRepository;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public ApiResponseWrapper<Void> inviteAdmin(AdminInvitationRequest request) {
        log.info("Starting admin invitation for email: {}", request.getEmail());

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new BadRequestException("User with this email already exists");
        }

        if (adminInvitationRepository.existsByEmail(request.getEmail())) {
            throw new BadRequestException("Invitation already sent to this email");
        }

        // Get current user (should be super admin)
        User currentUser = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        // Generate temporary password
        String tempPassword = generateTempPassword();

        // Create invitation
        AdminInvitation invitation = AdminInvitation.builder()
                .email(request.getEmail())
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .tempPassword(passwordEncoder.encode(tempPassword))
                .invitedBy(currentUser)
                .expiryDate(LocalDateTime.now().plusDays(3)) // 3 days to accept
                .build();

        adminInvitationRepository.save(invitation);

        emailService.sendAdminInvitation(request.getEmail(), tempPassword);

        log.info("Admin invitation completed successfully for email: {}", request.getEmail());
        return ApiResponseUtil.successful("Admin invitation sent successfully", null);
    }

    @Override
    public ApiResponseWrapper<Void> acceptAdminInvitation(String email, String tempPassword) {
        log.info("Starting admin invitation acceptance for email: {}", email);

        AdminInvitation invitation = adminInvitationRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Invitation not found"));

        if (!invitation.isValid()) {
            throw new BadRequestException("Invitation is expired or already accepted");
        }

        if (!passwordEncoder.matches(tempPassword, invitation.getTempPassword())) {
            throw new BadRequestException("Invalid temporary password");
        }

        // Create admin user
        User adminUser = User.builder()
                .email(invitation.getEmail())
                .firstName(invitation.getFirstName())
                .lastName(invitation.getLastName())
                .passwordHash(invitation.getTempPassword())
                .role(UserRole.ADMIN)
                .emailVerified(true)
                .enabled(true)
                .accountNonLocked(true)
                .accountNonExpired(true)
                .credentialsNonExpired(true)
                .canResetPassword(true) // Force password change
                .build();

        // Assign default admin authorities
        List<Authority> adminAuthorities = authorityRepository.findAllByNameIn(
                List.of("ROLE_ADMIN", "FEATURE_SUPPORT_ACCESS", "FEATURE_ANALYTICS_VIEW")
        );
        adminUser.setAuthorities(adminAuthorities);

        User savedUser = userRepository.save(adminUser);

        // Mark invitation as accepted
        invitation.accept(savedUser);
        adminInvitationRepository.save(invitation);

        log.info("Admin invitation acceptance completed successfully for email: {}", email);
        return ApiResponseUtil.successful("Admin invitation accepted successfully", null);
    }

    @Override
    @Transactional(readOnly = true)
    public List<AdminResponse> getAllAdmins() {
        log.info("Retrieving all admins");

        List<User> admins = userRepository.findByRoles(List.of(UserRole.ADMIN, UserRole.SUPER_ADMIN));
        List<AdminResponse> responses = admins.stream()
                .map(this::convertToAdminResponse)
                .collect(Collectors.toList());

        log.info("Retrieved {} admins", responses.size());
        return responses;
    }

    @Override
    @Transactional(readOnly = true)
    public Page<AdminResponse> getAdminsPaginated(int page, int size) {
        log.info("Retrieving paginated admins (page: {}, size: {})", page, size);

        Pageable pageable = PageRequest.of(page, size, Sort.by("createdOn").descending());
        Page<User> adminsPage = userRepository.findByRoleAndEmailVerifiedTrue(UserRole.ADMIN, pageable);

        Page<AdminResponse> responses = adminsPage.map(this::convertToAdminResponse);
        log.info("Retrieved {} total admins in paginated result", responses.getTotalElements());
        return responses;
    }

    @Override
    @Transactional(readOnly = true)
    public AdminResponse getAdminById(Long id) {
        log.info("Retrieving admin by ID: {}", id);

        User admin = userRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("Admin not found"));

        if (!admin.isAdmin()) {
            throw new BadRequestException("User is not an admin");
        }

        AdminResponse response = convertToAdminResponse(admin);
        log.info("Retrieved admin with ID: {}", id);
        return response;
    }

    @Override
    public ApiResponseWrapper<Void> updateAdminAuthorities(String email, List<String> authorities) {
        log.info("Starting authority update for admin: {} - authorities: {}", email, authorities);

        User admin = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Admin not found"));

        if (!admin.isAdmin()) {
            throw new BadRequestException("User is not an admin");
        }

        // Ensure ROLE_ADMIN is always included
        if (!authorities.contains("ROLE_ADMIN")) {
            authorities.add("ROLE_ADMIN");
        }

        List<Authority> authorityEntities = authorityRepository.findAllByNameIn(authorities);
        if (authorityEntities.size() != authorities.size()) {
            throw new BadRequestException("One or more authorities not found");
        }

        admin.setAuthorities(authorityEntities);
        userRepository.save(admin);

        log.info("Authority update completed successfully for admin: {}", email);
        return ApiResponseUtil.successful("Admin authorities updated successfully", null);
    }

    @Override
    public ApiResponseWrapper<Void> deactivateAdmin(String email) {
        log.info("Starting admin deactivation for email: {}", email);

        User admin = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Admin not found"));

        if (!admin.isAdmin()) {
            throw new BadRequestException("User is not an admin");
        }

        if (admin.isSuperAdmin()) {
            throw new BadRequestException("Cannot deactivate super admin");
        }

        admin.setEnabled(false);
        userRepository.save(admin);

        log.info("Admin deactivation completed successfully for email: {}", email);
        return ApiResponseUtil.successful("Admin deactivated successfully", null);
    }

    @Override
    public ApiResponseWrapper<Void> reactivateAdmin(String email) {
        log.info("Starting admin reactivation for email: {}", email);

        User admin = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("Admin not found"));

        if (!admin.isAdmin()) {
            throw new BadRequestException("User is not an admin");
        }

        admin.setEnabled(true);
        userRepository.save(admin);

        log.info("Admin reactivation completed successfully for email: {}", email);
        return ApiResponseUtil.successful("Admin reactivated successfully", null);
    }

    @Override
    public void cleanupExpiredInvitations() {
        log.info("Starting cleanup of expired admin invitations");
        adminInvitationRepository.deleteExpiredInvitations(LocalDateTime.now());
        log.info("Expired admin invitations cleanup completed");
    }

    private AdminResponse convertToAdminResponse(User admin) {
        String invitedBy = null;

        // Try to find who invited this admin
        AdminInvitation invitation = adminInvitationRepository.findByEmail(admin.getEmail()).orElse(null);
        if (invitation != null && invitation.getInvitedBy() != null) {
            invitedBy = invitation.getInvitedBy().getFullName();
        }

        // Get authorities safely to avoid generic type conflicts
        List<String> authorityNames = getAdminAuthorities(admin).stream()
                .map(Authority::getName)
                .collect(Collectors.toList());

        return AdminResponse.builder()
                .id(admin.getId())
                .email(admin.getEmail())
                .firstName(admin.getFirstName())
                .lastName(admin.getLastName())
                .role(admin.getRole())
                .emailVerified(admin.getEmailVerified())
                .enabled(admin.isEnabled())
                .authorities(authorityNames)
                .createdOn(admin.getCreatedOn())
                .invitedBy(invitedBy)
                .build();
    }

    private List<Authority> getAdminAuthorities(User admin) {
        // Access the authorities field directly to avoid UserDetails generic issues
        if (admin.getAuthorities() == null) {
            return new ArrayList<>();
        }

        // Since Authority implements GrantedAuthority, we can safely cast
        List<Authority> authorities = new ArrayList<>();
        for (GrantedAuthority authority : admin.getAuthorities()) {
            if (authority instanceof Authority) {
                authorities.add((Authority) authority);
            }
        }
        return authorities;
    }

    private String generateTempPassword() {
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%";
        StringBuilder password = new StringBuilder();

        for (int i = 0; i < 12; i++) {
            password.append(chars.charAt(secureRandom.nextInt(chars.length())));
        }

        return password.toString();
    }
}