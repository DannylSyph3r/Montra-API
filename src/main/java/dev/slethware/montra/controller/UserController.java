package dev.slethware.montra.controller;

import dev.slethware.montra.shared.ApiResponseWrapper;
import dev.slethware.montra.shared.util.ApiResponseUtil;
import dev.slethware.montra.user.UserService;
import dev.slethware.montra.user.dto.UserProfileUpdateRequest;
import dev.slethware.montra.user.dto.UserResponse;
import dev.slethware.montra.user.model.User;
import dev.slethware.montra.user.model.UserRole;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/user")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/profile")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<ApiResponseWrapper<UserResponse>> getProfile(@AuthenticationPrincipal User user) {
        UserResponse userResponse = userService.getUserResponse(user);
        return ResponseEntity.ok(ApiResponseUtil.successful("Profile retrieved successfully", userResponse));
    }

    @PutMapping("/profile")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<ApiResponseWrapper<UserResponse>> updateProfile(
            @AuthenticationPrincipal User user,
            @Valid @RequestBody UserProfileUpdateRequest request) {

        request.setEmail(user.getEmail()); // Ensure user can only update their own profile
        User updatedUser = userService.updateUserProfile(request);
        UserResponse response = userService.getUserResponse(updatedUser);

        return ResponseEntity.ok(ApiResponseUtil.successful("Profile updated successfully", response));
    }

    @GetMapping("/users")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<ApiResponseWrapper<Page<UserResponse>>> getUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Page<User> users = userService.getActiveUsersByRole(UserRole.USER, page, size);
        Page<UserResponse> userResponses = users.map(userService::getUserResponse);

        return ResponseEntity.ok(ApiResponseUtil.successful("Users retrieved successfully", userResponses));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<ApiResponseWrapper<UserResponse>> getUserById(@PathVariable Long id) {
        User user = userService.getUserById(id);
        UserResponse response = userService.getUserResponse(user);

        return ResponseEntity.ok(ApiResponseUtil.successful("User retrieved successfully", response));
    }
}