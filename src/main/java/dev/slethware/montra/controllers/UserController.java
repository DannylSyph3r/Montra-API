package dev.slethware.montra.controllers;

import dev.slethware.montra.shared.ApiResponseWrapper;
import dev.slethware.montra.shared.util.ApiResponseUtil;
import dev.slethware.montra.user.UserService;
import dev.slethware.montra.user.dto.UpdateUserProfileRequest;
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
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<ApiResponseWrapper<UserResponse>> updateProfile(
            @AuthenticationPrincipal User user,
            @Valid @RequestBody UpdateUserProfileRequest request) {

        User updatedUser = userService.updateUserProfile(user, request);
        UserResponse response = userService.getUserResponse(updatedUser);

        return ResponseEntity.ok(ApiResponseUtil.successful("Profile updated successfully", response));
    }

    @GetMapping("/users")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<ApiResponseWrapper<Page<UserResponse>>> getUsers(
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "10") int size) {

        Page<User> users = userService.getActiveUsersByRole(UserRole.USER, page, size);
        Page<UserResponse> userResponses = users.map(userService::getPublicUserResponse);

        return ResponseEntity.ok(ApiResponseUtil.successful("Users retrieved successfully", userResponses));
    }

    @GetMapping("/{id}")
    @PreAuthorize("hasAnyRole('ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<ApiResponseWrapper<UserResponse>> getUserById(@PathVariable Long id) {
        User user = userService.getUserById(id);
        UserResponse response = userService.getPublicUserResponse(user);

        return ResponseEntity.ok(ApiResponseUtil.successful("User retrieved successfully", response));
    }

    @GetMapping("/public/{id}")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<ApiResponseWrapper<UserResponse>> getPublicUserProfile(@PathVariable Long id) {
        User user = userService.getUserById(id);
        UserResponse response = userService.getPublicUserResponse(user);

        return ResponseEntity.ok(ApiResponseUtil.successful("Public profile retrieved successfully", response));
    }

    @GetMapping("/search")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<ApiResponseWrapper<UserResponse>> findUserByUsername(@RequestParam String username) {
        User user = userService.getUserByUsername(username);
        UserResponse response = userService.getPublicUserResponse(user);
        return ResponseEntity.ok(ApiResponseUtil.successful("User found successfully", response));
    }

    @GetMapping("/username-available")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<ApiResponseWrapper<Boolean>> checkUsernameAvailability(
            @RequestParam String username,
            @AuthenticationPrincipal User currentUser) {

        boolean available = userService.isUsernameAvailable(username, currentUser.getId());
        return ResponseEntity.ok(ApiResponseUtil.successful("Username availability checked", available));
    }
}