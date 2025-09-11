package dev.slethware.montra.controller;

import dev.slethware.montra.auth.AuthenticationService;
import dev.slethware.montra.auth.dto.*;
import dev.slethware.montra.shared.response.ApiResponse;
import dev.slethware.montra.shared.util.ApiResponseUtil;
import dev.slethware.montra.user.UserService;
import dev.slethware.montra.user.dto.*;
import dev.slethware.montra.user.model.User;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationService authenticationService;
    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<Void>> register(@Valid @RequestBody UserRegistrationRequest request) {
        ApiResponse<Void> response = authenticationService.registerUser(request);
        return ResponseEntity.status(201).body(response);
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthenticationResponse>> login(@Valid @RequestBody LoginRequest request) {
        if (!request.hasValidCredentials()) {
            return ResponseEntity.badRequest().body(
                    ApiResponseUtil.badRequest("Either password or PIN must be provided")
            );
        }

        ApiResponse<AuthenticationResponse> response = authenticationService.login(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthenticationResponse>> refreshToken(@Valid @RequestBody TokenRefreshRequest request) {
        ApiResponse<AuthenticationResponse> response = authenticationService.refreshToken(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify-email")
    public ResponseEntity<ApiResponse<Void>> verifyEmail(@Valid @RequestBody EmailVerificationRequest request) {
        ApiResponse<Void> response = authenticationService.verifyEmail(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/resend-verification")
    public ResponseEntity<ApiResponse<Void>> resendEmailVerification(@RequestParam String email) {
        ApiResponse<Void> response = authenticationService.resendEmailVerification(email);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/setup-pin")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<Void>> setupPin(
            @AuthenticationPrincipal User user,
            @Valid @RequestBody SetupPinRequest request) {

        if (!request.isPinMatching()) {
            return ResponseEntity.badRequest().body(
                    ApiResponseUtil.badRequest("PIN and confirmation do not match")
            );
        }

        userService.setupUserPin(user, request.getPin());
        return ResponseEntity.ok(ApiResponseUtil.successful("PIN setup successfully", null));
    }

    @PostMapping("/complete-setup")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<Void>> completeAccountSetup(
            @AuthenticationPrincipal User user,
            @Valid @RequestBody CompleteAccountSetupRequest request) {

        userService.completeUserAccountSetup(user, request);
        return ResponseEntity.ok(ApiResponseUtil.successful("Account setup completed successfully", null));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(@Valid @RequestBody TokenRefreshRequest request) {
        ApiResponse<Void> response = authenticationService.logout(request.getRefreshToken());
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout-all")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN', 'SUPER_ADMIN')")
    public ResponseEntity<ApiResponse<Void>> logoutAllDevices(@AuthenticationPrincipal User user) {
        ApiResponse<Void> response = authenticationService.logoutAllDevices(user.getEmail());
        return ResponseEntity.ok(response);
    }
}