package dev.slethware.montra.auth;

import dev.slethware.montra.auth.dto.*;
import dev.slethware.montra.shared.response.ApiResponse;
import dev.slethware.montra.user.dto.UserRegistrationRequest;

public interface AuthenticationService {

    // Registration
    ApiResponse<Void> registerUser(UserRegistrationRequest request);

    // Unified login endpoint - handles both password and PIN
    ApiResponse<AuthenticationResponse> login(LoginRequest request);

    // Token management
    ApiResponse<AuthenticationResponse> refreshToken(TokenRefreshRequest request);

    // Email verification
    ApiResponse<Void> verifyEmail(EmailVerificationRequest request);

    ApiResponse<Void> resendEmailVerification(String email);

    // Logout
    ApiResponse<Void> logout(String refreshToken);

    ApiResponse<Void> logoutAllDevices(String email);
}