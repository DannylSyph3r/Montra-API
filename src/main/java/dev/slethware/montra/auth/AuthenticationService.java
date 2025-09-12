package dev.slethware.montra.auth;

import dev.slethware.montra.auth.dto.*;
import dev.slethware.montra.shared.ApiResponseWrapper;
import dev.slethware.montra.user.dto.UserRegistrationRequest;

public interface AuthenticationService {

    // Registration
    ApiResponseWrapper<Void> registerUser(UserRegistrationRequest request);

    // Unified login endpoint - handles both password and PIN
    ApiResponseWrapper<AuthenticationResponse> login(LoginRequest request);

    // Token management
    ApiResponseWrapper<AuthenticationResponse> refreshToken(TokenRefreshRequest request);

    // Email verification
    ApiResponseWrapper<Void> verifyEmail(EmailVerificationRequest request);

    ApiResponseWrapper<Void> resendEmailVerification(String email);

    // Logout
    ApiResponseWrapper<Void> logout(String refreshToken);

    ApiResponseWrapper<Void> logoutAllDevices(String email);
}