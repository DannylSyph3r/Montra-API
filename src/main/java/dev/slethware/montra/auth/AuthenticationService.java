package dev.slethware.montra.auth;

import dev.slethware.montra.auth.dto.*;
import dev.slethware.montra.shared.response.ApiResponse;
import dev.slethware.montra.user.dto.UserRegistrationRequest;

public interface AuthenticationService {

    ApiResponse<Void> registerUser(UserRegistrationRequest request);

    ApiResponse<AuthenticationResponse> loginWithPassword(LoginRequest request);

    ApiResponse<AuthenticationResponse> refreshToken(dev.slethware.montra.authentication.dto.TokenRefreshRequest request);

    ApiResponse<Void> verifyEmail(EmailVerificationRequest request);

    ApiResponse<Void> resendEmailVerification(String email);

    ApiResponse<Void> logout(String refreshToken);

    ApiResponse<Void> logoutAllDevices(String email);
}
