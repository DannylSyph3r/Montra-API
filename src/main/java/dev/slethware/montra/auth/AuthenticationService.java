package dev.slethware.montra.auth;

import dev.slethware.montra.auth.dto.*;
import dev.slethware.montra.shared.ApiResponseWrapper;
import dev.slethware.montra.user.dto.UserRegistrationRequest;

public interface AuthenticationService {

    ApiResponseWrapper<Void> registerUser(UserRegistrationRequest request);

    ApiResponseWrapper<AuthenticationResponse> login(LoginRequest request);

    ApiResponseWrapper<AuthenticationResponse> refreshToken(TokenRefreshRequest request);

    ApiResponseWrapper<Void> verifyEmail(EmailVerificationRequest request);

    ApiResponseWrapper<Void> resendEmailVerification(String email);

    ApiResponseWrapper<Void> logout(String refreshToken);

    ApiResponseWrapper<Void> logoutAllDevices(String email);
}