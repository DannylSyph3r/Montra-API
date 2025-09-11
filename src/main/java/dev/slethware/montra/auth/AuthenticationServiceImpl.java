package dev.slethware.montra.auth;

import dev.slethware.montra.auth.dto.*;
import dev.slethware.montra.email.EmailService;
import dev.slethware.montra.jwt.JwtService;
import dev.slethware.montra.shared.exception.BadRequestException;
import dev.slethware.montra.shared.exception.UnauthorizedAccessException;
import dev.slethware.montra.shared.response.ApiResponse;
import dev.slethware.montra.shared.util.ApiResponseUtil;
import dev.slethware.montra.token.TokenService;
import dev.slethware.montra.token.model.Token;
import dev.slethware.montra.token.model.TokenType;
import dev.slethware.montra.user.UserService;
import dev.slethware.montra.user.dto.UserRegistrationRequest;
import dev.slethware.montra.user.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserService userService;
    private final JwtService jwtService;
    private final TokenService tokenService;
    private final EmailService emailService;
    private final PasswordEncoder passwordEncoder;

    @Override
    public ApiResponse<Void> registerUser(UserRegistrationRequest request) {
        log.info("Registering user with email: {}", request.getEmail());

        User user = userService.createUser(request);

        // Generate email verification token (24 hours)
        String verificationToken = tokenService.generateToken(user, TokenType.EMAIL_VERIFICATION, 24 * 60 * 60);

        // Send verification email
        emailService.sendEmailVerification(user.getEmail(), verificationToken);

        log.info("User registered successfully: {}", user.getEmail());
        return ApiResponseUtil.successfulCreate("User registered successfully. Please check your email for verification.", null);
    }

    @Override
    public ApiResponse<AuthenticationResponse> login(LoginRequest request) {
        log.info("Attempting login for user: {} with method: {}",
                request.getEmail(),
                request.isPasswordLogin() ? "PASSWORD" : "PIN");

        // Validate that either password or PIN is provided
        if (!request.hasValidCredentials()) {
            throw new BadRequestException("Either password or PIN must be provided");
        }

        // Check if user exists
        if (!userService.doesUserExist(request.getEmail())) {
            throw new UnauthorizedAccessException("Invalid credentials");
        }

        User user = userService.getUserByEmail(request.getEmail());

        // Check if email is verified
        if (!user.isEmailVerified()) {
            throw new BadRequestException("Email not verified. Please verify your email before logging in.");
        }

        // Authenticate based on method
        boolean authSuccess = false;

        if (request.isPasswordLogin()) {
            authSuccess = authenticateWithPassword(user, request.getPassword());
        } else if (request.isPinLogin()) {
            authSuccess = authenticateWithPin(user, request.getPin());
        }

        if (!authSuccess) {
            throw new UnauthorizedAccessException("Invalid credentials");
        }

        return generateAuthenticationResponse(user);
    }

    @Override
    @Transactional(readOnly = true)
    public ApiResponse<AuthenticationResponse> refreshToken(TokenRefreshRequest request) {
        log.info("Attempting to refresh token");

        Token refreshToken = tokenService.validateAndGetRefreshToken(request.getRefreshToken());
        User user = refreshToken.getUser();

        // Generate new tokens
        String newAccessToken = jwtService.generateToken(user);
        String newRefreshTokenValue = jwtService.generateRefreshToken(user);

        // Revoke old refresh token
        refreshToken.revoke();

        // Create new refresh token
        Token newRefreshToken = tokenService.generateRefreshToken(
                user,
                newRefreshTokenValue,
                30 * 24 * 60 * 60, // 30 days
                refreshToken.getDeviceInfo(),
                refreshToken.getIpAddress()
        );

        AuthenticationResponse response = AuthenticationResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshToken.getToken())
                .accessTokenExpiry(jwtService.getExpirationDate(newAccessToken))
                .refreshTokenExpiry(jwtService.getRefreshTokenExpirationDate(newRefreshTokenValue))
                .userDetails(userService.getUserDetails(user))
                .requiresPinSetup(false) // No setup required for refresh
                .requiresAccountSetup(false)
                .build();

        return ApiResponseUtil.successful("Token refreshed successfully", response);
    }

    @Override
    public ApiResponse<Void> verifyEmail(EmailVerificationRequest request) {
        log.info("Verifying email for user: {}", request.getEmail());

        User user = userService.getUserByEmail(request.getEmail());

        if (user.isEmailVerified()) {
            throw new BadRequestException("Email already verified");
        }

        tokenService.validateToken(request.getToken(), user, TokenType.EMAIL_VERIFICATION);

        userService.verifyUserEmail(request.getEmail());

        // Send welcome email
        emailService.sendWelcomeEmail(user.getEmail(), user.getFirstName());

        log.info("Email verified successfully for user: {}", request.getEmail());
        return ApiResponseUtil.successful("Email verified successfully", null);
    }

    @Override
    public ApiResponse<Void> resendEmailVerification(String email) {
        log.info("Resending email verification for user: {}", email);

        User user = userService.getUserByEmail(email);

        if (user.isEmailVerified()) {
            throw new BadRequestException("Email already verified");
        }

        String verificationToken = tokenService.generateToken(user, TokenType.EMAIL_VERIFICATION, 24 * 60 * 60);
        emailService.sendEmailVerification(email, verificationToken);

        return ApiResponseUtil.successful("Verification email sent successfully", null);
    }

    @Override
    public ApiResponse<Void> logout(String refreshToken) {
        log.info("Logging out user");

        Token token = tokenService.validateAndGetRefreshToken(refreshToken);
        token.revoke();

        return ApiResponseUtil.successful("Logged out successfully", null);
    }

    @Override
    public ApiResponse<Void> logoutAllDevices(String email) {
        log.info("Logging out all devices for user: {}", email);

        User user = userService.getUserByEmail(email);
        tokenService.revokeAllUserRefreshTokens(user);

        return ApiResponseUtil.successful("Logged out from all devices successfully", null);
    }

    // Private helper methods

    private boolean authenticateWithPassword(User user, String password) {
        return passwordEncoder.matches(password, user.getPassword());
    }

    private boolean authenticateWithPin(User user, String pin) {
        if (!user.isPinSet()) {
            throw new BadRequestException("PIN not set. Please log in with password to set up PIN.");
        }

        if (!user.canAttemptPin()) {
            throw new BadRequestException("PIN attempts exceeded. Please try again later or use password login.");
        }

        return userService.validateUserPin(user.getEmail(), pin);
    }

    private ApiResponse<AuthenticationResponse> generateAuthenticationResponse(User user) {
        String accessToken = jwtService.generateToken(user);
        String refreshTokenValue = jwtService.generateRefreshToken(user);

        // Create refresh token entity with device info (would be passed from request in real implementation)
        Token refreshToken = tokenService.generateRefreshToken(
                user,
                refreshTokenValue,
                30 * 24 * 60 * 60, // 30 days
                "Unknown Device", // TODO: Extract from request headers
                "Unknown IP"      // TODO: Extract from request
        );

        AuthenticationResponse response = AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken.getToken())
                .accessTokenExpiry(jwtService.getExpirationDate(accessToken))
                .refreshTokenExpiry(jwtService.getRefreshTokenExpirationDate(refreshTokenValue))
                .userDetails(userService.getUserDetails(user))
                .requiresPinSetup(!user.isPinSet() && user.isEmailVerified())
                .requiresAccountSetup(!user.isAccountSetupComplete() && user.isEmailVerified())
                .build();

        log.info("Authentication successful for user: {}", user.getEmail());
        return ApiResponseUtil.successful("Login successful", response);
    }
}