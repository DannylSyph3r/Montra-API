package dev.slethware.montra.auth;

import dev.slethware.montra.auth.dto.*;
import dev.slethware.montra.email.EmailService;
import dev.slethware.montra.jwt.JwtService;
import dev.slethware.montra.shared.exception.BadRequestException;
import dev.slethware.montra.shared.exception.UnauthorizedAccessException;
import dev.slethware.montra.shared.ApiResponseWrapper;
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
    public ApiResponseWrapper<Void> registerUser(UserRegistrationRequest request) {
        log.info("Registering user with email: {}", request.getEmail());

        try {
            // Create user (username will be automatically set to email in UserService)
            User user = userService.createUser(request);

            // Generate email verification token (24 hours)
            String verificationToken = tokenService.generateToken(user, TokenType.EMAIL_VERIFICATION, 24 * 60 * 60);

            // Send verification email
            emailService.sendEmailVerification(user.getEmail(), verificationToken);

            log.info("User registered successfully: {}", user.getEmail());
            return ApiResponseUtil.successfulCreate("User registered successfully. Please check your email for verification.", null);

        } catch (Exception e) {
            log.error("Registration failed for email: {} - Error: {}", request.getEmail(), e.getMessage(), e);
            throw e;
        }
    }

    @Override
    public ApiResponseWrapper<AuthenticationResponse> login(LoginRequest request) {
        log.info("Attempting login for user: {} with method: {}",
                request.getEmail(),
                request.isPasswordLogin() ? "PASSWORD" : "PIN");

        try {
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
            if (user.getEmailVerified() == null || !user.getEmailVerified()) {
                throw new BadRequestException("Email not verified. Please verify your email before logging in.");
            }

            // Check if user is enabled
            if (user.getEnabled() == null || !user.getEnabled()) {
                throw new UnauthorizedAccessException("Account is disabled");
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

            ApiResponseWrapper<AuthenticationResponse> response = generateAuthenticationResponse(user);
            log.info("Login successful for user: {}", user.getEmail());
            return response;

        } catch (Exception e) {
            log.error("Login failed for user: {} - Error: {}", request.getEmail(), e.getMessage());
            throw e;
        }
    }

    @Override
    @Transactional(readOnly = true)
    public ApiResponseWrapper<AuthenticationResponse> refreshToken(TokenRefreshRequest request) {
        log.info("Attempting to refresh token");

        try {
            Token refreshToken = tokenService.validateAndGetRefreshToken(request.getRefreshToken());
            User user = refreshToken.getUser();

            // Check if user is still enabled
            if (user.getEnabled() == null || !user.getEnabled()) {
                throw new UnauthorizedAccessException("Account is disabled");
            }

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

            log.info("Token refreshed successfully for user: {}", user.getEmail());
            return ApiResponseUtil.successful("Token refreshed successfully", response);

        } catch (Exception e) {
            log.error("Token refresh failed - Error: {}", e.getMessage());
            throw e;
        }
    }

    @Override
    public ApiResponseWrapper<Void> verifyEmail(EmailVerificationRequest request) {
        log.info("Verifying email for user: {}", request.getEmail());

        try {
            User user = userService.getUserByEmail(request.getEmail());

            if (user.getEmailVerified() != null && user.getEmailVerified()) {
                throw new BadRequestException("Email already verified");
            }

            // Validate the verification token
            tokenService.validateToken(request.getToken(), user, TokenType.EMAIL_VERIFICATION);

            // Verify the email
            userService.verifyUserEmail(request.getEmail());

            // Send welcome email
            emailService.sendWelcomeEmail(user.getEmail(), user.getFirstName());

            log.info("Email verified successfully for user: {}", request.getEmail());
            return ApiResponseUtil.successful("Email verified successfully", null);

        } catch (Exception e) {
            log.error("Email verification failed for user: {} - Error: {}", request.getEmail(), e.getMessage());
            throw e;
        }
    }

    @Override
    public ApiResponseWrapper<Void> resendEmailVerification(String email) {
        log.info("Resending email verification for user: {}", email);

        try {
            User user = userService.getUserByEmail(email);

            if (user.getEmailVerified() != null && user.getEmailVerified()) {
                throw new BadRequestException("Email already verified");
            }

            // Generate new verification token
            String verificationToken = tokenService.generateToken(user, TokenType.EMAIL_VERIFICATION, 24 * 60 * 60);

            // Send verification email
            emailService.sendEmailVerification(email, verificationToken);

            log.info("Email verification resent successfully for user: {}", email);
            return ApiResponseUtil.successful("Verification email sent successfully", null);

        } catch (Exception e) {
            log.error("Failed to resend email verification for user: {} - Error: {}", email, e.getMessage());
            throw e;
        }
    }

    @Override
    public ApiResponseWrapper<Void> logout(String refreshToken) {
        log.info("Processing logout request");

        try {
            Token token = tokenService.validateAndGetRefreshToken(refreshToken);

            // Revoke the refresh token
            token.revoke();

            log.info("User logged out successfully");
            return ApiResponseUtil.successful("Logged out successfully", null);

        } catch (Exception e) {
            log.error("Logout failed - Error: {}", e.getMessage());
            throw e;
        }
    }

    @Override
    public ApiResponseWrapper<Void> logoutAllDevices(String email) {
        log.info("Logging out all devices for user: {}", email);

        try {
            User user = userService.getUserByEmail(email);

            // Revoke all refresh tokens for the user
            tokenService.revokeAllUserRefreshTokens(user);

            log.info("All devices logged out successfully for user: {}", email);
            return ApiResponseUtil.successful("Logged out from all devices successfully", null);

        } catch (Exception e) {
            log.error("Failed to logout all devices for user: {} - Error: {}", email, e.getMessage());
            throw e;
        }
    }

    // HELPER METHODS
    private boolean authenticateWithPassword(User user, String password) {
        try {
            boolean matches = passwordEncoder.matches(password, user.getPassword());

            if (!matches) {
                log.warn("Password authentication failed for user: {}", user.getEmail());
            }

            return matches;
        } catch (Exception e) {
            log.error("Error during password authentication for user: {} - Error: {}", user.getEmail(), e.getMessage());
            return false;
        }
    }

    private boolean authenticateWithPin(User user, String pin) {
        try {
            if (!user.isPinSet()) {
                throw new BadRequestException("PIN not set. Please log in with password to set up PIN.");
            }

            if (!user.canAttemptPin()) {
                throw new BadRequestException("PIN attempts exceeded. Please try again later or use password login.");
            }

            boolean isValid = userService.validateUserPin(user.getEmail(), pin);

            if (!isValid) {
                log.warn("PIN authentication failed for user: {}", user.getEmail());
            }

            return isValid;
        } catch (BadRequestException e) {
            // Re-throw business rule exceptions
            throw e;
        } catch (Exception e) {
            log.error("Error during PIN authentication for user: {} - Error: {}", user.getEmail(), e.getMessage());
            return false;
        }
    }

    private ApiResponseWrapper<AuthenticationResponse> generateAuthenticationResponse(User user) {
        try {
            String accessToken = jwtService.generateToken(user);
            String refreshTokenValue = jwtService.generateRefreshToken(user);

            // Create refresh token entity with device info
            // TODO: Extract actual device info and IP from request headers
            Token refreshToken = tokenService.generateRefreshToken(
                    user,
                    refreshTokenValue,
                    30 * 24 * 60 * 60, // 30 days
                    "Unknown Device",
                    "Unknown IP"
            );

            // Safe boolean checks for nullable fields
            boolean emailVerified = user.getEmailVerified() != null && user.getEmailVerified();
            boolean accountSetupComplete = user.getAccountSetupComplete() != null && user.getAccountSetupComplete();
            boolean pinSet = user.isPinSet();

            // Determine what setup steps are needed
            boolean requiresPinSetup = emailVerified && !pinSet;
            boolean requiresAccountSetup = emailVerified && !accountSetupComplete;

            AuthenticationResponse response = AuthenticationResponse.builder()
                    .accessToken(accessToken)
                    .refreshToken(refreshToken.getToken())
                    .accessTokenExpiry(jwtService.getExpirationDate(accessToken))
                    .refreshTokenExpiry(jwtService.getRefreshTokenExpirationDate(refreshTokenValue))
                    .userDetails(userService.getUserDetails(user))
                    .requiresPinSetup(requiresPinSetup)
                    .requiresAccountSetup(requiresAccountSetup)
                    .build();

            log.debug("Generated authentication response for user: {} - PIN setup required: {}, Account setup required: {}",
                    user.getEmail(), requiresPinSetup, requiresAccountSetup);

            return ApiResponseUtil.successful("Login successful", response);

        } catch (Exception e) {
            log.error("Failed to generate authentication response for user: {} - Error: {}", user.getEmail(), e.getMessage());
            throw new RuntimeException("Failed to generate authentication response", e);
        }
    }
}