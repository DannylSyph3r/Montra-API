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
        log.info("Starting user registration for email: {}", request.getEmail());

        // Create user
        User user = userService.createUser(request);

        // Generate email verification token (Valid for 24 hrs)
        String verificationToken = tokenService.generateToken(user, TokenType.EMAIL_VERIFICATION, 24 * 60 * 60);

        emailService.sendEmailVerification(user.getEmail(), verificationToken);

        log.info("User registration completed successfully for email: {}", user.getEmail());
        return ApiResponseUtil.successfulCreate("User registered successfully. Please check your email for verification.", null);
    }

    @Override
    public ApiResponseWrapper<AuthenticationResponse> login(LoginRequest request) {
        log.info("Starting login attempt for user: {} with method: {}",
                request.getEmail(),
                request.isPasswordLogin() ? "PASSWORD" : "PIN");

        if (!request.hasValidCredentials()) {
            throw new BadRequestException("Either password or PIN must be provided");
        }

        if (!userService.doesUserExist(request.getEmail())) {
            throw new UnauthorizedAccessException("Invalid credentials");
        }

        User user = userService.getUserByEmail(request.getEmail());

        if (!user.getEmailVerified()) {
            throw new BadRequestException("Email not verified. Please verify your email before logging in.");
        }

        if (!user.getEnabled()) {
            throw new UnauthorizedAccessException("Account is disabled");
        }

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
        log.info("Login completed successfully for user: {}", user.getEmail());
        return response;
    }

    @Override
    @Transactional(readOnly = true)
    public ApiResponseWrapper<AuthenticationResponse> refreshToken(TokenRefreshRequest request) {
        log.info("Starting token refresh");

        Token refreshToken = tokenService.validateAndGetRefreshToken(request.getRefreshToken());
        User user = refreshToken.getUser();

        if (!user.getEnabled()) {
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
                .requiresPinSetup(false)
                .requiresAccountSetup(false)
                .build();

        log.info("Token refresh completed successfully for user: {}", user.getEmail());
        return ApiResponseUtil.successful("Token refreshed successfully", response);
    }

    @Override
    public ApiResponseWrapper<Void> verifyEmail(EmailVerificationRequest request) {
        log.info("Starting email verification for user: {}", request.getEmail());

        User user = userService.getUserByEmail(request.getEmail());

        if (user.getEmailVerified()) {
            throw new BadRequestException("Email already verified");
        }

        // Validate the verification token
        tokenService.validateToken(request.getToken(), user, TokenType.EMAIL_VERIFICATION);

        // Verify the email
        userService.verifyUserEmail(request.getEmail());

        // Send welcome email
        emailService.sendWelcomeEmail(user.getEmail(), user.getFirstName());

        log.info("Email verification completed successfully for user: {}", request.getEmail());
        return ApiResponseUtil.successful("Email verified successfully", null);
    }

    @Override
    public ApiResponseWrapper<Void> resendEmailVerification(String email) {
        log.info("Starting email verification resend for user: {}", email);

        User user = userService.getUserByEmail(email);

        if (user.getEmailVerified()) {
            throw new BadRequestException("Email already verified");
        }

        // Generate new verification token
        String verificationToken = tokenService.generateToken(user, TokenType.EMAIL_VERIFICATION, 24 * 60 * 60);

        // Send verification email
        emailService.sendEmailVerification(email, verificationToken);

        log.info("Email verification resent successfully for user: {}", email);
        return ApiResponseUtil.successful("Verification email sent successfully", null);
    }

    @Override
    public ApiResponseWrapper<Void> logout(String refreshToken) {
        log.info("Starting logout");

        Token token = tokenService.validateAndGetRefreshToken(refreshToken);

        // Revoke the refresh token
        token.revoke();

        log.info("Logout completed successfully");
        return ApiResponseUtil.successful("Logged out successfully", null);
    }

    @Override
    public ApiResponseWrapper<Void> logoutAllDevices(String email) {
        log.info("Starting logout all devices for user: {}", email);

        User user = userService.getUserByEmail(email);

        // Revoke all refresh tokens for the user
        tokenService.revokeAllUserRefreshTokens(user);

        log.info("Logout all devices completed successfully for user: {}", email);
        return ApiResponseUtil.successful("Logged out from all devices successfully", null);
    }


    // HELPERS
    private boolean authenticateWithPassword(User user, String password) {
        boolean matches = passwordEncoder.matches(password, user.getPassword());

        if (!matches) {
            log.warn("Password authentication failed for user: {}", user.getEmail());
        }

        return matches;
    }

    private boolean authenticateWithPin(User user, String pin) {
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
    }

    private ApiResponseWrapper<AuthenticationResponse> generateAuthenticationResponse(User user) {
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

        boolean emailVerified = user.getEmailVerified();
        boolean accountSetupComplete = user.getAccountSetupComplete();
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
    }
}