package dev.slethware.montra.auth;

import dev.slethware.montra.auth.dto.*;
import dev.slethware.montra.email.EmailService;
import dev.slethware.montra.jwt.JwtService;
import dev.slethware.montra.shared.exception.BadRequestException;
import dev.slethware.montra.shared.exception.UnauthorizedAccessException;
import dev.slethware.montra.shared.response.ApiResponse;
import dev.slethware.montra.shared.util.ApiResponseUtil;
import dev.slethware.montra.token.TokenService;
import dev.slethware.montra.token.model.TokenType;
import dev.slethware.montra.user.UserService;
import dev.slethware.montra.user.dto.UserRegistrationRequest;
import dev.slethware.montra.user.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.UUID;

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
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    public ApiResponse<Void> registerUser(UserRegistrationRequest request) {
        log.info("Registering user with email: {}", request.getEmail());

        User user = userService.createUser(request);

        // Generate email verification token
        String verificationToken = tokenService.generateToken(user, TokenType.EMAIL_VERIFICATION, 24 * 60 * 60); // 24 hours

        // Send verification email
        emailService.sendEmailVerification(user.getEmail(), verificationToken);

        log.info("User registered successfully: {}", user.getEmail());
        return ApiResponseUtil.successfulCreate("User registered successfully. Please check your email for verification.", null);
    }

    @Override
    public ApiResponse<AuthenticationResponse> loginWithPassword(LoginRequest request) {
        log.info("Attempting password login for user: {}", request.getEmail());

        if (!userService.doesUserExist(request.getEmail())) {
            throw new UnauthorizedAccessException("Invalid credentials");
        }

        User user = userService.getUserByEmail(request.getEmail());

        if (!user.isEmailVerified()) {
            throw new BadRequestException("Email not verified. Please verify your email before logging in.");
        }

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new UnauthorizedAccessException("Invalid credentials");
        }

        return generateAuthenticationResponse(user);
    }

    @Override
    public ApiResponse<AuthenticationResponse> loginWithPin(PinLoginRequest request) {
        log.info("Attempting PIN login for user: {}", request.getEmail());

        User user = userService.getUserByEmail(request.getEmail());

        if (!user.isEmailVerified()) {
            throw new BadRequestException("Email not verified");
        }

        if (!user.isPinSet()) {
            throw new BadRequestException("PIN not set. Please log in with password first.");
        }

        boolean pinValid = userService.validateUserPin(request.getEmail(), request.getPin());
        if (!pinValid) {
            throw new UnauthorizedAccessException("Invalid PIN");
        }

        return generateAuthenticationResponse(user);
    }

    @Override
    @Transactional(readOnly = true)
    public ApiResponse<AuthenticationResponse> refreshToken(TokenRefreshRequest request) {
        log.info("Attempting to refresh token");

        RefreshToken refreshToken = refreshTokenRepository.findByToken(request.getRefreshToken())
                .orElseThrow(() -> new UnauthorizedAccessException("Invalid refresh token"));

        if (!refreshToken.isValid()) {
            throw new UnauthorizedAccessException("Refresh token expired or revoked");
        }

        User user = refreshToken.getUser();

        // Generate new tokens
        String newAccessToken = jwtService.generateToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);

        // Revoke old refresh token
        refreshToken.revoke();
        refreshTokenRepository.save(refreshToken);

        // Create new refresh token
        RefreshToken newRefreshTokenEntity = createRefreshToken(user, newRefreshToken);

        AuthenticationResponse response = AuthenticationResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(newRefreshTokenEntity.getToken())
                .accessTokenExpiry(jwtService.getExpirationDate(newAccessToken))
                .refreshTokenExpiry(jwtService.getRefreshTokenExpirationDate(newRefreshToken))
                .userDetails(userService.getUserDetails(user))
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

        RefreshToken token = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new UnauthorizedAccessException("Invalid refresh token"));

        token.revoke();
        refreshTokenRepository.save(token);

        return ApiResponseUtil.successful("Logged out successfully", null);
    }

    @Override
    public ApiResponse<Void> logoutAllDevices(String email) {
        log.info("Logging out all devices for user: {}", email);

        User user = userService.getUserByEmail(email);
        refreshTokenRepository.revokeAllUserTokens(user);

        return ApiResponseUtil.successful("Logged out from all devices successfully", null);
    }

    private ApiResponse<AuthenticationResponse> generateAuthenticationResponse(User user) {
        String accessToken = jwtService.generateToken(user);
        String refreshToken = jwtService.generateRefreshToken(user);

        RefreshToken refreshTokenEntity = createRefreshToken(user, refreshToken);

        AuthenticationResponse response = AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshTokenEntity.getToken())
                .accessTokenExpiry(jwtService.getExpirationDate(accessToken))
                .refreshTokenExpiry(jwtService.getRefreshTokenExpirationDate(refreshToken))
                .userDetails(userService.getUserDetails(user))
                .requiresPinSetup(!user.isPinSet() && user.isEmailVerified())
                .requiresAccountSetup(!user.isAccountSetupComplete() && user.isEmailVerified())
                .build();

        log.info("Authentication successful for user: {}", user.getEmail());
        return ApiResponseUtil.successful("Login successful", response);
    }

    private RefreshToken createRefreshToken(User user, String token) {
        RefreshToken refreshToken = RefreshToken.builder()
                .token(token)
                .user(user)
                .expiryDate(LocalDateTime.now().plusDays(30)) // 30 days
                .build();

        return refreshTokenRepository.save(refreshToken);
    }
}