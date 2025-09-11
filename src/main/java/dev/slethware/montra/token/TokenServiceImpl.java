package dev.slethware.montra.token;

import dev.slethware.montra.shared.exception.BadRequestException;
import dev.slethware.montra.shared.exception.UnauthorizedAccessException;
import dev.slethware.montra.token.model.Token;
import dev.slethware.montra.token.model.TokenType;
import dev.slethware.montra.user.model.User;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Service
@RequiredArgsConstructor
@Slf4j
@Transactional
public class TokenServiceImpl implements TokenService {

    private final TokenRepository tokenRepository;
    private final SecureRandom secureRandom = new SecureRandom();

    @Override
    public String generateToken(User user, TokenType tokenType, long validityInSeconds) {
        log.info("Generating token for user: {} with type: {}", user.getEmail(), tokenType);

        // Invalidate existing tokens of the same type (except refresh tokens)
        if (tokenType != TokenType.REFRESH_TOKEN) {
            invalidateAllUserTokens(user, tokenType);
        }

        String tokenValue = UUID.randomUUID().toString();
        LocalDateTime expiryDate = LocalDateTime.now().plusSeconds(validityInSeconds);

        Token token = new Token();
        token.setToken(tokenValue);
        token.setTokenType(tokenType);
        token.setUser(user);
        token.setExpiryDate(expiryDate);

        tokenRepository.save(token);

        log.info("Token generated successfully for user: {}", user.getEmail());
        return tokenValue;
    }

    @Override
    public String generateOTP(User user, TokenType tokenType, long validityInSeconds, int otpLength) {
        log.info("Generating OTP for user: {} with type: {}", user.getEmail(), tokenType);

        // Invalidate existing tokens of the same type
        invalidateAllUserTokens(user, tokenType);

        String otpValue = generateNumericOTP(otpLength);
        LocalDateTime expiryDate = LocalDateTime.now().plusSeconds(validityInSeconds);

        Token token = new Token();
        token.setToken(otpValue);
        token.setTokenType(tokenType);
        token.setUser(user);
        token.setExpiryDate(expiryDate);

        tokenRepository.save(token);

        log.info("OTP generated successfully for user: {}", user.getEmail());
        return otpValue;
    }

    @Override
    public Token generateRefreshToken(User user, String tokenValue, long validityInSeconds, String deviceInfo, String ipAddress) {
        log.info("Generating refresh token for user: {}", user.getEmail());

        LocalDateTime expiryDate = LocalDateTime.now().plusSeconds(validityInSeconds);

        Token refreshToken = new Token();
        refreshToken.setToken(tokenValue);
        refreshToken.setTokenType(TokenType.REFRESH_TOKEN);
        refreshToken.setUser(user);
        refreshToken.setExpiryDate(expiryDate);
        refreshToken.setDeviceInfo(deviceInfo);
        refreshToken.setIpAddress(ipAddress);

        Token savedToken = tokenRepository.save(refreshToken);

        log.info("Refresh token generated successfully for user: {}", user.getEmail());
        return savedToken;
    }

    @Override
    @Transactional(readOnly = true)
    public void validateToken(String tokenValue, User user, TokenType tokenType) {
        log.info("Validating token for user: {} with type: {}", user.getEmail(), tokenType);

        Token token = tokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> new BadRequestException("Invalid token"));

        if (!token.getUser().getId().equals(user.getId())) {
            throw new BadRequestException("Token does not belong to the specified user");
        }

        if (!token.getTokenType().equals(tokenType)) {
            throw new BadRequestException("Invalid token type");
        }

        if (!token.isValid()) {
            throw new BadRequestException("Token has expired or is no longer valid");
        }

        // Mark token as used (except for refresh tokens which are revoked differently)
        if (tokenType != TokenType.REFRESH_TOKEN) {
            token.markAsUsed();
            tokenRepository.save(token);
        }

        log.info("Token validated successfully for user: {}", user.getEmail());
    }

    @Override
    @Transactional(readOnly = true)
    public Token validateAndGetRefreshToken(String tokenValue) {
        log.info("Validating refresh token");

        Token refreshToken = tokenRepository.findByToken(tokenValue)
                .orElseThrow(() -> new UnauthorizedAccessException("Invalid refresh token"));

        if (!refreshToken.isRefreshToken()) {
            throw new UnauthorizedAccessException("Token is not a refresh token");
        }

        if (!refreshToken.isValid()) {
            throw new UnauthorizedAccessException("Refresh token expired or revoked");
        }

        log.info("Refresh token validated successfully for user: {}", refreshToken.getUser().getEmail());
        return refreshToken;
    }

    @Override
    public void invalidateAllUserTokens(User user, TokenType tokenType) {
        log.info("Invalidating all tokens for user: {} with type: {}", user.getEmail(), tokenType);

        List<Token> validTokens = tokenRepository.findValidTokensByUserAndType(
                user,
                tokenType,
                LocalDateTime.now()
        );

        validTokens.forEach(Token::markAsUsed);
        tokenRepository.saveAll(validTokens);

        log.info("Invalidated {} tokens for user: {}", validTokens.size(), user.getEmail());
    }

    @Override
    public void revokeAllUserRefreshTokens(User user) {
        log.info("Revoking all refresh tokens for user: {}", user.getEmail());

        List<Token> activeRefreshTokens = tokenRepository.findActiveRefreshTokensByUser(user, LocalDateTime.now());
        activeRefreshTokens.forEach(Token::revoke);
        tokenRepository.saveAll(activeRefreshTokens);

        log.info("Revoked {} refresh tokens for user: {}", activeRefreshTokens.size(), user.getEmail());
    }

    @Override
    @Transactional(readOnly = true)
    public List<Token> getActiveRefreshTokens(User user) {
        return tokenRepository.findActiveRefreshTokensByUser(user, LocalDateTime.now());
    }

    @Override
    public void cleanupExpiredTokens() {
        log.info("Cleaning up expired tokens");

        int deletedCount = tokenRepository.findAll().stream()
                .mapToInt(token -> {
                    if (token.isExpired()) {
                        tokenRepository.delete(token);
                        return 1;
                    }
                    return 0;
                })
                .sum();

        log.info("Cleaned up {} expired tokens", deletedCount);
    }

    private String generateNumericOTP(int length) {
        StringBuilder otp = new StringBuilder();

        for (int i = 0; i < length; i++) {
            otp.append(secureRandom.nextInt(10));
        }

        return otp.toString();
    }
}