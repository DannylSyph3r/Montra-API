package dev.slethware.montra.token;

import dev.slethware.montra.token.model.Token;
import dev.slethware.montra.token.model.TokenType;
import dev.slethware.montra.user.model.User;

import java.util.List;

public interface TokenService {

    // Generate verification/reset tokens
    String generateToken(User user, TokenType tokenType, long validityInSeconds);

    String generateOTP(User user, TokenType tokenType, long validityInSeconds, int otpLength);

    // Generate refresh tokens with device info
    Token generateRefreshToken(User user, String tokenValue, long validityInSeconds, String deviceInfo, String ipAddress);

    // Validation methods
    void validateToken(String token, User user, TokenType tokenType);

    Token validateAndGetRefreshToken(String tokenValue);

    // Token management
    void invalidateAllUserTokens(User user, TokenType tokenType);

    void revokeAllUserRefreshTokens(User user);

    List<Token> getActiveRefreshTokens(User user);

    void cleanupExpiredTokens();
}