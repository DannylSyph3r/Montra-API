package dev.slethware.montra.token;

import dev.slethware.montra.token.model.TokenType;
import dev.slethware.montra.user.model.User;

public interface TokenService {

    String generateToken(User user, TokenType tokenType, long validityInSeconds);

    String generateOTP(User user, TokenType tokenType, long validityInSeconds, int otpLength);

    String ge

    void validateToken(String token, User user, TokenType tokenType);

    void invalidateAllUserTokens(User user, TokenType tokenType);

    void cleanupExpiredTokens();
}