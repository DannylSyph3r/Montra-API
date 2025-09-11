package dev.slethware.montra.token;

import dev.slethware.montra.token.model.Token;
import dev.slethware.montra.token.model.TokenType;
import dev.slethware.montra.user.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface TokenRepository extends JpaRepository<Token, Long> {

    Optional<Token> findByToken(String token);

    List<Token> findByUser(User user);

    List<Token> findByUserAndTokenType(User user, TokenType tokenType);

    @Query("SELECT t FROM Token t WHERE t.user = :user AND t.tokenType = :tokenType AND t.used = false AND t.expiryDate > :now")
    List<Token> findValidTokensByUserAndType(@Param("user") User user, @Param("tokenType") TokenType tokenType, @Param("now") LocalDateTime now);

    @Modifying
    @Query("UPDATE Token t SET t.used = true WHERE t.user = :user AND t.tokenType = :tokenType")
    void markAllTokensAsUsed(@Param("user") User user, @Param("tokenType") TokenType tokenType);

    @Modifying
    @Query("DELETE FROM Token t WHERE t.expiryDate < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);
}