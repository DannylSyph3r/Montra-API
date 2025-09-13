package dev.slethware.montra.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Slf4j
@Service
public class JwtServiceImpl implements JwtService {

    @Value("${montra.jwt.secret}")
    private String jwtSigningKey;

    @Value("${montra.jwt.access-token-expiration}")
    private Long accessTokenExpirationInMillis;

    @Value("${montra.jwt.refresh-token-expiration}")
    private Long refreshTokenExpirationInMillis;

    @Override
    public String extractUserName(String token) {
        log.debug("Extracting username from token");
        return extractClaim(token, Claims::getSubject);
    }

    @Override
    public String generateToken(UserDetails userDetails) {
        log.debug("Generating access token for user: {}", userDetails.getUsername());

        Map<String, Object> claims = new HashMap<>();
        var roles = userDetails.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();
        claims.put("roles", roles);

        String token = generateToken(claims, userDetails, accessTokenExpirationInMillis);
        log.debug("Access token generated successfully for user: {}", userDetails.getUsername());
        return token;
    }

    @Override
    public String generateRefreshToken(UserDetails userDetails) {
        log.debug("Generating refresh token for user: {}", userDetails.getUsername());

        Map<String, Object> claims = new HashMap<>();
        claims.put("type", "refresh");

        String token = generateToken(claims, userDetails, refreshTokenExpirationInMillis);
        log.debug("Refresh token generated successfully for user: {}", userDetails.getUsername());
        return token;
    }

    @Override
    public boolean isTokenValid(String token, UserDetails userDetails) {
        log.debug("Validating access token for user: {}", userDetails.getUsername());

        final String userName = extractUserName(token);
        boolean isValid = (userName.equals(userDetails.getUsername())) && !isTokenExpired(token);

        log.debug("Access token validation result for user {}: {}", userDetails.getUsername(), isValid);
        return isValid;
    }

    @Override
    public boolean isRefreshTokenValid(String token, UserDetails userDetails) {
        log.debug("Validating refresh token for user: {}", userDetails.getUsername());

        boolean isValid = isTokenValid(token, userDetails) && isRefreshToken(token);

        log.debug("Refresh token validation result for user {}: {}", userDetails.getUsername(), isValid);
        return isValid;
    }

    @Override
    public Date getExpirationDate(String token) {
        log.debug("Extracting expiration date from token");
        return extractExpiration(token);
    }

    @Override
    public Date getRefreshTokenExpirationDate(String token) {
        log.debug("Extracting refresh token expiration date");
        return extractExpiration(token);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolvers) {
        final Claims claims = extractAllClaims(token);
        return claimsResolvers.apply(claims);
    }

    private String generateToken(Map<String, Object> extraClaims, UserDetails userDetails, Long expirationTime) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(Date.from(Instant.now()))
                .setExpiration(Date.from(Instant.now().plusMillis(expirationTime)))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private boolean isRefreshToken(String token) {
        try {
            Claims claims = extractAllClaims(token);
            return "refresh".equals(claims.get("type"));
        } catch (Exception e) {
            log.warn("Error checking if token is refresh token: {}", e.getMessage());
            return false;
        }
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSigningKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}