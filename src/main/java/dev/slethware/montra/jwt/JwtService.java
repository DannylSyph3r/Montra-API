package dev.slethware.montra.jwt;

import org.springframework.security.core.userdetails.UserDetails;

import java.util.Date;

public interface JwtService {
    String extractUserName(String token);
    String generateToken(UserDetails userDetails);
    String generateRefreshToken(UserDetails userDetails);
    boolean isTokenValid(String token, UserDetails userDetails);
    boolean isRefreshTokenValid(String token, UserDetails userDetails);
    Date getExpirationDate(String token);
    Date getRefreshTokenExpirationDate(String token);
}