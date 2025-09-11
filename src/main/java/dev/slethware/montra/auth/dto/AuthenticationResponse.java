package dev.slethware.montra.auth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.Map;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationResponse {

    private String accessToken;
    private String refreshToken;
    private Date accessTokenExpiry;
    private Date refreshTokenExpiry;
    private Map<String, Object> userDetails;
    private boolean requiresPinSetup;
    private boolean requiresAccountSetup;
}