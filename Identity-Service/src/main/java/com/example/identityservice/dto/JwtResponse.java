package com.example.identityservice.dto;

import lombok.*;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class JwtResponse {
    private String accessToken;
    private String refreshToken;
    private final String tokenType = "Bearer";
    private long expireAccessToken;
    private long expireRefreshToken;
}
