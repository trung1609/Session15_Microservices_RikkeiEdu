package com.example.gatewayservice.config;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;

@Component
public class JwtUtil {
    @Value("${jwt.secret}")
    private String secretKey;

    @Value("${jwt.expiration_access_token}")
    private long expirationAccessToken;

    @Value("${jwt.expiration_refresh_token}")
    private long expirationRefreshToken;

    private SecretKey getSigningKey(){
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }

    public boolean validateToken(String token){
        try {
            Jwts.parserBuilder()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token);
            return true;
        }catch (ExpiredJwtException e){
            throw new JwtException("Token expired");
        }catch (MalformedJwtException | SignatureException | IllegalArgumentException e){
            throw new JwtException("Invalid token");
        }catch (UnsupportedJwtException e){
            throw new JwtException("Token unsupported");
        } catch (Exception e) {
            throw new JwtException("Have an error occur");
        }
    }

    public Claims extractAllClaims(String token){
        return Jwts.parserBuilder()
                .setSigningKey(getSigningKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }
}
