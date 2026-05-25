package com.example.identityservice.config;

import com.example.identityservice.entity.Users;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

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

    public String generateAccessToken(Users users){
        Date now = new Date();
        String jti = UUID.randomUUID().toString();
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", users.getRole());
        claims.put("permissions", users.getPermissions());
        claims.put("jti", jti);
        claims.put("type", "access");

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(users.getUsername())
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + expirationAccessToken))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    public String generateRefreshToken(Users users){
        Date now = new Date();
        String jti = UUID.randomUUID().toString();
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", users.getRole());
        claims.put("jti", jti);
        claims.put("type", "refresh");

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(users.getUsername())
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + (expirationRefreshToken * 7)))
                .signWith(getSigningKey(), SignatureAlgorithm.HS256)
                .compact();
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
