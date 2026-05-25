package com.example.identityservice.service;

import com.example.identityservice.config.JwtUtil;
import com.example.identityservice.dto.FormLogin;
import com.example.identityservice.dto.FormRegister;
import com.example.identityservice.dto.JwtResponse;
import com.example.identityservice.entity.RefreshToken;
import com.example.identityservice.entity.Users;
import com.example.identityservice.repository.RefreshTokenRepository;
import com.example.identityservice.repository.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final StringRedisTemplate redisTemplate;

    @Value("${jwt.expiration_refresh_token}")
    long expirationRefreshToken;

    @Value("${jwt.expiration_access_token}")
    private long expirationAccessToken;

    public JwtResponse login(FormLogin request) {
        Users users = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new JwtException("Invalid username or password"));

        if (!passwordEncoder.matches(request.getPassword(), users.getPassword())) {
            throw new JwtException("Invalid username or password");
        }

        String accessToken = jwtUtil.generateAccessToken(users);
        String refreshToken = jwtUtil.generateRefreshToken(users);

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .token(refreshToken)
                .users(users)
                .expireAt(new Date(System.currentTimeMillis() + (expirationRefreshToken * 7)))
                .build();

        refreshTokenRepository.save(refreshTokenEntity);

        return JwtResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expireAccessToken(System.currentTimeMillis() + expirationAccessToken)
                .expireRefreshToken(System.currentTimeMillis() + (expirationRefreshToken * 7))
                .build();
    }

    public String register(FormRegister request) {
        if (userRepository.findByUsername(request.getUsername()).isPresent()) {
            throw new JwtException("Username already exists");
        }
        Users users = new Users();
        users.setUsername(request.getUsername());
        users.setPassword(passwordEncoder.encode(request.getPassword()));
        users.setRole(request.getRole());
        users.setPermissions(request.getPermissions());

        userRepository.save(users);

        return "Register success";
    }

    public JwtResponse refresh(String refreshTokenOld) {
        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshTokenOld)
                .orElseThrow(() -> new JwtException("Invalid refresh token"));

        int compare = refreshToken.getExpireAt().compareTo(new Date());
        if (compare <= 0) {
            throw new JwtException("Refresh token expired");
        }

        Users users = refreshToken.getUsers();
        String accessToken = jwtUtil.generateAccessToken(users);
        String newRefreshToken = jwtUtil.generateRefreshToken(users);

        refreshTokenRepository.delete(refreshToken);

        RefreshToken newRefreshTokenEntity = RefreshToken.builder()
                .token(newRefreshToken)
                .users(users)
                .expireAt(new Date(System.currentTimeMillis() + (expirationRefreshToken * 7)))
                .build();
        refreshTokenRepository.save(newRefreshTokenEntity);

        return JwtResponse.builder()
                .accessToken(accessToken)
                .refreshToken(newRefreshToken)
                .expireAccessToken(System.currentTimeMillis() + expirationAccessToken)
                .expireRefreshToken(System.currentTimeMillis() + (expirationRefreshToken * 7))
                .build();
    }

    public void logout(HttpServletRequest request, String refreshToken) {
        RefreshToken refreshTokenEntity = refreshTokenRepository.findByToken(refreshToken)
                .orElseThrow(() -> new JwtException("Invalid refresh token"));
        refreshTokenRepository.delete(refreshTokenEntity);
        String authorization = request.getHeader("Authorization");
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            throw new JwtException("Invalid access token");
        }
        String accessToken = authorization.substring(7);

        try {
            Claims claims = jwtUtil.extractAllClaims(accessToken);
            String jti = claims.get("jti", String.class);
            long expirationMillis = claims.get("exp", Long.class) * 1000L;
            long ttlMillis = expirationMillis - System.currentTimeMillis();

            if (ttlMillis > 0) {
                redisTemplate.opsForValue().set("blacklist:" + jti, "revoked", ttlMillis, TimeUnit.MILLISECONDS);
            }
        } catch (ExpiredJwtException e) {

        } catch (Exception e) {
            throw new JwtException("Invalid token");
        }
    }
}
