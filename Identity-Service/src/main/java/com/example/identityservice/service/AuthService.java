package com.example.identityservice.service;

import com.example.identityservice.config.JwtUtil;
import com.example.identityservice.dto.FormLogin;
import com.example.identityservice.dto.FormRegister;
import com.example.identityservice.dto.JwtResponse;
import com.example.identityservice.entity.RefreshToken;
import com.example.identityservice.entity.Users;
import com.example.identityservice.repository.RefreshTokenRepository;
import com.example.identityservice.repository.UserRepository;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;
    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt.expiration_refresh_token}")
    long expirationRefreshToken;

    @Value("${jwt.expiration_access_token}")
    private long expirationAccessToken;

    public JwtResponse login(FormLogin request){
        Users users = userRepository.findByUsername(request.getUsername())
                .orElseThrow(() -> new JwtException("Invalid username or password"));

        if (!passwordEncoder.matches(request.getPassword(), users.getPassword())){
            throw new JwtException("Invalid username or password");
        }

        String accessToken = jwtUtil.generateAccessToken(users);
        String refreshToken = jwtUtil.generateRefreshToken(users);

        RefreshToken refreshTokenEntity = RefreshToken.builder()
                .token(refreshToken)
                .users(users)
                .expireAt(System.currentTimeMillis() + (expirationRefreshToken * 7))
                .build();

        refreshTokenRepository.save(refreshTokenEntity);

        return JwtResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expireAccessToken(System.currentTimeMillis() + expirationAccessToken)
                .expireRefreshToken(System.currentTimeMillis() + (expirationRefreshToken * 7))
                .build();
    }

    public String register(FormRegister request){
        if (userRepository.findByUsername(request.getUsername()).isPresent()){
            throw new JwtException("Username already exists");
        }
        Users users = new Users();
        users.setUsername(request.getUsername());
        users.setPassword(passwordEncoder.encode(request.getPassword()));
        users.setRole(request.getRole());

        userRepository.save(users);

        return "Register success";
    }
}
