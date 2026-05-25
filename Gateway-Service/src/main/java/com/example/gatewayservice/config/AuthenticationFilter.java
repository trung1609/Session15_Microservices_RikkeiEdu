package com.example.gatewayservice.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

@Component
@RequiredArgsConstructor
public class AuthenticationFilter implements GlobalFilter, Ordered {

    @Value("${jwt.secret}")
    private String secretKey;

    private final JwtUtil jwtUtil;
    private final ReactiveRedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    private final List<String> openApiEndpoints = List.of(
            "/api/auth/login",
            "/api/auth/register"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        if (openApiEndpoints.stream().anyMatch(path::startsWith)) {
            return chain.filter(exchange);
        }

        if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }
        String token = authHeader.substring(7);

        try {
            Claims claims = jwtUtil.extractAllClaims(token);
            String jti = claims.get("jti", String.class);
            String type = claims.get("type", String.class);
            if (!"access".equals(type) || !jwtUtil.validateToken(token)) {
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }

            return  (redisTemplate.hasKey("blacklist:"+jti).flatMap(
                    isBlacklist ->{
                        if (Boolean.TRUE.equals(isBlacklist)){
                            return onError(exchange, HttpStatus.UNAUTHORIZED);
                        }

                        String role = claims.get("role", String.class);
                        String username = claims.getSubject();
                        List<String> permissions = claims.get("permissions", List.class);

                        String permissionsJson = "[]";
                        if (permissions != null) {
                            try {
                                permissionsJson = objectMapper.writeValueAsString(permissions);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        }

                        ServerHttpRequest mutatedRequest = request.mutate()
                                .header("X-User-Role", role)
                                .header("X-User-Username", username)
                                .header("X-User-Permissions", permissionsJson)
                                .build();

                        ServerWebExchange mutatedExchange = exchange.mutate().request(mutatedRequest).build();
                        return chain.filter(mutatedExchange);
                    }
            ));
        } catch (ExpiredJwtException e) {
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus httpStatus) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);
        return response.setComplete();
    }

    @Override
    public int getOrder() {
        return -1;
    }
}
