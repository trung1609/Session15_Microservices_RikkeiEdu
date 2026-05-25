package com.example.gatewayservice.config;

import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
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

        String token = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (token == null || !token.startsWith("Bearer ")) {
            return onError(exchange, HttpStatus.UNAUTHORIZED);
        }
        token = token.substring(7);
        try {
            if (jwtUtil.validateToken(token) && jwtUtil.extractAllClaims(token).get("type").equals("access")) {
                String role = jwtUtil.extractAllClaims(token).get("role").toString();

                ServerHttpRequest mutedRequest = request.mutate()
                        .header("X-User-Role", role)
                        .build();
                ServerWebExchange mutedExchange = exchange.mutate().request(mutedRequest).build();
                return chain.filter(mutedExchange);
            } else {
                return onError(exchange, HttpStatus.UNAUTHORIZED);
            }
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
