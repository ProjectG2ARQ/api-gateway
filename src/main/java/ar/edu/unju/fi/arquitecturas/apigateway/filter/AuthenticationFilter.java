package ar.edu.unju.fi.arquitecturas.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;

@Component
public class AuthenticationFilter implements GlobalFilter, Ordered {

    @Value("${jwt.secret:MiClaveSecretaSuperSeguraParaLogiTrackSprint2UNJu2026DeAlMenos256Bits}")
    private String secret;

    private static final List<String> PUBLIC_ENDPOINTS = List.of(
            "/api/v1/auth",
            "/v3/api-docs",
            "/swagger-ui",
            "/actuator"
    );

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        ServerHttpRequest request = exchange.getRequest();
        String path = request.getURI().getPath();

        // 1. Omitir validación en endpoints públicos
        if (isPublicEndpoint(path)) {
            return chain.filter(exchange);
        }

        // 2. Comprobar presencia de la cabecera Authorization
        if (!request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
            return onError(exchange, HttpStatus.UNAUTHORIZED, "Falta la cabecera Authorization.");
        }

        String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return onError(exchange, HttpStatus.UNAUTHORIZED, "El token debe iniciar con Bearer.");
        }

        String token = authHeader.substring(7);

        try {
            // 3. Validar firma criptográfica y vigencia
            Claims claims = validateToken(token);
            String rol = claims.get("rol", String.class);
            Long userId = claims.get("userId", Long.class);

            // 4. Validar reglas de acceso por rol
            if (!hasRequiredRole(request.getMethod(), path, rol)) {
                return onError(exchange, HttpStatus.FORBIDDEN, "Acceso denegado: El rol " + rol + " no tiene permisos para esta operación.");
            }

            // 5. Inyectar datos del usuario autenticado hacia los microservicios downstream
            ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                    .header("X-Auth-User-Id", String.valueOf(userId))
                    .header("X-Auth-User-Role", rol)
                    .header("X-Auth-User-Email", claims.getSubject())
                    .build();

            return chain.filter(exchange.mutate().request(mutatedRequest).build());

        } catch (Exception ex) {
            return onError(exchange, HttpStatus.UNAUTHORIZED, "Token inválido o expirado: " + ex.getMessage());
        }
    }

    private boolean isPublicEndpoint(String path) {
        return PUBLIC_ENDPOINTS.stream().anyMatch(path::contains);
    }

    private Claims validateToken(String token) {
        SecretKey key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        return Jwts.parser()
                .verifyWith(key)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private boolean hasRequiredRole(HttpMethod method, String path, String rol) {
        if (rol == null) return false;

        // Reglas para Envíos (/applications/api-shipment)
        if (path.contains("/api-shipment")) {
            if (method == HttpMethod.POST && path.contains("/envios")) {
                return "CLIENTE".equalsIgnoreCase(rol) || "ADMIN".equalsIgnoreCase(rol);
            }
            if (method == HttpMethod.PATCH && path.contains("/estado")) {
                return "REPARTIDOR".equalsIgnoreCase(rol) || "ADMIN".equalsIgnoreCase(rol);
            }
            if (method == HttpMethod.PATCH && path.contains("/repartidores")) {
                return "ADMIN".equalsIgnoreCase(rol);
            }
        }

        // Reglas para Repartidores (/applications/api-courier)
        if (path.contains("/api-courier")) {
            if ((method == HttpMethod.POST || method == HttpMethod.DELETE) && path.contains("/repartidores")) {
                return "ADMIN".equalsIgnoreCase(rol);
            }
        }

        return "ADMIN".equalsIgnoreCase(rol) || "CLIENTE".equalsIgnoreCase(rol) || "REPARTIDOR".equalsIgnoreCase(rol);
    }

    private Mono<Void> onError(ServerWebExchange exchange, HttpStatus status, String message) {
        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        String path = exchange.getRequest().getURI().getPath();
        String jsonError = String.format(
                "{\"timestamp\":\"%s\",\"status\":%d,\"error\":\"%s\",\"message\":\"%s\",\"path\":\"%s\"}",
                Instant.now(), status.value(), status.getReasonPhrase(), message, path
        );

        DataBuffer buffer = response.bufferFactory().wrap(jsonError.getBytes(StandardCharsets.UTF_8));
        return response.writeWith(Mono.just(buffer));
    }

    @Override
    public int getOrder() {
        return -1;
    }
}