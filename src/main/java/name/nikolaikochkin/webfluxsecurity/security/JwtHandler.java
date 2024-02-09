package name.nikolaikochkin.webfluxsecurity.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.RequiredArgsConstructor;
import name.nikolaikochkin.webfluxsecurity.exception.AuthException;
import name.nikolaikochkin.webfluxsecurity.exception.UnauthorizedException;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.time.Instant;

@RequiredArgsConstructor
public class JwtHandler {
    private final SecretKey key;

    public Mono<VerificationResult> check(String accessToken) {
        return Mono.just(verify(accessToken))
                .onErrorResume(e -> Mono.error(new UnauthorizedException(e.getMessage())));
    }

    private VerificationResult verify(String token) {
        Claims claims = getClaimsFromToken(token);
        Instant expiration = claims.getExpiration().toInstant();
        if (expiration.isBefore(Instant.now())) {
            throw new RuntimeException("Token expired");
        }

        return new VerificationResult(claims, token);
    }

    private Claims getClaimsFromToken(String token) {
        return Jwts.parser().verifyWith(key).build().parseSignedClaims(token).getPayload();
    }

    public record VerificationResult(Claims claims, String token) {
    }
}
