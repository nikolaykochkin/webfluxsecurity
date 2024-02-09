package name.nikolaikochkin.webfluxsecurity.security;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import lombok.RequiredArgsConstructor;
import name.nikolaikochkin.webfluxsecurity.config.JwtConfig;
import name.nikolaikochkin.webfluxsecurity.entity.UserEntity;
import name.nikolaikochkin.webfluxsecurity.exception.AuthException;
import name.nikolaikochkin.webfluxsecurity.service.UserService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class SecurityService {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JwtConfig jwtConfig;

    public Mono<TokenDetails> authenticate(String username, String password) {
        return userService.getUserByUsername(username)
                .flatMap(userEntity -> {
                    if (!userEntity.isEnabled()) {
                        return Mono.error(new AuthException("User is disabled", "USER_ACCOUNT_DISABLED"));
                    }

                    if (!passwordEncoder.matches(password, userEntity.getPassword())) {
                        return Mono.error(new AuthException("Invalid password", "USER_INVALID_PASSWORD"));
                    }
                    var token = generateToken(userEntity).toBuilder()
                            .userId(userEntity.getId())
                            .build();
                    return Mono.just(token);
                })
                .switchIfEmpty(Mono.error(new AuthException("User not found", "USER_NOT_FOUND")));
    }

    private TokenDetails generateToken(Map<String, Object> claims, String subject) {
        var createdDate = Instant.now();
        var expiredDate = createdDate.plus(jwtConfig.expiration());

        SecretKey key = Keys.hmacShaKeyFor(Base64.getEncoder().encode(jwtConfig.secret().getBytes()));

        String token = Jwts.builder()
                .claims(claims)
                .issuer(jwtConfig.issuer())
                .issuedAt(Date.from(createdDate))
                .subject(subject)
                .id(UUID.randomUUID().toString())
                .expiration(Date.from(expiredDate))
                .signWith(key)
                .compact();

        return TokenDetails.builder()
                .token(token)
                .issuedAt(createdDate)
                .expiresAt(expiredDate)
                .build();
    }

    private TokenDetails generateToken(UserEntity user) {
        Map<String, Object> claims = Map.of(
                "role", user.getRole(),
                "username", user.getUsername()
        );
        return generateToken(claims, user.getId().toString());
    }
}
