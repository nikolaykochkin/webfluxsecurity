package name.nikolaikochkin.webfluxsecurity.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties("jwt")
public record JwtConfig(String secret, Duration expiration, String issuer) {
}
