package name.nikolaikochkin.webfluxsecurity.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("jwt.password.encoder")
public record PBKDF2EncoderConfig(String secret, int iteration, int keyLength) {
}
