package name.nikolaikochkin.webfluxsecurity.dto;

import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.annotation.JsonNaming;

import java.time.Instant;

@JsonNaming(PropertyNamingStrategies.SnakeCaseStrategy.class)
public record AuthResponseDto(Long userId, String token, Instant issuedAt, Instant expiredAt) {
}
