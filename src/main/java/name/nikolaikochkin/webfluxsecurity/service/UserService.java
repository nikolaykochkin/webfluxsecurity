package name.nikolaikochkin.webfluxsecurity.service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import name.nikolaikochkin.webfluxsecurity.entity.UserEntity;
import name.nikolaikochkin.webfluxsecurity.entity.UserRole;
import name.nikolaikochkin.webfluxsecurity.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Mono;

import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public Mono<UserEntity> registerUser(UserEntity userEntity) {
        return userRepository.save(
                        userEntity.toBuilder()
                                .password(passwordEncoder.encode(userEntity.getPassword()))
                                .role(UserRole.USER)
                                .enabled(true)
                                .createdAt(Instant.now())
                                .updatedAt(Instant.now())
                                .build()
                )
                .doOnSuccess(user -> log.info("User created {}", user))
                .doOnError(e -> log.error("Couldn't save user {}. Cause {}", userEntity, e.getMessage(), e));
    }

    public Mono<UserEntity> getUserById(Long id) {
        return userRepository.findById(id);
    }

    public Mono<UserEntity> getUserByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}
