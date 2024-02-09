package name.nikolaikochkin.webfluxsecurity.security;

import lombok.RequiredArgsConstructor;
import name.nikolaikochkin.webfluxsecurity.entity.UserEntity;
import name.nikolaikochkin.webfluxsecurity.exception.UnauthorizedException;
import name.nikolaikochkin.webfluxsecurity.repository.UserRepository;
import name.nikolaikochkin.webfluxsecurity.service.UserService;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
@RequiredArgsConstructor
public class AuthenticationManager implements ReactiveAuthenticationManager {
    private final UserService userService;

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        CustomPrincipal principal = (CustomPrincipal) authentication.getPrincipal();
        return userService.getUserById(principal.getId())
                .filter(UserEntity::isEnabled)
                .switchIfEmpty(Mono.error(new UnauthorizedException("User disabled")))
                .map(userEntity -> authentication);
    }
}
