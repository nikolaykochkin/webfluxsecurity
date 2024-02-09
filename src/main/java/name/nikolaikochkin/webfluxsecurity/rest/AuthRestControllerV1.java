package name.nikolaikochkin.webfluxsecurity.rest;

import lombok.RequiredArgsConstructor;
import name.nikolaikochkin.webfluxsecurity.dto.AuthRequestDto;
import name.nikolaikochkin.webfluxsecurity.dto.AuthResponseDto;
import name.nikolaikochkin.webfluxsecurity.dto.UserDto;
import name.nikolaikochkin.webfluxsecurity.entity.UserEntity;
import name.nikolaikochkin.webfluxsecurity.mapper.UserMapper;
import name.nikolaikochkin.webfluxsecurity.security.CustomPrincipal;
import name.nikolaikochkin.webfluxsecurity.security.SecurityService;
import name.nikolaikochkin.webfluxsecurity.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import reactor.core.publisher.Mono;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/v1/auth")
public class AuthRestControllerV1 {
    private final SecurityService securityService;
    private final UserService userService;
    private final UserMapper userMapper;

    @PostMapping("/register")
    public Mono<UserDto> register(@RequestBody UserDto userDto) {
        UserEntity userEntity = userMapper.userDtoToUserEntity(userDto);
        return userService.registerUser(userEntity)
                .map(userMapper::userEntityToUserDto);
    }

    @PostMapping("/login")
    public Mono<AuthResponseDto> login(@RequestBody AuthRequestDto authRequestDto) {
        return securityService.authenticate(authRequestDto.username(), authRequestDto.password())
                .map(tokenDetails ->
                        new AuthResponseDto(
                                tokenDetails.getUserId(),
                                tokenDetails.getToken(),
                                tokenDetails.getIssuedAt(),
                                tokenDetails.getExpiresAt()
                        )
                );
    }

    @GetMapping("/info")
    public Mono<UserDto> getUserInfo(Authentication authentication) {
        var principal = (CustomPrincipal) authentication.getPrincipal();
        return userService.getUserById(principal.getId()).map(userMapper::userEntityToUserDto);
    }
}
