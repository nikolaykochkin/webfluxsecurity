package name.nikolaikochkin.webfluxsecurity.mapper;

import name.nikolaikochkin.webfluxsecurity.dto.UserDto;
import name.nikolaikochkin.webfluxsecurity.entity.UserEntity;
import org.mapstruct.InheritInverseConfiguration;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {
    UserDto userEntityToUserDto(UserEntity userEntity);

    @InheritInverseConfiguration
    UserEntity userDtoToUserEntity(UserDto userDto);
}
