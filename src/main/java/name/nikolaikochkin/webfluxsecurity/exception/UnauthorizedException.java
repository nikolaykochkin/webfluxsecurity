package name.nikolaikochkin.webfluxsecurity.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class UnauthorizedException extends ApiException {
    public UnauthorizedException(String message) {
        super(message, "USER_UNAUTHORIZED");
    }
}
