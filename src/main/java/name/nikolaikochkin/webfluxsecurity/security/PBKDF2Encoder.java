package name.nikolaikochkin.webfluxsecurity.security;

import lombok.RequiredArgsConstructor;
import name.nikolaikochkin.webfluxsecurity.config.PBKDF2EncoderConfig;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.util.Base64;

@Component
@RequiredArgsConstructor
public class PBKDF2Encoder implements PasswordEncoder {
    private static final String SECRET_KEY_INSTANCE = "PBKDF2WithHmacSHA512";

    private final PBKDF2EncoderConfig config;

    @Override
    public String encode(CharSequence rawPassword) {
        try {
            var result = SecretKeyFactory.getInstance(SECRET_KEY_INSTANCE)
                    .generateSecret(new PBEKeySpec(rawPassword.toString().toCharArray(),
                            config.secret().getBytes(), config.iteration(), config.keyLength()))
                    .getEncoded();
            return Base64.getEncoder().encodeToString(result);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return encode(rawPassword).equals(encodedPassword);
    }
}
