package med.voll.api.infra.config;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Getter
@Configuration
public class ValuesConfig {
    @Value("${api.secrety.token.secret}")
    private String urlSecret;
}
