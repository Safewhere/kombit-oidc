package kombit.oidc;

import kombit.oidc.config.OidcProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@SpringBootApplication
@ConfigurationPropertiesScan(basePackageClasses = { OidcProperties.class })
public class KombitOidcApplication {

	public static void main(String[] args) {
		SpringApplication.run(KombitOidcApplication.class, args);
	}

}
