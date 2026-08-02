package com.conpec.crypto_service_template;

import com.conpec.crypto_service_template.config.CryptoProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(CryptoProperties.class)
public class CryptoServiceTemplateApplication {

	public static void main(String[] args) {
		SpringApplication.run(CryptoServiceTemplateApplication.class, args);
	}

}
