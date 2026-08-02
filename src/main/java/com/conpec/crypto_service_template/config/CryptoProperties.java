package com.conpec.crypto_service_template.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "crypto")
public record CryptoProperties(
        Keystore keystore,
        Algorithm algorithm,
        Key key
) {
    public record Keystore(
            String path,
            String password,
            @DefaultValue("PKCS12") String type,
            String keyAlias
    ) {}

    public record Algorithm(
            @DefaultValue("AES/GCM/NoPadding") String symmetric,
            @DefaultValue("X25519") String asymmetric
    ) {}

    public record Key(
            @DefaultValue("1") int version
    ) {}
}