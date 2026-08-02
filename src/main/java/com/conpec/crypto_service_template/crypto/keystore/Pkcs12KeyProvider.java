package com.conpec.crypto_service_template.crypto.keystore;

import com.conpec.crypto_service_template.config.CryptoProperties;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Component
public class Pkcs12KeyProvider implements KeyProvider {

    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final int keyVersion;

    public Pkcs12KeyProvider(CryptoProperties properties) {
        try {
            KeyStore keyStore = KeyStore.getInstance(properties.keystore().type());
            char[] password = properties.keystore().password().toCharArray();

            Resource resource = new DefaultResourceLoader().getResource(properties.keystore().path());
            try (InputStream in = resource.getInputStream()) {
                keyStore.load(in, password);
            }

            String alias = properties.keystore().keyAlias();
            KeyStore.PasswordProtection protection = new KeyStore.PasswordProtection(password);

            SecretKey privEntry = ((KeyStore.SecretKeyEntry) keyStore.getEntry(alias + "-priv", protection)).getSecretKey();
            SecretKey pubEntry = ((KeyStore.SecretKeyEntry) keyStore.getEntry(alias + "-pub", protection)).getSecretKey();

            KeyFactory keyFactory = KeyFactory.getInstance("X25519");
            this.privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privEntry.getEncoded()));
            this.publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(pubEntry.getEncoded()));
            this.keyVersion = properties.key().version();

        } catch (Exception e) {
            throw new IllegalStateException("Falha ao carregar KeyStore do projeto", e);
        }
    }

    @Override
    public PrivateKey getPrivateKey() { return privateKey; }

    @Override
    public PublicKey getPublicKey() { return publicKey; }

    @Override
    public int getKeyVersion() { return keyVersion; }
}