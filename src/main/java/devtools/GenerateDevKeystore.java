package devtools;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;

public class GenerateDevKeystore {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("X25519");
        KeyPair pair = generator.generateKeyPair();

        char[] password = "changeit".toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, password);

        SecretKeySpec privSpec = new SecretKeySpec(pair.getPrivate().getEncoded(), "X25519");
        SecretKeySpec pubSpec = new SecretKeySpec(pair.getPublic().getEncoded(), "X25519");

        keyStore.setEntry("project-key-v1-priv",
                new KeyStore.SecretKeyEntry(privSpec),
                new KeyStore.PasswordProtection(password));
        keyStore.setEntry("project-key-v1-pub",
                new KeyStore.SecretKeyEntry(pubSpec),
                new KeyStore.PasswordProtection(password));

        Path keystorePath = Path.of(
                "src/main/resources/keystore/dev-keystore.p12"
        );

        Files.createDirectories(keystorePath.getParent());

        try (var out = Files.newOutputStream(keystorePath)) {
            keyStore.store(out, password);
        }

        System.out.println(
                "Keystore gerado com sucesso em: " + keystorePath.toAbsolutePath()
        );
    }
}