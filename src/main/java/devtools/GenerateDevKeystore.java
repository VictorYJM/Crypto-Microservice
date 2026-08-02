package devtools;

import javax.crypto.KeyGenerator;
import javax.crypto.spec.SecretKeySpec;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;

public class GenerateDevKeystore {
    public static void main(String[] args) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("X25519");
        KeyPair pair = generator.generateKeyPair();

        char[] password = "changeit".toCharArray();
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, password); // null = cria um keystore vazio novo

        SecretKeySpec privSpec = new SecretKeySpec(pair.getPrivate().getEncoded(), "RAW");
        SecretKeySpec pubSpec = new SecretKeySpec(pair.getPublic().getEncoded(), "RAW");

        keyStore.setEntry("project-key-v1-priv",
                new KeyStore.SecretKeyEntry(privSpec),
                new KeyStore.PasswordProtection(password));
        keyStore.setEntry("project-key-v1-pub",
                new KeyStore.SecretKeyEntry(pubSpec),
                new KeyStore.PasswordProtection(password));

        try (var out = new java.io.FileOutputStream("src/main/resources/keystore/dev-keystore.p12")) {
            keyStore.store(out, password);
        }
        System.out.println("Keystore gerado com sucesso.");
    }
}