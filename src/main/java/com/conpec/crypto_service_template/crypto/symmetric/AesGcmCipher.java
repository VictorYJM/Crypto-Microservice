package com.conpec.crypto_service_template.crypto.symmetric;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

@Component
public class AesGcmCipher {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int IV_LENGTH_BYTES = 12;       // padrão recomendado pelo NIST para GCM
    private static final int TAG_LENGTH_BITS = 128;       // tamanho da tag de autenticação
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    public record EncryptedData(byte[] ciphertext, byte[] iv) {}

    public EncryptedData encrypt(byte[] plaintext, byte[] aesKeyBytes) throws GeneralSecurityException {
        byte[] iv = new byte[IV_LENGTH_BYTES];
        SECURE_RANDOM.nextBytes(iv);

        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec key = new SecretKeySpec(aesKeyBytes, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);

        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] ciphertext = cipher.doFinal(plaintext);

        return new EncryptedData(ciphertext, iv);
    }

    public byte[] decrypt(byte[] ciphertext, byte[] aesKeyBytes, byte[] iv) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(TRANSFORMATION);
        SecretKeySpec key = new SecretKeySpec(aesKeyBytes, "AES");
        GCMParameterSpec spec = new GCMParameterSpec(TAG_LENGTH_BITS, iv);

        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(ciphertext); // lança AEADBadTagException se ciphertext foi adulterado
    }
}