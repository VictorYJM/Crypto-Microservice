package com.conpec.crypto_service_template.crypto.symmetric;

import org.junit.jupiter.api.Test;

import javax.crypto.AEADBadTagException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

class AesGcmCipherTest {

    private final AesGcmCipher cipher = new AesGcmCipher();
    private final SecureRandom random = new SecureRandom();

    private byte[] generateRandomAesKey() {
        byte[] key = new byte[32]; // 256 bits
        random.nextBytes(key);
        return key;
    }

    @Test
    void deveCriptografarEDescriptografarCorretamente() throws GeneralSecurityException {
        byte[] key = generateRandomAesKey();
        byte[] plaintext = "12345678900".getBytes(StandardCharsets.UTF_8);

        AesGcmCipher.EncryptedData encrypted = cipher.encrypt(plaintext, key);
        byte[] decrypted = cipher.decrypt(encrypted.ciphertext(), key, encrypted.iv());

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void ivDeveSerDiferenteACadaChamada() throws GeneralSecurityException {
        byte[] key = generateRandomAesKey();
        byte[] plaintext = "mesmo dado".getBytes(StandardCharsets.UTF_8);

        AesGcmCipher.EncryptedData primeira = cipher.encrypt(plaintext, key);
        AesGcmCipher.EncryptedData segunda = cipher.encrypt(plaintext, key);

        // mesmo com o mesmo dado e mesma chave, o IV nunca deve se repetir
        assertFalse(java.util.Arrays.equals(primeira.iv(), segunda.iv()));
        // consequência direta: ciphertexts diferentes, mesmo criptografando o mesmo plaintext
        assertFalse(java.util.Arrays.equals(primeira.ciphertext(), segunda.ciphertext()));
    }

    @Test
    void deveDetectarCiphertextAdulterado() throws GeneralSecurityException {
        byte[] key = generateRandomAesKey();
        byte[] plaintext = "dado sensivel".getBytes(StandardCharsets.UTF_8);

        AesGcmCipher.EncryptedData encrypted = cipher.encrypt(plaintext, key);

        // flipa um único bit do ciphertext, simulando adulteração
        byte[] adulterado = encrypted.ciphertext().clone();
        adulterado[0] ^= 0x01;

        assertThrows(AEADBadTagException.class, () ->
                cipher.decrypt(adulterado, key, encrypted.iv())
        );
    }

    @Test
    void deveDetectarChaveErrada() throws GeneralSecurityException {
        byte[] chaveCorreta = generateRandomAesKey();
        byte[] chaveErrada = generateRandomAesKey();
        byte[] plaintext = "dado".getBytes(StandardCharsets.UTF_8);

        AesGcmCipher.EncryptedData encrypted = cipher.encrypt(plaintext, chaveCorreta);

        assertThrows(AEADBadTagException.class, () ->
                cipher.decrypt(encrypted.ciphertext(), chaveErrada, encrypted.iv())
        );
    }

    @Test
    void deveDetectarIvErrado() throws GeneralSecurityException {
        byte[] key = generateRandomAesKey();
        byte[] plaintext = "dado".getBytes(StandardCharsets.UTF_8);

        AesGcmCipher.EncryptedData encrypted = cipher.encrypt(plaintext, key);
        byte[] ivErrado = new byte[12];
        random.nextBytes(ivErrado);

        assertThrows(AEADBadTagException.class, () ->
                cipher.decrypt(encrypted.ciphertext(), key, ivErrado)
        );
    }
}