package com.conpec.crypto_service_template.service;

import com.conpec.crypto_service_template.crypto.EncryptedEnvelope;
import com.conpec.crypto_service_template.crypto.asymmetric.EciesKeyWrapper;
import com.conpec.crypto_service_template.crypto.keystore.KeyProvider;
import com.conpec.crypto_service_template.crypto.symmetric.AesGcmCipher;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import static org.junit.jupiter.api.Assertions.*;

class CryptoEnvelopeServiceTest {

    private CryptoEnvelopeService service;
    private InMemoryKeyProvider keyProvider;

    @BeforeEach
    void setUp() throws Exception {
        KeyPair projectKeyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        keyProvider = new InMemoryKeyProvider(projectKeyPair, 1);
        service = new CryptoEnvelopeService(keyProvider, new EciesKeyWrapper(), new AesGcmCipher());
    }

    @Test
    void shouldEncryptAndDecryptRoundTrip() throws GeneralSecurityException {
        byte[] plaintext = "12345678900".getBytes(StandardCharsets.UTF_8);

        EncryptedEnvelope envelope = service.encrypt(plaintext);
        byte[] decrypted = service.decrypt(envelope);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void envelopeShouldCarryCurrentKeyVersion() throws GeneralSecurityException {
        EncryptedEnvelope envelope = service.encrypt("data".getBytes(StandardCharsets.UTF_8));

        assertEquals(1, envelope.keyVersion());
    }

    @Test
    void encryptingSamePlaintextTwiceShouldProduceDifferentCiphertexts() throws GeneralSecurityException {
        byte[] plaintext = "repeated value".getBytes(StandardCharsets.UTF_8);

        EncryptedEnvelope first = service.encrypt(plaintext);
        EncryptedEnvelope second = service.encrypt(plaintext);

        // fresh DEK + fresh ephemeral key on every call, even for identical input
        assertFalse(java.util.Arrays.equals(first.ciphertext(), second.ciphertext()));
        assertFalse(java.util.Arrays.equals(first.encryptedDek(), second.encryptedDek()));
    }

    @Test
    void decryptShouldFailWithADifferentProjectKeyPair() throws Exception {
        EncryptedEnvelope envelope = service.encrypt("secret".getBytes(StandardCharsets.UTF_8));

        // simulates another project trying to decrypt data that isn't theirs
        KeyPair anotherProjectKeyPair = KeyPairGenerator.getInstance("X25519").generateKeyPair();
        InMemoryKeyProvider anotherProvider = new InMemoryKeyProvider(anotherProjectKeyPair, 1);
        CryptoEnvelopeService anotherService = new CryptoEnvelopeService(anotherProvider, new EciesKeyWrapper(), new AesGcmCipher());

        assertThrows(GeneralSecurityException.class, () -> anotherService.decrypt(envelope));
    }

    @Test
    void shouldHandleEmptyPlaintext() throws GeneralSecurityException {
        byte[] plaintext = new byte[0];

        EncryptedEnvelope envelope = service.encrypt(plaintext);
        byte[] decrypted = service.decrypt(envelope);

        assertArrayEquals(plaintext, decrypted);
    }

    @Test
    void shouldHandleLargePlaintext() throws GeneralSecurityException {
        // simulates encrypting something like a serialized JSON or small file
        byte[] plaintext = new byte[1_000_000];
        new java.security.SecureRandom().nextBytes(plaintext);

        EncryptedEnvelope envelope = service.encrypt(plaintext);
        byte[] decrypted = service.decrypt(envelope);

        assertArrayEquals(plaintext, decrypted);
    }

    /**
     * Fake in-memory KeyProvider used only for tests.
     * Avoids touching any real KeyStore file or Spring context,
     * keeping this test fast and fully isolated.
     */
    private record InMemoryKeyProvider(KeyPair keyPair, int version) implements KeyProvider {

        @Override
        public PrivateKey getPrivateKey() {
            return keyPair.getPrivate();
        }

        @Override
        public PublicKey getPublicKey() {
            return keyPair.getPublic();
        }

        @Override
        public int getKeyVersion() {
            return version;
        }
    }
}