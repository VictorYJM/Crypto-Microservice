package com.conpec.crypto_service_template.service;

import com.conpec.crypto_service_template.crypto.EncryptedEnvelope;
import com.conpec.crypto_service_template.crypto.asymmetric.EciesKeyWrapper;
import com.conpec.crypto_service_template.crypto.keystore.KeyProvider;
import com.conpec.crypto_service_template.crypto.symmetric.AesGcmCipher;
import org.springframework.stereotype.Service;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.X509EncodedKeySpec;

@Service
public class CryptoEnvelopeService {

    private static final String ALGORITHM_LABEL = "AES256GCM+X25519HKDF";
    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final KeyProvider keyProvider;
    private final EciesKeyWrapper keyWrapper;
    private final AesGcmCipher cipher;

    public CryptoEnvelopeService(KeyProvider keyProvider, EciesKeyWrapper keyWrapper, AesGcmCipher cipher) {
        this.keyProvider = keyProvider;
        this.keyWrapper = keyWrapper;
        this.cipher = cipher;
    }

    public EncryptedEnvelope encrypt(byte[] plaintext) throws GeneralSecurityException {
        // 1. DEK nova, efêmera, só para esse dado
        byte[] dek = new byte[32];
        SECURE_RANDOM.nextBytes(dek);

        // 2. Criptografa o dado com a DEK
        AesGcmCipher.EncryptedData dataResult = cipher.encrypt(plaintext, dek);

        // 3. Deriva a wrapping key via ECDH(efêmera, chave pública do projeto)
        EciesKeyWrapper.WrapResult wrapResult = keyWrapper.deriveWrappingKey(keyProvider.getPublicKey());

        // 4. Embrulha a DEK com a wrapping key
        AesGcmCipher.EncryptedData dekResult = cipher.encrypt(dek, wrapResult.wrappingKey());

        return new EncryptedEnvelope(
                dataResult.ciphertext(),
                dataResult.iv(),
                dekResult.ciphertext(),
                dekResult.iv(),
                wrapResult.ephemeralPublicKey(),
                keyProvider.getKeyVersion(),
                ALGORITHM_LABEL
        );
    }

    public byte[] decrypt(EncryptedEnvelope envelope) throws GeneralSecurityException {
        // 1. Reconstrói a chave pública efêmera a partir dos bytes recebidos
        PublicKey ephemeralPublicKey = KeyFactory.getInstance("X25519")
                .generatePublic(new X509EncodedKeySpec(envelope.ephemeralPublicKey()));

        // 2. Refaz a mesma wrapping key: ECDH(chave privada real do projeto, efêmera)
        byte[] wrappingKey = keyWrapper.deriveUnwrappingKey(keyProvider.getPrivateKey(), ephemeralPublicKey);

        // 3. Desembrulha a DEK
        byte[] dek = cipher.decrypt(envelope.encryptedDek(), wrappingKey, envelope.dekIv());

        // 4. Usa a DEK para descriptografar o dado real
        return cipher.decrypt(envelope.ciphertext(), dek, envelope.dataIv());
    }
}