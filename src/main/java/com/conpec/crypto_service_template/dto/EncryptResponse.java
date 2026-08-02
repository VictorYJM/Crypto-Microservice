package com.conpec.crypto_service_template.dto;

public record EncryptResponse(
        String ciphertext,
        String dataIv,
        String encryptedDek,
        String dekIv,
        String ephemeralPublicKey,
        int keyVersion,
        String algorithm
) {}
