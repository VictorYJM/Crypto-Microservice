package com.conpec.crypto_service_template.crypto;

public record EncryptedEnvelope(
        byte[] ciphertext,
        byte[] dataIv,
        byte[] encryptedDek,
        byte[] dekIv,
        byte[] ephemeralPublicKey,
        int keyVersion,
        String algorithm
) {}