package com.conpec.crypto_service_template.dto;

import jakarta.validation.constraints.NotBlank;

public record DecryptRequest(
        @NotBlank String ciphertext,
        @NotBlank String dataIv,
        @NotBlank String encryptedDek,
        @NotBlank String dekIv,
        @NotBlank String ephemeralPublicKey,
        int keyVersion
) {}
