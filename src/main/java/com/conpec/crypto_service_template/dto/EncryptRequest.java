package com.conpec.crypto_service_template.dto;

import jakarta.validation.constraints.NotBlank;

public record EncryptRequest(
        @NotBlank(message = "plaintext não pode ser vazio")
        String plaintext
) {}
