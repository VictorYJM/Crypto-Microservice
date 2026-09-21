package com.conpec.crypto_service_template.dto;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;

import java.util.List;

public record DecryptBatchRequest(
        @NotEmpty(message = "envelopes list cannot be empty")
        @Valid
        List<DecryptRequest> envelopes


) {}