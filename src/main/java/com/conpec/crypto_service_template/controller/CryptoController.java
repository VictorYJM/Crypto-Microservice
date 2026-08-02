package com.conpec.crypto_service_template.controller;

import com.conpec.crypto_service_template.crypto.EncryptedEnvelope;
import com.conpec.crypto_service_template.dto.DecryptRequest;
import com.conpec.crypto_service_template.dto.DecryptResponse;
import com.conpec.crypto_service_template.dto.EncryptRequest;
import com.conpec.crypto_service_template.dto.EncryptResponse;
import com.conpec.crypto_service_template.service.CryptoEnvelopeService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

@RestController
@RequestMapping("/api/v1/crypto")
public class CryptoController {

    private final CryptoEnvelopeService cryptoService;

    public CryptoController(CryptoEnvelopeService cryptoService) {
        this.cryptoService = cryptoService;
    }

    @PostMapping("/encrypt")
    public ResponseEntity<EncryptResponse> encrypt(@Valid @RequestBody EncryptRequest request) throws GeneralSecurityException {
        byte[] plaintextBytes = request.plaintext().getBytes(StandardCharsets.UTF_8);
        EncryptedEnvelope envelope = cryptoService.encrypt(plaintextBytes);

        EncryptResponse response = new EncryptResponse(
                encode(envelope.ciphertext()),
                encode(envelope.dataIv()),
                encode(envelope.encryptedDek()),
                encode(envelope.dekIv()),
                encode(envelope.ephemeralPublicKey()),
                envelope.keyVersion(),
                envelope.algorithm()
        );

        return ResponseEntity.ok(response);
    }

    @PostMapping("/decrypt")
    public ResponseEntity<DecryptResponse> decrypt(@Valid @RequestBody DecryptRequest request) throws GeneralSecurityException {
        EncryptedEnvelope envelope = new EncryptedEnvelope(
                decode(request.ciphertext()),
                decode(request.dataIv()),
                decode(request.encryptedDek()),
                decode(request.dekIv()),
                decode(request.ephemeralPublicKey()),
                request.keyVersion(),
                null // algorithm não é necessário para decriptar
        );

        byte[] plaintextBytes = cryptoService.decrypt(envelope);
        return ResponseEntity.ok(new DecryptResponse(new String(plaintextBytes, StandardCharsets.UTF_8)));
    }

    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }
}