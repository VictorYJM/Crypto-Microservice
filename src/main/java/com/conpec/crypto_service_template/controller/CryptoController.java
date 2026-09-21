package com.conpec.crypto_service_template.controller;

import com.conpec.crypto_service_template.crypto.EncryptedEnvelope;
import com.conpec.crypto_service_template.dto.*;
import com.conpec.crypto_service_template.service.CryptoEnvelopeService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.util.List;

@RestController
@RequestMapping("/api/v1/crypto")
public class CryptoController {

    private final CryptoEnvelopeService cryptoService;
    private static final Logger log = LoggerFactory.getLogger(CryptoController.class);

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
                null
        );

        byte[] plaintextBytes = cryptoService.decrypt(envelope);
        return ResponseEntity.ok(new DecryptResponse(new String(plaintextBytes, StandardCharsets.UTF_8)));
    }

    @PostMapping("/decrypt-batch")
    public ResponseEntity<DecryptBatchResponse> decryptBatch(@Valid @RequestBody DecryptBatchRequest request) {
        List<DecryptBatchResponse.Result> results = request.envelopes().stream()
                .map(this::decryptSingleSafely)
                .toList();

        return ResponseEntity.ok(new DecryptBatchResponse(results));
    }

    private DecryptBatchResponse.Result decryptSingleSafely(DecryptRequest item) {
        try {
            EncryptedEnvelope envelope = new EncryptedEnvelope(
                    decode(item.ciphertext()),
                    decode(item.dataIv()),
                    decode(item.encryptedDek()),
                    decode(item.dekIv()),
                    decode(item.ephemeralPublicKey()),
                    item.keyVersion(),
                    null
            );

            byte[] plaintextBytes = cryptoService.decrypt(envelope);
            return DecryptBatchResponse.Result.ok(new String(plaintextBytes, StandardCharsets.UTF_8));

        }

        catch (GeneralSecurityException e) {
            log.warn("Batch item decryption failed. reason={}", e.getClass().getSimpleName());
            return DecryptBatchResponse.Result.failed("decryption_failed");
        }

        catch (IllegalArgumentException e) {
            log.warn("Batch item has invalid base64 payload.");
            return DecryptBatchResponse.Result.failed("invalid_format");
        }
    }

    private String encode(byte[] data) {
        return Base64.getEncoder().encodeToString(data);
    }

    private byte[] decode(String data) {
        return Base64.getDecoder().decode(data);
    }
}