package com.conpec.crypto_service_template.controller;

import com.conpec.crypto_service_template.crypto.EncryptedEnvelope;
import com.conpec.crypto_service_template.service.CryptoEnvelopeService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.WebMvcTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import javax.crypto.AEADBadTagException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(CryptoController.class)
class CryptoControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private CryptoEnvelopeService cryptoService;

    private static final byte[] FAKE_BYTES = "fake".getBytes();

    private EncryptedEnvelope sampleEnvelope() {
        return new EncryptedEnvelope(FAKE_BYTES, FAKE_BYTES, FAKE_BYTES, FAKE_BYTES, FAKE_BYTES, 1, "AES256GCM+X25519HKDF");
    }

    @Test
    void encryptShouldReturn200WithValidPayload() throws Exception {
        when(cryptoService.encrypt(any())).thenReturn(sampleEnvelope());

        mockMvc.perform(post("/api/v1/crypto/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"plaintext\": \"12345678900\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keyVersion").value(1))
                .andExpect(jsonPath("$.algorithm").value("AES256GCM+X25519HKDF"))
                .andExpect(jsonPath("$.ciphertext").exists());
    }

    @Test
    void encryptShouldReturn400WhenPlaintextIsBlank() throws Exception {
        mockMvc.perform(post("/api/v1/crypto/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"plaintext\": \"\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Dados de requisição inválidos."));
    }

    @Test
    void encryptShouldReturn400WhenPlaintextFieldIsMissing() throws Exception {
        mockMvc.perform(post("/api/v1/crypto/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{}"))
                .andExpect(status().isBadRequest());
    }

    @Test
    void encryptShouldReturn400OnMalformedJson() throws Exception {
        mockMvc.perform(post("/api/v1/crypto/encrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"plaintext\": \"12345\""))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Corpo da requisição malformado."));
    }

    @Test
    void decryptShouldReturn200WithValidPayload() throws Exception {
        when(cryptoService.decrypt(any())).thenReturn("12345678900".getBytes());

        String requestBody = """
                {
                  "ciphertext": "ZmFrZQ==",
                  "dataIv": "ZmFrZQ==",
                  "encryptedDek": "ZmFrZQ==",
                  "dekIv": "ZmFrZQ==",
                  "ephemeralPublicKey": "ZmFrZQ==",
                  "keyVersion": 1
                }
                """;

        mockMvc.perform(post("/api/v1/crypto/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.plaintext").value("12345678900"));
    }

    @Test
    void decryptShouldReturn400WhenCiphertextWasTampered() throws Exception {
        when(cryptoService.decrypt(any())).thenThrow(new AEADBadTagException("Tag mismatch"));

        String requestBody = """
                {
                  "ciphertext": "dGFtcGVyZWQ=",
                  "dataIv": "ZmFrZQ==",
                  "encryptedDek": "ZmFrZQ==",
                  "dekIv": "ZmFrZQ==",
                  "ephemeralPublicKey": "ZmFrZQ==",
                  "keyVersion": 1
                }
                """;

        mockMvc.perform(post("/api/v1/crypto/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Não foi possível descriptografar os dados fornecidos."));
    }

    @Test
    void decryptShouldReturn400WithInvalidBase64() throws Exception {
        String requestBody = """
                {
                  "ciphertext": "not-valid-base64!!!",
                  "dataIv": "ZmFrZQ==",
                  "encryptedDek": "ZmFrZQ==",
                  "dekIv": "ZmFrZQ==",
                  "ephemeralPublicKey": "ZmFrZQ==",
                  "keyVersion": 1
                }
                """;

        mockMvc.perform(post("/api/v1/crypto/decrypt")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(requestBody))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.message").value("Formato de dados inválido."));
    }
}