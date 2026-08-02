package com.conpec.crypto_service_template.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import javax.crypto.AEADBadTagException;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // JSON sintaticamente inválido (chave faltando, vírgula sobrando, etc.)
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<Map<String, Object>> handleMalformedJson(HttpMessageNotReadableException ex) {
        log.warn("JSON malformado na requisição. status=400");
        return buildResponse(HttpStatus.BAD_REQUEST, "Corpo da requisição malformado.");
    }

    // Validação do @Valid falhou (ex: plaintext vazio)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, Object>> handleValidation(MethodArgumentNotValidException ex) {
        log.warn("Falha de validação em requisição. status=400");
        return buildResponse(HttpStatus.BAD_REQUEST, "Dados de requisição inválidos.");
    }

    // Tag de autenticação do GCM não bateu: ciphertext adulterado, chave errada, ou payload incompatível
    @ExceptionHandler(AEADBadTagException.class)
    public ResponseEntity<Map<String, Object>> handleBadTag(AEADBadTagException ex) {
        log.warn("Falha de autenticação na descriptografia. status=400 possivelCausa=dado_adulterado_ou_chave_incorreta");
        return buildResponse(HttpStatus.BAD_REQUEST, "Não foi possível descriptografar os dados fornecidos.");
    }

    // Qualquer outro erro criptográfico (ex: chave malformada, Base64 inválido, algoritmo incompatível)
    @ExceptionHandler(GeneralSecurityException.class)
    public ResponseEntity<Map<String, Object>> handleCryptoError(GeneralSecurityException ex) {
        log.warn("Erro criptográfico não classificado. status=400 tipo={}", ex.getClass().getSimpleName());
        return buildResponse(HttpStatus.BAD_REQUEST, "Não foi possível processar a operação criptográfica.");
    }

    // Base64 inválido, JSON malformado, etc.
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<Map<String, Object>> handleIllegalArgument(IllegalArgumentException ex) {
        log.warn("Argumento inválido na requisição. status=400");
        return buildResponse(HttpStatus.BAD_REQUEST, "Formato de dados inválido.");
    }

    // Fallback genérico — nunca deve vazar detalhe interno
    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleGeneric(Exception ex) {
        log.error("Erro interno não tratado. status=500 tipo={}", ex.getClass().getSimpleName());
        return buildResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Erro interno do servidor.");
    }

    private ResponseEntity<Map<String, Object>> buildResponse(HttpStatus status, String message) {
        Map<String, Object> body = Map.of(
                "timestamp", Instant.now().toString(),
                "status", status.value(),
                "message", message
        );
        return ResponseEntity.status(status).body(body);
    }
}