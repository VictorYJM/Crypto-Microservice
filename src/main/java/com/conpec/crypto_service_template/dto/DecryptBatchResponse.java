package com.conpec.crypto_service_template.dto;

import java.util.List;

public record DecryptBatchResponse(List<Result> results) {

    public record Result(String plaintext, boolean success, String error) {

        public static Result ok(String plaintext) {
            return new Result(plaintext, true, null);
        }

        public static Result failed(String error) {
            return new Result(null, false, error);
        }
    }
}