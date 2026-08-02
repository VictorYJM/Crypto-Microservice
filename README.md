# Crypto Microservice

Stateless envelope encryption microservice. AES-256-GCM for data, X25519 + HKDF for key wrapping.

## Setup (new client instance)

1. Generate a fresh keystore for this project — **do not reuse another client's keystore**.
   Run the key generation routine once, save output to `src/main/resources/keystore/dev-keystore.p12` (or point to an external path in production).
2. Set environment variables (never commit these):
   - `CRYPTO_KEYSTORE_PASSWORD`
3. Update `application.yaml` if the key alias or path differs from defaults.
4. Run `./mvnw spring-boot:run` (or use your IDE's run configuration).

## API

- `POST /api/v1/crypto/encrypt` — body: `{ "plaintext": "string" }`
- `POST /api/v1/crypto/decrypt` — body: the full envelope returned by `/encrypt`

## Running tests

`./mvnw test`

## Production notes

- Replace the PKCS12 keystore with a real KMS/HSM/Vault before going live.
- Never log plaintext, keys, IVs, or tokens (see `GlobalExceptionHandler`).
- Each client/project must have its own isolated key pair.
