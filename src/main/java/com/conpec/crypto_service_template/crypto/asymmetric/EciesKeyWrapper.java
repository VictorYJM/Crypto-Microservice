package com.conpec.crypto_service_template.crypto.asymmetric;

import org.springframework.stereotype.Component;

import javax.crypto.KeyAgreement;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;

@Component
public class EciesKeyWrapper {

    private static final String CURVE = "X25519";
    private static final String HKDF_ALGORITHM = "HmacSHA256";
    private static final byte[] HKDF_INFO = "crypto-service-template-dek-wrap".getBytes();

    public record WrapResult(byte[] wrappingKey, byte[] ephemeralPublicKey) {}

    /**
     * Deriva uma chave AES de 256 bits a partir de ECDH(efêmera, chave pública do projeto).
     * Usada tanto pra embrulhar quanto pra desembrulhar (o processo de derivar é o mesmo,
     * só muda de qual lado vem a chave privada).
     */
    public WrapResult deriveWrappingKey(PublicKey projectPublicKey) throws GeneralSecurityException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(CURVE);
        KeyPair ephemeralKeyPair = generator.generateKeyPair();

        byte[] sharedSecret = computeSharedSecret(ephemeralKeyPair.getPrivate(), projectPublicKey);
        byte[] aesKey = hkdf(sharedSecret);

        return new WrapResult(aesKey, ephemeralKeyPair.getPublic().getEncoded());
    }

    /**
     * Refaz a mesma derivação do lado de quem descriptografa: usa a chave privada real
     * do projeto + a chave pública efêmera que veio junto no payload criptografado.
     */
    public byte[] deriveUnwrappingKey(PrivateKey projectPrivateKey, PublicKey ephemeralPublicKey) throws GeneralSecurityException {
        byte[] sharedSecret = computeSharedSecret(projectPrivateKey, ephemeralPublicKey);
        return hkdf(sharedSecret);
    }

    private byte[] computeSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws GeneralSecurityException {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(CURVE);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

    /**
     * HKDF simplificado (RFC 5869) usando HMAC-SHA256.
     * Transforma o segredo ECDH "cru" (que pode ter viés estatístico)
     * numa chave AES de 256 bits uniformemente distribuída.
     */
    private byte[] hkdf(byte[] sharedSecret) throws GeneralSecurityException {
        javax.crypto.Mac hmac = javax.crypto.Mac.getInstance(HKDF_ALGORITHM);

        // Extract: gera uma chave pseudo-aleatória a partir do segredo
        hmac.init(new SecretKeySpec(new byte[32], HKDF_ALGORITHM)); // salt vazio (aceitável para ECDH)
        byte[] pseudoRandomKey = hmac.doFinal(sharedSecret);

        // Expand: gera os 32 bytes finais (256 bits) a partir da PRK + contexto
        hmac.init(new SecretKeySpec(pseudoRandomKey, HKDF_ALGORITHM));
        hmac.update(HKDF_INFO);
        hmac.update((byte) 0x01);
        return java.util.Arrays.copyOf(hmac.doFinal(), 32);
    }
}