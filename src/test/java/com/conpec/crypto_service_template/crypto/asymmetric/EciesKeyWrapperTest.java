package com.conpec.crypto_service_template.crypto.asymmetric;

import org.junit.jupiter.api.Test;

import java.security.*;

import static org.junit.jupiter.api.Assertions.*;

class EciesKeyWrapperTest {

    private final EciesKeyWrapper keyWrapper = new EciesKeyWrapper();

    private KeyPair generateProjectKeyPair() throws NoSuchAlgorithmException {
        return KeyPairGenerator.getInstance("X25519").generateKeyPair();
    }

    @Test
    void bothSidesShouldDeriveTheSameWrappingKey() throws GeneralSecurityException {
        KeyPair projectKeyPair = generateProjectKeyPair();

        // Encryption side: derives a key using an ephemeral key pair + the project's public key
        EciesKeyWrapper.WrapResult wrapResult = keyWrapper.deriveWrappingKey(projectKeyPair.getPublic());

        // Decryption side: rebuilds the ephemeral public key from raw bytes,
        // then derives the key using the project's real private key
        PublicKey ephemeralPublicKey = KeyFactory.getInstance("X25519")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(wrapResult.ephemeralPublicKey()));
        byte[] unwrappingKey = keyWrapper.deriveUnwrappingKey(projectKeyPair.getPrivate(), ephemeralPublicKey);

        assertArrayEquals(wrapResult.wrappingKey(), unwrappingKey);
    }

    @Test
    void derivedKeyShouldBe256Bits() throws GeneralSecurityException {
        KeyPair projectKeyPair = generateProjectKeyPair();
        EciesKeyWrapper.WrapResult wrapResult = keyWrapper.deriveWrappingKey(projectKeyPair.getPublic());

        assertEquals(32, wrapResult.wrappingKey().length); // 256 bits = 32 bytes
    }

    @Test
    void ephemeralKeyPairShouldBeDifferentOnEachCall() throws GeneralSecurityException {
        KeyPair projectKeyPair = generateProjectKeyPair();

        EciesKeyWrapper.WrapResult first = keyWrapper.deriveWrappingKey(projectKeyPair.getPublic());
        EciesKeyWrapper.WrapResult second = keyWrapper.deriveWrappingKey(projectKeyPair.getPublic());

        // even wrapping for the same project public key, each call must use a fresh ephemeral key,
        // which means the resulting wrapping key is different every time (forward secrecy)
        assertFalse(java.util.Arrays.equals(first.ephemeralPublicKey(), second.ephemeralPublicKey()));
        assertFalse(java.util.Arrays.equals(first.wrappingKey(), second.wrappingKey()));
    }

    @Test
    void wrongPrivateKeyShouldProduceADifferentKey() throws GeneralSecurityException {
        KeyPair projectKeyPair = generateProjectKeyPair();
        KeyPair wrongKeyPair = generateProjectKeyPair();

        EciesKeyWrapper.WrapResult wrapResult = keyWrapper.deriveWrappingKey(projectKeyPair.getPublic());

        PublicKey ephemeralPublicKey = KeyFactory.getInstance("X25519")
                .generatePublic(new java.security.spec.X509EncodedKeySpec(wrapResult.ephemeralPublicKey()));

        // using the wrong project's private key should NOT reproduce the same wrapping key
        byte[] wrongUnwrappingKey = keyWrapper.deriveUnwrappingKey(wrongKeyPair.getPrivate(), ephemeralPublicKey);

        assertFalse(java.util.Arrays.equals(wrapResult.wrappingKey(), wrongUnwrappingKey));
    }
}