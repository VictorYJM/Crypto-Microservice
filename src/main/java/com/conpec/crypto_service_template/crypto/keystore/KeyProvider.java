package com.conpec.crypto_service_template.crypto.keystore;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyProvider {
    PrivateKey getPrivateKey();
    PublicKey getPublicKey();
    int getKeyVersion();
}
