package com.fabiankevin.springbootcryptographic;


import org.junit.jupiter.api.Test;

import javax.crypto.KeyAgreement;
import java.security.*;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class KeyExchangeX25519Test {


    @Test
    void testKeyExchangeX25519() throws NoSuchAlgorithmException, InvalidKeyException {
        // Generate key pairs for Alice and Bob
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("X25519");
        KeyPair aliceKeyPair = kpg.generateKeyPair();
        KeyPair bobKeyPair = kpg.generateKeyPair();

        // Alice creates shared secret
        KeyAgreement aliceKeyAgree = KeyAgreement.getInstance("X25519");
        aliceKeyAgree.init(aliceKeyPair.getPrivate());
        aliceKeyAgree.doPhase(bobKeyPair.getPublic(), true);
        byte[] aliceSharedSecret = aliceKeyAgree.generateSecret();

        // Bob creates shared secret
        KeyAgreement bobKeyAgree = KeyAgreement.getInstance("X25519");
        bobKeyAgree.init(bobKeyPair.getPrivate());
        bobKeyAgree.doPhase(aliceKeyPair.getPublic(), true);
        byte[] bobSharedSecret = bobKeyAgree.generateSecret();

        assertEquals(32, MessageDigest.getInstance("SHA-256").digest(aliceSharedSecret).length, "Shared secret length should be 32 bytes");
        assertTrue(java.util.Arrays.equals(aliceSharedSecret, bobSharedSecret), "Shared secrets should match");
    }
}
