package com.fabiankevin.springbootcryptographic;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

public class SecureExchangeDemo {

    public static void main(String[] args) throws Exception {
        String message = "Hello Bob, this is Alice.";

        // --- 1. Generate X25519 key pairs (for shared AES key) ---
        KeyPairGenerator x25519Gen = KeyPairGenerator.getInstance("X25519");
        KeyPair aliceKeyPair = x25519Gen.generateKeyPair();
        KeyPair bobKeyPair = x25519Gen.generateKeyPair();

        // Derive shared AES key (both sides will compute same key)
        byte[] sharedSecret = deriveSharedSecret(aliceKeyPair.getPrivate(), bobKeyPair.getPublic());
        SecretKey aesKey = new SecretKeySpec(Arrays.copyOf(sharedSecret, 16), "AES");

        // --- 2. Generate Ed25519 key pair for signing (Alice signs) ---
        KeyPairGenerator edGen = KeyPairGenerator.getInstance("Ed25519");
        KeyPair aliceSignKeyPair = edGen.generateKeyPair();

        // --- 3. Alice encrypts the message ---
        byte[] iv = new byte[12]; // GCM nonce
        new SecureRandom().nextBytes(iv);
        byte[] encrypted = encryptAESGCM(aesKey, iv, message.getBytes());

        // --- 4. Alice signs the ciphertext ---
        byte[] signature = signMessage(encrypted, aliceSignKeyPair.getPrivate());

        // --- Bob receives: encrypted message, IV, signature, Alice's public signing key ---
        boolean verified = verifySignature(encrypted, signature, aliceSignKeyPair.getPublic());
        if (!verified) {
            throw new SecurityException("Signature verification failed!");
        }

        String decrypted = new String(decryptAESGCM(aesKey, iv, encrypted));
        System.out.println("✅ Message verified and decrypted: " + decrypted);
    }

    static byte[] deriveSharedSecret(PrivateKey priv, PublicKey pub) throws Exception {
        KeyAgreement ka = KeyAgreement.getInstance("X25519");
        ka.init(priv);
        ka.doPhase(pub, true);
        return ka.generateSecret(); // shared key
    }

    static byte[] encryptAESGCM(SecretKey key, byte[] iv, byte[] plaintext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(plaintext);
    }

    static byte[] decryptAESGCM(SecretKey key, byte[] iv, byte[] ciphertext) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, gcmSpec);
        return cipher.doFinal(ciphertext);
    }

    static byte[] signMessage(byte[] message, PrivateKey signingKey) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initSign(signingKey);
        signature.update(message);
        return signature.sign();
    }

    static boolean verifySignature(byte[] message, byte[] sigBytes, PublicKey pubKey) throws Exception {
        Signature signature = Signature.getInstance("Ed25519");
        signature.initVerify(pubKey);
        signature.update(message);
        return signature.verify(sigBytes);
    }
}
