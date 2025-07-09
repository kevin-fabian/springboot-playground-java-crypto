package com.fabiankevin.springbootcryptographic.service;

import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class EncryptionService {
    // 256-bit key (32 bytes), should be securely stored (e.g., in a secret manager)
    private final byte[] ENCRYPTION_KEY = new byte[32];
    private static final int GCM_IV_LENGTH = 12; // Recommended IV length for GCM
    private static final int GCM_TAG_LENGTH = 16; // Authentication tag length in bytes

    public EncryptionService() {
        SecureRandom random = new SecureRandom();
        random.nextBytes(ENCRYPTION_KEY);
    }

    public String encrypt(String plaintext) throws Exception {
        // Generate random IV
        byte[] iv = new byte[GCM_IV_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // Initialize cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY, "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, parameterSpec);

        // Encrypt
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));

        // Prepend IV to ciphertext
        byte[] encryptedData = new byte[GCM_IV_LENGTH + ciphertext.length];
        System.arraycopy(iv, 0, encryptedData, 0, GCM_IV_LENGTH);
        System.arraycopy(ciphertext, 0, encryptedData, GCM_IV_LENGTH, ciphertext.length);

        // Encode to Base64 for easy storage/transmission
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public String decrypt(String encryptedData) throws Exception {
        // Decode Base64 input
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);

        // Extract IV and ciphertext
        if (decodedData.length < GCM_IV_LENGTH) {
            throw new IllegalArgumentException("Invalid encrypted data length");
        }
        byte[] iv = new byte[GCM_IV_LENGTH];
        byte[] ciphertext = new byte[decodedData.length - GCM_IV_LENGTH];
        System.arraycopy(decodedData, 0, iv, 0, GCM_IV_LENGTH);
        System.arraycopy(decodedData, GCM_IV_LENGTH, ciphertext, 0, ciphertext.length);

        // Initialize cipher
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        SecretKeySpec keySpec = new SecretKeySpec(ENCRYPTION_KEY, "AES");
        cipher.init(Cipher.DECRYPT_MODE, keySpec, parameterSpec);

        // Decrypt
        byte[] decryptedData = cipher.doFinal(ciphertext);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }
}