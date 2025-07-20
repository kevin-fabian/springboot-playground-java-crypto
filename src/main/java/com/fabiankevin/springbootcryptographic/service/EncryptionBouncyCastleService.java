package com.fabiankevin.springbootcryptographic.service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;

@Service
public class EncryptionBouncyCastleService {

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int KEY_SIZE = 256; // AES-256
    private static final int GCM_NONCE_LENGTH = 12; // 96 bits for GCM
    private static final int GCM_TAG_LENGTH = 128; // 128-bit authentication tag

    public EncryptionBouncyCastleService() {
        // Register BouncyCastle as a security provider
        Security.addProvider(new BouncyCastleProvider());
    }

    public String encrypt(String plaintext, String secretKey) throws Exception {
        // Generate a random nonce
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        SecureRandom random = new SecureRandom();
        random.nextBytes(nonce);

        // Prepare the secret key
        SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(secretKey), ALGORITHM);

        // Initialize cipher for encryption
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, "BC");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmSpec);

        // Encrypt the plaintext
        byte[] ciphertext = cipher.doFinal(plaintext.getBytes("UTF-8"));

        // Combine nonce and ciphertext for storage
        byte[] encryptedData = new byte[nonce.length + ciphertext.length];
        System.arraycopy(nonce, 0, encryptedData, 0, nonce.length);
        System.arraycopy(ciphertext, 0, encryptedData, nonce.length, ciphertext.length);

        // Return Base64-encoded result
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    public String decrypt(String encryptedData, String secretKey) throws Exception {
        // Decode the encrypted data
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);

        // Extract nonce and ciphertext
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        byte[] ciphertext = new byte[decodedData.length - GCM_NONCE_LENGTH];
        System.arraycopy(decodedData, 0, nonce, 0, GCM_NONCE_LENGTH);
        System.arraycopy(decodedData, GCM_NONCE_LENGTH, ciphertext, 0, ciphertext.length);

        // Prepare the secret key
        SecretKeySpec keySpec = new SecretKeySpec(Base64.getDecoder().decode(secretKey), ALGORITHM);

        // Initialize cipher for decryption
        Cipher cipher = Cipher.getInstance(TRANSFORMATION, "BC");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmSpec);

        // Decrypt the ciphertext
        byte[] plaintext = cipher.doFinal(ciphertext);

        return new String(plaintext, "UTF-8");
    }

}