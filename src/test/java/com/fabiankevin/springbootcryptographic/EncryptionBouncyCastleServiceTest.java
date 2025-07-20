package com.fabiankevin.springbootcryptographic;

import com.fabiankevin.springbootcryptographic.service.EncryptionBouncyCastleService;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EncryptionBouncyCastleServiceTest {

    private final EncryptionBouncyCastleService encryptionService = new EncryptionBouncyCastleService();
    private final String secretKey = Base64.getEncoder().encodeToString(new SecureRandom().generateSeed(32));

    @Test
    void testEncryptDecrypt() throws Exception {
        String plaintext = "Hello, World!";
        String encrypted = encryptionService.encrypt(plaintext, secretKey);
        System.out.println("encrypted = " + encrypted);
        String decrypted = encryptionService.decrypt(encrypted, secretKey);

        assertEquals(plaintext, decrypted, "Should be able to decrypt back to original plaintext");
    }
}
