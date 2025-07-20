package com.fabiankevin.springbootcryptographic;

import com.fabiankevin.springbootcryptographic.service.EncryptionAESGCMService;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EncryptionAESGCMServiceTest {
    private final EncryptionAESGCMService encryptionService = new EncryptionAESGCMService();

    @Test
     void testEncryptDecrypt() throws Exception {
        String plaintext = "Hello, World!";
        String encrypted = encryptionService.encrypt(plaintext);
        System.out.println("encrypted = " + encrypted);
        String decrypted = encryptionService.decrypt(encrypted);

        assertEquals(plaintext, decrypted, "Should be able to decrypt back to original plaintext");
    }

    @Test
     void testEncodingDecoding() {
        byte[] encryptionKey = new byte[32];
        SecureRandom random = new SecureRandom();
        random.nextBytes(encryptionKey);

        String base64Key = Base64.getEncoder().encodeToString(encryptionKey);
        System.out.println(base64Key);
        byte[] decodedEncryptionKey = Base64.getDecoder().decode(base64Key);
        assertEquals(32, decodedEncryptionKey.length);
    }
}
