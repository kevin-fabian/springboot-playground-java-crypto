package com.fabiankevin.springbootcryptographic;

import com.fabiankevin.springbootcryptographic.service.EncryptionService;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EncryptionServiceTest {
    private final EncryptionService encryptionService = new EncryptionService();

    @Test
     void testEncryptDecrypt() throws Exception {
        String plaintext = "Hello, World!";
        String encrypted = encryptionService.encrypt(plaintext);
        System.out.println("encrypted = " + encrypted);
        String decrypted = encryptionService.decrypt(encrypted);

        assert plaintext.equals(decrypted) : "Decryption did not return the original plaintext";
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
