package com.fabiankevin.springbootcryptographic;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.iv.RandomIvGenerator;
import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JasyptEncyptDecryptTest {


    @Test
    void encryptDecryptTest() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = random.generateSeed(32);
        String base64Key = Base64.getEncoder().encodeToString(bytes);
        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setPassword(base64Key);
        encryptor.setAlgorithm("PBEWithHMACSHA256AndAES_256");
        encryptor.setIvGenerator(new RandomIvGenerator());

        String plaintext = "Hello, World!";
        String encrypted = encryptor.encrypt(plaintext);
        assertEquals(plaintext, encryptor.decrypt(encrypted), "Should be able to decrypt back to original plaintext" );
    }
}
