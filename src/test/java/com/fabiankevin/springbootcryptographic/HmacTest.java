package com.fabiankevin.springbootcryptographic;

import org.junit.jupiter.api.Test;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class HmacTest {

    @Test
    void hmacTest() throws NoSuchAlgorithmException, InvalidKeyException {
        String secretKey = "mySuperSecretKey123";
        String message = "Kevin is learning HMAC";

        // Convert key to bytes
        byte[] keyBytes = secretKey.getBytes();

        // Initialize HMAC with SHA-256
        Mac hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(keyBytes, "HmacSHA256");
        hmac.init(keySpec);

        // Compute HMAC
        byte[] macBytes = hmac.doFinal(message.getBytes());

        // Encode to base64 for readable output
        String hmacBase64 = Base64.getEncoder().encodeToString(macBytes);

//        The receiver should have the same key to verify the HMAC and they should generate the same HMAC
        assertEquals("GHuUTRtdX7rdWVds+PvRCXt84U9Y1zvRqocPShfzCeA=", hmacBase64);
        System.out.println("HMAC (Base64): " + hmacBase64);
    }
}
