package com.fabiankevin.springbootcryptographic;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.junit.jupiter.api.Test;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;

class JwtSymmetricTest {

    @Test
    void signAndVerify() {
        String userId = "userId1";
        String base64EncyptionKey = "K41amgtcyriACf6dOFQDQe+sOorDLFPdG9utjetzy5M=";
        byte[] decodedKey = Base64.getDecoder().decode(base64EncyptionKey);
        Key key = new SecretKeySpec(decodedKey, SignatureAlgorithm.HS256.getJcaName());

//        SecureRandom random = new SecureRandom();
//        byte[] encryptionKey = new byte[32]; // 256 bits
//        random.nextBytes(encryptionKey);
//        String encodedBase64Key = Base64.getEncoder().encodeToString(encryptionKey);

//        System.out.println("Base64 Encoded Key: " + encodedBase64Key);

        String jwt = Jwts.builder()
                .subject(userId)
                .id(UUID.randomUUID().toString()) // Unique token ID
                .issuedAt(Date.from(Instant.now()))
                .expiration(Date.from(Instant.now().plusSeconds(300)))
                .signWith(key)
                .compact();


        String subject = Jwts.parser()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(jwt)
                .getBody()
                .getSubject();

        assertEquals(userId, subject, "JWT subject does not match the original userId");
    }
}
