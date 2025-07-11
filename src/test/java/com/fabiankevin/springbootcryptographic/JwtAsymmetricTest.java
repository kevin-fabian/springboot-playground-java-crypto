package com.fabiankevin.springbootcryptographic;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.security.*;
import java.time.Instant;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertEquals;

class JwtAsymmetricTest {

    @ParameterizedTest
    @ValueSource(strings = {"RSA", "Ed25519"})
    void testJwtAsymmetric(String algorithm) throws NoSuchAlgorithmException {
        // Generate RSA key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(algorithm);
        if(algorithm.equals("RSA")){
                    keyPairGenerator.initialize(2048);
        }
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        // Create JWT
        Instant now = Instant.now();
        String jwt = Jwts.builder()
                .subject("user123")
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(3600)))
                .claim("role", "admin")
                .signWith(privateKey)
                .compact();

        System.out.println("Generated JWT: " + jwt);

        String subject = Jwts.parser()
                .verifyWith(publicKey)
                .build()
                .parseSignedClaims(jwt)
                .getPayload()
                .getSubject();

        assertEquals("user123", subject, "JWT subject does not match the original userId");
    }
}
