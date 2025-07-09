package com.fabiankevin.springbootcryptographic;

import jakarta.xml.bind.DatatypeConverter;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ChecksumTest {


    @Test
    void checkSumTest() {
        String input = "1234567890";

        String checksum = generateSHA256(input);

        assertEquals(64, checksum.length(), "SHA-256 checksum should be 64 characters long");
        assertEquals("c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646", checksum);
        assertEquals("c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646", generateSHA256ViaStringFormatHexadecimal(input));
        assertEquals("c775e7b757ede630cd0aa1113bd102661ab38829ca52a6422ab782862f268646", generateSHA256ViaStringFormatString(input));
    }

    @Test
    void test() {
        String input = "1234567890";
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            BigInteger bigInteger = new BigInteger(1, hash);
            assertEquals(64, bigInteger.toString(16).length(), "SHA-256 hash should be 64 characters long");
            System.out.println(bigInteger);
            System.out.println(bigInteger.toString(16));
        } catch (Exception e) {
            throw new RuntimeException("Error generating SHA-256 checksum", e);
        }

    }

    public static String generateSHA256(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return DatatypeConverter.printHexBinary(hash).toLowerCase();
        } catch (Exception e) {
            throw new RuntimeException("Error generating SHA-256 checksum", e);
        }
    }

    public static String generateSHA256ViaStringFormatHexadecimal(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return String.format("%064x", new BigInteger(1, hash));
        } catch (Exception e) {
            throw new RuntimeException("Error generating SHA-256 checksum", e);
        }
    }

    public static String generateSHA256ViaStringFormatString(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));

            return String.format("%64s", new BigInteger(1, hash).toString(16)).replace(' ', '0');
        } catch (Exception e) {
            throw new RuntimeException("Error generating SHA-256 checksum", e);
        }
    }
}
