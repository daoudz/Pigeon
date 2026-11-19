package com.pigeon.voice.crypto;

import org.junit.Test;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class CryptoEngineTest {

    @Test
    public void testEcdhKeyAgreementAndSessionKeysDerivation() throws Exception {
        KeyPair hostKp = CryptoEngine.generateEphemeralKeyPair();
        KeyPair clientKp = CryptoEngine.generateEphemeralKeyPair();

        byte[] hostSecret = CryptoEngine.computeEcdhSharedSecret(
                hostKp.getPrivate(), clientKp.getPublic().getEncoded());
        byte[] clientSecret = CryptoEngine.computeEcdhSharedSecret(
                clientKp.getPrivate(), hostKp.getPublic().getEncoded());

        assertArrayEquals("ECDH shared secrets must match", hostSecret, clientSecret);

        byte[] inviteSecret = CryptoEngine.randomBytes(CryptoEngine.INVITE_SECRET_BYTES);
        byte[] hostNonce = CryptoEngine.randomBytes(CryptoEngine.NONCE_CHALLENGE_BYTES);
        byte[] clientNonce = CryptoEngine.randomBytes(CryptoEngine.NONCE_CHALLENGE_BYTES);

        CryptoEngine.SessionKeys hostKeys = CryptoEngine.deriveSessionKeys(
                hostSecret,
                inviteSecret,
                hostKp.getPublic().getEncoded(),
                clientKp.getPublic().getEncoded(),
                hostNonce,
                clientNonce);

        CryptoEngine.SessionKeys clientKeys = CryptoEngine.deriveSessionKeys(
                clientSecret,
                inviteSecret,
                hostKp.getPublic().getEncoded(),
                clientKp.getPublic().getEncoded(),
                hostNonce,
                clientNonce);

        assertEquals("Safety Numbers (SAS) must match on both ends",
                hostKeys.getSafetyNumber(), clientKeys.getSafetyNumber());
        assertArrayEquals(
                hostKeys.getOutboundControlKey(true).getEncoded(),
                clientKeys.getInboundControlKey(false).getEncoded());
        assertArrayEquals(
                clientKeys.getOutboundControlKey(false).getEncoded(),
                hostKeys.getInboundControlKey(true).getEncoded());
        assertArrayEquals(
                hostKeys.getOutboundAudioKey(true).getEncoded(),
                clientKeys.getInboundAudioKey(false).getEncoded());

        // Directional keys must be cryptographically distinct
        assertFalse(CryptoEngine.constantTimeEquals(
                hostKeys.getOutboundControlKey(true).getEncoded(),
                hostKeys.getInboundControlKey(true).getEncoded()));
    }

    @Test
    public void testAesGcmEncryptDecryptAndTamperRejection() throws Exception {
        KeyPair hostKp = CryptoEngine.generateEphemeralKeyPair();
        KeyPair clientKp = CryptoEngine.generateEphemeralKeyPair();
        byte[] ecdh = CryptoEngine.computeEcdhSharedSecret(
                hostKp.getPrivate(), clientKp.getPublic().getEncoded());
        byte[] tokenSecret = CryptoEngine.randomBytes(CryptoEngine.INVITE_SECRET_BYTES);
        byte[] hNonce = CryptoEngine.randomBytes(CryptoEngine.NONCE_CHALLENGE_BYTES);
        byte[] cNonce = CryptoEngine.randomBytes(CryptoEngine.NONCE_CHALLENGE_BYTES);

        CryptoEngine.SessionKeys keys = CryptoEngine.deriveSessionKeys(
                ecdh, tokenSecret,
                hostKp.getPublic().getEncoded(), clientKp.getPublic().getEncoded(),
                hNonce, cNonce);

        byte[] plaintext = "Secret voice & chat payload".getBytes(StandardCharsets.UTF_8);
        byte[] ciphertext = CryptoEngine.encryptFrame(
                keys.getOutboundControlKey(true),
                CryptoEngine.CHANNEL_HOST_TO_CLIENT_CTRL,
                (byte) 0x20,
                42L,
                plaintext);

        assertNotNull(ciphertext);
        assertEquals(plaintext.length + CryptoEngine.GCM_TAG_BYTES, ciphertext.length);

        byte[] decrypted = CryptoEngine.decryptFrame(
                keys.getInboundControlKey(false),
                CryptoEngine.CHANNEL_HOST_TO_CLIENT_CTRL,
                (byte) 0x20,
                42L,
                ciphertext);
        assertArrayEquals(plaintext, decrypted);

        // 1. Wrong sequence number must fail GCM AAD authentication
        try {
            CryptoEngine.decryptFrame(
                    keys.getInboundControlKey(false),
                    CryptoEngine.CHANNEL_HOST_TO_CLIENT_CTRL,
                    (byte) 0x20,
                    43L,
                    ciphertext);
            fail("Expected GeneralSecurityException on wrong sequence number");
        } catch (GeneralSecurityException expected) {
        }

        // 2. Wrong channel ID must fail GCM AAD authentication
        try {
            CryptoEngine.decryptFrame(
                    keys.getInboundControlKey(false),
                    CryptoEngine.CHANNEL_CLIENT_TO_HOST_CTRL,
                    (byte) 0x20,
                    42L,
                    ciphertext);
            fail("Expected GeneralSecurityException on wrong channel ID");
        } catch (GeneralSecurityException expected) {
        }

        // 3. Flipped bit in ciphertext must fail GCM authentication
        ciphertext[0] ^= 0x01;
        try {
            CryptoEngine.decryptFrame(
                    keys.getInboundControlKey(false),
                    CryptoEngine.CHANNEL_HOST_TO_CLIENT_CTRL,
                    (byte) 0x20,
                    42L,
                    ciphertext);
            fail("Expected GeneralSecurityException on tampered ciphertext");
        } catch (GeneralSecurityException expected) {
        }
    }

    @Test
    public void testReplayWindowSlidingBitmap() {
        CryptoEngine.ReplayWindow window = new CryptoEngine.ReplayWindow();

        assertFalse("Negative sequence must be rejected", window.checkAndAccept(-1));
        assertTrue(window.checkAndAccept(10));
        assertFalse("Duplicate seq 10 must be rejected", window.checkAndAccept(10));

        // Out-of-order packets
        assertTrue(window.checkAndAccept(15));
        assertTrue(window.checkAndAccept(12));
        assertFalse("Duplicate seq 12 must be rejected", window.checkAndAccept(12));
        assertTrue(window.checkAndAccept(11));

        // Large jump forward beyond 64-packet window
        assertTrue(window.checkAndAccept(100));
        assertFalse("Packet 20 is outside 64-packet window (100 - 20 >= 64)", window.checkAndAccept(20));
        assertTrue("Packet 50 is inside 64-packet window (100 - 50 < 64)", window.checkAndAccept(50));
        assertFalse("Duplicate packet 50 must be rejected", window.checkAndAccept(50));
    }

    @Test
    public void testSafetyNumberIntegerMinValueAndReplayPrecheck() {
        // 0x80000000 is Integer.MIN_VALUE; Math.abs(Integer.MIN_VALUE) is negative in Java
        byte[] minValBytes = new byte[]{(byte) 0x80, 0x00, 0x00, 0x00};
        String sas = CryptoEngine.formatSafetyNumber(minValBytes);
        assertEquals("000-000", sas);
        assertFalse("SAS must never contain negative sign", sas.contains("--"));

        CryptoEngine.ReplayWindow window = new CryptoEngine.ReplayWindow();
        assertTrue(window.checkAndAccept(1L));
        // Unauthenticated pre-check with huge sequence number must not mutate window state
        assertTrue(window.isPotentiallyValid(500_000L));
        assertTrue("Legitimate seq 2 must still be accepted after unauthenticated pre-check",
                window.checkAndAccept(2L));
        assertFalse("Already accepted seq 2 must fail pre-check",
                window.isPotentiallyValid(2L));
    }
}
