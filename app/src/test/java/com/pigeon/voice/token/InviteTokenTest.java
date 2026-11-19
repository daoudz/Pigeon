package com.pigeon.voice.token;

import com.pigeon.voice.contacts.ContactItem;
import com.pigeon.voice.crypto.CryptoEngine;

import org.junit.Test;

import java.security.KeyPair;
import java.util.Arrays;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class InviteTokenTest {

    @Test
    public void testTokenAndDeepLinkRoundtrip() throws Exception {
        KeyPair kp = CryptoEngine.generateEphemeralKeyPair();
        byte[] secret = CryptoEngine.randomBytes(CryptoEngine.INVITE_SECRET_BYTES);
        String aliceHash = ContactItem.computeContactHash("+1 (555) 234-5678");
        long expires = System.currentTimeMillis() + 600_000L;

        InviteToken original = new InviteToken(
                "sess12345678",
                Arrays.asList("192.168.1.42", "10.0.0.8"),
                44551,
                44552,
                kp.getPublic().getEncoded(),
                secret,
                "Daoud",
                aliceHash,
                expires
        );

        // 1. Parse from compact token
        String compact = original.toCompactToken();
        assertTrue(compact.startsWith("PGN1."));
        InviteToken fromCompact = InviteToken.fromTokenOrLink(compact);
        assertTokensMatch(original, fromCompact);

        // 2. Parse from pigeon:// deep link
        String deepLink = original.toShareableLink();
        assertTrue(deepLink.startsWith("pigeon://call/join?token=PGN1."));
        InviteToken fromLink = InviteToken.fromTokenOrLink(deepLink);
        assertTokensMatch(original, fromLink);

        // 3. Parse from full multi-line SMS / WhatsApp share message
        String fullMessage = original.toShareMessage("Alice");
        InviteToken fromMessage = InviteToken.fromTokenOrLink(fullMessage);
        assertTokensMatch(original, fromMessage);
    }

    @Test
    public void testContactRestrictionAndPhoneNormalization() throws Exception {
        KeyPair kp = CryptoEngine.generateEphemeralKeyPair();
        byte[] secret = CryptoEngine.randomBytes(CryptoEngine.INVITE_SECRET_BYTES);
        String aliceHash = ContactItem.computeContactHash("+1 (555) 867-5309");

        InviteToken restrictedToken = new InviteToken(
                "sessContact1",
                Arrays.asList("192.168.1.10"),
                5000,
                5001,
                kp.getPublic().getEncoded(),
                secret,
                "HostUser",
                aliceHash,
                System.currentTimeMillis() + 300_000L
        );

        assertTrue(restrictedToken.isContactRestricted());
        // Same phone number formatted without country code or parentheses must match
        String aliceLocalFormatHash = ContactItem.computeContactHash("555-867-5309");
        assertTrue(restrictedToken.isContactPermitted(aliceLocalFormatHash));

        // Different phone number must be rejected
        String intruderHash = ContactItem.computeContactHash("555-999-0000");
        assertFalse(restrictedToken.isContactPermitted(intruderHash));
        assertFalse(restrictedToken.isContactPermitted(""));
        assertFalse(restrictedToken.isContactPermitted(null));
    }

    @Test
    public void testTamperedTokenRejected() throws Exception {
        KeyPair kp = CryptoEngine.generateEphemeralKeyPair();
        byte[] secret = CryptoEngine.randomBytes(CryptoEngine.INVITE_SECRET_BYTES);

        InviteToken token = new InviteToken(
                "sessTamper01",
                Arrays.asList("192.168.1.5"),
                6000,
                6001,
                kp.getPublic().getEncoded(),
                secret,
                "Host",
                "",
                System.currentTimeMillis() + 300_000L
        );

        String compact = token.toCompactToken();
        // Flip an interior character of the HMAC tag (guarantees real MAC bits change)
        int interiorIdx = compact.length() - 3;
        char interiorChar = compact.charAt(interiorIdx);
        char interiorRepl = (interiorChar == 'A') ? 'B' : 'A';
        String tamperedInterior = compact.substring(0, interiorIdx) + interiorRepl + compact.substring(interiorIdx + 1);

        try {
            InviteToken.fromTokenOrLink(tamperedInterior);
            fail("Expected IllegalArgumentException on tampered token HMAC");
        } catch (IllegalArgumentException expected) {
        }

        // Also verify flipping the trailing character (including non-canonical pad bits) is rejected
        char lastChar = compact.charAt(compact.length() - 1);
        char lastRepl = (lastChar == 'A') ? 'B' : 'A';
        String tamperedTail = compact.substring(0, compact.length() - 1) + lastRepl;

        try {
            InviteToken.fromTokenOrLink(tamperedTail);
            fail("Expected IllegalArgumentException on tampered trailing HMAC char");
        } catch (IllegalArgumentException expected) {
        }
    }

    @Test
    public void testTokenSanitizesAndCapsExcessHostAddresses() throws Exception {
        KeyPair kp = CryptoEngine.generateEphemeralKeyPair();
        byte[] secret = CryptoEngine.randomBytes(CryptoEngine.INVITE_SECRET_BYTES);
        java.util.List<String> manyAddresses = new java.util.ArrayList<>();
        manyAddresses.add(null);
        manyAddresses.add("   ");
        for (int i = 1; i <= 22; i++) {
            manyAddresses.add("192.168.1." + i);
        }

        InviteToken token = new InviteToken(
                "sessManyIps",
                manyAddresses,
                7000,
                7001,
                kp.getPublic().getEncoded(),
                secret,
                "HostMany",
                "",
                System.currentTimeMillis() + 300_000L
        );

        assertEquals("Address list must be sanitized and capped at 16", 16, token.getHostAddresses().size());
        InviteToken parsed = InviteToken.fromTokenOrLink(token.toCompactToken());
        assertTokensMatch(token, parsed);
    }

    private static void assertTokensMatch(InviteToken a, InviteToken b) {
        assertEquals(a.getSessionId(), b.getSessionId());
        assertEquals(a.getHostAddresses(), b.getHostAddresses());
        assertEquals(a.getTcpPort(), b.getTcpPort());
        assertEquals(a.getUdpPort(), b.getUdpPort());
        assertArrayEquals(a.getHostPublicKey(), b.getHostPublicKey());
        assertArrayEquals(a.getInviteSecret(), b.getInviteSecret());
        assertEquals(a.getHostDisplayName(), b.getHostDisplayName());
        assertEquals(a.getAllowedContactHash(), b.getAllowedContactHash());
        assertEquals(a.getExpiresAtEpochMs(), b.getExpiresAtEpochMs());
    }
}
