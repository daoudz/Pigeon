package com.pigeon.voice.crypto;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Core cryptographic engine providing:
 * - Ephemeral ECDH (secp256r1 / P-256) key agreement
 * - RFC 5869 HKDF-SHA256 key derivation bound to the one-time Invite Token secret
 * - Directional AES-256-GCM authenticated encryption for control, text, image, and voice frames
 * - Deterministic 96-bit nonce construction with AAD sequence binding
 * - O(1) 64-packet sliding window anti-replay filter for UDP voice packets
 * - Short Authentication String (SAS / Safety Number) derivation for MITM detection
 */
public final class CryptoEngine {

    public static final int AES_KEY_BYTES = 32; // 256-bit AES
    public static final int GCM_NONCE_BYTES = 12; // 96-bit nonce
    public static final int GCM_TAG_BITS = 128; // 16-byte auth tag
    public static final int GCM_TAG_BYTES = 16;
    public static final int INVITE_SECRET_BYTES = 16; // 128-bit one-time token secret
    public static final int NONCE_CHALLENGE_BYTES = 16;

    public static final byte CHANNEL_HOST_TO_CLIENT_CTRL = 0x01;
    public static final byte CHANNEL_CLIENT_TO_HOST_CTRL = 0x02;
    public static final byte CHANNEL_HOST_TO_CLIENT_AUDIO = 0x03;
    public static final byte CHANNEL_CLIENT_TO_HOST_AUDIO = 0x04;

    private static final String EC_ALGORITHM = "EC";
    private static final String EC_CURVE = "secp256r1";
    private static final String ECDH_ALGORITHM = "ECDH";
    private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String HMAC_SHA256 = "HmacSHA256";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private CryptoEngine() {
    }

    public static byte[] randomBytes(int length) {
        byte[] bytes = new byte[length];
        SECURE_RANDOM.nextBytes(bytes);
        return bytes;
    }

    /**
     * Generates an ephemeral NIST P-256 (secp256r1) key pair for a single call session.
     */
    public static KeyPair generateEphemeralKeyPair() throws GeneralSecurityException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(EC_ALGORITHM);
        keyGen.initialize(new ECGenParameterSpec(EC_CURVE), SECURE_RANDOM);
        return keyGen.generateKeyPair();
    }

    /**
     * Decodes an X.509 encoded EC public key received from a peer.
     */
    public static PublicKey decodePublicKey(byte[] encodedPublicKey) throws GeneralSecurityException {
        if (encodedPublicKey == null || encodedPublicKey.length == 0) {
            throw new GeneralSecurityException("Empty public key bytes");
        }
        KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM);
        return keyFactory.generatePublic(new X509EncodedKeySpec(encodedPublicKey));
    }

    /**
     * Performs ECDH key agreement between our ephemeral private key and the peer's public key.
     */
    public static byte[] computeEcdhSharedSecret(PrivateKey myPrivateKey, byte[] peerPublicKeyBytes)
            throws GeneralSecurityException {
        PublicKey peerPublicKey = decodePublicKey(peerPublicKeyBytes);
        KeyAgreement agreement = KeyAgreement.getInstance(ECDH_ALGORITHM);
        agreement.init(myPrivateKey);
        agreement.doPhase(peerPublicKey, true);
        return agreement.generateSecret();
    }

    /**
     * RFC 5869 HKDF-Extract using HMAC-SHA256.
     */
    public static byte[] hkdfExtract(byte[] salt, byte[] ikm) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HMAC_SHA256);
        byte[] actualSalt = (salt == null || salt.length == 0) ? new byte[32] : salt;
        mac.init(new SecretKeySpec(actualSalt, HMAC_SHA256));
        return mac.doFinal(ikm);
    }

    /**
     * RFC 5869 HKDF-Expand using HMAC-SHA256.
     */
    public static byte[] hkdfExpand(byte[] prk, byte[] info, int outputLength)
            throws GeneralSecurityException {
        if (outputLength <= 0 || outputLength > 255 * 32) {
            throw new IllegalArgumentException("Invalid HKDF output length: " + outputLength);
        }
        Mac mac = Mac.getInstance(HMAC_SHA256);
        mac.init(new SecretKeySpec(prk, HMAC_SHA256));

        byte[] result = new byte[outputLength];
        byte[] t = new byte[0];
        int offset = 0;
        byte counter = 1;

        while (offset < outputLength) {
            mac.reset();
            mac.update(t);
            if (info != null) {
                mac.update(info);
            }
            mac.update(counter);
            t = mac.doFinal();

            int copyLen = Math.min(t.length, outputLength - offset);
            System.arraycopy(t, 0, result, offset, copyLen);
            offset += copyLen;
            counter++;
        }
        return result;
    }

    /**
     * Computes HMAC-SHA256 over data using the given key.
     */
    public static byte[] hmacSha256(byte[] key, byte[] data) throws GeneralSecurityException {
        Mac mac = Mac.getInstance(HMAC_SHA256);
        mac.init(new SecretKeySpec(key, HMAC_SHA256));
        return mac.doFinal(data);
    }

    /**
     * Computes SHA-256 digest.
     */
    public static byte[] sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(data);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    /**
     * Constant-time byte array comparison to prevent timing side-channel attacks.
     */
    public static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }

    /**
     * Derives directional AES-256-GCM session keys, mutual handshake authentication keys,
     * and the human-verifiable Safety Number (SAS) from:
     * - ECDH ephemeral shared secret
     * - One-time invite secret token (PSK)
     * - Host & Client public keys and challenge nonces
     */
    public static SessionKeys deriveSessionKeys(
            byte[] ecdhSharedSecret,
            byte[] inviteSecretToken,
            byte[] hostPublicKey,
            byte[] clientPublicKey,
            byte[] hostNonce,
            byte[] clientNonce) throws GeneralSecurityException {

        if (ecdhSharedSecret == null || ecdhSharedSecret.length == 0) {
            throw new GeneralSecurityException("Invalid ECDH shared secret");
        }
        if (inviteSecretToken == null || inviteSecretToken.length < INVITE_SECRET_BYTES) {
            throw new GeneralSecurityException("Invalid invite secret token");
        }

        // Build transcript hash binding both public keys, both nonces, and the invite token
        MessageDigest transcriptDigest = MessageDigest.getInstance("SHA-256");
        transcriptDigest.update("PIGEON_V1_TRANSCRIPT".getBytes(StandardCharsets.UTF_8));
        transcriptDigest.update(hostPublicKey);
        transcriptDigest.update(clientPublicKey);
        transcriptDigest.update(hostNonce);
        transcriptDigest.update(clientNonce);
        byte[] transcriptHash = transcriptDigest.digest();

        // Combine ECDH shared secret and one-time invite secret token into IKM
        byte[] ikm = new byte[ecdhSharedSecret.length + inviteSecretToken.length];
        System.arraycopy(ecdhSharedSecret, 0, ikm, 0, ecdhSharedSecret.length);
        System.arraycopy(inviteSecretToken, 0, ikm, ecdhSharedSecret.length, inviteSecretToken.length);

        byte[] prk = hkdfExtract(transcriptHash, ikm);
        Arrays.fill(ikm, (byte) 0);

        byte[] h2cCtrl = hkdfExpand(prk, "PIGEON_H2C_CTRL".getBytes(StandardCharsets.UTF_8), AES_KEY_BYTES);
        byte[] c2hCtrl = hkdfExpand(prk, "PIGEON_C2H_CTRL".getBytes(StandardCharsets.UTF_8), AES_KEY_BYTES);
        byte[] h2cAudio = hkdfExpand(prk, "PIGEON_H2C_AUDIO".getBytes(StandardCharsets.UTF_8), AES_KEY_BYTES);
        byte[] c2hAudio = hkdfExpand(prk, "PIGEON_C2H_AUDIO".getBytes(StandardCharsets.UTF_8), AES_KEY_BYTES);
        byte[] authKey = hkdfExpand(prk, "PIGEON_HANDSHAKE_AUTH".getBytes(StandardCharsets.UTF_8), AES_KEY_BYTES);
        byte[] sasBytes = hkdfExpand(prk, "PIGEON_SAS_SAFETY".getBytes(StandardCharsets.UTF_8), 8);

        Arrays.fill(prk, (byte) 0);

        // Format 6-digit safety number XXX-XXX
        String safetyNumber = formatSafetyNumber(sasBytes);

        return new SessionKeys(
                new SecretKeySpec(h2cCtrl, "AES"),
                new SecretKeySpec(c2hCtrl, "AES"),
                new SecretKeySpec(h2cAudio, "AES"),
                new SecretKeySpec(c2hAudio, "AES"),
                authKey,
                transcriptHash,
                safetyNumber
        );
    }

    /**
     * Deterministically formats a 6-digit Safety Number (XXX-XXX) from at least 4 bytes.
     * Uses unsigned masking (0x7FFFFFFF) to avoid Math.abs(Integer.MIN_VALUE) negative overflow.
     */
    public static String formatSafetyNumber(byte[] sasBytes) {
        if (sasBytes == null || sasBytes.length < 4) {
            throw new IllegalArgumentException("sasBytes must be at least 4 bytes");
        }
        int code = ((sasBytes[0] & 0xFF) << 24)
                | ((sasBytes[1] & 0xFF) << 16)
                | ((sasBytes[2] & 0xFF) << 8)
                | (sasBytes[3] & 0xFF);
        int sixDigits = (code & 0x7FFFFFFF) % 1_000_000;
        return String.format(java.util.Locale.US, "%03d-%03d", sixDigits / 1000, sixDigits % 1000);
    }

    /**
     * Encrypts a frame with AES-256-GCM using a deterministic 96-bit nonce derived from
     * [channelId (1B), frameType (1B), 0x00, 0x00, sequenceNumber (8B)] and binds the
     * header metadata as Additional Authenticated Data (AAD).
     */
    public static byte[] encryptFrame(
            SecretKey key,
            byte channelId,
            byte frameType,
            long sequenceNumber,
            byte[] plaintext,
            int offset,
            int length) throws GeneralSecurityException {

        if (sequenceNumber < 0) {
            throw new GeneralSecurityException("Negative sequence number not allowed");
        }

        byte[] nonce = buildNonce(channelId, frameType, sequenceNumber);
        byte[] aad = buildAad(channelId, frameType, sequenceNumber);

        Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        cipher.updateAAD(aad);
        return cipher.doFinal(plaintext, offset, length);
    }

    public static byte[] encryptFrame(
            SecretKey key,
            byte channelId,
            byte frameType,
            long sequenceNumber,
            byte[] plaintext) throws GeneralSecurityException {
        return encryptFrame(key, channelId, frameType, sequenceNumber, plaintext, 0, plaintext.length);
    }

    /**
     * Decrypts and authenticates an AES-256-GCM frame. Throws GeneralSecurityException if
     * tampered, wrong key, wrong sequence number, or wrong channel/frame type.
     */
    public static byte[] decryptFrame(
            SecretKey key,
            byte channelId,
            byte frameType,
            long sequenceNumber,
            byte[] ciphertext,
            int offset,
            int length) throws GeneralSecurityException {

        if (sequenceNumber < 0) {
            throw new GeneralSecurityException("Negative sequence number not allowed");
        }
        if (ciphertext == null || length < GCM_TAG_BYTES) {
            throw new GeneralSecurityException("Ciphertext too short for GCM tag");
        }

        byte[] nonce = buildNonce(channelId, frameType, sequenceNumber);
        byte[] aad = buildAad(channelId, frameType, sequenceNumber);

        Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        cipher.updateAAD(aad);
        return cipher.doFinal(ciphertext, offset, length);
    }

    public static byte[] decryptFrame(
            SecretKey key,
            byte channelId,
            byte frameType,
            long sequenceNumber,
            byte[] ciphertext) throws GeneralSecurityException {
        return decryptFrame(key, channelId, frameType, sequenceNumber, ciphertext, 0, ciphertext.length);
    }

    private static byte[] buildNonce(byte channelId, byte frameType, long sequenceNumber) {
        byte[] nonce = new byte[GCM_NONCE_BYTES];
        nonce[0] = channelId;
        nonce[1] = frameType;
        nonce[2] = 0x50; // 'P'
        nonce[3] = 0x47; // 'G'
        ByteBuffer.wrap(nonce, 4, 8).putLong(sequenceNumber);
        return nonce;
    }

    private static byte[] buildAad(byte channelId, byte frameType, long sequenceNumber) {
        byte[] aad = new byte[10];
        aad[0] = channelId;
        aad[1] = frameType;
        ByteBuffer.wrap(aad, 2, 8).putLong(sequenceNumber);
        return aad;
    }

    /**
     * Holds the derived directional keys and authentication material for an active P2P session.
     */
    public static final class SessionKeys {
        private final SecretKey hostToClientControlKey;
        private final SecretKey clientToHostControlKey;
        private final SecretKey hostToClientAudioKey;
        private final SecretKey clientToHostAudioKey;
        private final byte[] handshakeAuthKey;
        private final byte[] transcriptHash;
        private final String safetyNumber;

        public SessionKeys(
                SecretKey hostToClientControlKey,
                SecretKey clientToHostControlKey,
                SecretKey hostToClientAudioKey,
                SecretKey clientToHostAudioKey,
                byte[] handshakeAuthKey,
                byte[] transcriptHash,
                String safetyNumber) {
            this.hostToClientControlKey = hostToClientControlKey;
            this.clientToHostControlKey = clientToHostControlKey;
            this.hostToClientAudioKey = hostToClientAudioKey;
            this.clientToHostAudioKey = clientToHostAudioKey;
            this.handshakeAuthKey = handshakeAuthKey;
            this.transcriptHash = transcriptHash;
            this.safetyNumber = safetyNumber;
        }

        public SecretKey getOutboundControlKey(boolean isHost) {
            return isHost ? hostToClientControlKey : clientToHostControlKey;
        }

        public SecretKey getInboundControlKey(boolean isHost) {
            return isHost ? clientToHostControlKey : hostToClientControlKey;
        }

        public SecretKey getOutboundAudioKey(boolean isHost) {
            return isHost ? hostToClientAudioKey : clientToHostAudioKey;
        }

        public SecretKey getInboundAudioKey(boolean isHost) {
            return isHost ? clientToHostAudioKey : hostToClientAudioKey;
        }

        public byte[] getHandshakeAuthKey() {
            return handshakeAuthKey;
        }

        public byte[] getTranscriptHash() {
            return transcriptHash;
        }

        public String getSafetyNumber() {
            return safetyNumber;
        }

        /**
         * Computes mutual authentication proof for Either Client or Host role.
         */
        public byte[] computeAuthProof(boolean isHostRole, String contactHash) throws GeneralSecurityException {
            String label = isHostRole ? "HOST_AUTH_V1:" : "CLIENT_AUTH_V1:";
            String normalizedContact = (contactHash == null) ? "" : contactHash;
            byte[] prefix = (label + normalizedContact).getBytes(StandardCharsets.UTF_8);
            byte[] data = new byte[prefix.length + transcriptHash.length];
            System.arraycopy(prefix, 0, data, 0, prefix.length);
            System.arraycopy(transcriptHash, 0, data, prefix.length, transcriptHash.length);
            return hmacSha256(handshakeAuthKey, data);
        }
    }

    /**
     * Thread-safe 64-packet sliding-window anti-replay tracker (RFC 6479 style) for UDP audio packets.
     */
    public static final class ReplayWindow {
        private static final int WINDOW_SIZE = 64;
        private long highestSeq = -1;
        private long bitmap = 0L;

        /**
         * Non-mutating pre-check before AEAD decryption so unauthenticated/spoofed UDP packets
         * cannot poison or advance the sliding replay window (RFC 4303 / RFC 6479).
         */
        public synchronized boolean isPotentiallyValid(long seq) {
            if (seq < 0) {
                return false;
            }
            if (highestSeq == -1) {
                return true;
            }
            long diff = seq - highestSeq;
            if (diff > 0) {
                return true;
            }
            long backDiff = -diff;
            if (backDiff >= WINDOW_SIZE) {
                return false; // Too old
            }
            long mask = 1L << backDiff;
            return (bitmap & mask) == 0L;
        }

        public synchronized boolean checkAndAccept(long seq) {
            if (seq < 0) {
                return false;
            }
            if (highestSeq == -1) {
                highestSeq = seq;
                bitmap = 1L;
                return true;
            }
            long diff = seq - highestSeq;
            if (diff > 0) {
                if (diff >= WINDOW_SIZE) {
                    bitmap = 1L;
                } else {
                    bitmap = (bitmap << diff) | 1L;
                }
                highestSeq = seq;
                return true;
            } else {
                long backDiff = -diff;
                if (backDiff >= WINDOW_SIZE) {
                    return false; // Too old
                }
                long mask = 1L << backDiff;
                if ((bitmap & mask) != 0L) {
                    return false; // Duplicate / replay
                }
                bitmap |= mask;
                return true;
            }
        }
    }
}
