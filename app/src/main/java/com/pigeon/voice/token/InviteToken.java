package com.pigeon.voice.token;

import com.pigeon.voice.crypto.CryptoEngine;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Serverless P2P Call Invitation Token & Deep Link Generator/Parser.
 *
 * Encapsulates:
 * - Session ID
 * - Host candidate IPv4 addresses (LAN, Hotspot, VPN, Direct)
 * - TCP control/data port & UDP low-latency voice port
 * - Host ephemeral EC P-256 public key
 * - 128-bit one-time Invite Secret (PSK required to complete ECDH handshake)
 * - Host display name
 * - Optional target Contact binding hash (ensures only the selected contact can join)
 * - Expiration timestamp
 */
public final class InviteToken {

    public static final String TOKEN_PREFIX = "PGN1";
    public static final String DEEP_LINK_SCHEME = "pigeon";
    public static final String DEEP_LINK_HOST = "call";
    public static final String DEEP_LINK_PATH = "/join";
    public static final String DEEP_LINK_BASE = "pigeon://call/join?token=";
    public static final long DEFAULT_TTL_MS = 15 * 60 * 1000L; // 15 minutes

    private static final byte FORMAT_VERSION = 1;
    private static final int INTEGRITY_TAG_BYTES = 8;
    private static final Pattern TOKEN_EXTRACT_PATTERN =
            Pattern.compile("(PGN1\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+)");

    private final String sessionId;
    private final List<String> hostAddresses;
    private final int tcpPort;
    private final int udpPort;
    private final byte[] hostPublicKey;
    private final byte[] inviteSecret;
    private final String hostDisplayName;
    private final String allowedContactHash;
    private final long expiresAtEpochMs;

    public InviteToken(
            String sessionId,
            List<String> hostAddresses,
            int tcpPort,
            int udpPort,
            byte[] hostPublicKey,
            byte[] inviteSecret,
            String hostDisplayName,
            String allowedContactHash,
            long expiresAtEpochMs) {

        if (sessionId == null || sessionId.trim().isEmpty()) {
            throw new IllegalArgumentException("sessionId required");
        }
        if (hostAddresses == null || hostAddresses.isEmpty()) {
            throw new IllegalArgumentException("At least one host address required");
        }
        List<String> cleanedAddresses = new ArrayList<>();
        for (String addr : hostAddresses) {
            if (addr != null && !addr.trim().isEmpty()) {
                String trimmedAddr = addr.trim();
                if (!cleanedAddresses.contains(trimmedAddr)) {
                    cleanedAddresses.add(trimmedAddr);
                    if (cleanedAddresses.size() == 16) {
                        break;
                    }
                }
            }
        }
        if (cleanedAddresses.isEmpty()) {
            throw new IllegalArgumentException("At least one valid host address required");
        }
        if (tcpPort <= 0 || tcpPort > 65535 || udpPort <= 0 || udpPort > 65535) {
            throw new IllegalArgumentException("Invalid TCP or UDP port");
        }
        if (hostPublicKey == null || hostPublicKey.length == 0) {
            throw new IllegalArgumentException("hostPublicKey required");
        }
        if (inviteSecret == null || inviteSecret.length < CryptoEngine.INVITE_SECRET_BYTES) {
            throw new IllegalArgumentException("inviteSecret must be at least 16 bytes");
        }

        this.sessionId = sessionId.trim();
        this.hostAddresses = Collections.unmodifiableList(cleanedAddresses);
        this.tcpPort = tcpPort;
        this.udpPort = udpPort;
        this.hostPublicKey = Arrays.copyOf(hostPublicKey, hostPublicKey.length);
        this.inviteSecret = Arrays.copyOf(inviteSecret, inviteSecret.length);
        this.hostDisplayName = (hostDisplayName == null || hostDisplayName.trim().isEmpty())
                ? "Pigeon Peer" : hostDisplayName.trim();
        this.allowedContactHash = (allowedContactHash == null) ? "" : allowedContactHash.trim();
        this.expiresAtEpochMs = expiresAtEpochMs;
    }

    public String getSessionId() {
        return sessionId;
    }

    public List<String> getHostAddresses() {
        return hostAddresses;
    }

    public String getPrimaryHostAddress() {
        return hostAddresses.get(0);
    }

    public int getTcpPort() {
        return tcpPort;
    }

    public int getUdpPort() {
        return udpPort;
    }

    public byte[] getHostPublicKey() {
        return Arrays.copyOf(hostPublicKey, hostPublicKey.length);
    }

    public byte[] getInviteSecret() {
        return Arrays.copyOf(inviteSecret, inviteSecret.length);
    }

    public String getHostDisplayName() {
        return hostDisplayName;
    }

    public String getAllowedContactHash() {
        return allowedContactHash;
    }

    public boolean isContactRestricted() {
        return !allowedContactHash.isEmpty();
    }

    public long getExpiresAtEpochMs() {
        return expiresAtEpochMs;
    }

    public boolean isExpired(long currentEpochMs) {
        return currentEpochMs > expiresAtEpochMs;
    }

    /**
     * Checks whether a joining peer's normalized contact hash is permitted by this token.
     */
    public boolean isContactPermitted(String joinerContactHash) {
        if (!isContactRestricted()) {
            return true;
        }
        if (joinerContactHash == null || joinerContactHash.trim().isEmpty()) {
            return false;
        }
        return CryptoEngine.constantTimeEquals(
                allowedContactHash.getBytes(StandardCharsets.UTF_8),
                joinerContactHash.trim().getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Encodes this invitation into a compact, signed Base64URL string:
     * PGN1.<payload>.<hmac8>
     */
    public String toCompactToken() {
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            dos.writeByte(FORMAT_VERSION);
            dos.writeUTF(sessionId);
            dos.writeByte(hostAddresses.size());
            for (String addr : hostAddresses) {
                dos.writeUTF(addr);
            }
            dos.writeInt(tcpPort);
            dos.writeInt(udpPort);
            dos.writeShort(hostPublicKey.length);
            dos.write(hostPublicKey);
            dos.writeByte(inviteSecret.length);
            dos.write(inviteSecret);
            dos.writeUTF(hostDisplayName);
            dos.writeUTF(allowedContactHash);
            dos.writeLong(expiresAtEpochMs);
            dos.flush();

            byte[] payloadBytes = baos.toByteArray();
            byte[] tag = computeIntegrityTag(inviteSecret, payloadBytes);

            Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
            return TOKEN_PREFIX + "."
                    + encoder.encodeToString(payloadBytes) + "."
                    + encoder.encodeToString(tag);
        } catch (IOException | GeneralSecurityException e) {
            throw new IllegalStateException("Failed to serialize InviteToken", e);
        }
    }

    /**
     * Formats a clickable deep link URI: pigeon://call/join?token=PGN1...
     */
    public String toShareableLink() {
        return DEEP_LINK_BASE + toCompactToken();
    }

    /**
     * Builds a user-friendly share message containing both the clickable deep link and raw token.
     */
    public String toShareMessage(String invitedContactName) {
        String compact = toCompactToken();
        String link = DEEP_LINK_BASE + compact;
        StringBuilder sb = new StringBuilder();
        if (invitedContactName != null && !invitedContactName.trim().isEmpty()) {
            sb.append("Hi ").append(invitedContactName.trim()).append(", ");
        }
        sb.append(hostDisplayName).append(" is inviting you to an encrypted Pigeon voice call.\n\n");
        sb.append("Tap link to join:\n").append(link).append("\n\n");
        sb.append("Or paste this one-time secure token in Pigeon:\n").append(compact);
        return sb.toString();
    }

    /**
     * Parses an InviteToken from a raw token string, a pigeon:// deep link URI,
     * or an entire chat/SMS invitation text containing the token.
     */
    public static InviteToken fromTokenOrLink(String rawInput) throws IllegalArgumentException {
        if (rawInput == null || rawInput.trim().isEmpty()) {
            throw new IllegalArgumentException("Empty invite token or link");
        }

        String candidate = extractCompactToken(rawInput.trim());
        String[] parts = candidate.split("\\.");
        if (parts.length != 3 || !TOKEN_PREFIX.equals(parts[0])) {
            throw new IllegalArgumentException("Invalid Pigeon token format");
        }

        try {
            Base64.Decoder decoder = Base64.getUrlDecoder();
            byte[] payloadBytes = decoder.decode(parts[1]);
            byte[] providedTag = decoder.decode(parts[2]);

            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(payloadBytes));
            byte version = dis.readByte();
            if (version != FORMAT_VERSION) {
                throw new IllegalArgumentException("Unsupported token version: " + version);
            }

            String sessionId = dis.readUTF();
            int addrCount = dis.readUnsignedByte();
            if (addrCount <= 0 || addrCount > 16) {
                throw new IllegalArgumentException("Invalid address count in token");
            }
            List<String> addresses = new ArrayList<>(addrCount);
            for (int i = 0; i < addrCount; i++) {
                addresses.add(dis.readUTF());
            }

            int tcpPort = dis.readInt();
            int udpPort = dis.readInt();

            int pubKeyLen = dis.readUnsignedShort();
            if (pubKeyLen <= 0 || pubKeyLen > 512) {
                throw new IllegalArgumentException("Invalid public key length in token");
            }
            byte[] hostPublicKey = new byte[pubKeyLen];
            dis.readFully(hostPublicKey);

            int secretLen = dis.readUnsignedByte();
            if (secretLen < CryptoEngine.INVITE_SECRET_BYTES || secretLen > 64) {
                throw new IllegalArgumentException("Invalid secret length in token");
            }
            byte[] inviteSecret = new byte[secretLen];
            dis.readFully(inviteSecret);

            String hostDisplayName = dis.readUTF();
            String allowedContactHash = dis.readUTF();
            long expiresAtEpochMs = dis.readLong();
            if (dis.available() != 0) {
                throw new IllegalArgumentException("Unexpected trailing bytes in token payload");
            }

            // Verify canonical Base64URL encoding and integrity tag
            String canonicalTag = Base64.getUrlEncoder().withoutPadding().encodeToString(providedTag);
            byte[] expectedTag = computeIntegrityTag(inviteSecret, payloadBytes);
            if (!canonicalTag.equals(parts[2])
                    || !CryptoEngine.constantTimeEquals(expectedTag, providedTag)) {
                throw new IllegalArgumentException("Token integrity check failed (corrupted or tampered)");
            }

            // Validate that public key is a valid EC P-256 key
            CryptoEngine.decodePublicKey(hostPublicKey);

            return new InviteToken(
                    sessionId,
                    addresses,
                    tcpPort,
                    udpPort,
                    hostPublicKey,
                    inviteSecret,
                    hostDisplayName,
                    allowedContactHash,
                    expiresAtEpochMs
            );
        } catch (IllegalArgumentException e) {
            throw e;
        } catch (Exception e) {
            throw new IllegalArgumentException("Malformed Pigeon invite token: " + e.getMessage(), e);
        }
    }

    private static String extractCompactToken(String input) {
        Matcher matcher = TOKEN_EXTRACT_PATTERN.matcher(input);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return input;
    }

    private static byte[] computeIntegrityTag(byte[] inviteSecret, byte[] payloadBytes)
            throws GeneralSecurityException {
        byte[] hmacKey = CryptoEngine.sha256(
                ("PIGEON_TOKEN_MAC:" + Base64.getUrlEncoder().encodeToString(inviteSecret))
                        .getBytes(StandardCharsets.UTF_8));
        byte[] fullMac = CryptoEngine.hmacSha256(hmacKey, payloadBytes);
        return Arrays.copyOf(fullMac, INTEGRITY_TAG_BYTES);
    }
}
