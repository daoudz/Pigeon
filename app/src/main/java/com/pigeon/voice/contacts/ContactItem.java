package com.pigeon.voice.contacts;

import com.pigeon.voice.crypto.CryptoEngine;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

/**
 * Represents a callable contact (either imported from Android ContactsContract or saved in Pigeon).
 * Provides deterministic identifier normalization and privacy-preserving SHA-256 contact hashing
 * for binding a one-time call token to a specific recipient.
 */
public final class ContactItem {

    private final String id;
    private final String name;
    private final String phoneOrHandle;
    private final boolean systemContact;
    private final long lastCalledEpochMs;

    public ContactItem(
            String id,
            String name,
            String phoneOrHandle,
            boolean systemContact,
            long lastCalledEpochMs) {
        this.id = (id == null) ? "" : id;
        this.name = (name == null || name.trim().isEmpty()) ? "Unknown Contact" : name.trim();
        this.phoneOrHandle = (phoneOrHandle == null) ? "" : phoneOrHandle.trim();
        this.systemContact = systemContact;
        this.lastCalledEpochMs = lastCalledEpochMs;
    }

    public String getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public String getPhoneOrHandle() {
        return phoneOrHandle;
    }

    public boolean isSystemContact() {
        return systemContact;
    }

    public long getLastCalledEpochMs() {
        return lastCalledEpochMs;
    }

    public String getContactHash() {
        return computeContactHash(phoneOrHandle);
    }

    public String getInitials() {
        String trimmed = name.trim();
        if (trimmed.isEmpty()) {
            return "?";
        }
        String[] parts = trimmed.split("\\s+");
        if (parts.length >= 2 && !parts[0].isEmpty() && !parts[1].isEmpty()) {
            return ("" + parts[0].charAt(0) + parts[1].charAt(0)).toUpperCase(Locale.US);
        }
        return ("" + trimmed.charAt(0)).toUpperCase(Locale.US);
    }

    /**
     * Normalizes a phone number or handle so that formatting differences
     * (e.g. "+1 (555) 234-5678" vs "555-234-5678") produce the same canonical identifier.
     */
    public static String normalizeIdentifier(String raw) {
        if (raw == null) {
            return "";
        }
        String trimmed = raw.trim().toLowerCase(Locale.US);
        if (trimmed.isEmpty()) {
            return "";
        }
        // Extract digits if it looks like a phone number
        StringBuilder digits = new StringBuilder();
        int alphaCount = 0;
        for (int i = 0; i < trimmed.length(); i++) {
            char c = trimmed.charAt(i);
            if (Character.isDigit(c)) {
                digits.append(c);
            } else if (Character.isLetter(c)) {
                alphaCount++;
            }
        }
        if (alphaCount == 0 && digits.length() >= 7) {
            // Use the last 9 digits as canonical phone tail to avoid country-code mismatch
            String d = digits.toString();
            return d.length() > 9 ? d.substring(d.length() - 9) : d;
        }
        // Otherwise normalize alphanumeric handle
        return trimmed.replaceAll("[^a-z0-9@._-]", "");
    }

    /**
     * Computes a 16-character hex SHA-256 hash of the normalized contact identifier.
     */
    public static String computeContactHash(String rawIdentifier) {
        String normalized = normalizeIdentifier(rawIdentifier);
        if (normalized.isEmpty()) {
            return "";
        }
        byte[] digest = CryptoEngine.sha256(
                ("PIGEON_CONTACT_V1:" + normalized).getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder(16);
        for (int i = 0; i < 8; i++) {
            hex.append(String.format(Locale.US, "%02x", digest[i] & 0xFF));
        }
        return hex.toString();
    }

    @Override
    public String toString() {
        return name + " (" + phoneOrHandle + ")";
    }
}
