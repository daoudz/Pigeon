package com.pigeon.voice.net;

/**
 * Represents an encrypted chat message (Text, Shared Image, or System Security Event)
 * inside a Pigeon call session.
 */
public final class ChatMessage {

    public enum Type {
        TEXT,
        IMAGE,
        SYSTEM
    }

    private final String messageId;
    private final Type type;
    private final String senderName;
    private final boolean outgoing;
    private final long timestampEpochMs;
    private final String text;
    private final byte[] imageBytes;
    private volatile boolean delivered;
    private volatile int transferProgress; // 0..100

    public ChatMessage(
            String messageId,
            Type type,
            String senderName,
            boolean outgoing,
            long timestampEpochMs,
            String text,
            byte[] imageBytes,
            boolean delivered,
            int transferProgress) {
        this.messageId = messageId;
        this.type = type;
        this.senderName = senderName;
        this.outgoing = outgoing;
        this.timestampEpochMs = timestampEpochMs;
        this.text = text;
        this.imageBytes = imageBytes;
        this.delivered = delivered;
        this.transferProgress = transferProgress;
    }

    public static ChatMessage createText(
            String messageId,
            String senderName,
            boolean outgoing,
            String text,
            long timestampMs) {
        return new ChatMessage(
                messageId,
                Type.TEXT,
                senderName,
                outgoing,
                timestampMs,
                text,
                null,
                !outgoing,
                100);
    }

    public static ChatMessage createImage(
            String messageId,
            String senderName,
            boolean outgoing,
            byte[] imageBytes,
            long timestampMs,
            boolean delivered) {
        return new ChatMessage(
                messageId,
                Type.IMAGE,
                senderName,
                outgoing,
                timestampMs,
                "Encrypted Image (" + (imageBytes != null ? (imageBytes.length / 1024) : 0) + " KB)",
                imageBytes,
                delivered,
                100);
    }

    public static ChatMessage createSystem(String text) {
        return new ChatMessage(
                "sys-" + System.nanoTime(),
                Type.SYSTEM,
                "Security Engine",
                false,
                System.currentTimeMillis(),
                text,
                null,
                true,
                100);
    }

    public String getMessageId() {
        return messageId;
    }

    public Type getType() {
        return type;
    }

    public String getSenderName() {
        return senderName;
    }

    public boolean isOutgoing() {
        return outgoing;
    }

    public long getTimestampEpochMs() {
        return timestampEpochMs;
    }

    public String getText() {
        return text;
    }

    public byte[] getImageBytes() {
        return imageBytes;
    }

    public boolean isDelivered() {
        return delivered;
    }

    public void setDelivered(boolean delivered) {
        this.delivered = delivered;
    }

    public int getTransferProgress() {
        return transferProgress;
    }

    public void setTransferProgress(int transferProgress) {
        this.transferProgress = transferProgress;
    }
}
