package com.pigeon.voice.net;

import com.pigeon.voice.crypto.CryptoEngine;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Blinded E2EE Serverless Rendezvous Stream Channel over Redundant Public MQTT v3.1.1 Brokers.
 *
 * Enables two devices behind CGNAT, Symmetric 5G NAT, or carrier firewalls to establish
 * their 3-step ECDH P-256 handshake, contact-locked verification, single-peer lockout (1/1 Peer),
 * third-party intruder rejection, encrypted chat, 16KB chunked image transfer, and voice fallback
 * without deploying any custom backend server:
 *
 * 1. Derives a zero-knowledge blinded topic and an outer 256-bit AES-GCM transport key from
 *    (sessionId + inviteSecret) via RFC 5869 HKDF-SHA256.
 * 2. Connects outbound via standard Java SSLSocket (TLS 8883) / Socket (TCP 1883) to redundant
 *    public MQTT v3.1.1 brokers (EMQX, HiveMQ, Eclipse Mosquitto).
 * 3. Multiplexes per-connection virtual byte streams (clientConnId) with sequence-ordered
 *    deduplication across brokers so every P2PSessionManager security guarantee works
 *    identically over the Internet/5G and local LAN.
 */
public final class ServerlessRendezvousChannel {

    public interface HostStreamListener {
        void onIncomingClientStream(RendezvousStream stream);
    }

    public static final class BrokerEndpoint {
        private final String host;
        private final int port;
        private final boolean useTls;

        public BrokerEndpoint(String host, int port, boolean useTls) {
            if (host == null || host.trim().isEmpty()) {
                throw new IllegalArgumentException("Broker host required");
            }
            if (port <= 0 || port > 65535) {
                throw new IllegalArgumentException("Invalid broker port: " + port);
            }
            this.host = host.trim();
            this.port = port;
            this.useTls = useTls;
        }

        public String getHost() {
            return host;
        }

        public int getPort() {
            return port;
        }

        public boolean isUseTls() {
            return useTls;
        }

        @Override
        public String toString() {
            return (useTls ? "mqtts://" : "mqtt://") + host + ":" + port;
        }
    }

    public static final byte ENVELOPE_MAGIC = 0x52; // 'R'
    public static final byte DIR_CLIENT_TO_HOST = 0x01;
    public static final byte DIR_HOST_TO_CLIENT = 0x02;

    public static final byte PKT_CONN_SYN = 0x01;
    public static final byte PKT_CONN_SYN_ACK = 0x02;
    public static final byte PKT_DATA = 0x03;
    public static final byte PKT_FIN = 0x04;
    public static final byte PKT_ACK = 0x05;
    public static final byte PKT_DATAGRAM = 0x06;

    private static final byte ACK_FLAG_NORMAL = 0x00;
    private static final byte ACK_FLAG_NACK = 0x01;

    private static final int BROKER_CONNECT_TIMEOUT_MS = 2800;
    private static final int SYN_RETRY_INTERVAL_MS = 350;
    private static final int MAX_ENVELOPE_DATA_BYTES = 128 * 1024;
    private static final int STREAM_WRITE_CHUNK_BYTES = 16 * 1024;
    private static final int MAX_REORDER_BUFFER_PACKETS = 512;
    private static final int MAX_OUTBOUND_CACHE_PACKETS = 2048;
    private static final long RETRANSMIT_INTERVAL_MS = 220L;

    private static final List<BrokerEndpoint> DEFAULT_PUBLIC_BROKERS = Collections.unmodifiableList(
            Arrays.asList(
                    new BrokerEndpoint("broker.hivemq.com", 8883, true),
                    new BrokerEndpoint("broker.emqx.io", 8883, true)
            )
    );

    private final String sessionId;
    private final boolean isHostRole;
    private final List<BrokerEndpoint> brokerEndpoints;
    private final String blindedTopicRoot;
    private final String c2hTopic;
    private final String h2cTopic;
    private final SecretKey outerAeadKey;

    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final List<MqttBrokerConnection> activeBrokers = new CopyOnWriteArrayList<>();
    private final Map<Long, RendezvousStream> hostStreams = new ConcurrentHashMap<>();
    private final CountDownLatch firstBrokerReadyLatch = new CountDownLatch(1);
    private final AtomicBoolean isClosed = new AtomicBoolean(false);

    private volatile HostStreamListener hostStreamListener;
    private volatile RendezvousStream clientStream;
    private final CountDownLatch clientSynAckLatch = new CountDownLatch(1);

    public ServerlessRendezvousChannel(
            String sessionId,
            byte[] inviteSecret,
            boolean isHostRole,
            List<BrokerEndpoint> customBrokers) throws GeneralSecurityException {

        if (sessionId == null || sessionId.trim().isEmpty()) {
            throw new IllegalArgumentException("sessionId required");
        }
        if (inviteSecret == null || inviteSecret.length < CryptoEngine.INVITE_SECRET_BYTES) {
            throw new IllegalArgumentException("inviteSecret must be at least 16 bytes");
        }

        this.sessionId = sessionId.trim();
        this.isHostRole = isHostRole;
        this.brokerEndpoints = (customBrokers != null && !customBrokers.isEmpty())
                ? new ArrayList<>(customBrokers)
                : DEFAULT_PUBLIC_BROKERS;

        byte[] salt = CryptoEngine.sha256(
                ("PIGEON_RV_SALT_V1:" + this.sessionId).getBytes(StandardCharsets.UTF_8));
        byte[] prk = CryptoEngine.hkdfExtract(salt, inviteSecret);
        byte[] topicBytes = CryptoEngine.hkdfExpand(
                prk, "PIGEON_RV_TOPIC_V1".getBytes(StandardCharsets.UTF_8), 16);
        byte[] keyBytes = CryptoEngine.hkdfExpand(
                prk, "PIGEON_RV_AEAD_KEY_V1".getBytes(StandardCharsets.UTF_8), CryptoEngine.AES_KEY_BYTES);
        Arrays.fill(prk, (byte) 0);

        this.blindedTopicRoot = "pgn/v1/" + toHex(topicBytes);
        this.c2hTopic = blindedTopicRoot + "/c2h";
        this.h2cTopic = blindedTopicRoot + "/h2c";
        this.outerAeadKey = new SecretKeySpec(keyBytes, "AES");
    }

    public static List<BrokerEndpoint> getDefaultPublicBrokers() {
        return DEFAULT_PUBLIC_BROKERS;
    }

    public String getBlindedTopicRoot() {
        return blindedTopicRoot;
    }

    public String getC2hTopic() {
        return c2hTopic;
    }

    public String getH2cTopic() {
        return h2cTopic;
    }

    public int getConnectedBrokerCount() {
        return activeBrokers.size();
    }

    /**
     * Starts the Host rendezvous listener, subscribing to the blinded client-to-host topic
     * across the configured MQTT brokers and invoking {@link HostStreamListener} for each
     * incoming client virtual connection stream.
     */
    public void startHost(HostStreamListener listener) {
        if (!isHostRole) {
            throw new IllegalStateException("Channel not initialized in Host role");
        }
        this.hostStreamListener = listener;
        startBrokerConnections(c2hTopic);
    }

    /**
     * Waits until at least one MQTT broker connection has completed CONNECT and SUBSCRIBE.
     */
    public boolean awaitAtLeastOneBrokerReady(long timeoutMs) throws InterruptedException {
        return firstBrokerReadyLatch.await(timeoutMs, TimeUnit.MILLISECONDS);
    }

    /**
     * Opens a client virtual stream to the Host over the blinded rendezvous channel.
     */
    public RendezvousStream connectClientStream(long timeoutMs) throws IOException {
        if (isHostRole) {
            throw new IllegalStateException("Cannot call connectClientStream in Host role");
        }
        startBrokerConnections(h2cTopic);

        long connId = 0;
        while (connId == 0) {
            connId = ByteBuffer.wrap(CryptoEngine.randomBytes(8)).getLong();
        }

        RendezvousStream stream = new RendezvousStream(connId);
        this.clientStream = stream;

        long deadlineMs = System.currentTimeMillis() + Math.max(1000L, timeoutMs);
        try {
            long waitBrokerMs = Math.min(3500L, Math.max(800L, timeoutMs / 2));
            if (!firstBrokerReadyLatch.await(waitBrokerMs, TimeUnit.MILLISECONDS)) {
                throw new IOException("Could not reach any rendezvous broker");
            }

            while (!isClosed.get() && System.currentTimeMillis() < deadlineMs) {
                publishEnvelope(DIR_CLIENT_TO_HOST, PKT_CONN_SYN, connId, 0L, new byte[0]);
                long waitStep = Math.min(SYN_RETRY_INTERVAL_MS, Math.max(50L, deadlineMs - System.currentTimeMillis()));
                if (clientSynAckLatch.await(waitStep, TimeUnit.MILLISECONDS)) {
                    return stream;
                }
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("Interrupted during rendezvous connect", e);
        }

        throw new IOException("Timed out waiting for host on rendezvous channel");
    }

    private final AtomicBoolean brokerConnectionsStarted = new AtomicBoolean(false);

    private void startBrokerConnections(String subscribeTopic) {
        if (!brokerConnectionsStarted.compareAndSet(false, true)) {
            return;
        }
        for (BrokerEndpoint endpoint : brokerEndpoints) {
            executeIfOpen(() -> connectToBrokerWithFallback(endpoint, subscribeTopic));
        }
        executeIfOpen(this::runRetransmitLoop);
    }

    /**
     * Actively probes open MQTT broker sockets with PINGREQ on network change (e.g. Wi-Fi <-> 4G)
     * and closes any half-open/dead sockets within 1.5s instead of waiting for the 45s SO_TIMEOUT.
     */
    public void notifyNetworkChanged() {
        if (isClosed.get()) {
            return;
        }
        List<MqttBrokerConnection> snapshot = new ArrayList<>(activeBrokers);
        if (snapshot.isEmpty()) {
            return;
        }
        executeIfOpen(() -> {
            long probeStartNano = System.nanoTime();
            for (MqttBrokerConnection conn : snapshot) {
                if (conn != null && !conn.isClosed()) {
                    executeIfOpen(conn::sendPingNow);
                }
            }
            long deadlineMs = System.currentTimeMillis() + 1500L;
            while (!isClosed.get() && System.currentTimeMillis() < deadlineMs) {
                boolean allResolved = true;
                for (MqttBrokerConnection conn : snapshot) {
                    if (conn != null && !conn.isClosed() && !conn.hasInboundActivitySince(probeStartNano)) {
                        allResolved = false;
                        break;
                    }
                }
                if (allResolved) {
                    return;
                }
                try {
                    Thread.sleep(100L);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
            for (MqttBrokerConnection conn : snapshot) {
                if (conn != null && !conn.isClosed() && !conn.hasInboundActivitySince(probeStartNano)) {
                    conn.closeImmediate();
                }
            }
        });
    }

    private void executeIfOpen(Runnable task) {
        if (isClosed.get() || task == null) {
            return;
        }
        try {
            executor.execute(task);
        } catch (java.util.concurrent.RejectedExecutionException ignored) {
        }
    }

    private void connectToBrokerWithFallback(BrokerEndpoint primary, String subscribeTopic) {
        while (!isClosed.get()) {
            boolean wasConnected = false;
            MqttBrokerConnection conn = new MqttBrokerConnection(primary, subscribeTopic);
            if (conn.connectAndSubscribe()) {
                if (isClosed.get()) {
                    conn.close();
                    return;
                }
                wasConnected = true;
                activeBrokers.add(conn);
                firstBrokerReadyLatch.countDown();
                syncUnackedPacketsToBroker(conn);
                conn.runLoops();
            } else if (primary.isUseTls() && primary.getPort() == 8883 && !isClosed.get()) {
                // If TLS 8883 failed on a public broker, automatically try plain TCP 1883 fallback
                // (outer AES-256-GCM + inner ECDH AES-256-GCM still keep all traffic 100% E2EE)
                BrokerEndpoint fallback = new BrokerEndpoint(primary.getHost(), 1883, false);
                MqttBrokerConnection fallbackConn = new MqttBrokerConnection(fallback, subscribeTopic);
                if (fallbackConn.connectAndSubscribe()) {
                    if (isClosed.get()) {
                        fallbackConn.close();
                        return;
                    }
                    wasConnected = true;
                    activeBrokers.add(fallbackConn);
                    firstBrokerReadyLatch.countDown();
                    syncUnackedPacketsToBroker(fallbackConn);
                    fallbackConn.runLoops();
                }
            }

            if (isClosed.get()) {
                return;
            }
            try {
                Thread.sleep(wasConnected ? 150L : 1000L);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
        }
    }

    private void syncUnackedPacketsToBroker(MqttBrokerConnection broker) {
        if (broker == null || isClosed.get()) {
            return;
        }
        try {
            if (isHostRole) {
                for (RendezvousStream stream : hostStreams.values()) {
                    stream.republishUnackedPacketsToBroker(broker, 8);
                }
            } else {
                RendezvousStream stream = this.clientStream;
                if (stream != null) {
                    if (clientSynAckLatch.getCount() > 0) {
                        publishEnvelopeToSingleBroker(
                                broker, DIR_CLIENT_TO_HOST, PKT_CONN_SYN, stream.getClientConnId(), 0L, new byte[0]);
                    }
                    stream.republishUnackedPacketsToBroker(broker, 8);
                }
            }
        } catch (Exception ignored) {
        }
    }

    private void runRetransmitLoop() {
        while (!isClosed.get()) {
            try {
                Thread.sleep(RETRANSMIT_INTERVAL_MS);
                if (isClosed.get()) {
                    return;
                }
                long now = System.currentTimeMillis();
                if (isHostRole) {
                    for (RendezvousStream stream : hostStreams.values()) {
                        stream.checkAndRetransmitTimedOutPackets(now);
                    }
                } else {
                    RendezvousStream stream = this.clientStream;
                    if (stream != null) {
                        stream.checkAndRetransmitTimedOutPackets(now);
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception ignored) {
            }
        }
    }

    private void publishEnvelopeToSingleBroker(
            MqttBrokerConnection broker,
            byte direction,
            byte packetType,
            long clientConnId,
            long packetSeq,
            byte[] data) {
        if (isClosed.get() || broker == null) {
            return;
        }
        try {
            byte[] encryptedEnvelope = encryptEnvelope(
                    outerAeadKey, direction, packetType, clientConnId, packetSeq, data);
            String targetTopic = (direction == DIR_CLIENT_TO_HOST) ? c2hTopic : h2cTopic;
            broker.publishAsync(targetTopic, encryptedEnvelope, packetType == PKT_DATAGRAM);
        } catch (Exception ignored) {
        }
    }

    private void publishEnvelope(
            byte direction,
            byte packetType,
            long clientConnId,
            long packetSeq,
            byte[] data) {

        if (isClosed.get()) {
            return;
        }
        try {
            byte[] encryptedEnvelope = encryptEnvelope(
                    outerAeadKey, direction, packetType, clientConnId, packetSeq, data);
            String targetTopic = (direction == DIR_CLIENT_TO_HOST) ? c2hTopic : h2cTopic;
            boolean isDatagram = (packetType == PKT_DATAGRAM);
            for (MqttBrokerConnection broker : activeBrokers) {
                broker.publishAsync(targetTopic, encryptedEnvelope, isDatagram);
            }
        } catch (Exception ignored) {
        }
    }

    private void onInboundMqttPayload(byte[] payload) {
        if (isClosed.get() || payload == null || payload.length < 1 + CryptoEngine.GCM_NONCE_BYTES + CryptoEngine.GCM_TAG_BYTES) {
            return;
        }
        byte expectedDir = isHostRole ? DIR_CLIENT_TO_HOST : DIR_HOST_TO_CLIENT;
        EnvelopePacket pkt;
        try {
            pkt = decryptEnvelope(outerAeadKey, expectedDir, payload);
        } catch (GeneralSecurityException e) {
            // Unauthenticated or wrong-session packet: drop silently
            return;
        }

        if (isHostRole) {
            handleHostInboundPacket(pkt);
        } else {
            handleClientInboundPacket(pkt);
        }
    }

    private void handleHostInboundPacket(EnvelopePacket pkt) {
        final long connId = pkt.clientConnId;
        if (connId == 0) {
            return;
        }

        if (pkt.packetType == PKT_CONN_SYN) {
            final boolean[] createdNew = new boolean[]{false};
            RendezvousStream stream = hostStreams.computeIfAbsent(connId, id -> {
                createdNew[0] = true;
                return new RendezvousStream(id);
            });

            // Always send SYN_ACK (and re-send cached initial handshake frame if SYN was retried)
            publishEnvelope(DIR_HOST_TO_CLIENT, PKT_CONN_SYN_ACK, connId, 0L, new byte[0]);
            byte[] cachedFirstPacket = stream.getCachedInitialOutboundData();
            if (cachedFirstPacket != null) {
                publishEnvelope(DIR_HOST_TO_CLIENT, PKT_DATA, connId, 1L, cachedFirstPacket);
            }

            if (createdNew[0]) {
                HostStreamListener listener = this.hostStreamListener;
                if (listener != null) {
                    executeIfOpen(() -> listener.onIncomingClientStream(stream));
                }
            }
        } else if (pkt.packetType == PKT_DATA) {
            final boolean[] createdNew = new boolean[]{false};
            RendezvousStream stream = hostStreams.computeIfAbsent(connId, id -> {
                createdNew[0] = true;
                return new RendezvousStream(id);
            });
            stream.onInboundData(pkt.packetSeq, pkt.data);
            if (createdNew[0]) {
                HostStreamListener listener = this.hostStreamListener;
                if (listener != null) {
                    executeIfOpen(() -> listener.onIncomingClientStream(stream));
                }
            }
        } else if (pkt.packetType == PKT_FIN) {
            RendezvousStream stream = hostStreams.get(connId);
            if (stream != null) {
                stream.onInboundFin(pkt.packetSeq);
            }
        } else if (pkt.packetType == PKT_ACK) {
            RendezvousStream stream = hostStreams.get(connId);
            if (stream != null) {
                stream.onInboundAck(pkt.packetSeq, pkt.data);
            }
        } else if (pkt.packetType == PKT_DATAGRAM) {
            final boolean[] createdNew = new boolean[]{false};
            RendezvousStream stream = hostStreams.computeIfAbsent(connId, id -> {
                createdNew[0] = true;
                return new RendezvousStream(id);
            });
            stream.onInboundDatagram(pkt.packetSeq, pkt.data);
            if (createdNew[0]) {
                HostStreamListener listener = this.hostStreamListener;
                if (listener != null) {
                    executeIfOpen(() -> listener.onIncomingClientStream(stream));
                }
            }
        }
    }

    private void handleClientInboundPacket(EnvelopePacket pkt) {
        RendezvousStream stream = this.clientStream;
        if (stream == null || pkt.clientConnId != stream.getClientConnId()) {
            return;
        }

        if (pkt.packetType == PKT_CONN_SYN_ACK) {
            clientSynAckLatch.countDown();
        } else if (pkt.packetType == PKT_DATA) {
            clientSynAckLatch.countDown();
            stream.onInboundData(pkt.packetSeq, pkt.data);
        } else if (pkt.packetType == PKT_FIN) {
            clientSynAckLatch.countDown();
            stream.onInboundFin(pkt.packetSeq);
        } else if (pkt.packetType == PKT_ACK) {
            clientSynAckLatch.countDown();
            stream.onInboundAck(pkt.packetSeq, pkt.data);
        } else if (pkt.packetType == PKT_DATAGRAM) {
            clientSynAckLatch.countDown();
            stream.onInboundDatagram(pkt.packetSeq, pkt.data);
        }
    }

    public void close() {
        if (!isClosed.compareAndSet(false, true)) {
            return;
        }
        if (clientStream != null) {
            try { clientStream.close(); } catch (Exception ignored) {}
        }
        for (RendezvousStream s : hostStreams.values()) {
            try { s.close(); } catch (Exception ignored) {}
        }
        hostStreams.clear();

        for (MqttBrokerConnection conn : activeBrokers) {
            conn.close();
        }
        activeBrokers.clear();
        executor.shutdownNow();
    }

    /**
     * Encrypts an outer rendezvous envelope with AES-256-GCM using a fresh 96-bit random nonce
     * and directional AAD binding.
     */
    public static byte[] encryptEnvelope(
            SecretKey key,
            byte direction,
            byte packetType,
            long clientConnId,
            long packetSeq,
            byte[] data) throws GeneralSecurityException {

        byte[] safeData = (data == null) ? new byte[0] : data;
        if (safeData.length > MAX_ENVELOPE_DATA_BYTES) {
            throw new GeneralSecurityException("Envelope data too large: " + safeData.length);
        }

        byte[] inner = new byte[1 + 8 + 8 + 4 + safeData.length];
        ByteBuffer innerBuf = ByteBuffer.wrap(inner);
        innerBuf.put(packetType);
        innerBuf.putLong(clientConnId);
        innerBuf.putLong(packetSeq);
        innerBuf.putInt(safeData.length);
        innerBuf.put(safeData);

        byte[] nonce = CryptoEngine.randomBytes(CryptoEngine.GCM_NONCE_BYTES);
        byte[] aad = new byte[]{ENVELOPE_MAGIC, direction};

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(CryptoEngine.GCM_TAG_BITS, nonce));
        cipher.updateAAD(aad);
        byte[] ciphertext = cipher.doFinal(inner);

        byte[] wire = new byte[1 + CryptoEngine.GCM_NONCE_BYTES + ciphertext.length];
        wire[0] = ENVELOPE_MAGIC;
        System.arraycopy(nonce, 0, wire, 1, CryptoEngine.GCM_NONCE_BYTES);
        System.arraycopy(ciphertext, 0, wire, 1 + CryptoEngine.GCM_NONCE_BYTES, ciphertext.length);
        return wire;
    }

    /**
     * Decrypts and authenticates an outer rendezvous envelope with AES-256-GCM.
     */
    public static EnvelopePacket decryptEnvelope(
            SecretKey key,
            byte expectedDirection,
            byte[] wire) throws GeneralSecurityException {

        if (wire == null || wire.length < 1 + CryptoEngine.GCM_NONCE_BYTES + CryptoEngine.GCM_TAG_BYTES + 21) {
            throw new GeneralSecurityException("Envelope too short");
        }
        if (wire[0] != ENVELOPE_MAGIC) {
            throw new GeneralSecurityException("Invalid envelope magic");
        }

        byte[] nonce = Arrays.copyOfRange(wire, 1, 1 + CryptoEngine.GCM_NONCE_BYTES);
        byte[] aad = new byte[]{ENVELOPE_MAGIC, expectedDirection};

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(CryptoEngine.GCM_TAG_BITS, nonce));
        cipher.updateAAD(aad);
        byte[] inner = cipher.doFinal(
                wire,
                1 + CryptoEngine.GCM_NONCE_BYTES,
                wire.length - (1 + CryptoEngine.GCM_NONCE_BYTES));

        if (inner.length < 21) {
            throw new GeneralSecurityException("Decrypted envelope header truncated");
        }

        ByteBuffer buf = ByteBuffer.wrap(inner);
        byte packetType = buf.get();
        long clientConnId = buf.getLong();
        long packetSeq = buf.getLong();
        int dataLen = buf.getInt();
        if (dataLen < 0 || dataLen > MAX_ENVELOPE_DATA_BYTES || 21 + dataLen != inner.length) {
            throw new GeneralSecurityException("Invalid inner data length: " + dataLen);
        }
        byte[] data = new byte[dataLen];
        buf.get(data);
        return new EnvelopePacket(packetType, clientConnId, packetSeq, data);
    }

    public static final class EnvelopePacket {
        public final byte packetType;
        public final long clientConnId;
        public final long packetSeq;
        public final byte[] data;

        EnvelopePacket(byte packetType, long clientConnId, long packetSeq, byte[] data) {
            this.packetType = packetType;
            this.clientConnId = clientConnId;
            this.packetSeq = packetSeq;
            this.data = data;
        }
    }

    private static final class OutboundDataEntry {
        final byte[] payload;
        volatile long lastSentMs;

        OutboundDataEntry(byte[] payload, long lastSentMs) {
            this.payload = payload;
            this.lastSentMs = lastSentMs;
        }
    }

    /**
     * Per-connection virtual bidirectional byte stream multiplexed over the rendezvous channel.
     * Exposes standard {@link DataInputStream} and {@link DataOutputStream} with automatic
     * ACK/NACK ARQ retransmission across redundant brokers so reliable control/chat/image frames
     * never stall, plus an out-of-band deduplicated datagram channel for real-time voice fallback.
     */
    public final class RendezvousStream {

        public interface DatagramListener {
            void onDatagramReceived(byte[] data);
        }

        private final long clientConnId;
        private final LinkedBlockingQueue<byte[]> inboundQueue = new LinkedBlockingQueue<>();
        private final byte[] eofSentinel = new byte[0];

        private final Object inboundSeqLock = new Object();
        private long nextExpectedInboundSeq = 1L;
        private long pendingFinSeq = -1L;
        private boolean inboundEofDelivered = false;
        private final TreeMap<Long, byte[]> reorderBuffer = new TreeMap<>();
        private long lastAckSentTimeMs = 0L;
        private long lastNackSentTimeMs = 0L;
        private long lastNackSentForSeq = -1L;

        private final AtomicLong outboundSeq = new AtomicLong(0L);
        private final ConcurrentSkipListMap<Long, OutboundDataEntry> outboundCache = new ConcurrentSkipListMap<>();
        private final AtomicLong outboundDatagramSeq = new AtomicLong(0L);
        private final CryptoEngine.ReplayWindow inboundDatagramWindow = new CryptoEngine.ReplayWindow();
        private final LinkedBlockingQueue<byte[]> earlyDatagramQueue = new LinkedBlockingQueue<>(32);
        private volatile DatagramListener datagramListener;

        private final AtomicBoolean streamClosed = new AtomicBoolean(false);
        private volatile int readTimeoutMs = 8000;
        private volatile byte[] cachedInitialOutboundData = null;

        private final DataInputStream dataIn;
        private final DataOutputStream dataOut;

        RendezvousStream(long clientConnId) {
            this.clientConnId = clientConnId;
            this.dataIn = new DataInputStream(new StreamInput());
            this.dataOut = new DataOutputStream(new StreamOutput());
        }

        public long getClientConnId() {
            return clientConnId;
        }

        public String getRemoteLabel() {
            return "RendezvousPeer#" + Long.toHexString(clientConnId);
        }

        public DataInputStream getDataInputStream() {
            return dataIn;
        }

        public DataOutputStream getDataOutputStream() {
            return dataOut;
        }

        public void setReadTimeoutMs(int timeoutMs) {
            this.readTimeoutMs = Math.max(0, timeoutMs);
        }

        public void setDatagramListener(DatagramListener listener) {
            this.datagramListener = listener;
            if (listener != null) {
                byte[] pending;
                while ((pending = earlyDatagramQueue.poll()) != null) {
                    try {
                        listener.onDatagramReceived(pending);
                    } catch (Exception ignored) {
                    }
                }
            }
        }

        public void sendDatagram(byte[] payload) {
            if (streamClosed.get() || isClosed.get() || payload == null || payload.length == 0) {
                return;
            }
            long dgramSeq = outboundDatagramSeq.incrementAndGet();
            byte dir = isHostRole ? DIR_HOST_TO_CLIENT : DIR_CLIENT_TO_HOST;
            publishEnvelope(dir, PKT_DATAGRAM, clientConnId, dgramSeq, payload);
        }

        void onInboundDatagram(long dgramSeq, byte[] data) {
            if (streamClosed.get() || data == null || data.length == 0 || dgramSeq <= 0) {
                return;
            }
            if (!inboundDatagramWindow.checkAndAccept(dgramSeq)) {
                return; // Duplicate datagram from redundant broker
            }
            DatagramListener listener = this.datagramListener;
            if (listener != null) {
                try {
                    listener.onDatagramReceived(data);
                } catch (Exception ignored) {
                }
            } else {
                if (!earlyDatagramQueue.offer(data)) {
                    earlyDatagramQueue.poll();
                    earlyDatagramQueue.offer(data);
                }
            }
        }

        byte[] getCachedInitialOutboundData() {
            return cachedInitialOutboundData;
        }

        void onInboundData(long seq, byte[] data) {
            if (streamClosed.get() || data == null || seq <= 0) {
                return;
            }
            long ackSeqToSend = -1L;
            byte ackFlagToSend = ACK_FLAG_NORMAL;

            synchronized (inboundSeqLock) {
                if (inboundEofDelivered) {
                    return;
                }
                long now = System.currentTimeMillis();
                if (seq < nextExpectedInboundSeq) {
                    // Duplicate / already-delivered packet: re-send cumulative ACK if throttled window passed
                    if ((now - lastAckSentTimeMs) >= 60L) {
                        lastAckSentTimeMs = now;
                        ackSeqToSend = nextExpectedInboundSeq;
                        ackFlagToSend = reorderBuffer.isEmpty() ? ACK_FLAG_NORMAL : ACK_FLAG_NACK;
                    }
                } else if (seq == nextExpectedInboundSeq) {
                    if (data.length > 0) {
                        inboundQueue.offer(data);
                    }
                    nextExpectedInboundSeq++;
                    while (reorderBuffer.containsKey(nextExpectedInboundSeq)) {
                        byte[] nextData = reorderBuffer.remove(nextExpectedInboundSeq);
                        if (nextData != null && nextData.length > 0) {
                            inboundQueue.offer(nextData);
                        }
                        nextExpectedInboundSeq++;
                    }
                    checkPendingFinLocked();
                    lastAckSentTimeMs = now;
                    ackSeqToSend = nextExpectedInboundSeq;
                    ackFlagToSend = reorderBuffer.isEmpty() ? ACK_FLAG_NORMAL : ACK_FLAG_NACK;
                } else {
                    if (!reorderBuffer.containsKey(seq) && reorderBuffer.size() < MAX_REORDER_BUFFER_PACKETS) {
                        reorderBuffer.put(seq, data);
                    }
                    if (lastNackSentForSeq != nextExpectedInboundSeq || (now - lastNackSentTimeMs) >= 45L) {
                        lastNackSentForSeq = nextExpectedInboundSeq;
                        lastNackSentTimeMs = now;
                        ackSeqToSend = nextExpectedInboundSeq;
                        ackFlagToSend = ACK_FLAG_NACK;
                    }
                }
            }

            if (ackSeqToSend > 0) {
                byte dir = isHostRole ? DIR_HOST_TO_CLIENT : DIR_CLIENT_TO_HOST;
                publishEnvelope(dir, PKT_ACK, clientConnId, ackSeqToSend, new byte[]{ackFlagToSend});
            }
        }

        void onInboundAck(long ackNextSeq, byte[] ackData) {
            if (streamClosed.get() || ackNextSeq <= 0) {
                return;
            }
            if (ackNextSeq > 1) {
                outboundCache.headMap(ackNextSeq, false).clear();
            }
            boolean isNack = (ackData != null && ackData.length > 0 && ackData[0] == ACK_FLAG_NACK);
            if (isNack && !outboundCache.isEmpty()) {
                long now = System.currentTimeMillis();
                byte dir = isHostRole ? DIR_HOST_TO_CLIENT : DIR_CLIENT_TO_HOST;
                int resent = 0;
                for (Map.Entry<Long, OutboundDataEntry> entry : outboundCache.tailMap(ackNextSeq, true).entrySet()) {
                    OutboundDataEntry item = entry.getValue();
                    if (item == null) {
                        continue;
                    }
                    if ((now - item.lastSentMs) >= 25L || resent == 0) {
                        item.lastSentMs = now;
                        publishEnvelope(dir, PKT_DATA, clientConnId, entry.getKey(), item.payload);
                    }
                    resent++;
                    if (resent >= 4) {
                        break;
                    }
                }
            }
        }

        void checkAndRetransmitTimedOutPackets(long nowMs) {
            if (streamClosed.get() || outboundCache.isEmpty()) {
                return;
            }
            byte dir = isHostRole ? DIR_HOST_TO_CLIENT : DIR_CLIENT_TO_HOST;
            int resent = 0;
            for (Map.Entry<Long, OutboundDataEntry> entry : outboundCache.entrySet()) {
                OutboundDataEntry item = entry.getValue();
                if (item != null && (nowMs - item.lastSentMs) >= 240L) {
                    item.lastSentMs = nowMs;
                    publishEnvelope(dir, PKT_DATA, clientConnId, entry.getKey(), item.payload);
                    resent++;
                    if (resent >= 3) {
                        break;
                    }
                }
            }
        }

        void republishUnackedPacketsToBroker(MqttBrokerConnection broker, int maxPackets) {
            if (streamClosed.get() || broker == null || outboundCache.isEmpty()) {
                return;
            }
            byte dir = isHostRole ? DIR_HOST_TO_CLIENT : DIR_CLIENT_TO_HOST;
            int count = 0;
            for (Map.Entry<Long, OutboundDataEntry> entry : outboundCache.entrySet()) {
                OutboundDataEntry item = entry.getValue();
                if (item != null) {
                    publishEnvelopeToSingleBroker(broker, dir, PKT_DATA, clientConnId, entry.getKey(), item.payload);
                    count++;
                    if (count >= maxPackets) {
                        break;
                    }
                }
            }
        }

        void onInboundFin(long finSeq) {
            synchronized (inboundSeqLock) {
                if (inboundEofDelivered) {
                    return;
                }
                if (finSeq <= 0 || finSeq <= nextExpectedInboundSeq) {
                    inboundEofDelivered = true;
                    inboundQueue.offer(eofSentinel);
                } else {
                    pendingFinSeq = finSeq;
                    checkPendingFinLocked();
                }
            }
        }

        private void checkPendingFinLocked() {
            if (!inboundEofDelivered && pendingFinSeq > 0 && nextExpectedInboundSeq >= pendingFinSeq) {
                inboundEofDelivered = true;
                inboundQueue.offer(eofSentinel);
            }
        }

        public void close() {
            if (!streamClosed.compareAndSet(false, true)) {
                return;
            }
            try {
                dataOut.flush();
            } catch (Exception ignored) {
            }
            outboundCache.clear();
            earlyDatagramQueue.clear();
            long finSeq = outboundSeq.incrementAndGet();
            byte dir = isHostRole ? DIR_HOST_TO_CLIENT : DIR_CLIENT_TO_HOST;
            publishEnvelope(dir, PKT_FIN, clientConnId, finSeq, new byte[0]);
            inboundQueue.offer(eofSentinel);
        }

        private final class StreamInput extends InputStream {
            private byte[] currentChunk = null;
            private int currentPos = 0;
            private boolean reachedEof = false;

            @Override
            public int read() throws IOException {
                byte[] one = new byte[1];
                int n = read(one, 0, 1);
                return (n == -1) ? -1 : (one[0] & 0xFF);
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                if (b == null) {
                    throw new NullPointerException();
                }
                if (off < 0 || len < 0 || len > b.length - off) {
                    throw new IndexOutOfBoundsException();
                }
                if (len == 0) {
                    return 0;
                }
                if (reachedEof) {
                    return -1;
                }

                while (currentChunk == null || currentPos >= currentChunk.length) {
                    if (streamClosed.get() && inboundQueue.isEmpty()) {
                        reachedEof = true;
                        return -1;
                    }
                    byte[] next;
                    try {
                        int timeout = readTimeoutMs;
                        if (timeout > 0) {
                            next = inboundQueue.poll(timeout, TimeUnit.MILLISECONDS);
                            if (next == null) {
                                throw new SocketTimeoutException("Rendezvous stream read timed out");
                            }
                        } else {
                            next = inboundQueue.take();
                        }
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Interrupted waiting on rendezvous stream", e);
                    }

                    if (next == eofSentinel || next.length == 0) {
                        reachedEof = true;
                        return -1;
                    }
                    currentChunk = next;
                    currentPos = 0;
                }

                int copyLen = Math.min(len, currentChunk.length - currentPos);
                System.arraycopy(currentChunk, currentPos, b, off, copyLen);
                currentPos += copyLen;
                return copyLen;
            }

            @Override
            public int available() {
                if (currentChunk != null && currentPos < currentChunk.length) {
                    return currentChunk.length - currentPos;
                }
                byte[] peeked = inboundQueue.peek();
                if (peeked != null && peeked != eofSentinel) {
                    return peeked.length;
                }
                return 0;
            }

            @Override
            public void close() {
                RendezvousStream.this.close();
            }
        }

        private final class StreamOutput extends OutputStream {
            private final ByteArrayOutputStream buffer = new ByteArrayOutputStream(1024);

            @Override
            public synchronized void write(int b) throws IOException {
                if (streamClosed.get()) {
                    throw new IOException("Rendezvous stream is closed");
                }
                buffer.write(b);
                if (buffer.size() >= STREAM_WRITE_CHUNK_BYTES) {
                    flushBufferLocked();
                }
            }

            @Override
            public synchronized void write(byte[] b, int off, int len) throws IOException {
                if (streamClosed.get()) {
                    throw new IOException("Rendezvous stream is closed");
                }
                int remaining = len;
                int cursor = off;
                while (remaining > 0) {
                    int space = STREAM_WRITE_CHUNK_BYTES - buffer.size();
                    int toWrite = Math.min(remaining, space);
                    buffer.write(b, cursor, toWrite);
                    cursor += toWrite;
                    remaining -= toWrite;
                    if (buffer.size() >= STREAM_WRITE_CHUNK_BYTES) {
                        flushBufferLocked();
                    }
                }
            }

            @Override
            public synchronized void flush() throws IOException {
                if (streamClosed.get()) {
                    return;
                }
                flushBufferLocked();
            }

            private void flushBufferLocked() {
                if (buffer.size() == 0) {
                    return;
                }
                byte[] payload = buffer.toByteArray();
                buffer.reset();

                long seq = outboundSeq.incrementAndGet();
                if (seq == 1L && isHostRole) {
                    cachedInitialOutboundData = payload;
                }
                outboundCache.put(seq, new OutboundDataEntry(payload, System.currentTimeMillis()));
                while (outboundCache.size() > MAX_OUTBOUND_CACHE_PACKETS) {
                    Long oldestKey = outboundCache.firstKey();
                    if (oldestKey == null) {
                        break;
                    }
                    outboundCache.remove(oldestKey);
                }
                byte dir = isHostRole ? DIR_HOST_TO_CLIENT : DIR_CLIENT_TO_HOST;
                publishEnvelope(dir, PKT_DATA, clientConnId, seq, payload);
            }

            @Override
            public void close() {
                RendezvousStream.this.close();
            }
        }
    }

    /**
     * Minimal, zero-dependency MQTT v3.1.1 client connection over SSLSocket or Socket
     * with non-blocking asynchronous outbound publish queueing so a slow or congested
     * broker socket on 4G never blocks other active brokers or real-time audio/UI threads.
     */
    private final class MqttBrokerConnection {
        private final BrokerEndpoint endpoint;
        private final String subscribeTopic;
        private final ReentrantLock writeLock = new ReentrantLock();
        private final LinkedBlockingQueue<byte[]> reliablePublishQueue = new LinkedBlockingQueue<>(512);
        private final LinkedBlockingQueue<byte[]> datagramPublishQueue = new LinkedBlockingQueue<>(24);
        private final java.util.concurrent.Semaphore publishSignal = new java.util.concurrent.Semaphore(0);
        private final AtomicBoolean closed = new AtomicBoolean(false);
        private volatile long lastInboundActivityNano = System.nanoTime();

        private Socket socket;
        private DataInputStream in;
        private DataOutputStream out;

        MqttBrokerConnection(BrokerEndpoint endpoint, String subscribeTopic) {
            this.endpoint = endpoint;
            this.subscribeTopic = subscribeTopic;
        }

        boolean connectAndSubscribe() {
            try {
                Socket rawSocket = new Socket();
                rawSocket.setTcpNoDelay(true);
                rawSocket.connect(
                        new InetSocketAddress(endpoint.getHost(), endpoint.getPort()),
                        BROKER_CONNECT_TIMEOUT_MS);

                if (endpoint.isUseTls()) {
                    SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
                    SSLSocket sslSocket = (SSLSocket) factory.createSocket(
                            rawSocket, endpoint.getHost(), endpoint.getPort(), true);
                    sslSocket.setSoTimeout(BROKER_CONNECT_TIMEOUT_MS);
                    sslSocket.startHandshake();
                    this.socket = sslSocket;
                } else {
                    rawSocket.setSoTimeout(BROKER_CONNECT_TIMEOUT_MS);
                    this.socket = rawSocket;
                }

                this.in = new DataInputStream(socket.getInputStream());
                this.out = new DataOutputStream(socket.getOutputStream());

                // 1. Send MQTT v3.1.1 CONNECT packet
                String clientId = "pgn-" + toHex(CryptoEngine.randomBytes(6));
                sendMqttConnect(clientId);

                // 2. Read CONNACK (0x20)
                int connAckHeader = in.readUnsignedByte();
                int connAckLen = readRemainingLength(in);
                if ((connAckHeader & 0xF0) != 0x20 || connAckLen < 2) {
                    close();
                    return false;
                }
                byte[] connAckBody = new byte[connAckLen];
                in.readFully(connAckBody);
                if (connAckBody[1] != 0x00) { // 0x00 == Connection Accepted
                    close();
                    return false;
                }

                // 3. Send SUBSCRIBE (0x82) to blinded topic
                sendMqttSubscribe(1, subscribeTopic);

                // 4. Wait for SUBACK (0x90), processing any early PUBLISH packets
                long subDeadline = System.currentTimeMillis() + BROKER_CONNECT_TIMEOUT_MS;
                boolean subAcked = false;
                while (System.currentTimeMillis() < subDeadline && !closed.get()) {
                    int hdr = in.readUnsignedByte();
                    int remLen = readRemainingLength(in);
                    byte[] body = new byte[remLen];
                    in.readFully(body);
                    int pktType = hdr & 0xF0;
                    if (pktType == 0x90) { // SUBACK
                        if (remLen >= 3 && (body[2] & 0xFF) != 0x80) {
                            subAcked = true;
                            break;
                        } else {
                            close();
                            return false;
                        }
                    } else if (pktType == 0x30) {
                        handleMqttPublishPacket(hdr, body);
                    }
                }

                if (!subAcked) {
                    close();
                    return false;
                }

                // Set 45s read timeout (3x 15s PINGREQ interval) to detect half-open dead sockets after network switches
                socket.setSoTimeout(45_000);
                return true;
            } catch (Exception e) {
                close();
                return false;
            }
        }

        boolean isClosed() {
            return closed.get();
        }

        boolean hasInboundActivitySince(long timestampNano) {
            return lastInboundActivityNano >= timestampNano;
        }

        void sendPingNow() {
            if (closed.get() || isClosed.get()) {
                return;
            }
            boolean locked;
            try {
                locked = writeLock.tryLock(150, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            if (!locked) {
                // Another writer (e.g. runWriteLoop) is stalled holding writeLock;
                // notifyNetworkChanged() will force-close the dead socket after 1.5s.
                return;
            }
            try {
                if (!closed.get() && out != null) {
                    out.writeByte(0xC0); // PINGREQ
                    out.writeByte(0x00);
                    out.flush();
                }
            } catch (Exception e) {
                closeImmediate();
            } finally {
                writeLock.unlock();
            }
        }

        void runLoops() {
            lastInboundActivityNano = System.nanoTime();
            executeIfOpen(this::runWriteLoop);
            executeIfOpen(this::runPingLoop);
            runReadLoop();
        }

        private void runWriteLoop() {
            try {
                while (!closed.get() && !isClosed.get()) {
                    publishSignal.tryAcquire(500, TimeUnit.MILLISECONDS);
                    if (closed.get() || isClosed.get()) {
                        break;
                    }
                    while (!closed.get() && !isClosed.get()) {
                        byte[] reliableFrame = reliablePublishQueue.poll();
                        byte[] nextFrame = (reliableFrame != null) ? reliableFrame : datagramPublishQueue.poll();
                        if (nextFrame == null) {
                            break;
                        }
                        writeLock.lock();
                        try {
                            if (closed.get() || out == null) {
                                return;
                            }
                            out.write(nextFrame);
                            int batched = 0;
                            while (batched < 8) {
                                byte[] extra = reliablePublishQueue.poll();
                                if (extra == null) {
                                    extra = datagramPublishQueue.poll();
                                }
                                if (extra == null) {
                                    break;
                                }
                                out.write(extra);
                                batched++;
                            }
                            out.flush();
                        } finally {
                            writeLock.unlock();
                        }
                    }
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (Exception e) {
                closeImmediate();
            }
        }

        private void runReadLoop() {
            try {
                while (!closed.get() && !isClosed.get()) {
                    int hdr = in.readUnsignedByte();
                    int remLen = readRemainingLength(in);
                    if (remLen < 0 || remLen > 512 * 1024) {
                        break;
                    }
                    byte[] body = new byte[remLen];
                    in.readFully(body);
                    lastInboundActivityNano = System.nanoTime();

                    int pktType = hdr & 0xF0;
                    if (pktType == 0x30) { // PUBLISH
                        handleMqttPublishPacket(hdr, body);
                    }
                }
            } catch (Exception ignored) {
            } finally {
                activeBrokers.remove(this);
                closeImmediate();
            }
        }

        private void handleMqttPublishPacket(int hdr, byte[] body) throws IOException {
            int qos = (hdr >> 1) & 0x03;
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(body));
            int topicLen = dis.readUnsignedShort();
            if (topicLen < 0 || 2 + topicLen > body.length) {
                return;
            }
            dis.skipBytes(topicLen);
            int consumed = 2 + topicLen;

            if (qos == 1 || qos == 2) {
                if (consumed + 2 > body.length) {
                    return;
                }
                int pktId = dis.readUnsignedShort();
                consumed += 2;
                if (qos == 1) {
                    sendMqttPubAck(pktId);
                }
            }

            int payloadLen = body.length - consumed;
            if (payloadLen > 0) {
                byte[] payload = new byte[payloadLen];
                dis.readFully(payload);
                onInboundMqttPayload(payload);
            }
        }

        private void runPingLoop() {
            while (!closed.get() && !isClosed.get()) {
                try {
                    Thread.sleep(15_000L);
                    writeLock.lock();
                    try {
                        if (!closed.get() && out != null) {
                            out.writeByte(0xC0); // PINGREQ
                            out.writeByte(0x00);
                            out.flush();
                        }
                    } finally {
                        writeLock.unlock();
                    }
                } catch (Exception e) {
                    closeImmediate();
                    break;
                }
            }
        }

        void publishAsync(String topic, byte[] payload, boolean isDatagram) {
            if (closed.get() || isClosed.get()) {
                return;
            }
            try {
                byte[] topicBytes = topic.getBytes(StandardCharsets.UTF_8);
                int remLen = 2 + topicBytes.length + payload.length;
                ByteArrayOutputStream baos = new ByteArrayOutputStream(5 + remLen);
                DataOutputStream dos = new DataOutputStream(baos);
                dos.writeByte(0x30); // PUBLISH QoS 0
                writeRemainingLength(dos, remLen);
                dos.writeShort(topicBytes.length);
                dos.write(topicBytes);
                dos.write(payload);
                byte[] wireFrame = baos.toByteArray();

                if (isDatagram) {
                    if (!datagramPublishQueue.offer(wireFrame)) {
                        datagramPublishQueue.poll();
                        datagramPublishQueue.offer(wireFrame);
                    }
                } else {
                    if (!reliablePublishQueue.offer(wireFrame)) {
                        reliablePublishQueue.poll();
                        reliablePublishQueue.offer(wireFrame);
                    }
                }
                if (publishSignal.availablePermits() == 0) {
                    publishSignal.release();
                }
            } catch (Exception ignored) {
            }
        }

        private void sendMqttConnect(String clientId) throws IOException {
            byte[] idBytes = clientId.getBytes(StandardCharsets.UTF_8);
            ByteArrayOutputStream varAndPayload = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(varAndPayload);

            // Protocol Name "MQTT"
            dos.writeShort(4);
            dos.writeBytes("MQTT");
            // Protocol Level 4 (v3.1.1)
            dos.writeByte(0x04);
            // Connect Flags: Clean Session (0x02)
            dos.writeByte(0x02);
            // Keep Alive: 30 seconds
            dos.writeShort(30);
            // Payload: Client ID
            dos.writeShort(idBytes.length);
            dos.write(idBytes);
            dos.flush();

            byte[] body = varAndPayload.toByteArray();
            writeLock.lock();
            try {
                out.writeByte(0x10); // CONNECT
                writeRemainingLength(out, body.length);
                out.write(body);
                out.flush();
            } finally {
                writeLock.unlock();
            }
        }

        private void sendMqttSubscribe(int packetId, String topicFilter) throws IOException {
            byte[] topicBytes = topicFilter.getBytes(StandardCharsets.UTF_8);
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeShort(packetId);
            dos.writeShort(topicBytes.length);
            dos.write(topicBytes);
            dos.writeByte(0x00); // QoS 0
            dos.flush();

            byte[] body = baos.toByteArray();
            writeLock.lock();
            try {
                out.writeByte(0x82); // SUBSCRIBE
                writeRemainingLength(out, body.length);
                out.write(body);
                out.flush();
            } finally {
                writeLock.unlock();
            }
        }

        private void sendMqttPubAck(int packetId) {
            try {
                if (!writeLock.tryLock(250, TimeUnit.MILLISECONDS)) {
                    return;
                }
                try {
                    if (!closed.get() && out != null) {
                        out.writeByte(0x40); // PUBACK
                        out.writeByte(0x02);
                        out.writeShort(packetId);
                        out.flush();
                    }
                } finally {
                    writeLock.unlock();
                }
            } catch (Exception ignored) {
            }
        }

        void closeImmediate() {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            activeBrokers.remove(this);
            reliablePublishQueue.clear();
            datagramPublishQueue.clear();
            publishSignal.release();
            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (Exception ignored) {
            }
        }

        void close() {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            activeBrokers.remove(this);
            try {
                if (out != null && socket != null && !socket.isClosed() && !reliablePublishQueue.isEmpty()) {
                    if (writeLock.tryLock(150, TimeUnit.MILLISECONDS)) {
                        try {
                            int drained = 0;
                            byte[] pending;
                            while (drained < 16 && (pending = reliablePublishQueue.poll()) != null) {
                                out.write(pending);
                                drained++;
                            }
                            if (drained > 0) {
                                out.flush();
                            }
                        } finally {
                            writeLock.unlock();
                        }
                    }
                }
            } catch (Exception ignored) {
            }
            reliablePublishQueue.clear();
            datagramPublishQueue.clear();
            publishSignal.release();
            try {
                if (socket != null) {
                    socket.close();
                }
            } catch (Exception ignored) {
            }
        }
    }

    public static void writeRemainingLength(DataOutputStream out, int length) throws IOException {
        int val = length;
        do {
            int encodedByte = val % 128;
            val /= 128;
            if (val > 0) {
                encodedByte |= 128;
            }
            out.writeByte(encodedByte);
        } while (val > 0);
    }

    public static int readRemainingLength(DataInputStream in) throws IOException {
        int multiplier = 1;
        int value = 0;
        int encodedByte;
        do {
            encodedByte = in.readUnsignedByte();
            value += (encodedByte & 127) * multiplier;
            multiplier *= 128;
            if (multiplier > 128 * 128 * 128) {
                throw new IOException("Malformed MQTT remaining length");
            }
        } while ((encodedByte & 128) != 0);
        return value;
    }

    private static String toHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        final char[] digits = "0123456789abcdef".toCharArray();
        for (int i = 0; i < bytes.length; i++) {
            int v = bytes[i] & 0xFF;
            hexChars[i * 2] = digits[v >>> 4];
            hexChars[i * 2 + 1] = digits[v & 0x0F];
        }
        return new String(hexChars);
    }
}
