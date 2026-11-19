package com.pigeon.voice.net;

import com.pigeon.voice.contacts.ContactItem;
import com.pigeon.voice.crypto.CryptoEngine;
import com.pigeon.voice.token.InviteToken;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.SecretKey;

/**
 * Serverless Peer-to-Peer Encrypted Session Manager with 4-Layer Internet & 5G Connectivity.
 *
 * Handles:
 * 1. Host mode (acting as server, generating one-time InviteToken & deep link with STUN + IPv6 + IPv4 endpoints)
 * 2. Client mode (parallel racing of direct IPv6/IPv4/STUN TCP candidates and Blinded E2EE Serverless Rendezvous)
 * 3. Ephemeral ECDH P-256 + HKDF-SHA256 + One-Time PSK mutual authentication
 * 4. Strict single-peer lockout: once 1 valid peer joins, all other direct or rendezvous attempts are rejected
 * 5. Simultaneous bidirectional UDP hole punching across STUN, IPv6, and LAN candidates with automatic fallback
 * 6. AES-256-GCM encrypted low-latency UDP voice stream with automatic E2EE control-stream fallback & anti-replay window
 * 7. AES-256-GCM encrypted text chat with delivery acknowledgments
 * 8. AES-256-GCM chunked image sharing with SHA-256 integrity verification
 */
public final class P2PSessionManager {

    public enum State {
        IDLE,
        HOSTING_WAITING,
        CONNECTING,
        HANDSHAKING,
        CONNECTED_SECURE,
        DISCONNECTED,
        ERROR
    }

    public interface SessionListener {
        void onStateChanged(State newState, String statusMessage);
        void onHandshakeCompleted(String peerDisplayName, String safetyNumber);
        void onChatMessageReceived(ChatMessage message);
        void onChatMessageUpdated(ChatMessage message);
        void onEncryptedAudioFrameReceived(long sequenceNumber, byte[] adpcmFrame);
        void onPeerMuteChanged(boolean peerMuted);
        void onLatencyUpdated(long rttMs);
        void onSecurityAlert(String alertMessage);
    }

    // Handshake frames (authenticated via HMAC-SHA256 over transcript; outer-AES-256-GCM encrypted on Rendezvous)
    private static final byte FRAME_HELLO_CHALLENGE = 0x01;
    private static final byte FRAME_AUTH_RESPONSE = 0x02;
    private static final byte FRAME_AUTH_CONFIRM = 0x03;
    private static final byte FRAME_AUTH_REJECT = 0x04;

    // Post-handshake AES-256-GCM encrypted frames
    private static final byte FRAME_CALL_CONTROL = 0x10;
    private static final byte FRAME_PING = 0x11;
    private static final byte FRAME_PONG = 0x12;
    private static final byte FRAME_UDP_CANDIDATES = 0x13;
    private static final byte FRAME_TEXT_MESSAGE = 0x20;
    private static final byte FRAME_MESSAGE_ACK = 0x21;
    private static final byte FRAME_IMAGE_HEADER = 0x30;
    private static final byte FRAME_IMAGE_CHUNK = 0x31;
    private static final byte FRAME_IMAGE_COMPLETE = 0x32;
    private static final byte FRAME_AUDIO_TCP_FALLBACK = 0x40;

    // Call control subtypes
    private static final byte CTRL_MUTE_OFF = 0x00;
    private static final byte CTRL_MUTE_ON = 0x01;
    private static final byte CTRL_END_CALL = 0x02;

    // UDP magic header bytes
    private static final byte UDP_MAGIC = 0x50; // 'P' - encrypted ADPCM voice packet
    private static final byte UDP_KEEPALIVE_MAGIC = 0x51; // 'Q' - encrypted UDP hole-punch/keepalive packet
    private static final byte DATAGRAM_MAGIC_AUDIO_BATCH = 0x41; // 'A' - batched encrypted audio over Rendezvous datagram

    // Bidirectional UDP verification flags carried inside encrypted UDP_KEEPALIVE_MAGIC payload
    private static final byte KEEPALIVE_FLAG_PEER_UDP_RECEIVED = 0x01;
    private static final byte KEEPALIVE_FLAG_BIDIRECTIONAL_LOCKED = 0x02;

    public static final int IMAGE_CHUNK_SIZE = 16 * 1024; // 16 KB per encrypted chunk
    private static final int MAX_FRAME_SIZE = 256 * 1024;
    private static final int HANDSHAKE_TIMEOUT_MS = 8000;
    private static final int CONNECT_TIMEOUT_MS = 2500;
    private static final int DIRECT_TCP_HEADSTART_MS = 200;
    private static final int RENDEZVOUS_CONNECT_TIMEOUT_MS = 7500;
    private static final long UDP_HEALTHY_WINDOW_MS = 2500L;
    private static final long RENDEZVOUS_AUDIO_BATCH_INTERVAL_MS = 160L;
    private static final int RENDEZVOUS_AUDIO_MAX_BATCH_FRAMES = 8;

    private final List<SessionListener> listeners = new CopyOnWriteArrayList<>();
    private final List<ChatMessage> chatHistory = new CopyOnWriteArrayList<>();
    private final Map<String, IncomingImageTransfer> incomingImages = new ConcurrentHashMap<>();
    private final List<InetSocketAddress> localUdpCandidates = new CopyOnWriteArrayList<>();
    private final List<InetSocketAddress> peerUdpCandidates = new CopyOnWriteArrayList<>();
    private final ExecutorService ioExecutor = Executors.newCachedThreadPool();

    private final AtomicBoolean isClosed = new AtomicBoolean(false);
    private final AtomicBoolean isSessionLocked = new AtomicBoolean(false);
    private final AtomicLong outboundControlSeq = new AtomicLong(0);
    private final AtomicLong outboundAudioSeq = new AtomicLong(0);
    private final AtomicLong outboundUdpKeepAliveSeq = new AtomicLong(0);
    private final CryptoEngine.ReplayWindow audioReplayWindow = new CryptoEngine.ReplayWindow();
    private final CryptoEngine.ReplayWindow udpKeepAliveReplayWindow = new CryptoEngine.ReplayWindow();
    private final AtomicInteger blockedIntruderAttempts = new AtomicInteger(0);

    private volatile State currentState = State.IDLE;
    private volatile boolean isHostRole = false;
    private volatile String localDisplayName = "Pigeon User";
    private volatile String peerDisplayName = "Remote Peer";
    private volatile InviteToken activeInviteToken;
    private volatile CryptoEngine.SessionKeys sessionKeys;
    private volatile long lastInboundControlSeq = -1;
    private volatile long connectedSinceEpochMs = 0;
    private volatile long lastRttMs = 0;

    private volatile List<InetSocketAddress> customStunServers = null;
    private volatile List<ServerlessRendezvousChannel.BrokerEndpoint> customRendezvousBrokers = null;
    private volatile StunClient.StunEndpoint localStunEndpoint = null;
    private volatile boolean allowProductionStunDiscovery = false;

    private ServerSocket serverSocket;
    private volatile ControlConnection activeControlConn;
    private volatile ServerlessRendezvousChannel hostRendezvousChannel;
    private volatile ServerlessRendezvousChannel clientRendezvousChannel;
    private DataInputStream tcpIn;
    private DataOutputStream tcpOut;
    private final Object tcpWriteLock = new Object();

    private volatile DatagramSocket udpSocket;
    private volatile InetAddress peerUdpAddress;
    private volatile int peerUdpPort = -1;
    private volatile long lastUdpReceivedTimestampMs = 0;
    private volatile long lastUdpAckedByPeerTimestampMs = 0;
    private volatile long lastImmediateKeepAliveReplyMs = 0;
    private volatile byte lastImmediateKeepAliveFlagsSent = 0;
    private volatile byte[] activeStunTxId = null;
    private volatile boolean dropInboundUdpForTest = false;
    private final Object handoffLock = new Object();

    private final Object rendezvousAudioBatchLock = new Object();
    private final List<EncodedAudioFrame> pendingRendezvousAudioBatch = new ArrayList<>();
    private long lastRendezvousAudioFlushMs = 0L;
    private boolean rendezvousAudioFlushScheduled = false;

    private static final class EncodedAudioFrame {
        final long seqNum;
        final byte[] ciphertext;

        EncodedAudioFrame(long seqNum, byte[] ciphertext) {
            this.seqNum = seqNum;
            this.ciphertext = ciphertext;
        }
    }

    public P2PSessionManager() {
    }

    /**
     * Configures custom STUN server endpoints (used for deterministic testing or custom STUN servers).
     */
    public void setStunServers(List<InetSocketAddress> stunServers) {
        this.customStunServers = (stunServers != null) ? new ArrayList<>(stunServers) : null;
    }

    /**
     * Configures custom MQTT v3.1.1 rendezvous broker endpoints.
     */
    public void setRendezvousBrokers(List<ServerlessRendezvousChannel.BrokerEndpoint> brokers) {
        this.customRendezvousBrokers = (brokers != null) ? new ArrayList<>(brokers) : null;
    }

    public StunClient.StunEndpoint getLocalStunEndpoint() {
        return localStunEndpoint;
    }

    public List<InetSocketAddress> getLocalUdpCandidates() {
        return new ArrayList<>(localUdpCandidates);
    }

    public List<InetSocketAddress> getPeerUdpCandidates() {
        return new ArrayList<>(peerUdpCandidates);
    }

    public boolean isUsingRendezvousControl() {
        ControlConnection conn = this.activeControlConn;
        return conn != null && conn.isRendezvous();
    }

    /**
     * Returns true if and only if direct UDP is verified in BOTH directions:
     * 1. We have received an authenticated UDP packet from the peer within the healthy window, AND
     * 2. The peer has acknowledged receiving our UDP packets within the healthy window.
     */
    public boolean isDirectUdpActive() {
        long now = System.currentTimeMillis();
        return (now - lastUdpReceivedTimestampMs) < UDP_HEALTHY_WINDOW_MS
                && (now - lastUdpAckedByPeerTimestampMs) < UDP_HEALTHY_WINDOW_MS;
    }

    /**
     * Package-private test hook: closes the Host's direct TCP ServerSocket to simulate
     * a 5G/CGNAT firewall blocking all unsolicited inbound TCP connections.
     */
    void simulateInboundTcpFirewallForTest() {
        if (serverSocket != null) {
            try {
                serverSocket.close();
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Package-private test hook: closes the UDP socket and resets UDP health timestamps to
     * simulate strict Symmetric 5G CGNAT blocking direct UDP packets completely.
     */
    void simulateSymmetricCgnatUdpBlockedForTest() {
        lastUdpReceivedTimestampMs = 0;
        lastUdpAckedByPeerTimestampMs = 0;
        lastImmediateKeepAliveFlagsSent = 0;
        if (udpSocket != null) {
            try {
                udpSocket.close();
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Package-private test hook: simulates an asymmetric / one-way NAT firewall on this peer
     * that blocks incoming UDP packets from the remote peer while still allowing this peer
     * to send outbound UDP packets to the remote peer.
     */
    void simulateOneWayInboundUdpBlockedForTest(boolean blockInboundUdp) {
        this.dropInboundUdpForTest = blockInboundUdp;
        if (blockInboundUdp) {
            this.lastUdpReceivedTimestampMs = 0;
            this.lastUdpAckedByPeerTimestampMs = 0;
            this.lastImmediateKeepAliveFlagsSent = 0;
        }
    }

    /**
     * Handles a mid-call network handoff (e.g. Wi-Fi to 5G cellular transition or NAT UDP rebinding)
     * by opening a fresh local UDP voice socket on the active network interface, resetting direct UDP
     * health so voice seamlessly falls back to the encrypted control stream during re-punching,
     * discovering updated STUN/IPv6/IPv4 candidates, advertising them to the peer via an encrypted
     * FRAME_UDP_CANDIDATES control frame, and firing a new bidirectional UDP hole-punch burst.
     */
    public void notifyNetworkChangedOrHandoff() {
        if (isClosed.get() || currentState != State.CONNECTED_SECURE) {
            return;
        }
        executeIfActive(() -> {
            synchronized (handoffLock) {
                if (isClosed.get() || currentState != State.CONNECTED_SECURE) {
                    return;
                }
                try {
                    lastUdpReceivedTimestampMs = 0;
                    lastUdpAckedByPeerTimestampMs = 0;
                    lastImmediateKeepAliveFlagsSent = 0;
                    localStunEndpoint = null;

                    DatagramSocket newUdp = new DatagramSocket(0);
                    if (isClosed.get()) {
                        try {
                            newUdp.close();
                        } catch (Exception ignored) {
                        }
                        return;
                    }
                    DatagramSocket oldUdp = this.udpSocket;
                    this.udpSocket = newUdp;
                    if (oldUdp != null) {
                        try {
                            oldUdp.close();
                        } catch (Exception ignored) {
                        }
                    }

                    int newLocalPort = newUdp.getLocalPort();
                    populateLocalUdpCandidates(newLocalPort, null, null);

                    // Start the UDP read loop on the new socket first (it handles both voice/keepalives and async STUN responses)
                    executeIfActive(this::runEncryptedUdpReadLoop);

                    // Fire non-blocking STUN Binding Requests on newUdp so runEncryptedUdpReadLoop can capture the new NAT mapping
                    sendAsyncStunDiscoveryProbes(newUdp);

                    // Probe active MQTT rendezvous broker sockets immediately so any half-open socket on the old
                    // network interface reconnects within ~1.5s instead of waiting for the 45s SO_TIMEOUT
                    ServerlessRendezvousChannel activeRv = (this.hostRendezvousChannel != null)
                            ? this.hostRendezvousChannel
                            : this.clientRendezvousChannel;
                    if (activeRv != null) {
                        activeRv.notifyNetworkChanged();
                    }

                    // Advertise updated local UDP candidates to peer and fire simultaneous hole-punch burst
                    sendEncryptedUdpCandidatesFrame();
                    sendEncryptedUdpHolePunchBurst();
                } catch (Exception ignored) {
                }
            }
        });
    }

    private boolean executeIfActive(Runnable task) {
        if (isClosed.get() || task == null) {
            return false;
        }
        try {
            ioExecutor.execute(task);
            return true;
        } catch (java.util.concurrent.RejectedExecutionException ignored) {
            return false;
        }
    }

    private <T> Future<T> submitIfActive(java.util.concurrent.Callable<T> task) {
        if (isClosed.get() || task == null) {
            return null;
        }
        try {
            return ioExecutor.submit(task);
        } catch (java.util.concurrent.RejectedExecutionException ignored) {
            return null;
        }
    }

    public void addListener(SessionListener listener) {
        if (listener != null && !listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    public void removeListener(SessionListener listener) {
        listeners.remove(listener);
    }

    public State getCurrentState() {
        return currentState;
    }

    public boolean isHostRole() {
        return isHostRole;
    }

    public boolean isSessionLocked() {
        return isSessionLocked.get();
    }

    public InviteToken getActiveInviteToken() {
        return activeInviteToken;
    }

    public String getPeerDisplayName() {
        return peerDisplayName;
    }

    public String getSafetyNumber() {
        CryptoEngine.SessionKeys keys = this.sessionKeys;
        return keys != null ? keys.getSafetyNumber() : "---";
    }

    public long getConnectedSinceEpochMs() {
        return connectedSinceEpochMs;
    }

    public long getLastRttMs() {
        return lastRttMs;
    }

    public int getBlockedIntruderAttempts() {
        return blockedIntruderAttempts.get();
    }

    public List<ChatMessage> getChatHistory() {
        return new ArrayList<>(chatHistory);
    }

    /**
     * Starts hosting a serverless P2P encrypted call on this device and returns the
     * generated one-time InviteToken (which can be shared as a token or pigeon:// deep link).
     *
     * @param hostDisplayName     Name of the local user
     * @param allowedContactHash  Optional SHA-256 contact hash if restricted to a chosen contact
     * @param overrideAddresses   Optional explicit IP list (used in tests; null uses STUN + IPv6 + IPv4)
     */
    public synchronized InviteToken startHosting(
            String hostDisplayName,
            String allowedContactHash,
            List<String> overrideAddresses) throws IOException, GeneralSecurityException {

        if (currentState != State.IDLE) {
            throw new IllegalStateException("Session already active in state: " + currentState);
        }

        this.isHostRole = true;
        this.localDisplayName = (hostDisplayName == null || hostDisplayName.trim().isEmpty())
                ? "Host" : hostDisplayName.trim();

        KeyPair hostKeyPair = CryptoEngine.generateEphemeralKeyPair();
        byte[] inviteSecret = CryptoEngine.randomBytes(CryptoEngine.INVITE_SECRET_BYTES);
        String sessionId = UUID.randomUUID().toString().replace("-", "").substring(0, 12);

        serverSocket = new ServerSocket(0);
        udpSocket = new DatagramSocket(0);
        if (isClosed.get()) {
            try { serverSocket.close(); } catch (Exception ignored) {}
            try { udpSocket.close(); } catch (Exception ignored) {}
            serverSocket = null;
            udpSocket = null;
            throw new IOException("Session closed");
        }

        int tcpPort = serverSocket.getLocalPort();
        int localUdpPort = udpSocket.getLocalPort();

        boolean isProductionDiscovery = (overrideAddresses == null || overrideAddresses.isEmpty());
        this.allowProductionStunDiscovery = isProductionDiscovery;

        // Layer 1: Discover NAT-translated public IP & UDP port via RFC 5389 STUN on background executor
        // (Running on ioExecutor prevents android.os.NetworkOnMainThreadException when called from UI)
        StunClient.StunEndpoint stunEndpoint = null;
        if (customStunServers != null && !customStunServers.isEmpty()) {
            stunEndpoint = runStunDiscoveryOffThread(udpSocket, customStunServers, 550, 900);
        } else if (isProductionDiscovery) {
            stunEndpoint = runStunDiscoveryOffThread(udpSocket, null, 550, 1100);
        }
        this.localStunEndpoint = stunEndpoint;

        // Layer 2: Gather STUN Public IP + Global Unicast IPv6 (2000::/3) + Local IPv4 candidate addresses
        List<String> addresses;
        if (!isProductionDiscovery) {
            addresses = new ArrayList<>();
            if (stunEndpoint != null && !overrideAddresses.contains(stunEndpoint.getPublicIp())) {
                addresses.add(stunEndpoint.getPublicIp());
            }
            addresses.addAll(overrideAddresses);
        } else {
            addresses = NetworkUtils.getCandidateHostAddresses(
                    stunEndpoint != null ? stunEndpoint.getPublicIp() : null);
        }

        populateLocalUdpCandidates(localUdpPort, stunEndpoint, addresses);

        int advertisedUdpPort = (isProductionDiscovery && stunEndpoint != null)
                ? stunEndpoint.getPublicPort()
                : localUdpPort;

        activeInviteToken = new InviteToken(
                sessionId,
                addresses,
                tcpPort,
                advertisedUdpPort,
                hostKeyPair.getPublic().getEncoded(),
                inviteSecret,
                this.localDisplayName,
                allowedContactHash,
                System.currentTimeMillis() + InviteToken.DEFAULT_TTL_MS
        );

        if (isClosed.get()) {
            if (serverSocket != null) {
                try { serverSocket.close(); } catch (Exception ignored) {}
                serverSocket = null;
            }
            if (udpSocket != null) {
                try { udpSocket.close(); } catch (Exception ignored) {}
                udpSocket = null;
            }
            return activeInviteToken;
        }

        updateState(State.HOSTING_WAITING, "Waiting for invited peer to join via link/token...");
        addSystemMessage("Session created (" + sessionId + "). One-time token active. Waiting for peer...");

        // Direct TCP accept loop (for LAN, Hotspot, VPN, and Direct Global IPv6 connections)
        executeIfActive(() -> runHostAcceptLoop(hostKeyPair));

        // Layer 3: Blinded E2EE Serverless Rendezvous listener (for CGNAT, 5G mobile, and cross-Internet)
        boolean enableRendezvous = isProductionDiscovery
                || (customRendezvousBrokers != null && !customRendezvousBrokers.isEmpty());
        if (enableRendezvous) {
            ServerlessRendezvousChannel rvChannel = new ServerlessRendezvousChannel(
                    sessionId,
                    inviteSecret,
                    true,
                    customRendezvousBrokers);
            this.hostRendezvousChannel = rvChannel;
            if (isClosed.get()) {
                this.hostRendezvousChannel = null;
                rvChannel.close();
                return activeInviteToken;
            }
            rvChannel.startHost(stream -> handleHostCandidateConnection(
                    new RendezvousControlConnection(stream),
                    hostKeyPair));
        }

        return activeInviteToken;
    }

    public InviteToken startHosting(String hostDisplayName, String allowedContactHash)
            throws IOException, GeneralSecurityException {
        return startHosting(hostDisplayName, allowedContactHash, null);
    }

    private StunClient.StunEndpoint runStunDiscoveryOffThread(
            DatagramSocket socket,
            List<InetSocketAddress> servers,
            int totalStunTimeoutMs,
            int maxWaitMs) {
        try {
            Future<StunClient.StunEndpoint> future = submitIfActive(() -> {
                List<InetSocketAddress> targetServers = (servers != null && !servers.isEmpty())
                        ? servers
                        : StunClient.getDefaultStunServers();
                return StunClient.discoverPublicEndpoint(socket, targetServers, totalStunTimeoutMs);
            });
            return future != null ? future.get(maxWaitMs, TimeUnit.MILLISECONDS) : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    /**
     * Sends non-blocking RFC 5389 STUN Binding Requests on {@code socket} so {@link #runEncryptedUdpReadLoop()}
     * can parse the response asynchronously without any second thread calling {@code receive()} or mutating {@code SO_TIMEOUT}.
     */
    private void sendAsyncStunDiscoveryProbes(DatagramSocket socket) {
        if (socket == null || socket.isClosed()) {
            return;
        }
        List<InetSocketAddress> servers = (customStunServers != null && !customStunServers.isEmpty())
                ? customStunServers
                : StunClient.getDefaultStunServers();
        if (servers == null || servers.isEmpty()) {
            return;
        }
        byte[] txId = CryptoEngine.randomBytes(StunClient.TRANSACTION_ID_BYTES);
        this.activeStunTxId = txId;
        byte[] reqBytes = StunClient.buildBindingRequest(txId);
        for (InetSocketAddress serverAddr : servers) {
            if (serverAddr == null || socket.isClosed()) {
                continue;
            }
            try {
                InetAddress addr = serverAddr.isUnresolved()
                        ? InetAddress.getByName(serverAddr.getHostString())
                        : serverAddr.getAddress();
                DatagramPacket pkt = new DatagramPacket(reqBytes, reqBytes.length, addr, serverAddr.getPort());
                socket.send(pkt);
            } catch (Exception ignored) {
            }
        }
    }

    private void populateLocalUdpCandidates(
            int localUdpPort,
            StunClient.StunEndpoint stunEndpoint,
            List<String> extraAddresses) {

        localUdpCandidates.clear();
        if (stunEndpoint != null) {
            addUniqueCandidate(localUdpCandidates, stunEndpoint.toSocketAddress());
        }
        for (String ipv6 : NetworkUtils.getGlobalUnicastIpv6Addresses()) {
            addNumericEndpointCandidate(localUdpCandidates, ipv6, localUdpPort);
        }
        for (String ipv4 : NetworkUtils.getLocalIpv4Addresses()) {
            if (!"127.0.0.1".equals(ipv4)) {
                addNumericEndpointCandidate(localUdpCandidates, ipv4, localUdpPort);
            }
        }
        if (extraAddresses != null) {
            for (String addr : extraAddresses) {
                addNumericEndpointCandidate(localUdpCandidates, addr, localUdpPort);
            }
        }
        if (localUdpCandidates.isEmpty()) {
            addNumericEndpointCandidate(localUdpCandidates, "127.0.0.1", localUdpPort);
        }
    }

    private void runHostAcceptLoop(KeyPair hostKeyPair) {
        while (!isClosed.get()) {
            ServerSocket ss = this.serverSocket;
            if (ss == null || ss.isClosed()) {
                break;
            }
            Socket candidate;
            try {
                candidate = ss.accept();
                candidate.setTcpNoDelay(true);
            } catch (IOException e) {
                if (!isClosed.get() && !isSessionLocked.get() && hostRendezvousChannel == null) {
                    updateState(State.ERROR, "Host server socket closed unexpectedly: " + e.getMessage());
                }
                break;
            }

            // Handle each incoming connection candidate (or immediately reject intruders if locked)
            boolean accepted = executeIfActive(() -> {
                try {
                    handleHostCandidateConnection(new TcpControlConnection(candidate), hostKeyPair);
                } catch (IOException e) {
                    try { candidate.close(); } catch (Exception ignored) {}
                }
            });
            if (!accepted) {
                try { candidate.close(); } catch (Exception ignored) {}
            }
        }
    }

    private void handleHostCandidateConnection(ControlConnection candidate, KeyPair hostKeyPair) {
        try {
            candidate.setReadTimeout(HANDSHAKE_TIMEOUT_MS);

            DataInputStream in = candidate.getInputStream();
            DataOutputStream out = candidate.getOutputStream();

            // 1. Check if session is already locked to an authenticated peer
            if (isSessionLocked.get()) {
                blockedIntruderAttempts.incrementAndGet();
                sendPlainHandshakeFrame(out, FRAME_AUTH_REJECT,
                        "Call is already locked to an authenticated peer. No third parties allowed."
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
                notifySecurityAlert("Blocked third-party join attempt from "
                        + candidate.getRemoteAddressLabel());
                candidate.close();
                return;
            }

            // 2. Check if invite token expired
            if (activeInviteToken.isExpired(System.currentTimeMillis())) {
                sendPlainHandshakeFrame(out, FRAME_AUTH_REJECT,
                        "Invite token has expired.".getBytes(java.nio.charset.StandardCharsets.UTF_8));
                candidate.close();
                return;
            }

            // 3. Send HELLO_CHALLENGE with sessionId + 16-byte random hostNonce
            byte[] hostNonce = CryptoEngine.randomBytes(CryptoEngine.NONCE_CHALLENGE_BYTES);
            ByteArrayOutputStream challengeBaos = new ByteArrayOutputStream();
            DataOutputStream challengeDos = new DataOutputStream(challengeBaos);
            challengeDos.writeUTF(activeInviteToken.getSessionId());
            challengeDos.write(hostNonce);
            sendPlainHandshakeFrame(out, FRAME_HELLO_CHALLENGE, challengeBaos.toByteArray());

            // 4. Read AUTH_RESPONSE from client
            PlainFrame responseFrame = readPlainHandshakeFrame(in);
            if (responseFrame.frameType != FRAME_AUTH_RESPONSE) {
                candidate.close();
                return;
            }

            DataInputStream respDis = new DataInputStream(new ByteArrayInputStream(responseFrame.payload));
            int pubKeyLen = respDis.readUnsignedShort();
            if (pubKeyLen <= 0 || pubKeyLen > 512) {
                candidate.close();
                return;
            }
            byte[] clientPublicKey = new byte[pubKeyLen];
            respDis.readFully(clientPublicKey);

            byte[] clientNonce = new byte[CryptoEngine.NONCE_CHALLENGE_BYTES];
            respDis.readFully(clientNonce);

            String joinerName = respDis.readUTF();
            String joinerContactHash = respDis.readUTF();
            int joinerUdpPort = respDis.readInt();

            int proofLen = respDis.readUnsignedByte();
            byte[] clientAuthProof = new byte[proofLen];
            respDis.readFully(clientAuthProof);

            List<InetSocketAddress> clientAdvertisedUdpCandidates = readUdpCandidatesFromStream(respDis);

            // 5. Verify contact restriction if host selected a specific contact to call
            if (!activeInviteToken.isContactPermitted(joinerContactHash)) {
                blockedIntruderAttempts.incrementAndGet();
                sendPlainHandshakeFrame(out, FRAME_AUTH_REJECT,
                        "Unauthorized contact: this call invite is locked to a specific contact."
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
                notifySecurityAlert("Blocked unauthorized contact attempt from '" + joinerName + "'");
                candidate.close();
                return;
            }

            // 6. Compute ECDH shared secret and derive session keys
            byte[] ecdhSecret = CryptoEngine.computeEcdhSharedSecret(
                    hostKeyPair.getPrivate(), clientPublicKey);
            CryptoEngine.SessionKeys derivedKeys = CryptoEngine.deriveSessionKeys(
                    ecdhSecret,
                    activeInviteToken.getInviteSecret(),
                    activeInviteToken.getHostPublicKey(),
                    clientPublicKey,
                    hostNonce,
                    clientNonce);
            Arrays.fill(ecdhSecret, (byte) 0);

            // 7. Verify client's HMAC authentication proof (proves client possesses the one-time token)
            byte[] expectedClientProof = derivedKeys.computeAuthProof(false, joinerContactHash);
            if (!CryptoEngine.constantTimeEquals(expectedClientProof, clientAuthProof)) {
                blockedIntruderAttempts.incrementAndGet();
                sendPlainHandshakeFrame(out, FRAME_AUTH_REJECT,
                        "Invalid invite token secret or cryptographic proof."
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
                notifySecurityAlert("Blocked connection with invalid token proof from "
                        + candidate.getRemoteAddressLabel());
                candidate.close();
                return;
            }

            // 8. Atomically lock the session to this single authenticated peer!
            if (!isSessionLocked.compareAndSet(false, true)) {
                blockedIntruderAttempts.incrementAndGet();
                sendPlainHandshakeFrame(out, FRAME_AUTH_REJECT,
                        "Call already locked to another peer."
                                .getBytes(java.nio.charset.StandardCharsets.UTF_8));
                notifySecurityAlert("Blocked concurrent third-party join attempt from "
                        + candidate.getRemoteAddressLabel());
                candidate.close();
                return;
            }

            // 9. Send AUTH_CONFIRM with host's mutual authentication proof + Host UDP candidate endpoints
            byte[] hostAuthProof = derivedKeys.computeAuthProof(true, activeInviteToken.getAllowedContactHash());
            ByteArrayOutputStream confirmBaos = new ByteArrayOutputStream();
            DataOutputStream confirmDos = new DataOutputStream(confirmBaos);
            confirmDos.writeByte(hostAuthProof.length);
            confirmDos.write(hostAuthProof);
            confirmDos.writeUTF(localDisplayName);
            writeUdpCandidatesToStream(confirmDos, localUdpCandidates);
            sendPlainHandshakeFrame(out, FRAME_AUTH_CONFIRM, confirmBaos.toByteArray());

            // Note: Do NOT close serverSocket or hostRendezvousChannel immediately here so that any
            // third-party intruder attempting to reuse the token over LAN OR Internet receives an explicit
            // FRAME_AUTH_REJECT ("Call is already locked") and triggers an intruder alert on the host UI!

            // 10. Transition to active encrypted session
            if (isClosed.get()) {
                candidate.close();
                return;
            }
            candidate.setReadTimeout(0); // Streaming mode
            this.activeControlConn = candidate;
            this.tcpIn = in;
            this.tcpOut = out;
            this.sessionKeys = derivedKeys;
            this.peerDisplayName = (joinerName == null || joinerName.trim().isEmpty()) ? "Peer" : joinerName.trim();

            if (candidate.getDirectInetAddress() != null && joinerUdpPort > 0) {
                addUniqueCandidate(
                        peerUdpCandidates,
                        new InetSocketAddress(candidate.getDirectInetAddress(), joinerUdpPort));
            }
            for (InetSocketAddress c : clientAdvertisedUdpCandidates) {
                addUniqueCandidate(peerUdpCandidates, c);
            }

            if (candidate.getDirectInetAddress() != null) {
                this.peerUdpAddress = candidate.getDirectInetAddress();
                this.peerUdpPort = joinerUdpPort;
            } else if (!peerUdpCandidates.isEmpty()) {
                InetSocketAddress primaryUdp = peerUdpCandidates.get(0);
                this.peerUdpAddress = primaryUdp.getAddress();
                this.peerUdpPort = primaryUdp.getPort();
            }

            this.connectedSinceEpochMs = System.currentTimeMillis();

            onEncryptedSessionEstablished();
        } catch (Exception e) {
            try { candidate.close(); } catch (Exception ignored) {}
        }
    }

    /**
     * Joins an existing peer-hosted call using an InviteToken or pigeon:// deep link.
     *
     * @param token                   Parsed InviteToken
     * @param clientDisplayName       Local user's display name
     * @param clientContactIdentifier Local user's phone number or handle (for contact-locked calls)
     */
    public synchronized void joinSession(
            InviteToken token,
            String clientDisplayName,
            String clientContactIdentifier) {

        if (currentState != State.IDLE) {
            throw new IllegalStateException("Session already active in state: " + currentState);
        }
        if (token == null) {
            throw new IllegalArgumentException("InviteToken cannot be null");
        }
        if (token.isExpired(System.currentTimeMillis())) {
            updateState(State.ERROR, "This call invite token has expired.");
            return;
        }

        this.isHostRole = false;
        this.activeInviteToken = token;
        this.localDisplayName = (clientDisplayName == null || clientDisplayName.trim().isEmpty())
                ? "Peer" : clientDisplayName.trim();

        updateState(State.CONNECTING, "Connecting to " + token.getHostDisplayName() + "...");

        executeIfActive(() -> runClientConnectAndHandshake(token, clientContactIdentifier));
    }

    private void runClientConnectAndHandshake(InviteToken token, String clientContactIdentifier) {
        if (isClosed.get()) {
            return;
        }
        final DatagramSocket clientUdp;
        try {
            clientUdp = new DatagramSocket(0);
            udpSocket = clientUdp;
        } catch (IOException e) {
            if (!isClosed.get()) {
                updateState(State.ERROR, "Failed to open local UDP voice socket: " + e.getMessage());
            }
            return;
        }
        if (isClosed.get()) {
            try { clientUdp.close(); } catch (Exception ignored) {}
            udpSocket = null;
            return;
        }
        int localUdpPort = clientUdp.getLocalPort();

        boolean isLocalLoopbackOnlyTest = (token.getHostAddresses().size() == 1
                && "127.0.0.1".equals(token.getHostAddresses().get(0))
                && customStunServers == null
                && customRendezvousBrokers == null);

        // Start Layer 1 STUN discovery on udpSocket concurrently while racing TCP/Rendezvous control streams
        Future<StunClient.StunEndpoint> stunFuture = null;
        if (customStunServers != null && !customStunServers.isEmpty()) {
            stunFuture = submitIfActive(() ->
                    StunClient.discoverPublicEndpoint(clientUdp, customStunServers, 450));
        } else if (!isLocalLoopbackOnlyTest) {
            stunFuture = submitIfActive(() -> {
                List<InetSocketAddress> defaultServers = StunClient.getDefaultStunServers();
                return StunClient.discoverPublicEndpoint(clientUdp, defaultServers, 450);
            });
        }

        // Layer 2 & Layer 3: Race direct TCP candidates (STUN IP, Global IPv6, Local IPv4) and
        // Blinded E2EE Serverless Rendezvous Channel
        AtomicReference<String> lastErrorRef = new AtomicReference<>("Unreachable host");
        ControlConnection connectedConn = raceClientControlConnections(
                token, !isLocalLoopbackOnlyTest, lastErrorRef);

        if (connectedConn == null) {
            if (!isClosed.get()) {
                updateState(State.ERROR, "Could not reach host (" + lastErrorRef.get() + ")");
            }
            return;
        }
        if (isClosed.get()) {
            try { connectedConn.close(); } catch (Exception ignored) {}
            return;
        }

        try {
            connectedConn.setReadTimeout(HANDSHAKE_TIMEOUT_MS);
            updateState(State.HANDSHAKING, "Performing ECDH P-256 key exchange & token verification...");

            DataInputStream in = connectedConn.getInputStream();
            DataOutputStream out = connectedConn.getOutputStream();

            // 1. Read HELLO_CHALLENGE or immediate AUTH_REJECT
            PlainFrame helloFrame = readPlainHandshakeFrame(in);
            if (helloFrame.frameType == FRAME_AUTH_REJECT) {
                String reason = new String(helloFrame.payload, java.nio.charset.StandardCharsets.UTF_8);
                connectedConn.close();
                updateState(State.ERROR, "Join rejected: " + reason);
                return;
            }
            if (helloFrame.frameType != FRAME_HELLO_CHALLENGE) {
                connectedConn.close();
                updateState(State.ERROR, "Unexpected handshake frame from host");
                return;
            }

            DataInputStream helloDis = new DataInputStream(new ByteArrayInputStream(helloFrame.payload));
            String hostSessionId = helloDis.readUTF();
            if (!token.getSessionId().equals(hostSessionId)) {
                connectedConn.close();
                updateState(State.ERROR, "Session ID mismatch");
                return;
            }
            byte[] hostNonce = new byte[CryptoEngine.NONCE_CHALLENGE_BYTES];
            helloDis.readFully(hostNonce);

            // Collect STUN result and ensure STUN discovery on udpSocket finishes completely
            // before runEncryptedUdpReadLoop() starts on udpSocket
            StunClient.StunEndpoint stunEndpoint = null;
            if (stunFuture != null) {
                try {
                    stunEndpoint = stunFuture.get(1200, TimeUnit.MILLISECONDS);
                } catch (Exception ignored) {
                }
            }
            this.localStunEndpoint = stunEndpoint;
            populateLocalUdpCandidates(localUdpPort, stunEndpoint, null);

            // 2. Generate ephemeral client ECDH key pair and client nonce
            KeyPair clientKeyPair = CryptoEngine.generateEphemeralKeyPair();
            byte[] clientPublicKey = clientKeyPair.getPublic().getEncoded();
            byte[] clientNonce = CryptoEngine.randomBytes(CryptoEngine.NONCE_CHALLENGE_BYTES);

            // 3. Derive ECDH shared secret and session keys
            byte[] ecdhSecret = CryptoEngine.computeEcdhSharedSecret(
                    clientKeyPair.getPrivate(), token.getHostPublicKey());
            CryptoEngine.SessionKeys derivedKeys = CryptoEngine.deriveSessionKeys(
                    ecdhSecret,
                    token.getInviteSecret(),
                    token.getHostPublicKey(),
                    clientPublicKey,
                    hostNonce,
                    clientNonce);
            Arrays.fill(ecdhSecret, (byte) 0);

            String myContactHash = ContactItem.computeContactHash(clientContactIdentifier);
            byte[] clientAuthProof = derivedKeys.computeAuthProof(false, myContactHash);

            int advertisedClientUdpPort = (stunEndpoint != null && connectedConn.isRendezvous())
                    ? stunEndpoint.getPublicPort()
                    : localUdpPort;

            // 4. Send AUTH_RESPONSE (including Client's STUN, IPv6, and LAN UDP candidate endpoints)
            ByteArrayOutputStream respBaos = new ByteArrayOutputStream();
            DataOutputStream respDos = new DataOutputStream(respBaos);
            respDos.writeShort(clientPublicKey.length);
            respDos.write(clientPublicKey);
            respDos.write(clientNonce);
            respDos.writeUTF(localDisplayName);
            respDos.writeUTF(myContactHash);
            respDos.writeInt(advertisedClientUdpPort);
            respDos.writeByte(clientAuthProof.length);
            respDos.write(clientAuthProof);
            writeUdpCandidatesToStream(respDos, localUdpCandidates);
            sendPlainHandshakeFrame(out, FRAME_AUTH_RESPONSE, respBaos.toByteArray());

            // 5. Wait for AUTH_CONFIRM or AUTH_REJECT
            PlainFrame confirmFrame = readPlainHandshakeFrame(in);
            if (confirmFrame.frameType == FRAME_AUTH_REJECT) {
                String reason = new String(confirmFrame.payload, java.nio.charset.StandardCharsets.UTF_8);
                connectedConn.close();
                updateState(State.ERROR, "Join rejected: " + reason);
                return;
            }
            if (confirmFrame.frameType != FRAME_AUTH_CONFIRM) {
                connectedConn.close();
                updateState(State.ERROR, "Invalid confirmation frame from host");
                return;
            }

            DataInputStream confirmDis = new DataInputStream(new ByteArrayInputStream(confirmFrame.payload));
            int hostProofLen = confirmDis.readUnsignedByte();
            byte[] hostAuthProof = new byte[hostProofLen];
            confirmDis.readFully(hostAuthProof);
            String verifiedHostName = confirmDis.readUTF();
            List<InetSocketAddress> hostAdvertisedUdpCandidates = readUdpCandidatesFromStream(confirmDis);

            // 6. Verify host's mutual authentication proof
            byte[] expectedHostProof = derivedKeys.computeAuthProof(true, token.getAllowedContactHash());
            if (!CryptoEngine.constantTimeEquals(expectedHostProof, hostAuthProof)) {
                connectedConn.close();
                updateState(State.ERROR, "Host authentication proof failed (potential MITM)");
                return;
            }

            // 7. Lock session & start encrypted transport loops
            if (isClosed.get()) {
                connectedConn.close();
                return;
            }
            isSessionLocked.set(true);
            connectedConn.setReadTimeout(0);
            this.activeControlConn = connectedConn;
            this.tcpIn = in;
            this.tcpOut = out;
            this.sessionKeys = derivedKeys;
            this.peerDisplayName = (verifiedHostName == null || verifiedHostName.trim().isEmpty())
                    ? token.getHostDisplayName() : verifiedHostName.trim();

            if (connectedConn.getDirectInetAddress() != null && token.getUdpPort() > 0) {
                addUniqueCandidate(
                        peerUdpCandidates,
                        new InetSocketAddress(connectedConn.getDirectInetAddress(), token.getUdpPort()));
            }
            for (InetSocketAddress c : hostAdvertisedUdpCandidates) {
                addUniqueCandidate(peerUdpCandidates, c);
            }
            for (String hostAddr : token.getHostAddresses()) {
                addNumericEndpointCandidate(peerUdpCandidates, hostAddr, token.getUdpPort());
            }

            if (connectedConn.getDirectInetAddress() != null) {
                this.peerUdpAddress = connectedConn.getDirectInetAddress();
                this.peerUdpPort = token.getUdpPort();
            } else if (!peerUdpCandidates.isEmpty()) {
                InetSocketAddress primaryUdp = peerUdpCandidates.get(0);
                this.peerUdpAddress = primaryUdp.getAddress();
                this.peerUdpPort = primaryUdp.getPort();
            }

            this.connectedSinceEpochMs = System.currentTimeMillis();

            onEncryptedSessionEstablished();

            // If STUN was not yet discovered before handshake completion, fire a non-blocking STUN probe
            // that runEncryptedUdpReadLoop() will parse directly without any concurrent socket reader
            if (stunEndpoint == null && (!isLocalLoopbackOnlyTest || customStunServers != null)) {
                executeIfActive(() -> sendAsyncStunDiscoveryProbes(this.udpSocket));
            }
        } catch (Exception e) {
            try { connectedConn.close(); } catch (Exception ignored) {}
            if (!isClosed.get()) {
                updateState(State.ERROR, "Handshake failed: " + e.getMessage());
            }
        }
    }

    /**
     * Races direct TCP connections across all candidate IPv6/IPv4/STUN host addresses in parallel,
     * and launches the Blinded E2EE Serverless Rendezvous stream if direct TCP does not connect
     * within the local head-start window (200ms) or fails immediately.
     */
    private ControlConnection raceClientControlConnections(
            InviteToken token,
            boolean allowRendezvous,
            AtomicReference<String> lastErrorRef) {

        List<String> hostAddrs = token.getHostAddresses();
        AtomicReference<ControlConnection> winnerRef = new AtomicReference<>(null);
        CountDownLatch winnerLatch = new CountDownLatch(1);
        CountDownLatch allDirectTcpDoneLatch = new CountDownLatch(hostAddrs.size());
        AtomicInteger remainingTotalAttempts = new AtomicInteger(hostAddrs.size() + (allowRendezvous ? 1 : 0));
        List<Socket> pendingTcpSockets = new ArrayList<>();

        // 1. Launch parallel Direct TCP candidate attempts (Global IPv6, STUN Public IP, Local IPv4)
        for (String hostAddr : hostAddrs) {
            boolean submitted = executeIfActive(() -> {
                Socket s = null;
                try {
                    s = new Socket();
                    s.setTcpNoDelay(true);
                    synchronized (pendingTcpSockets) {
                        if (isClosed.get() || winnerRef.get() != null) {
                            try { s.close(); } catch (Exception ignored) {}
                            return;
                        }
                        pendingTcpSockets.add(s);
                    }
                    s.connect(new InetSocketAddress(hostAddr, token.getTcpPort()), CONNECT_TIMEOUT_MS);
                    if (isClosed.get()) {
                        s.close();
                        return;
                    }
                    ControlConnection tcpConn = new TcpControlConnection(s);
                    if (winnerRef.compareAndSet(null, tcpConn)) {
                        closeLosingPendingSockets(pendingTcpSockets, s);
                        winnerLatch.countDown();
                    } else {
                        tcpConn.close();
                    }
                } catch (IOException e) {
                    if (s != null) {
                        try { s.close(); } catch (Exception ignored) {}
                    }
                    if (e.getMessage() != null) {
                        lastErrorRef.set(e.getMessage());
                    }
                } finally {
                    allDirectTcpDoneLatch.countDown();
                    if (remainingTotalAttempts.decrementAndGet() == 0) {
                        winnerLatch.countDown();
                    }
                }
            });
            if (!submitted) {
                allDirectTcpDoneLatch.countDown();
                if (remainingTotalAttempts.decrementAndGet() == 0) {
                    winnerLatch.countDown();
                }
            }
        }

        // 2. Give direct TCP a brief 200ms head-start (so LAN & direct IPv6 win in <20ms without touching MQTT).
        // If all direct TCP candidates fail faster than 200ms (e.g. ENETUNREACH/ECONNREFUSED in 5ms),
        // allDirectTcpDoneLatch unblocks immediately!
        if (allowRendezvous) {
            try {
                allDirectTcpDoneLatch.await(DIRECT_TCP_HEADSTART_MS, TimeUnit.MILLISECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            if (winnerRef.get() == null && !isClosed.get()) {
                boolean rvSubmitted = executeIfActive(() -> {
                    ServerlessRendezvousChannel rvChannel = null;
                    try {
                        rvChannel = new ServerlessRendezvousChannel(
                                token.getSessionId(),
                                token.getInviteSecret(),
                                false,
                                customRendezvousBrokers);
                        this.clientRendezvousChannel = rvChannel;
                        if (isClosed.get()) {
                            this.clientRendezvousChannel = null;
                            rvChannel.close();
                            return;
                        }

                        ServerlessRendezvousChannel.RendezvousStream stream =
                                rvChannel.connectClientStream(RENDEZVOUS_CONNECT_TIMEOUT_MS);
                        if (isClosed.get()) {
                            rvChannel.close();
                            return;
                        }
                        ControlConnection rvConn = new RendezvousControlConnection(stream);
                        if (winnerRef.compareAndSet(null, rvConn)) {
                            closeLosingPendingSockets(pendingTcpSockets, null);
                            winnerLatch.countDown();
                        } else {
                            rvConn.close();
                            rvChannel.close();
                        }
                    } catch (Exception e) {
                        if (e.getMessage() != null) {
                            lastErrorRef.set(e.getMessage());
                        }
                        if (rvChannel != null) {
                            rvChannel.close();
                        }
                    } finally {
                        if (remainingTotalAttempts.decrementAndGet() == 0) {
                            winnerLatch.countDown();
                        }
                    }
                });
                if (!rvSubmitted) {
                    if (remainingTotalAttempts.decrementAndGet() == 0) {
                        winnerLatch.countDown();
                    }
                }
            } else {
                if (remainingTotalAttempts.decrementAndGet() == 0) {
                    winnerLatch.countDown();
                }
            }
        }

        try {
            long totalWaitMs = allowRendezvous
                    ? (RENDEZVOUS_CONNECT_TIMEOUT_MS + 1500L)
                    : (CONNECT_TIMEOUT_MS + 500L);
            winnerLatch.await(totalWaitMs, TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        ControlConnection winner = winnerRef.get();
        Socket winningSocket = (winner instanceof TcpControlConnection)
                ? ((TcpControlConnection) winner).socket
                : null;
        closeLosingPendingSockets(pendingTcpSockets, winningSocket);
        if (winner != null && !winner.isRendezvous() && clientRendezvousChannel != null) {
            // Direct TCP won while rendezvous was connecting in background -> close unused rendezvous channel
            ServerlessRendezvousChannel unusedRv = this.clientRendezvousChannel;
            this.clientRendezvousChannel = null;
            if (unusedRv != null) {
                executeIfActive(unusedRv::close);
            }
        }
        return winner;
    }

    private static void closeLosingPendingSockets(List<Socket> pendingTcpSockets, Socket winnerSocket) {
        List<Socket> toClose;
        synchronized (pendingTcpSockets) {
            toClose = new ArrayList<>(pendingTcpSockets);
            pendingTcpSockets.clear();
        }
        for (Socket s : toClose) {
            if (s != null && s != winnerSocket) {
                try {
                    s.close();
                } catch (Exception ignored) {
                }
            }
        }
    }

    private void onEncryptedSessionEstablished() {
        updateState(State.CONNECTED_SECURE,
                "E2EE Connected with " + peerDisplayName + " • AES-256-GCM Locked");
        addSystemMessage("End-to-End Encrypted session established with " + peerDisplayName
                + ".\nSafety Number: " + getSafetyNumber()
                + "\nSession locked (1/1 peer) — no other party can join.");

        for (SessionListener l : listeners) {
            l.onHandshakeCompleted(peerDisplayName, getSafetyNumber());
        }

        // Attach out-of-band datagram voice listener if running over Serverless Rendezvous
        ControlConnection ctrlConn = this.activeControlConn;
        if (ctrlConn instanceof RendezvousControlConnection) {
            ((RendezvousControlConnection) ctrlConn).setDatagramListener(
                    this::handleInboundRendezvousAudioDatagram);
        }

        // Start encrypted control/chat/image reader loop (over Direct TCP or Serverless Rendezvous)
        executeIfActive(this::runEncryptedTcpReadLoop);

        // Start encrypted UDP low-latency voice reader loop
        executeIfActive(this::runEncryptedUdpReadLoop);

        // Exchange AES-256-GCM encrypted UDP candidate endpoints (STUN + IPv6 + LAN)
        executeIfActive(this::sendEncryptedUdpCandidatesFrame);

        // Layer 4: Fire simultaneous bidirectional UDP hole-punch burst across all candidate endpoints
        executeIfActive(this::sendEncryptedUdpHolePunchBurst);

        // Start periodic ping/latency probe & UDP keepalive loop
        executeIfActive(this::runPingLoop);

        // If Host's initial STUN timed out or failed, retry async STUN discovery on udpSocket
        if (isHostRole && localStunEndpoint == null
                && (allowProductionStunDiscovery || (customStunServers != null && !customStunServers.isEmpty()))) {
            executeIfActive(() -> sendAsyncStunDiscoveryProbes(this.udpSocket));
        }
    }

    private void runEncryptedTcpReadLoop() {
        final byte inboundChannel = isHostRole
                ? CryptoEngine.CHANNEL_CLIENT_TO_HOST_CTRL
                : CryptoEngine.CHANNEL_HOST_TO_CLIENT_CTRL;
        final SecretKey inboundKey = sessionKeys.getInboundControlKey(isHostRole);

        try {
            while (!isClosed.get() && currentState == State.CONNECTED_SECURE) {
                byte frameType = tcpIn.readByte();
                long seqNum = tcpIn.readLong();
                int cipherLen = tcpIn.readInt();

                if (cipherLen < CryptoEngine.GCM_TAG_BYTES || cipherLen > MAX_FRAME_SIZE) {
                    throw new IOException("Invalid encrypted frame size: " + cipherLen);
                }

                // Enforce strict monotonic sequence number on control channel
                if (seqNum <= lastInboundControlSeq) {
                    throw new GeneralSecurityException("Replay attack detected on control channel seq=" + seqNum);
                }
                lastInboundControlSeq = seqNum;

                byte[] ciphertext = new byte[cipherLen];
                tcpIn.readFully(ciphertext);

                byte[] plaintext = CryptoEngine.decryptFrame(
                        inboundKey,
                        inboundChannel,
                        frameType,
                        seqNum,
                        ciphertext);

                handleDecryptedControlFrame(frameType, plaintext);
            }
        } catch (EOFException e) {
            if (!isClosed.get()) {
                updateState(State.DISCONNECTED, peerDisplayName + " ended the call.");
            }
        } catch (Exception e) {
            if (!isClosed.get()) {
                updateState(State.DISCONNECTED, "Call disconnected: " + e.getMessage());
            }
        } finally {
            close();
        }
    }

    private void handleDecryptedControlFrame(byte frameType, byte[] plaintext)
            throws IOException, GeneralSecurityException {
        DataInputStream dis = new DataInputStream(new ByteArrayInputStream(plaintext));
        switch (frameType) {
            case FRAME_CALL_CONTROL: {
                byte ctrlCode = dis.readByte();
                if (ctrlCode == CTRL_MUTE_ON || ctrlCode == CTRL_MUTE_OFF) {
                    boolean muted = (ctrlCode == CTRL_MUTE_ON);
                    for (SessionListener l : listeners) {
                        l.onPeerMuteChanged(muted);
                    }
                } else if (ctrlCode == CTRL_END_CALL) {
                    addSystemMessage(peerDisplayName + " hung up.");
                    updateState(State.DISCONNECTED, peerDisplayName + " ended the call.");
                    close();
                }
                break;
            }
            case FRAME_PING: {
                long sentNano = dis.readLong();
                ByteArrayOutputStream baos = new ByteArrayOutputStream(8);
                new DataOutputStream(baos).writeLong(sentNano);
                sendEncryptedControlFrame(FRAME_PONG, baos.toByteArray());
                break;
            }
            case FRAME_PONG: {
                long sentNano = dis.readLong();
                long rtt = Math.max(1L, (System.nanoTime() - sentNano) / 1_000_000L);
                this.lastRttMs = rtt;
                for (SessionListener l : listeners) {
                    l.onLatencyUpdated(rtt);
                }
                break;
            }
            case FRAME_UDP_CANDIDATES: {
                List<InetSocketAddress> incomingCandidates = readUdpCandidatesFromStream(dis);
                boolean addedAny = false;
                for (InetSocketAddress candidate : incomingCandidates) {
                    if (addUniqueCandidate(peerUdpCandidates, candidate)) {
                        addedAny = true;
                    }
                }
                if (addedAny) {
                    // Peer advertised new UDP endpoint(s) (e.g. mid-call Wi-Fi <-> 4G handoff or late STUN):
                    // reset direct-UDP health so audio immediately falls back until the new path is verified,
                    // and ensure sendEncryptedUdpHolePunchBurst() completes all rounds instead of exiting early.
                    lastUdpReceivedTimestampMs = 0L;
                    lastUdpAckedByPeerTimestampMs = 0L;
                    lastImmediateKeepAliveFlagsSent = 0;
                }
                if ((peerUdpAddress == null || peerUdpPort <= 0 || !isDirectUdpActive())
                        && !incomingCandidates.isEmpty()) {
                    InetSocketAddress latest = incomingCandidates.get(0);
                    peerUdpAddress = latest.getAddress();
                    peerUdpPort = latest.getPort();
                }
                // Always fire a hole-punch burst across all candidates whenever the peer advertises
                // a new UDP endpoint (including mid-call Wi-Fi -> 5G network handoff or late STUN discovery)
                if (addedAny || !isDirectUdpActive()) {
                    executeIfActive(this::sendEncryptedUdpHolePunchBurst);
                }
                break;
            }
            case FRAME_TEXT_MESSAGE: {
                String msgId = dis.readUTF();
                String sender = dis.readUTF();
                long timestamp = dis.readLong();
                String text = dis.readUTF();

                ChatMessage incoming = ChatMessage.createText(msgId, sender, false, text, timestamp);
                chatHistory.add(incoming);
                for (SessionListener l : listeners) {
                    l.onChatMessageReceived(incoming);
                }

                // Send encrypted delivery ACK
                ByteArrayOutputStream ackBaos = new ByteArrayOutputStream();
                new DataOutputStream(ackBaos).writeUTF(msgId);
                sendEncryptedControlFrame(FRAME_MESSAGE_ACK, ackBaos.toByteArray());
                break;
            }
            case FRAME_MESSAGE_ACK: {
                String ackedId = dis.readUTF();
                markMessageDelivered(ackedId);
                break;
            }
            case FRAME_IMAGE_HEADER: {
                String imageId = dis.readUTF();
                String sender = dis.readUTF();
                int totalBytes = dis.readInt();
                int totalChunks = dis.readInt();
                int hashLen = dis.readUnsignedByte();
                if (hashLen != 32) {
                    break;
                }
                byte[] expectedHash = new byte[hashLen];
                dis.readFully(expectedHash);

                int expectedChunks = (totalBytes + IMAGE_CHUNK_SIZE - 1) / IMAGE_CHUNK_SIZE;
                if (totalBytes > 0 && totalBytes <= ImageCompressor.MAX_IMAGE_BYTES
                        && totalChunks > 0 && totalChunks <= 256
                        && totalChunks == expectedChunks) {
                    if (incomingImages.size() >= 4) {
                        incomingImages.clear();
                    }
                    incomingImages.put(imageId, new IncomingImageTransfer(
                            imageId, sender, totalBytes, totalChunks, expectedHash));
                }
                break;
            }
            case FRAME_IMAGE_CHUNK: {
                String imageId = dis.readUTF();
                int chunkIndex = dis.readInt();
                int chunkLen = dis.readInt();
                IncomingImageTransfer transfer = incomingImages.get(imageId);
                if (transfer != null && chunkLen > 0 && chunkLen <= IMAGE_CHUNK_SIZE) {
                    byte[] chunkData = new byte[chunkLen];
                    dis.readFully(chunkData);
                    if (transfer.addChunk(chunkIndex, chunkData)) {
                        incomingImages.remove(imageId);
                        byte[] completeBytes = transfer.reassembleAndVerify();
                        if (completeBytes != null) {
                            ChatMessage imgMsg = ChatMessage.createImage(
                                    imageId,
                                    transfer.senderName,
                                    false,
                                    completeBytes,
                                    System.currentTimeMillis(),
                                    true);
                            chatHistory.add(imgMsg);
                            for (SessionListener l : listeners) {
                                l.onChatMessageReceived(imgMsg);
                            }

                            // Acknowledge image receipt
                            ByteArrayOutputStream ackBaos = new ByteArrayOutputStream();
                            new DataOutputStream(ackBaos).writeUTF(imageId);
                            sendEncryptedControlFrame(FRAME_IMAGE_COMPLETE, ackBaos.toByteArray());
                        } else {
                            notifySecurityAlert("Dropped incoming image due to SHA-256 hash mismatch");
                        }
                    }
                }
                break;
            }
            case FRAME_IMAGE_COMPLETE: {
                String imageId = dis.readUTF();
                markMessageDelivered(imageId);
                break;
            }
            case FRAME_AUDIO_TCP_FALLBACK: {
                long audioSeq = dis.readLong();
                int adpcmLen = dis.readUnsignedShort();
                if (adpcmLen > 0 && adpcmLen <= 1024) {
                    byte[] adpcm = new byte[adpcmLen];
                    dis.readFully(adpcm);
                    if (audioReplayWindow.checkAndAccept(audioSeq)) {
                        for (SessionListener l : listeners) {
                            l.onEncryptedAudioFrameReceived(audioSeq, adpcm);
                        }
                    }
                }
                break;
            }
            default:
                break;
        }
    }

    private void runEncryptedUdpReadLoop() {
        final byte expectedChannel = isHostRole
                ? CryptoEngine.CHANNEL_CLIENT_TO_HOST_AUDIO
                : CryptoEngine.CHANNEL_HOST_TO_CLIENT_AUDIO;
        final SecretKey inboundAudioKey = sessionKeys.getInboundAudioKey(isHostRole);
        final byte[] receiveBuf = new byte[1024];

        final DatagramSocket localUdp = this.udpSocket;
        if (localUdp == null) {
            return;
        }
        try {
            localUdp.setSoTimeout(0);
        } catch (Exception ignored) {
        }

        final DatagramPacket packet = new DatagramPacket(receiveBuf, receiveBuf.length);
        while (!isClosed.get()
                && currentState == State.CONNECTED_SECURE
                && !localUdp.isClosed()
                && this.udpSocket == localUdp) {
            try {
                packet.setLength(receiveBuf.length);
                localUdp.receive(packet);
                int len = packet.getLength();

                // Check if this is an async RFC 5389 STUN Binding Success Response (0x0101)
                byte[] expectedStunTx = this.activeStunTxId;
                if (expectedStunTx != null
                        && len >= StunClient.STUN_HEADER_BYTES
                        && receiveBuf[0] == 0x01
                        && receiveBuf[1] == 0x01) {
                    StunClient.StunEndpoint stunEp = StunClient.parseBindingResponse(
                            receiveBuf, 0, len, expectedStunTx);
                    if (stunEp != null) {
                        this.activeStunTxId = null;
                        this.localStunEndpoint = stunEp;
                        if (addPriorityCandidate(localUdpCandidates, stunEp.toSocketAddress())) {
                            executeIfActive(() -> {
                                sendEncryptedUdpCandidatesFrame();
                                sendEncryptedUdpHolePunchBurst();
                            });
                        }
                    }
                    continue;
                }

                if (dropInboundUdpForTest) {
                    continue;
                }

                // Header: [magic (1B)][channel (1B)][seqNum (8B)] = 10 bytes + ciphertext (>= 16B)
                if (len < 10 + CryptoEngine.GCM_TAG_BYTES) {
                    continue;
                }
                byte packetMagic = receiveBuf[0];
                if ((packetMagic != UDP_MAGIC && packetMagic != UDP_KEEPALIVE_MAGIC)
                        || receiveBuf[1] != expectedChannel) {
                    continue;
                }
                long seqNum = java.nio.ByteBuffer.wrap(receiveBuf, 2, 8).getLong();
                CryptoEngine.ReplayWindow targetWindow = (packetMagic == UDP_MAGIC)
                        ? audioReplayWindow
                        : udpKeepAliveReplayWindow;

                // 1. Non-mutating replay window pre-check BEFORE AEAD decryption (prevents replay window DoS poisoning)
                if (!targetWindow.isPotentiallyValid(seqNum)) {
                    continue;
                }

                // 2. Authenticate and decrypt AES-256-GCM payload
                byte[] decryptedPayload = CryptoEngine.decryptFrame(
                        inboundAudioKey,
                        expectedChannel,
                        packetMagic,
                        seqNum,
                        receiveBuf,
                        10,
                        len - 10);

                // 3. Commit sequence number to replay window ONLY after GCM authentication tag succeeded
                if (!targetWindow.checkAndAccept(seqNum)) {
                    continue;
                }

                // Authentic packet: lock onto peer's verified NAT hole-punched UDP address/port and timestamp
                long now = System.currentTimeMillis();
                peerUdpAddress = packet.getAddress();
                peerUdpPort = packet.getPort();
                lastUdpReceivedTimestampMs = now;

                if (packetMagic == UDP_KEEPALIVE_MAGIC) {
                    byte peerFlags = (decryptedPayload.length >= 1) ? decryptedPayload[0] : 0;
                    if ((peerFlags & KEEPALIVE_FLAG_PEER_UDP_RECEIVED) != 0) {
                        lastUdpAckedByPeerTimestampMs = now;
                    }
                    byte myReplyFlags = computeCurrentKeepAliveFlags(now);
                    int bothLockedMask = KEEPALIVE_FLAG_PEER_UDP_RECEIVED | KEEPALIVE_FLAG_BIDIRECTIONAL_LOCKED;
                    if ((peerFlags & bothLockedMask) != bothLockedMask) {
                        if (myReplyFlags != lastImmediateKeepAliveFlagsSent
                                || (now - lastImmediateKeepAliveReplyMs) >= 25L) {
                            lastImmediateKeepAliveFlagsSent = myReplyFlags;
                            lastImmediateKeepAliveReplyMs = now;
                            executeIfActive(() -> sendEncryptedUdpKeepAlive(false));
                        }
                    }
                } else if (packetMagic == UDP_MAGIC && decryptedPayload.length > 0) {
                    if ((now - lastUdpAckedByPeerTimestampMs) >= UDP_HEALTHY_WINDOW_MS
                            && (now - lastImmediateKeepAliveReplyMs) >= 40L) {
                        lastImmediateKeepAliveReplyMs = now;
                        executeIfActive(() -> sendEncryptedUdpKeepAlive(false));
                    }
                    for (SessionListener l : listeners) {
                        l.onEncryptedAudioFrameReceived(seqNum, decryptedPayload);
                    }
                }
            } catch (SocketTimeoutException ignored) {
                // Never break out of UDP read loop on SocketTimeoutException; ensure blocking mode
                try {
                    localUdp.setSoTimeout(0);
                } catch (Exception e) {
                }
            } catch (GeneralSecurityException e) {
                // Invalid GCM tag on UDP packet: ignore spoofed/corrupted packet without poisoning replay window
            } catch (IOException e) {
                if (!isClosed.get()) {
                    break;
                }
            }
        }
    }

    private byte computeCurrentKeepAliveFlags(long nowMs) {
        boolean heardFromPeer = (nowMs - lastUdpReceivedTimestampMs) < UDP_HEALTHY_WINDOW_MS;
        boolean ackedByPeer = (nowMs - lastUdpAckedByPeerTimestampMs) < UDP_HEALTHY_WINDOW_MS;
        byte flags = 0;
        if (heardFromPeer) {
            flags |= KEEPALIVE_FLAG_PEER_UDP_RECEIVED;
        }
        if (heardFromPeer && ackedByPeer) {
            flags |= KEEPALIVE_FLAG_BIDIRECTIONAL_LOCKED;
        }
        return flags;
    }

    private void runPingLoop() {
        long lastControlPingMs = 0L;
        while (!isClosed.get() && currentState == State.CONNECTED_SECURE) {
            try {
                sendEncryptedUdpKeepAlive(false);
                long now = System.currentTimeMillis();
                long pingIntervalMs = isUsingRendezvousControl() ? 3000L : 1000L;
                if (lastControlPingMs == 0L || (now - lastControlPingMs) >= pingIntervalMs) {
                    lastControlPingMs = now;
                    ByteArrayOutputStream baos = new ByteArrayOutputStream(8);
                    new DataOutputStream(baos).writeLong(System.nanoTime());
                    sendEncryptedControlFrame(FRAME_PING, baos.toByteArray());
                }
                Thread.sleep(1000);
            } catch (Exception e) {
                break;
            }
        }
    }

    private void sendEncryptedUdpCandidatesFrame() {
        if (isClosed.get() || currentState != State.CONNECTED_SECURE || localUdpCandidates.isEmpty()) {
            return;
        }
        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            writeUdpCandidatesToStream(dos, localUdpCandidates);
            sendEncryptedControlFrame(FRAME_UDP_CANDIDATES, baos.toByteArray());
        } catch (Exception ignored) {
        }
    }

    /**
     * Fires a rapid multi-round burst of encrypted UDP keepalive/hole-punch packets across all
     * discovered peer UDP candidate endpoints (STUN public IP:port, Global IPv6, and LAN IPv4)
     * so simultaneous outbound packets open the bidirectional NAT pinhole on both routers.
     */
    private void sendEncryptedUdpHolePunchBurst() {
        int[] delaysMs = new int[]{0, 60, 160, 350};
        for (int delay : delaysMs) {
            if (isClosed.get() || currentState != State.CONNECTED_SECURE) {
                return;
            }
            if (delay > 0) {
                try {
                    Thread.sleep(delay);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    return;
                }
            }
            sendEncryptedUdpKeepAlive(true);
            if (isDirectUdpActive()) {
                return;
            }
        }
    }

    private void sendEncryptedUdpKeepAlive(boolean probeAllCandidates) {
        if (isClosed.get() || currentState != State.CONNECTED_SECURE || sessionKeys == null) {
            return;
        }
        DatagramSocket localUdp = this.udpSocket;
        if (localUdp == null || localUdp.isClosed()) {
            return;
        }

        List<InetSocketAddress> targets = new ArrayList<>();
        InetAddress lockedAddr = this.peerUdpAddress;
        int lockedPort = this.peerUdpPort;
        if (lockedAddr != null && lockedPort > 0) {
            targets.add(new InetSocketAddress(lockedAddr, lockedPort));
        }

        // Probe ALL candidate endpoints (STUN, IPv6, LAN) during hole-punch bursts or when UDP is not yet verified
        if (probeAllCandidates || !isDirectUdpActive()) {
            for (InetSocketAddress candidate : peerUdpCandidates) {
                addUniqueCandidate(targets, candidate);
            }
        }

        if (targets.isEmpty()) {
            return;
        }

        byte outboundChannel = isHostRole
                ? CryptoEngine.CHANNEL_HOST_TO_CLIENT_AUDIO
                : CryptoEngine.CHANNEL_CLIENT_TO_HOST_AUDIO;
        SecretKey outboundAudioKey = sessionKeys.getOutboundAudioKey(isHostRole);
        byte[] keepAlivePlaintext = new byte[]{computeCurrentKeepAliveFlags(System.currentTimeMillis())};

        for (InetSocketAddress target : targets) {
            if (target == null || target.getAddress() == null || target.getPort() <= 0) {
                continue;
            }
            try {
                long seqNum = outboundUdpKeepAliveSeq.incrementAndGet();
                byte[] ciphertext = CryptoEngine.encryptFrame(
                        outboundAudioKey,
                        outboundChannel,
                        UDP_KEEPALIVE_MAGIC,
                        seqNum,
                        keepAlivePlaintext,
                        0,
                        keepAlivePlaintext.length);

                byte[] udpPayload = new byte[10 + ciphertext.length];
                udpPayload[0] = UDP_KEEPALIVE_MAGIC;
                udpPayload[1] = outboundChannel;
                java.nio.ByteBuffer.wrap(udpPayload, 2, 8).putLong(seqNum);
                System.arraycopy(ciphertext, 0, udpPayload, 10, ciphertext.length);

                DatagramPacket packet = new DatagramPacket(
                        udpPayload, udpPayload.length, target.getAddress(), target.getPort());
                localUdp.send(packet);
            } catch (Exception ignored) {
            }
        }
    }

    /**
     * Encrypts and transmits a 20ms IMA ADPCM voice frame over low-latency UDP,
     * with automatic seamless fallback to either Direct TCP or out-of-band batched
     * Blinded E2EE Serverless Rendezvous datagrams if direct UDP is not yet hole-punched
     * or is blocked by Symmetric 5G/4G CGNAT.
     */
    public void sendEncryptedAudioFrame(byte[] adpcmFrame, int length) {
        if (isClosed.get() || currentState != State.CONNECTED_SECURE || sessionKeys == null
                || adpcmFrame == null || length <= 0 || length > 1024) {
            return;
        }
        long seqNum = outboundAudioSeq.incrementAndGet();
        byte outboundChannel = isHostRole
                ? CryptoEngine.CHANNEL_HOST_TO_CLIENT_AUDIO
                : CryptoEngine.CHANNEL_CLIENT_TO_HOST_AUDIO;
        SecretKey outboundAudioKey = sessionKeys.getOutboundAudioKey(isHostRole);

        boolean udpHealthy = isDirectUdpActive();

        // 1. Always attempt UDP if peerUdpAddress & peerUdpPort are known
        DatagramSocket localUdp = this.udpSocket;
        InetAddress targetAddr = this.peerUdpAddress;
        int targetPort = this.peerUdpPort;
        if (localUdp != null && !localUdp.isClosed() && targetAddr != null && targetPort > 0) {
            try {
                byte[] ciphertext = CryptoEngine.encryptFrame(
                        outboundAudioKey,
                        outboundChannel,
                        UDP_MAGIC,
                        seqNum,
                        adpcmFrame,
                        0,
                        length);

                byte[] udpPayload = new byte[10 + ciphertext.length];
                udpPayload[0] = UDP_MAGIC;
                udpPayload[1] = outboundChannel;
                java.nio.ByteBuffer.wrap(udpPayload, 2, 8).putLong(seqNum);
                System.arraycopy(ciphertext, 0, udpPayload, 10, ciphertext.length);

                DatagramPacket packet = new DatagramPacket(
                        udpPayload, udpPayload.length, targetAddr, targetPort);
                localUdp.send(packet);
            } catch (Exception ignored) {
                udpHealthy = false;
            }
        } else {
            udpHealthy = false;
        }

        // 2. If UDP path is not yet verified (< 2.5s bidirectional), fall back without blocking text/control
        if (!udpHealthy) {
            ControlConnection conn = this.activeControlConn;
            if (conn instanceof RendezvousControlConnection) {
                try {
                    byte[] fallbackCipher = CryptoEngine.encryptFrame(
                            outboundAudioKey,
                            outboundChannel,
                            FRAME_AUDIO_TCP_FALLBACK,
                            seqNum,
                            adpcmFrame,
                            0,
                            length);
                    queueRendezvousAudioFrame(seqNum, fallbackCipher);
                } catch (Exception ignored) {
                }
            } else {
                try {
                    ByteArrayOutputStream baos = new ByteArrayOutputStream(10 + length);
                    DataOutputStream dos = new DataOutputStream(baos);
                    dos.writeLong(seqNum);
                    dos.writeShort(length);
                    dos.write(adpcmFrame, 0, length);
                    sendEncryptedControlFrame(FRAME_AUDIO_TCP_FALLBACK, baos.toByteArray());
                } catch (Exception ignored) {
                }
            }
        }
    }

    private void queueRendezvousAudioFrame(long seqNum, byte[] ciphertext) {
        boolean flushImmediately = false;
        boolean scheduleDelayedFlush = false;
        synchronized (rendezvousAudioBatchLock) {
            if (isClosed.get() || currentState != State.CONNECTED_SECURE) {
                return;
            }
            pendingRendezvousAudioBatch.add(new EncodedAudioFrame(seqNum, ciphertext));
            long now = System.currentTimeMillis();
            if (pendingRendezvousAudioBatch.size() >= RENDEZVOUS_AUDIO_MAX_BATCH_FRAMES) {
                flushImmediately = true;
            } else if (pendingRendezvousAudioBatch.size() == 1
                    && (now - lastRendezvousAudioFlushMs) >= RENDEZVOUS_AUDIO_BATCH_INTERVAL_MS) {
                flushImmediately = true;
            } else if (!rendezvousAudioFlushScheduled) {
                rendezvousAudioFlushScheduled = true;
                scheduleDelayedFlush = true;
            }
        }

        if (flushImmediately) {
            flushRendezvousAudioBatch();
        } else if (scheduleDelayedFlush) {
            boolean scheduled = executeIfActive(() -> {
                while (!isClosed.get() && currentState == State.CONNECTED_SECURE) {
                    long waitMs;
                    synchronized (rendezvousAudioBatchLock) {
                        if (pendingRendezvousAudioBatch.isEmpty()) {
                            rendezvousAudioFlushScheduled = false;
                            return;
                        }
                        long elapsed = System.currentTimeMillis() - lastRendezvousAudioFlushMs;
                        waitMs = RENDEZVOUS_AUDIO_BATCH_INTERVAL_MS - elapsed;
                        if (waitMs <= 0) {
                            rendezvousAudioFlushScheduled = false;
                            break;
                        }
                    }
                    try {
                        Thread.sleep(Math.min(waitMs, RENDEZVOUS_AUDIO_BATCH_INTERVAL_MS));
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        synchronized (rendezvousAudioBatchLock) {
                            rendezvousAudioFlushScheduled = false;
                        }
                        return;
                    }
                }
                flushRendezvousAudioBatch();
            });
            if (!scheduled) {
                synchronized (rendezvousAudioBatchLock) {
                    rendezvousAudioFlushScheduled = false;
                }
            }
        }
    }

    private void flushRendezvousAudioBatch() {
        List<EncodedAudioFrame> batch;
        synchronized (rendezvousAudioBatchLock) {
            if (pendingRendezvousAudioBatch.isEmpty()) {
                return;
            }
            batch = new ArrayList<>(pendingRendezvousAudioBatch);
            pendingRendezvousAudioBatch.clear();
            lastRendezvousAudioFlushMs = System.currentTimeMillis();
        }

        ControlConnection conn = this.activeControlConn;
        if (!(conn instanceof RendezvousControlConnection)
                || isClosed.get()
                || currentState != State.CONNECTED_SECURE) {
            return;
        }

        try {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(2 + batch.size() * 200);
            DataOutputStream dos = new DataOutputStream(baos);
            dos.writeByte(DATAGRAM_MAGIC_AUDIO_BATCH);
            dos.writeByte(batch.size());
            for (EncodedAudioFrame item : batch) {
                dos.writeLong(item.seqNum);
                dos.writeShort(item.ciphertext.length);
                dos.write(item.ciphertext);
            }
            dos.flush();
            ((RendezvousControlConnection) conn).sendDatagram(baos.toByteArray());
        } catch (Exception ignored) {
        }
    }

    private void handleInboundRendezvousAudioDatagram(byte[] data) {
        if (isClosed.get() || currentState != State.CONNECTED_SECURE || sessionKeys == null) {
            return;
        }
        if (data == null || data.length < 2 || data[0] != DATAGRAM_MAGIC_AUDIO_BATCH) {
            return;
        }
        final byte expectedChannel = isHostRole
                ? CryptoEngine.CHANNEL_CLIENT_TO_HOST_AUDIO
                : CryptoEngine.CHANNEL_HOST_TO_CLIENT_AUDIO;
        final SecretKey inboundAudioKey = sessionKeys.getInboundAudioKey(isHostRole);

        try {
            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(data, 1, data.length - 1));
            int count = dis.readUnsignedByte();
            if (count <= 0 || count > 32) {
                return;
            }
            for (int i = 0; i < count; i++) {
                long audioSeq = dis.readLong();
                int cipherLen = dis.readUnsignedShort();
                if (cipherLen < CryptoEngine.GCM_TAG_BYTES || cipherLen > 1200) {
                    return;
                }
                byte[] ciphertext = new byte[cipherLen];
                dis.readFully(ciphertext);

                if (!audioReplayWindow.isPotentiallyValid(audioSeq)) {
                    continue;
                }
                try {
                    byte[] adpcm = CryptoEngine.decryptFrame(
                            inboundAudioKey,
                            expectedChannel,
                            FRAME_AUDIO_TCP_FALLBACK,
                            audioSeq,
                            ciphertext);
                    if (adpcm.length > 0 && audioReplayWindow.checkAndAccept(audioSeq)) {
                        for (SessionListener l : listeners) {
                            l.onEncryptedAudioFrameReceived(audioSeq, adpcm);
                        }
                    }
                } catch (GeneralSecurityException ignored) {
                }
            }
        } catch (IOException ignored) {
        }
    }

    /**
     * Encrypts and sends a UTF-8 text chat message to the connected peer.
     */
    public ChatMessage sendTextMessage(String text) {
        if (text == null || text.trim().isEmpty()) {
            return null;
        }
        if (currentState != State.CONNECTED_SECURE) {
            throw new IllegalStateException("Cannot send message before encrypted session is connected");
        }

        String msgId = UUID.randomUUID().toString();
        long now = System.currentTimeMillis();
        String cleanText = text.trim();
        ChatMessage msg = ChatMessage.createText(msgId, localDisplayName, true, cleanText, now);
        chatHistory.add(msg);

        executeIfActive(() -> {
            try {
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                DataOutputStream dos = new DataOutputStream(baos);
                dos.writeUTF(msgId);
                dos.writeUTF(localDisplayName);
                dos.writeLong(now);
                dos.writeUTF(cleanText);
                sendEncryptedControlFrame(FRAME_TEXT_MESSAGE, baos.toByteArray());
            } catch (Exception e) {
                notifySecurityAlert("Failed to send text message: " + e.getMessage());
            }
        });

        return msg;
    }

    /**
     * Encrypts and streams a compressed image in 16KB chunks with an end-to-end SHA-256 integrity hash.
     */
    public ChatMessage sendImage(byte[] jpegBytes) {
        if (jpegBytes == null || jpegBytes.length == 0) {
            throw new IllegalArgumentException("Empty image data");
        }
        if (jpegBytes.length > ImageCompressor.MAX_IMAGE_BYTES) {
            throw new IllegalArgumentException("Image exceeds maximum allowed size (2 MB)");
        }
        if (currentState != State.CONNECTED_SECURE) {
            throw new IllegalStateException("Cannot send image before encrypted session is connected");
        }

        String imageId = UUID.randomUUID().toString();
        long now = System.currentTimeMillis();
        ChatMessage msg = ChatMessage.createImage(
                imageId, localDisplayName, true, jpegBytes, now, false);
        msg.setTransferProgress(0);
        chatHistory.add(msg);

        executeIfActive(() -> {
            try {
                byte[] sha256 = CryptoEngine.sha256(jpegBytes);
                int totalChunks = (jpegBytes.length + IMAGE_CHUNK_SIZE - 1) / IMAGE_CHUNK_SIZE;

                // 1. Send encrypted IMAGE_HEADER
                ByteArrayOutputStream headerBaos = new ByteArrayOutputStream();
                DataOutputStream headerDos = new DataOutputStream(headerBaos);
                headerDos.writeUTF(imageId);
                headerDos.writeUTF(localDisplayName);
                headerDos.writeInt(jpegBytes.length);
                headerDos.writeInt(totalChunks);
                headerDos.writeByte(sha256.length);
                headerDos.write(sha256);
                sendEncryptedControlFrame(FRAME_IMAGE_HEADER, headerBaos.toByteArray());

                // 2. Send encrypted IMAGE_CHUNK frames
                for (int idx = 0; idx < totalChunks; idx++) {
                    int offset = idx * IMAGE_CHUNK_SIZE;
                    int len = Math.min(IMAGE_CHUNK_SIZE, jpegBytes.length - offset);

                    ByteArrayOutputStream chunkBaos = new ByteArrayOutputStream(len + 32);
                    DataOutputStream chunkDos = new DataOutputStream(chunkBaos);
                    chunkDos.writeUTF(imageId);
                    chunkDos.writeInt(idx);
                    chunkDos.writeInt(len);
                    chunkDos.write(jpegBytes, offset, len);
                    sendEncryptedControlFrame(FRAME_IMAGE_CHUNK, chunkBaos.toByteArray());

                    int progress = ((idx + 1) * 100) / totalChunks;
                    msg.setTransferProgress(progress);
                    for (SessionListener l : listeners) {
                        l.onChatMessageUpdated(msg);
                    }
                }
            } catch (Exception e) {
                notifySecurityAlert("Image transfer error: " + e.getMessage());
            }
        });

        return msg;
    }

    /**
     * Notifies the connected peer of our microphone mute state over the encrypted control channel.
     */
    public void sendMuteState(boolean isMuted) {
        if (currentState != State.CONNECTED_SECURE) {
            return;
        }
        executeIfActive(() -> {
            try {
                byte[] payload = new byte[]{isMuted ? CTRL_MUTE_ON : CTRL_MUTE_OFF};
                sendEncryptedControlFrame(FRAME_CALL_CONTROL, payload);
            } catch (Exception ignored) {
            }
        });
    }

    private void sendEncryptedControlFrame(byte frameType, byte[] plaintext)
            throws IOException, GeneralSecurityException {
        if (isClosed.get()) {
            return;
        }
        writeEncryptedControlFrameInternal(frameType, plaintext);
    }

    private void writeEncryptedControlFrameInternal(byte frameType, byte[] plaintext)
            throws IOException, GeneralSecurityException {
        CryptoEngine.SessionKeys keys = this.sessionKeys;
        DataOutputStream out = this.tcpOut;
        if (keys == null || out == null) {
            return;
        }
        byte outboundChannel = isHostRole
                ? CryptoEngine.CHANNEL_HOST_TO_CLIENT_CTRL
                : CryptoEngine.CHANNEL_CLIENT_TO_HOST_CTRL;
        SecretKey outboundKey = keys.getOutboundControlKey(isHostRole);

        synchronized (tcpWriteLock) {
            long seqNum = outboundControlSeq.incrementAndGet();
            byte[] ciphertext = CryptoEngine.encryptFrame(
                    outboundKey,
                    outboundChannel,
                    frameType,
                    seqNum,
                    plaintext);

            out.writeByte(frameType);
            out.writeLong(seqNum);
            out.writeInt(ciphertext.length);
            out.write(ciphertext);
            out.flush();
        }
    }

    private void markMessageDelivered(String messageId) {
        for (ChatMessage msg : chatHistory) {
            if (msg.getMessageId().equals(messageId)) {
                msg.setDelivered(true);
                msg.setTransferProgress(100);
                for (SessionListener l : listeners) {
                    l.onChatMessageUpdated(msg);
                }
                break;
            }
        }
    }

    private void addSystemMessage(String text) {
        ChatMessage sys = ChatMessage.createSystem(text);
        chatHistory.add(sys);
        for (SessionListener l : listeners) {
            l.onChatMessageReceived(sys);
        }
    }

    private void notifySecurityAlert(String alert) {
        addSystemMessage("SECURITY: " + alert);
        for (SessionListener l : listeners) {
            l.onSecurityAlert(alert);
        }
    }

    private void updateState(State newState, String statusMessage) {
        this.currentState = newState;
        for (SessionListener l : listeners) {
            l.onStateChanged(newState, statusMessage);
        }
    }

    public void close() {
        if (!isClosed.compareAndSet(false, true)) {
            return;
        }
        synchronized (rendezvousAudioBatchLock) {
            pendingRendezvousAudioBatch.clear();
            rendezvousAudioFlushScheduled = false;
        }
        final boolean shouldSendHangup =
                (currentState == State.CONNECTED_SECURE && tcpOut != null && sessionKeys != null);
        final ControlConnection connToClose = this.activeControlConn;
        this.activeControlConn = null;
        final ServerlessRendezvousChannel hostRvToClose = this.hostRendezvousChannel;
        this.hostRendezvousChannel = null;
        final ServerlessRendezvousChannel clientRvToClose = this.clientRendezvousChannel;
        this.clientRendezvousChannel = null;

        if (serverSocket != null) {
            try { serverSocket.close(); } catch (Exception ignored) {}
            serverSocket = null;
        }
        if (udpSocket != null) {
            try { udpSocket.close(); } catch (Exception ignored) {}
            udpSocket = null;
        }

        if (currentState != State.DISCONNECTED && currentState != State.ERROR) {
            updateState(State.DISCONNECTED, "Call ended");
        }

        Runnable hangupAndCloseControl = () -> {
            if (shouldSendHangup) {
                try {
                    writeEncryptedControlFrameInternal(FRAME_CALL_CONTROL, new byte[]{CTRL_END_CALL});
                } catch (Exception ignored) {
                }
            }
            if (connToClose != null) {
                try { connToClose.close(); } catch (Exception ignored) {}
            }
            if (hostRvToClose != null) {
                try { hostRvToClose.close(); } catch (Exception ignored) {}
            }
            if (clientRvToClose != null) {
                try { clientRvToClose.close(); } catch (Exception ignored) {}
            }
        };

        if (isAndroidMainThread()) {
            Thread closeThread = new Thread(hangupAndCloseControl, "Pigeon-SessionClose");
            closeThread.start();
        } else {
            hangupAndCloseControl.run();
        }

        ioExecutor.shutdownNow();
    }

    private static boolean isAndroidMainThread() {
        try {
            android.os.Looper mainLooper = android.os.Looper.getMainLooper();
            return mainLooper != null && mainLooper == android.os.Looper.myLooper();
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void writeUdpCandidatesToStream(
            DataOutputStream dos,
            List<InetSocketAddress> candidates) throws IOException {
        if (candidates == null || candidates.isEmpty()) {
            dos.writeByte(0);
            return;
        }
        int count = Math.min(16, candidates.size());
        dos.writeByte(count);
        for (int i = 0; i < count; i++) {
            InetSocketAddress addr = candidates.get(i);
            String ip = NetworkUtils.stripIpv6Zone(addr.getAddress().getHostAddress());
            dos.writeUTF(ip != null ? ip : "");
            dos.writeInt(addr.getPort());
        }
    }

    private static List<InetSocketAddress> readUdpCandidatesFromStream(DataInputStream dis) {
        List<InetSocketAddress> result = new ArrayList<>();
        try {
            if (dis.available() <= 0) {
                return result;
            }
            int count = dis.readUnsignedByte();
            if (count <= 0 || count > 32) {
                return result;
            }
            for (int i = 0; i < count; i++) {
                String ip = dis.readUTF();
                int port = dis.readInt();
                addNumericEndpointCandidate(result, ip, port);
            }
        } catch (Exception ignored) {
        }
        return result;
    }

    private static boolean addNumericEndpointCandidate(
            List<InetSocketAddress> list,
            String ipString,
            int port) {
        if (ipString == null || ipString.trim().isEmpty() || port <= 0 || port > 65535) {
            return false;
        }
        try {
            String cleanIp = NetworkUtils.stripIpv6Zone(ipString);
            if (cleanIp == null || cleanIp.isEmpty()) {
                return false;
            }
            InetAddress addr = InetAddress.getByName(cleanIp);
            return addUniqueCandidate(list, new InetSocketAddress(addr, port));
        } catch (Exception e) {
            return false;
        }
    }

    private static boolean addUniqueCandidate(
            List<InetSocketAddress> list,
            InetSocketAddress candidate) {
        if (candidate == null || candidate.getAddress() == null || candidate.getPort() <= 0) {
            return false;
        }
        if (!list.contains(candidate) && list.size() < 24) {
            list.add(candidate);
            return true;
        }
        return false;
    }

    private static boolean addPriorityCandidate(
            List<InetSocketAddress> list,
            InetSocketAddress candidate) {
        if (candidate == null || candidate.getAddress() == null || candidate.getPort() <= 0) {
            return false;
        }
        int existingIdx = list.indexOf(candidate);
        if (existingIdx == 0) {
            return false;
        }
        if (existingIdx > 0) {
            list.remove(existingIdx);
        }
        list.add(0, candidate);
        while (list.size() > 24) {
            list.remove(list.size() - 1);
        }
        return true;
    }

    private static void sendPlainHandshakeFrame(DataOutputStream out, byte frameType, byte[] payload)
            throws IOException {
        synchronized (out) {
            out.writeByte(frameType);
            out.writeInt(payload.length);
            out.write(payload);
            out.flush();
        }
    }

    private static PlainFrame readPlainHandshakeFrame(DataInputStream in) throws IOException {
        byte type = in.readByte();
        int len = in.readInt();
        if (len < 0 || len > 32768) {
            throw new IOException("Invalid handshake frame length: " + len);
        }
        byte[] payload = new byte[len];
        in.readFully(payload);
        return new PlainFrame(type, payload);
    }

    private static final class PlainFrame {
        final byte frameType;
        final byte[] payload;

        PlainFrame(byte frameType, byte[] payload) {
            this.frameType = frameType;
            this.payload = payload;
        }
    }

    private interface ControlConnection {
        DataInputStream getInputStream();
        DataOutputStream getOutputStream();
        String getRemoteAddressLabel();
        InetAddress getDirectInetAddress();
        void setReadTimeout(int timeoutMs) throws IOException;
        void close();
        boolean isRendezvous();
    }

    private static final class TcpControlConnection implements ControlConnection {
        private final Socket socket;
        private final DataInputStream in;
        private final DataOutputStream out;

        TcpControlConnection(Socket socket) throws IOException {
            this.socket = socket;
            this.in = new DataInputStream(socket.getInputStream());
            this.out = new DataOutputStream(socket.getOutputStream());
        }

        @Override
        public DataInputStream getInputStream() {
            return in;
        }

        @Override
        public DataOutputStream getOutputStream() {
            return out;
        }

        @Override
        public String getRemoteAddressLabel() {
            InetAddress addr = socket.getInetAddress();
            return addr != null ? addr.getHostAddress() : "tcp-peer";
        }

        @Override
        public InetAddress getDirectInetAddress() {
            return socket.getInetAddress();
        }

        @Override
        public void setReadTimeout(int timeoutMs) throws IOException {
            socket.setSoTimeout(timeoutMs);
        }

        @Override
        public void close() {
            try {
                socket.close();
            } catch (Exception ignored) {
            }
        }

        @Override
        public boolean isRendezvous() {
            return false;
        }
    }

    private static final class RendezvousControlConnection implements ControlConnection {
        private final ServerlessRendezvousChannel.RendezvousStream stream;

        RendezvousControlConnection(ServerlessRendezvousChannel.RendezvousStream stream) {
            this.stream = stream;
        }

        @Override
        public DataInputStream getInputStream() {
            return stream.getDataInputStream();
        }

        @Override
        public DataOutputStream getOutputStream() {
            return stream.getDataOutputStream();
        }

        @Override
        public String getRemoteAddressLabel() {
            return stream.getRemoteLabel();
        }

        @Override
        public InetAddress getDirectInetAddress() {
            return null;
        }

        @Override
        public void setReadTimeout(int timeoutMs) {
            stream.setReadTimeoutMs(timeoutMs);
        }

        @Override
        public void close() {
            stream.close();
        }

        @Override
        public boolean isRendezvous() {
            return true;
        }

        void setDatagramListener(ServerlessRendezvousChannel.RendezvousStream.DatagramListener listener) {
            stream.setDatagramListener(listener);
        }

        void sendDatagram(byte[] data) {
            stream.sendDatagram(data);
        }
    }

    private static final class IncomingImageTransfer {
        final String imageId;
        final String senderName;
        final int totalBytes;
        final int totalChunks;
        final byte[] expectedSha256;
        final byte[][] chunks;
        int receivedChunks = 0;
        int accumulatedBytes = 0;

        IncomingImageTransfer(
                String imageId,
                String senderName,
                int totalBytes,
                int totalChunks,
                byte[] expectedSha256) {
            this.imageId = imageId;
            this.senderName = senderName;
            this.totalBytes = totalBytes;
            this.totalChunks = totalChunks;
            this.expectedSha256 = expectedSha256;
            this.chunks = new byte[totalChunks][];
        }

        synchronized boolean addChunk(int index, byte[] data) {
            if (index < 0 || index >= totalChunks || chunks[index] != null || data == null) {
                return false;
            }
            if (accumulatedBytes + data.length > totalBytes) {
                return false;
            }
            chunks[index] = data;
            accumulatedBytes += data.length;
            receivedChunks++;
            return receivedChunks == totalChunks;
        }

        synchronized byte[] reassembleAndVerify() {
            ByteArrayOutputStream baos = new ByteArrayOutputStream(totalBytes);
            for (int i = 0; i < totalChunks; i++) {
                if (chunks[i] == null) {
                    return null;
                }
                baos.write(chunks[i], 0, chunks[i].length);
            }
            byte[] full = baos.toByteArray();
            if (full.length != totalBytes) {
                return null;
            }
            byte[] actualSha256 = CryptoEngine.sha256(full);
            if (!CryptoEngine.constantTimeEquals(expectedSha256, actualSha256)) {
                return null;
            }
            return full;
        }
    }
}
