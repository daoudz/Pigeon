package com.pigeon.voice.net;

import com.pigeon.voice.crypto.CryptoEngine;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

/**
 * Lightweight, zero-dependency RFC 5389 STUN Client.
 *
 * Discovers the external NAT-mapped public IP and UDP port for the active voice
 * {@link DatagramSocket} by querying redundant public STUN servers
 * (Google STUN & Cloudflare STUN) so two peers across the Internet or 5G
 * mobile networks can perform direct bidirectional UDP hole punching.
 */
public final class StunClient {

    public static final int STUN_HEADER_BYTES = 20;
    public static final int TRANSACTION_ID_BYTES = 12;
    public static final short MSG_BINDING_REQUEST = 0x0001;
    public static final short MSG_BINDING_SUCCESS_RESPONSE = 0x0101;
    public static final int MAGIC_COOKIE = 0x2112A442;

    public static final int ATTR_MAPPED_ADDRESS = 0x0001;
    public static final int ATTR_XOR_MAPPED_ADDRESS = 0x0020;
    public static final int ATTR_XOR_MAPPED_ADDRESS_ALT = 0x8020;

    public static final byte FAMILY_IPV4 = 0x01;
    public static final byte FAMILY_IPV6 = 0x02;

    public static final int DEFAULT_TIMEOUT_MS = 1000;

    private static final byte[] MAGIC_COOKIE_BYTES = new byte[]{
            0x21, 0x12, (byte) 0xA4, 0x42
    };

    private static final String[][] DEFAULT_PUBLIC_STUN_HOSTS = new String[][]{
            {"stun.l.google.com", "19302"},
            {"stun.cloudflare.com", "3478"},
            {"stun1.l.google.com", "19302"}
    };

    private static final String[][] FALLBACK_NUMERIC_STUN_ENDPOINTS = new String[][]{
            {"162.159.207.0", "3478"},
            {"74.125.250.129", "19302"}
    };

    private static final long DNS_CACHE_TTL_MS = 5 * 60 * 1000L;
    private static volatile List<InetSocketAddress> cachedDefaultServers = null;
    private static volatile long cachedDefaultServersTimestampMs = 0L;

    private StunClient() {
    }

    /**
     * Represents a NAT-translated external public IP and UDP port discovered via STUN.
     */
    public static final class StunEndpoint {
        private final String publicIp;
        private final int publicPort;
        private final InetAddress inetAddress;

        public StunEndpoint(InetAddress inetAddress, int publicPort) {
            if (inetAddress == null) {
                throw new IllegalArgumentException("inetAddress cannot be null");
            }
            if (publicPort <= 0 || publicPort > 65535) {
                throw new IllegalArgumentException("Invalid publicPort: " + publicPort);
            }
            this.inetAddress = inetAddress;
            this.publicIp = NetworkUtils.stripIpv6Zone(inetAddress.getHostAddress());
            this.publicPort = publicPort;
        }

        public String getPublicIp() {
            return publicIp;
        }

        public int getPublicPort() {
            return publicPort;
        }

        public InetAddress getInetAddress() {
            return inetAddress;
        }

        public InetSocketAddress toSocketAddress() {
            return new InetSocketAddress(inetAddress, publicPort);
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (!(o instanceof StunEndpoint)) return false;
            StunEndpoint that = (StunEndpoint) o;
            return publicPort == that.publicPort && Objects.equals(publicIp, that.publicIp);
        }

        @Override
        public int hashCode() {
            return Objects.hash(publicIp, publicPort);
        }

        @Override
        public String toString() {
            if (publicIp != null && publicIp.contains(":")) {
                return "[" + publicIp + "]:" + publicPort;
            }
            return publicIp + ":" + publicPort;
        }
    }

    /**
     * Resolves the default redundant public STUN server endpoints in parallel with a bounded timeout
     * and caches the resolved addresses so slow 4G/cellular DNS never stalls STUN discovery.
     */
    public static List<InetSocketAddress> getDefaultStunServers() {
        long now = System.currentTimeMillis();
        List<InetSocketAddress> cached = cachedDefaultServers;
        if (cached != null && !cached.isEmpty() && (now - cachedDefaultServersTimestampMs) < DNS_CACHE_TTL_MS) {
            return new ArrayList<>(cached);
        }

        List<InetSocketAddress> servers = new ArrayList<>(DEFAULT_PUBLIC_STUN_HOSTS.length + 2);
        ExecutorService dnsPool = Executors.newFixedThreadPool(DEFAULT_PUBLIC_STUN_HOSTS.length);
        try {
            List<Callable<InetSocketAddress>> tasks = new ArrayList<>(DEFAULT_PUBLIC_STUN_HOSTS.length);
            for (String[] entry : DEFAULT_PUBLIC_STUN_HOSTS) {
                final String host = entry[0];
                final int port = Integer.parseInt(entry[1]);
                tasks.add(() -> {
                    InetAddress addr = InetAddress.getByName(host);
                    return new InetSocketAddress(addr, port);
                });
            }
            List<Future<InetSocketAddress>> futures = dnsPool.invokeAll(tasks, 500, TimeUnit.MILLISECONDS);
            for (Future<InetSocketAddress> future : futures) {
                if (future.isDone() && !future.isCancelled()) {
                    try {
                        InetSocketAddress resolved = future.get();
                        if (resolved != null && !servers.contains(resolved)) {
                            servers.add(resolved);
                        }
                    } catch (Exception ignored) {
                    }
                }
            }
        } catch (Exception ignored) {
        } finally {
            dnsPool.shutdownNow();
        }

        for (String[] fb : FALLBACK_NUMERIC_STUN_ENDPOINTS) {
            try {
                InetAddress addr = InetAddress.getByName(fb[0]);
                InetSocketAddress sockAddr = new InetSocketAddress(addr, Integer.parseInt(fb[1]));
                if (!servers.contains(sockAddr)) {
                    servers.add(sockAddr);
                }
            } catch (Exception ignored) {
            }
        }

        if (!servers.isEmpty()) {
            cachedDefaultServers = Collections.unmodifiableList(new ArrayList<>(servers));
            cachedDefaultServersTimestampMs = System.currentTimeMillis();
        }
        return servers;
    }

    /**
     * Queries the default public STUN servers on the given UDP socket to discover
     * its external public IP and port. Returns null if all STUN servers are unreachable.
     */
    public static StunEndpoint discoverPublicEndpoint(DatagramSocket udpSocket) {
        if (udpSocket == null || udpSocket.isClosed()) {
            return null;
        }
        List<InetSocketAddress> servers = getDefaultStunServers();
        if (servers.isEmpty()) {
            return null;
        }
        return discoverPublicEndpoint(udpSocket, servers, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Queries the specified redundant STUN servers in parallel on the given UDP socket
     * and returns the first valid RFC 5389 Binding Success Response within {@code totalTimeoutMs}.
     * Restores the socket's original SO_TIMEOUT before returning.
     */
    public static StunEndpoint discoverPublicEndpoint(
            DatagramSocket udpSocket,
            List<InetSocketAddress> stunServers,
            int totalTimeoutMs) {

        if (udpSocket == null || udpSocket.isClosed() || stunServers == null || stunServers.isEmpty()) {
            return null;
        }

        List<InetSocketAddress> validServers = new ArrayList<>(stunServers.size());
        for (InetSocketAddress serverAddr : stunServers) {
            if (serverAddr == null) {
                continue;
            }
            if (serverAddr.isUnresolved()) {
                try {
                    InetAddress resolved = InetAddress.getByName(serverAddr.getHostString());
                    validServers.add(new InetSocketAddress(resolved, serverAddr.getPort()));
                } catch (Exception ignored) {
                }
            } else {
                validServers.add(serverAddr);
            }
        }
        if (validServers.isEmpty()) {
            return null;
        }

        int effectiveTimeoutMs = Math.max(100, totalTimeoutMs);
        int previousTimeout = 0;
        try {
            previousTimeout = udpSocket.getSoTimeout();
        } catch (Exception ignored) {
        }

        try {
            byte[] txId = CryptoEngine.randomBytes(TRANSACTION_ID_BYTES);
            byte[] requestBytes = buildBindingRequest(txId);

            // Send STUN Binding Request to all redundant servers in parallel so a dead primary
            // STUN server never delays discovery from a healthy secondary STUN server.
            sendBindingRequestsToAll(udpSocket, validServers, requestBytes);

            byte[] receiveBuf = new byte[512];
            long startMs = System.currentTimeMillis();
            long deadlineMs = startMs + effectiveTimeoutMs;
            long retryAtMs = startMs + Math.max(80L, effectiveTimeoutMs / 2L);
            boolean retried = false;

            while (System.currentTimeMillis() < deadlineMs && !udpSocket.isClosed()) {
                long now = System.currentTimeMillis();
                if (!retried && now >= retryAtMs) {
                    retried = true;
                    sendBindingRequestsToAll(udpSocket, validServers, requestBytes);
                }

                int remaining = (int) Math.max(20L, deadlineMs - now);
                int sliceTimeout = retried
                        ? remaining
                        : (int) Math.max(20L, Math.min(remaining, retryAtMs - now));
                try {
                    udpSocket.setSoTimeout(sliceTimeout);
                    DatagramPacket respPacket = new DatagramPacket(receiveBuf, receiveBuf.length);
                    udpSocket.receive(respPacket);

                    StunEndpoint endpoint = parseBindingResponse(
                            respPacket.getData(),
                            respPacket.getOffset(),
                            respPacket.getLength(),
                            txId);
                    if (endpoint != null) {
                        return endpoint;
                    }
                } catch (SocketTimeoutException ignored) {
                    // Continue loop (will trigger midway retry or exit at deadlineMs)
                } catch (IOException e) {
                    break;
                }
            }
            return null;
        } finally {
            try {
                if (!udpSocket.isClosed()) {
                    udpSocket.setSoTimeout(previousTimeout);
                }
            } catch (Exception ignored) {
            }
        }
    }

    private static void sendBindingRequestsToAll(
            DatagramSocket udpSocket,
            List<InetSocketAddress> servers,
            byte[] requestBytes) {
        for (InetSocketAddress serverAddr : servers) {
            if (udpSocket.isClosed()) {
                break;
            }
            try {
                DatagramPacket reqPacket = new DatagramPacket(
                        requestBytes,
                        requestBytes.length,
                        serverAddr.getAddress(),
                        serverAddr.getPort());
                udpSocket.send(reqPacket);
            } catch (IOException ignored) {
            }
        }
    }

    /**
     * Constructs a 20-byte RFC 5389 STUN Binding Request with the given 12-byte Transaction ID.
     */
    public static byte[] buildBindingRequest(byte[] transactionId) {
        if (transactionId == null || transactionId.length != TRANSACTION_ID_BYTES) {
            throw new IllegalArgumentException("Transaction ID must be 12 bytes");
        }
        byte[] packet = new byte[STUN_HEADER_BYTES];
        ByteBuffer buf = ByteBuffer.wrap(packet);
        buf.putShort(MSG_BINDING_REQUEST);
        buf.putShort((short) 0); // Message length: 0 attribute bytes
        buf.putInt(MAGIC_COOKIE);
        buf.put(transactionId);
        return packet;
    }

    /**
     * Builds a valid RFC 5389 STUN Binding Success Response with an XOR-MAPPED-ADDRESS attribute.
     * Useful for testing and local STUN responders.
     */
    public static byte[] buildBindingResponse(byte[] transactionId, InetAddress mappedAddr, int mappedPort) {
        if (transactionId == null || transactionId.length != TRANSACTION_ID_BYTES) {
            throw new IllegalArgumentException("Transaction ID must be 12 bytes");
        }
        byte[] rawIp = mappedAddr.getAddress();
        boolean isIpv6 = (rawIp.length == 16);
        int attrValueLen = isIpv6 ? 20 : 8;
        int totalLen = STUN_HEADER_BYTES + 4 + attrValueLen;

        byte[] packet = new byte[totalLen];
        ByteBuffer buf = ByteBuffer.wrap(packet);
        buf.putShort(MSG_BINDING_SUCCESS_RESPONSE);
        buf.putShort((short) (4 + attrValueLen));
        buf.putInt(MAGIC_COOKIE);
        buf.put(transactionId);

        // Attribute header: XOR-MAPPED-ADDRESS (0x0020)
        buf.putShort((short) ATTR_XOR_MAPPED_ADDRESS);
        buf.putShort((short) attrValueLen);
        buf.put((byte) 0x00); // Reserved
        buf.put(isIpv6 ? FAMILY_IPV6 : FAMILY_IPV4);

        int xorPort = (mappedPort & 0xFFFF) ^ (MAGIC_COOKIE >>> 16);
        buf.putShort((short) xorPort);

        byte[] xorIp = new byte[rawIp.length];
        for (int i = 0; i < 4; i++) {
            xorIp[i] = (byte) (rawIp[i] ^ MAGIC_COOKIE_BYTES[i]);
        }
        if (isIpv6) {
            for (int i = 4; i < 16; i++) {
                xorIp[i] = (byte) (rawIp[i] ^ transactionId[i - 4]);
            }
        }
        buf.put(xorIp);
        return packet;
    }

    public static StunEndpoint parseBindingResponse(byte[] data, int length, byte[] expectedTransactionId) {
        return parseBindingResponse(data, 0, length, expectedTransactionId);
    }

    /**
     * Parses an RFC 5389 STUN Binding Response and extracts the XOR-MAPPED-ADDRESS
     * (or fallback MAPPED-ADDRESS). Returns null if the packet is not a valid matching STUN response.
     */
    public static StunEndpoint parseBindingResponse(
            byte[] data,
            int offset,
            int length,
            byte[] expectedTransactionId) {

        if (data == null || expectedTransactionId == null
                || expectedTransactionId.length != TRANSACTION_ID_BYTES
                || length < STUN_HEADER_BYTES
                || offset < 0
                || offset + length > data.length) {
            return null;
        }

        int msgType = ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
        if (msgType != (MSG_BINDING_SUCCESS_RESPONSE & 0xFFFF)) {
            return null;
        }

        int msgLen = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
        if (msgLen < 0 || STUN_HEADER_BYTES + msgLen > length) {
            return null;
        }

        for (int i = 0; i < 4; i++) {
            if (data[offset + 4 + i] != MAGIC_COOKIE_BYTES[i]) {
                return null;
            }
        }

        for (int i = 0; i < TRANSACTION_ID_BYTES; i++) {
            if (data[offset + 8 + i] != expectedTransactionId[i]) {
                return null;
            }
        }

        StunEndpoint fallbackMapped = null;
        int pos = offset + STUN_HEADER_BYTES;
        int limit = offset + STUN_HEADER_BYTES + msgLen;

        while (pos + 4 <= limit) {
            int attrType = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
            int attrLen = ((data[pos + 2] & 0xFF) << 8) | (data[pos + 3] & 0xFF);
            int valOffset = pos + 4;

            if (attrLen < 0 || valOffset + attrLen > limit) {
                break;
            }

            if (attrType == ATTR_XOR_MAPPED_ADDRESS || attrType == ATTR_XOR_MAPPED_ADDRESS_ALT) {
                StunEndpoint xorEndpoint = parseAddressAttribute(
                        data, valOffset, attrLen, true, expectedTransactionId);
                if (xorEndpoint != null) {
                    return xorEndpoint;
                }
            } else if (attrType == ATTR_MAPPED_ADDRESS && fallbackMapped == null) {
                fallbackMapped = parseAddressAttribute(
                        data, valOffset, attrLen, false, expectedTransactionId);
            }

            int paddedAttrLen = (attrLen + 3) & ~3;
            pos = valOffset + paddedAttrLen;
        }

        return fallbackMapped;
    }

    private static StunEndpoint parseAddressAttribute(
            byte[] data,
            int valOffset,
            int attrLen,
            boolean isXor,
            byte[] transactionId) {

        if (attrLen < 8) {
            return null;
        }

        byte family = data[valOffset + 1];
        int rawPort = ((data[valOffset + 2] & 0xFF) << 8) | (data[valOffset + 3] & 0xFF);
        int port = isXor ? (rawPort ^ (MAGIC_COOKIE >>> 16)) : rawPort;
        if (port <= 0 || port > 65535) {
            return null;
        }

        byte[] ipBytes;
        if (family == FAMILY_IPV4) {
            ipBytes = new byte[4];
            for (int i = 0; i < 4; i++) {
                byte b = data[valOffset + 4 + i];
                ipBytes[i] = isXor ? (byte) (b ^ MAGIC_COOKIE_BYTES[i]) : b;
            }
        } else if (family == FAMILY_IPV6) {
            if (attrLen < 20) {
                return null;
            }
            ipBytes = new byte[16];
            for (int i = 0; i < 4; i++) {
                byte b = data[valOffset + 4 + i];
                ipBytes[i] = isXor ? (byte) (b ^ MAGIC_COOKIE_BYTES[i]) : b;
            }
            for (int i = 4; i < 16; i++) {
                byte b = data[valOffset + 4 + i];
                ipBytes[i] = isXor ? (byte) (b ^ transactionId[i - 4]) : b;
            }
        } else {
            return null;
        }

        try {
            InetAddress addr = InetAddress.getByAddress(ipBytes);
            return new StunEndpoint(addr, port);
        } catch (Exception e) {
            return null;
        }
    }
}
