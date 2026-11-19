package com.pigeon.voice.net;

import com.pigeon.voice.audio.AdpcmCodec;
import com.pigeon.voice.crypto.CryptoEngine;
import com.pigeon.voice.token.InviteToken;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Comprehensive verification tests for the 4-Layer Internet & 5G Connectivity Upgrade:
 * - Layer 1: RFC 5389 STUN Client (IPv4 & IPv6 XOR-MAPPED-ADDRESS, fallback MAPPED-ADDRESS, live UDP discovery)
 * - Layer 2: Global Unicast IPv6 (2000::/3) filtering, zone stripping, and candidate prioritization
 * - Layer 3: Blinded E2EE Serverless Rendezvous Stream (HKDF topic blinding, outer AES-256-GCM, MQTT v3.1.1)
 * - Layer 4: Simultaneous bidirectional UDP hole punching + Symmetric 5G CGNAT voice fallback
 */
public class InternetAnd5GConnectivityTest {

    @Test
    public void testLayer1Rfc5389StunXorMappedIpv4AndIpv6AndLiveSocketDiscovery() throws Exception {
        byte[] txId = CryptoEngine.randomBytes(StunClient.TRANSACTION_ID_BYTES);
        byte[] req = StunClient.buildBindingRequest(txId);
        assertEquals(StunClient.STUN_HEADER_BYTES, req.length);

        // 1. Verify IPv4 XOR-MAPPED-ADDRESS encoding & parsing
        InetAddress simPublicIpv4 = InetAddress.getByName("203.0.113.88");
        int simPublicPort4 = 54321;
        byte[] respIpv4 = StunClient.buildBindingResponse(txId, simPublicIpv4, simPublicPort4);

        StunClient.StunEndpoint parsed4 = StunClient.parseBindingResponse(respIpv4, respIpv4.length, txId);
        assertNotNull(parsed4);
        assertEquals("203.0.113.88", parsed4.getPublicIp());
        assertEquals(54321, parsed4.getPublicPort());

        // 2. Verify IPv6 XOR-MAPPED-ADDRESS (128-bit XOR with magic cookie + 96-bit transaction ID)
        InetAddress simPublicIpv6 = InetAddress.getByName("2607:f8b0:4005:805::200e");
        int simPublicPort6 = 61234;
        byte[] respIpv6 = StunClient.buildBindingResponse(txId, simPublicIpv6, simPublicPort6);

        StunClient.StunEndpoint parsed6 = StunClient.parseBindingResponse(respIpv6, respIpv6.length, txId);
        assertNotNull(parsed6);
        assertEquals(simPublicIpv6, parsed6.getInetAddress());
        assertEquals(61234, parsed6.getPublicPort());

        // 3. Mismatched Transaction ID must be rejected
        byte[] wrongTxId = CryptoEngine.randomBytes(StunClient.TRANSACTION_ID_BYTES);
        assertNull(StunClient.parseBindingResponse(respIpv4, respIpv4.length, wrongTxId));
        assertNull(StunClient.parseBindingResponse(null, 0, txId));
        assertNull(StunClient.parseBindingResponse(respIpv4, 10, txId));

        // 4. Test MAPPED-ADDRESS (0x0001) fallback preceded by a non-4-byte-aligned unknown attribute (e.g. 5 bytes padded to 8)
        ByteArrayOutputStream customStun = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(customStun);
        dos.writeShort(StunClient.MSG_BINDING_SUCCESS_RESPONSE);
        dos.writeShort(12 + 12); // 12 bytes unknown padded attr + 12 bytes MAPPED-ADDRESS
        dos.writeInt(StunClient.MAGIC_COOKIE);
        dos.write(txId);
        // Unknown attribute 0x8022 (SOFTWARE) with length 5 (padded to 8 bytes)
        dos.writeShort(0x8022);
        dos.writeShort(5);
        dos.write(new byte[]{1, 2, 3, 4, 5, 0, 0, 0});
        // MAPPED-ADDRESS (0x0001) IPv4 198.51.100.42:49152
        dos.writeShort(StunClient.ATTR_MAPPED_ADDRESS);
        dos.writeShort(8);
        dos.writeByte(0);
        dos.writeByte(StunClient.FAMILY_IPV4);
        dos.writeShort(49152);
        dos.write(new byte[]{(byte) 198, 51, 100, 42});
        byte[] fallbackPkt = customStun.toByteArray();

        StunClient.StunEndpoint fallbackParsed =
                StunClient.parseBindingResponse(fallbackPkt, fallbackPkt.length, txId);
        assertNotNull(fallbackParsed);
        assertEquals("198.51.100.42", fallbackParsed.getPublicIp());
        assertEquals(49152, fallbackParsed.getPublicPort());

        // 5. Test live UDP socket discovery against a local RFC 5389 STUN server,
        // including parallel failover when primary & secondary STUN servers are dead blackholes!
        try (DatagramSocket deadStun1 = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"));
             DatagramSocket deadStun2 = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"));
             LocalStunServer mockStun = new LocalStunServer();
             DatagramSocket voiceUdpSocket = new DatagramSocket(0)) {

            voiceUdpSocket.setSoTimeout(3333);
            List<InetSocketAddress> servers = Arrays.asList(
                    new InetSocketAddress(InetAddress.getByName("127.0.0.1"), deadStun1.getLocalPort()),
                    new InetSocketAddress(InetAddress.getByName("127.0.0.1"), deadStun2.getLocalPort()),
                    new InetSocketAddress(InetAddress.getByName("127.0.0.1"), mockStun.getPort())
            );

            long startMs = System.currentTimeMillis();
            StunClient.StunEndpoint discovered = StunClient.discoverPublicEndpoint(
                    voiceUdpSocket, servers, 450);
            long elapsedMs = System.currentTimeMillis() - startMs;

            assertNotNull("STUN client must discover external mapped endpoint even when first 2 servers are dead",
                    discovered);
            assertTrue("Parallel STUN failover must complete quickly (<350ms), took " + elapsedMs + "ms",
                    elapsedMs < 350L);
            assertEquals("127.0.0.1", discovered.getPublicIp());
            assertEquals(voiceUdpSocket.getLocalPort(), discovered.getPublicPort());
            assertEquals("Original socket timeout must be restored after STUN discovery",
                    3333, voiceUdpSocket.getSoTimeout());
        }
    }

    @Test
    public void testLayer2GlobalUnicastIpv6FilteringAndZoneStripping() throws Exception {
        // 1. Valid Global Unicast IPv6 addresses (2000::/3) must be accepted
        assertTrue(NetworkUtils.isGlobalUnicastIpv6(InetAddress.getByName("2001:4860:4860::8888")));
        assertTrue(NetworkUtils.isGlobalUnicastIpv6(InetAddress.getByName("2607:f8b0:4005:805::200e")));
        assertTrue(NetworkUtils.isGlobalUnicastIpv6(InetAddress.getByName("3fff:ffff:ffff:ffff::1")));

        // 2. Non-global IPv6 addresses must be rejected
        assertFalse("Loopback ::1 must be rejected",
                NetworkUtils.isGlobalUnicastIpv6(InetAddress.getByName("::1")));
        assertFalse("Link-local fe80::/10 must be rejected",
                NetworkUtils.isGlobalUnicastIpv6(InetAddress.getByName("fe80::1")));
        assertFalse("Site-local fec0::/10 must be rejected",
                NetworkUtils.isGlobalUnicastIpv6(InetAddress.getByName("fec0::1")));
        assertFalse("RFC 4193 ULA fc00::/7 (fc00::) must be rejected",
                NetworkUtils.isGlobalUnicastIpv6(InetAddress.getByName("fc00::1")));
        assertFalse("RFC 4193 ULA fc00::/7 (fd00::) must be rejected",
                NetworkUtils.isGlobalUnicastIpv6(InetAddress.getByName("fd12:3456:789a::1")));
        assertFalse("Multicast ff00::/8 must be rejected",
                NetworkUtils.isGlobalUnicastIpv6(InetAddress.getByName("ff02::1")));
        assertFalse("IPv4 address must not be classified as Global Unicast IPv6",
                NetworkUtils.isGlobalUnicastIpv6(InetAddress.getByName("192.168.1.10")));

        // 3. Zone suffix (%rmnet_data0, %wlan0) and brackets must be stripped cleanly
        assertEquals("2607:f8b0::1", NetworkUtils.stripIpv6Zone("2607:f8b0::1%rmnet_data0"));
        assertEquals("2001:db8::42", NetworkUtils.stripIpv6Zone("[2001:db8::42%wlan0]"));
        assertEquals("2001:db8::42", NetworkUtils.stripIpv6Zone("[2001:db8::42]%wlan0"));
        assertEquals("198.51.100.7", NetworkUtils.stripIpv6Zone(" 198.51.100.7 "));
        assertNull(NetworkUtils.stripIpv6Zone(null));

        // 4. Candidate ordering prioritizes STUN public IP first
        List<String> candidates = NetworkUtils.getCandidateHostAddresses("198.51.100.99");
        assertFalse(candidates.isEmpty());
        assertEquals("198.51.100.99", candidates.get(0));
    }

    @Test
    public void testLayer3BlindedRendezvousEnvelopeAeadAndAntiReflection() throws Exception {
        byte[] secretA = CryptoEngine.randomBytes(CryptoEngine.INVITE_SECRET_BYTES);
        byte[] secretB = CryptoEngine.randomBytes(CryptoEngine.INVITE_SECRET_BYTES);

        ServerlessRendezvousChannel hostCh = new ServerlessRendezvousChannel(
                "sessAbc12345", secretA, true, null);
        ServerlessRendezvousChannel clientCh = new ServerlessRendezvousChannel(
                "sessAbc12345", secretA, false, null);
        ServerlessRendezvousChannel otherCh = new ServerlessRendezvousChannel(
                "sessAbc12345", secretB, false, null);

        // Same session + inviteSecret must derive identical blinded topic
        assertEquals(hostCh.getBlindedTopicRoot(), clientCh.getBlindedTopicRoot());
        assertTrue(hostCh.getBlindedTopicRoot().startsWith("pgn/v1/"));
        // Different inviteSecret must derive completely different blinded topic
        assertNotEquals(hostCh.getBlindedTopicRoot(), otherCh.getBlindedTopicRoot());

        SecretKey key = new SecretKeySpec(CryptoEngine.randomBytes(32), "AES");
        byte[] innerPayload = "Encrypted handshake frame".getBytes(StandardCharsets.UTF_8);

        byte[] wire = ServerlessRendezvousChannel.encryptEnvelope(
                key,
                ServerlessRendezvousChannel.DIR_CLIENT_TO_HOST,
                ServerlessRendezvousChannel.PKT_DATA,
                0x1122334455667788L,
                7L,
                innerPayload);

        ServerlessRendezvousChannel.EnvelopePacket decrypted =
                ServerlessRendezvousChannel.decryptEnvelope(
                        key,
                        ServerlessRendezvousChannel.DIR_CLIENT_TO_HOST,
                        wire);
        assertEquals(ServerlessRendezvousChannel.PKT_DATA, decrypted.packetType);
        assertEquals(0x1122334455667788L, decrypted.clientConnId);
        assertEquals(7L, decrypted.packetSeq);
        assertArrayEquals(innerPayload, decrypted.data);

        // Reflection attack (replaying C2H packet on H2C direction) must fail GCM AAD authentication
        try {
            ServerlessRendezvousChannel.decryptEnvelope(
                    key,
                    ServerlessRendezvousChannel.DIR_HOST_TO_CLIENT,
                    wire);
            fail("Expected GeneralSecurityException on direction reflection attack");
        } catch (GeneralSecurityException expected) {
        }
    }

    @Test
    public void testLayers1To4FullCallOverRendezvousWithCgnatBlockedTcpHolePunchAndSymmetricFallback()
            throws Exception {

        try (LocalStunServer localStun = new LocalStunServer();
             LocalMqttBroker localMqtt = new LocalMqttBroker()) {

            List<InetSocketAddress> stunServers = Collections.singletonList(
                    new InetSocketAddress(InetAddress.getByName("127.0.0.1"), localStun.getPort()));
            List<ServerlessRendezvousChannel.BrokerEndpoint> brokers = Collections.singletonList(
                    new ServerlessRendezvousChannel.BrokerEndpoint("127.0.0.1", localMqtt.getPort(), false));

            P2PSessionManager host = new P2PSessionManager();
            host.setStunServers(stunServers);
            host.setRendezvousBrokers(brokers);

            P2PSessionManager client = new P2PSessionManager();
            client.setStunServers(stunServers);
            client.setRendezvousBrokers(brokers);

            P2PSessionManager intruder = new P2PSessionManager();
            intruder.setStunServers(stunServers);
            intruder.setRendezvousBrokers(brokers);

            try {
                CountDownLatch hostHandshakeLatch = new CountDownLatch(1);
                CountDownLatch clientHandshakeLatch = new CountDownLatch(1);
                CountDownLatch clientReceivedTextLatch = new CountDownLatch(1);
                CountDownLatch hostTextAckLatch = new CountDownLatch(1);
                CountDownLatch hostReceivedImageLatch = new CountDownLatch(1);
                CountDownLatch clientReceivedHolePunchedUdpVoiceLatch = new CountDownLatch(1);
                CountDownLatch hostReceivedFallbackVoiceLatch = new CountDownLatch(1);
                CountDownLatch intruderRejectedLatch = new CountDownLatch(1);
                CountDownLatch hostIntruderAlertLatch = new CountDownLatch(1);

                AtomicReference<ChatMessage> receivedTextRef = new AtomicReference<>();
                AtomicReference<ChatMessage> receivedImageRef = new AtomicReference<>();
                AtomicReference<byte[]> receivedUdpVoiceRef = new AtomicReference<>();
                AtomicReference<byte[]> receivedFallbackVoiceRef = new AtomicReference<>();

                host.addListener(new TestListenerAdapter() {
                    @Override
                    public void onHandshakeCompleted(String peerName, String safetyNumber) {
                        hostHandshakeLatch.countDown();
                    }

                    @Override
                    public void onChatMessageReceived(ChatMessage message) {
                        if (message.getType() == ChatMessage.Type.IMAGE) {
                            receivedImageRef.set(message);
                            hostReceivedImageLatch.countDown();
                        }
                    }

                    @Override
                    public void onChatMessageUpdated(ChatMessage message) {
                        if (message.getType() == ChatMessage.Type.TEXT && message.isDelivered()) {
                            hostTextAckLatch.countDown();
                        }
                    }

                    @Override
                    public void onEncryptedAudioFrameReceived(long sequenceNumber, byte[] adpcmFrame) {
                        if (receivedFallbackVoiceRef.compareAndSet(null, adpcmFrame)) {
                            hostReceivedFallbackVoiceLatch.countDown();
                        }
                    }

                    @Override
                    public void onSecurityAlert(String alertMessage) {
                        hostIntruderAlertLatch.countDown();
                    }
                });

                client.addListener(new TestListenerAdapter() {
                    @Override
                    public void onHandshakeCompleted(String peerName, String safetyNumber) {
                        clientHandshakeLatch.countDown();
                    }

                    @Override
                    public void onChatMessageReceived(ChatMessage message) {
                        if (message.getType() == ChatMessage.Type.TEXT) {
                            receivedTextRef.set(message);
                            clientReceivedTextLatch.countDown();
                        }
                    }

                    @Override
                    public void onEncryptedAudioFrameReceived(long sequenceNumber, byte[] adpcmFrame) {
                        if (receivedUdpVoiceRef.compareAndSet(null, adpcmFrame)) {
                            clientReceivedHolePunchedUdpVoiceLatch.countDown();
                        }
                    }
                });

                intruder.addListener(new TestListenerAdapter() {
                    @Override
                    public void onStateChanged(P2PSessionManager.State newState, String statusMessage) {
                        if (newState == P2PSessionManager.State.ERROR) {
                            intruderRejectedLatch.countDown();
                        }
                    }
                });

                // 1. Host starts hosting and discovers its STUN endpoint
                InviteToken token = host.startHosting(
                        "5GHostAlice",
                        "",
                        Collections.singletonList("127.0.0.1"));
                assertNotNull("Host must discover its STUN endpoint", host.getLocalStunEndpoint());

                // 2. Simulate 5G Carrier-Grade NAT (CGNAT) blocking ALL direct inbound TCP connections to Host!
                host.simulateInboundTcpFirewallForTest();

                // 3. Client joins using the token -> Direct TCP is refused by CGNAT ->
                // Client automatically falls back to Blinded E2EE Serverless Rendezvous Channel!
                client.joinSession(token, "5GClientBob", "");

                assertTrue("Host handshake must complete over Serverless Rendezvous",
                        hostHandshakeLatch.await(6, TimeUnit.SECONDS));
                assertTrue("Client handshake must complete over Serverless Rendezvous",
                        clientHandshakeLatch.await(6, TimeUnit.SECONDS));

                assertEquals(P2PSessionManager.State.CONNECTED_SECURE, host.getCurrentState());
                assertEquals(P2PSessionManager.State.CONNECTED_SECURE, client.getCurrentState());
                assertTrue("Host must be using Serverless Rendezvous control stream",
                        host.isUsingRendezvousControl());
                assertTrue("Client must be using Serverless Rendezvous control stream",
                        client.isUsingRendezvousControl());
                assertEquals("Safety Numbers (SAS) must match over Rendezvous",
                        host.getSafetyNumber(), client.getSafetyNumber());
                assertNotNull("Client must also discover its STUN endpoint", client.getLocalStunEndpoint());

                // 4. Verify simultaneous bidirectional UDP hole punching locked onto direct P2P UDP!
                long holePunchDeadline = System.currentTimeMillis() + 3000L;
                while (System.currentTimeMillis() < holePunchDeadline
                        && (!host.isDirectUdpActive() || !client.isDirectUdpActive())) {
                    Thread.sleep(40);
                }
                assertTrue("Host must lock onto direct hole-punched UDP", host.isDirectUdpActive());
                assertTrue("Client must lock onto direct hole-punched UDP", client.isDirectUdpActive());

                // 5. Stream encrypted voice over the hole-punched direct P2P UDP pinhole
                AdpcmCodec codec = new AdpcmCodec();
                short[] pcm = new short[AdpcmCodec.SAMPLES_PER_FRAME];
                for (int i = 0; i < pcm.length; i++) {
                    pcm[i] = (short) (Math.sin(i * 0.25) * 10000);
                }
                byte[] adpcmVoice = codec.encode(pcm, pcm.length);
                host.sendEncryptedAudioFrame(adpcmVoice, adpcmVoice.length);

                assertTrue("Client must receive encrypted voice over hole-punched UDP",
                        clientReceivedHolePunchedUdpVoiceLatch.await(5, TimeUnit.SECONDS));
                assertArrayEquals(adpcmVoice, receivedUdpVoiceRef.get());

                // 6. Test encrypted text chat & delivery ACK over Serverless Rendezvous
                host.sendTextMessage("Connected across 5G CGNAT via Blinded Rendezvous!");
                assertTrue("Client must receive encrypted chat over Rendezvous",
                        clientReceivedTextLatch.await(5, TimeUnit.SECONDS));
                assertEquals("Connected across 5G CGNAT via Blinded Rendezvous!",
                        receivedTextRef.get().getText());
                assertTrue("Host must receive delivery ACK over Rendezvous",
                        hostTextAckLatch.await(5, TimeUnit.SECONDS));

                // 7. Test multi-chunk 36KB encrypted image transfer with SHA-256 verification over Rendezvous
                byte[] imageBytes = CryptoEngine.randomBytes(36 * 1024);
                client.sendImage(imageBytes);
                assertTrue("Host must receive & SHA-256 verify multi-chunk image over Rendezvous",
                        hostReceivedImageLatch.await(5, TimeUnit.SECONDS));
                assertArrayEquals(imageBytes, receivedImageRef.get().getImageBytes());

                // 8. Test single-peer lockout (1/1 Peer): Intruder tries to join via Rendezvous with same token
                intruder.joinSession(token, "MobileIntruder", "");
                assertTrue("Intruder over Rendezvous must be rejected with FRAME_AUTH_REJECT",
                        intruderRejectedLatch.await(5, TimeUnit.SECONDS));
                assertEquals(P2PSessionManager.State.ERROR, intruder.getCurrentState());
                assertTrue("Host must fire security alert for Rendezvous intruder",
                        hostIntruderAlertLatch.await(5, TimeUnit.SECONDS));
                assertEquals(1, host.getBlockedIntruderAttempts());

                // 9. Simulate strict Symmetric 5G CGNAT blocking direct UDP packets completely ->
                // verify automatic fallback to FRAME_AUDIO_TCP_FALLBACK over Serverless Rendezvous!
                host.simulateSymmetricCgnatUdpBlockedForTest();
                client.simulateSymmetricCgnatUdpBlockedForTest();
                assertFalse(client.isDirectUdpActive());

                byte[] fallbackAdpcm = codec.encode(pcm, pcm.length);
                client.sendEncryptedAudioFrame(fallbackAdpcm, fallbackAdpcm.length);
                assertTrue("Host must receive encrypted voice via FRAME_AUDIO_TCP_FALLBACK over Rendezvous",
                        hostReceivedFallbackVoiceLatch.await(5, TimeUnit.SECONDS));
                assertArrayEquals(fallbackAdpcm, receivedFallbackVoiceRef.get());

            } finally {
                intruder.close();
                client.close();
                host.close();
            }
        }
    }

    @Test
    public void testMultiBrokerRedundancyDedupAndMidCallBrokerFailover() throws Exception {
        try (LocalMqttBroker broker1 = new LocalMqttBroker();
             LocalMqttBroker broker2 = new LocalMqttBroker()) {

            List<ServerlessRendezvousChannel.BrokerEndpoint> redundantBrokers = Arrays.asList(
                    new ServerlessRendezvousChannel.BrokerEndpoint("127.0.0.1", broker1.getPort(), false),
                    new ServerlessRendezvousChannel.BrokerEndpoint("127.0.0.1", broker2.getPort(), false)
            );

            P2PSessionManager host = new P2PSessionManager();
            host.setRendezvousBrokers(redundantBrokers);

            P2PSessionManager client = new P2PSessionManager();
            client.setRendezvousBrokers(redundantBrokers);

            try {
                CountDownLatch hostConnected = new CountDownLatch(1);
                CountDownLatch clientConnected = new CountDownLatch(1);
                CountDownLatch clientMsgAfterFailover = new CountDownLatch(1);
                CountDownLatch hostGracefulHangup = new CountDownLatch(1);
                AtomicReference<String> msgRef = new AtomicReference<>();

                host.addListener(new TestListenerAdapter() {
                    @Override
                    public void onHandshakeCompleted(String peerName, String safetyNumber) {
                        hostConnected.countDown();
                    }

                    @Override
                    public void onChatMessageReceived(ChatMessage message) {
                        if (message.getType() == ChatMessage.Type.SYSTEM
                                && message.getText().contains("hung up")) {
                            hostGracefulHangup.countDown();
                        }
                    }
                });

                client.addListener(new TestListenerAdapter() {
                    @Override
                    public void onHandshakeCompleted(String peerName, String safetyNumber) {
                        clientConnected.countDown();
                    }

                    @Override
                    public void onChatMessageReceived(ChatMessage message) {
                        if (message.getType() == ChatMessage.Type.TEXT) {
                            msgRef.set(message.getText());
                            clientMsgAfterFailover.countDown();
                        }
                    }
                });

                InviteToken token = host.startHosting(
                        "RedundantHost",
                        "",
                        Collections.singletonList("127.0.0.1"));
                host.simulateInboundTcpFirewallForTest();

                client.joinSession(token, "RedundantClient", "");

                assertTrue(hostConnected.await(6, TimeUnit.SECONDS));
                assertTrue(clientConnected.await(6, TimeUnit.SECONDS));

                // Kill Broker 1 mid-call! Traffic must continue over Broker 2 seamlessly
                broker1.close();
                Thread.sleep(50);

                host.sendTextMessage("Surviving broker 1 outage via broker 2 redundancy");
                assertTrue("Message must arrive over surviving broker 2",
                        clientMsgAfterFailover.await(5, TimeUnit.SECONDS));
                assertEquals("Surviving broker 1 outage via broker 2 redundancy", msgRef.get());

                // Client hangs up gracefully over Broker 2
                client.close();
                assertTrue("Host must receive graceful CTRL_END_CALL over surviving broker 2",
                        hostGracefulHangup.await(5, TimeUnit.SECONDS));
            } finally {
                client.close();
                host.close();
            }
        }
    }

    @Test
    public void testAsymmetricOneWayNatRequiresBidirectionalVerificationAndMidCallWifiTo5GHandoff()
            throws Exception {

        try (LocalStunServer localStun = new LocalStunServer();
             LocalMqttBroker localMqtt = new LocalMqttBroker()) {

            List<InetSocketAddress> stunServers = Collections.singletonList(
                    new InetSocketAddress(InetAddress.getByName("127.0.0.1"), localStun.getPort()));
            List<ServerlessRendezvousChannel.BrokerEndpoint> brokers = Collections.singletonList(
                    new ServerlessRendezvousChannel.BrokerEndpoint("127.0.0.1", localMqtt.getPort(), false));

            P2PSessionManager host = new P2PSessionManager();
            host.setStunServers(stunServers);
            host.setRendezvousBrokers(brokers);

            P2PSessionManager client = new P2PSessionManager();
            client.setStunServers(stunServers);
            client.setRendezvousBrokers(brokers);

            // Simulate Asymmetric / One-Way NAT on Client BEFORE joining:
            // Client's outbound UDP reaches Host, but Client's firewall drops all inbound UDP from Host!
            client.simulateOneWayInboundUdpBlockedForTest(true);

            try {
                CountDownLatch hostHandshakeLatch = new CountDownLatch(1);
                CountDownLatch clientHandshakeLatch = new CountDownLatch(1);
                CountDownLatch clientReceivedOneWayFallbackVoice = new CountDownLatch(1);
                CountDownLatch clientReceivedPostHandoffVoice = new CountDownLatch(1);
                CountDownLatch hostReceivedPostHandoffVoice = new CountDownLatch(1);

                AtomicReference<byte[]> oneWayVoiceRef = new AtomicReference<>();
                AtomicReference<byte[]> clientPostHandoffVoiceRef = new AtomicReference<>();
                AtomicReference<byte[]> hostPostHandoffVoiceRef = new AtomicReference<>();

                host.addListener(new TestListenerAdapter() {
                    @Override
                    public void onHandshakeCompleted(String peerName, String safetyNumber) {
                        hostHandshakeLatch.countDown();
                    }

                    @Override
                    public void onEncryptedAudioFrameReceived(long sequenceNumber, byte[] adpcmFrame) {
                        if (hostPostHandoffVoiceRef.compareAndSet(null, adpcmFrame)) {
                            hostReceivedPostHandoffVoice.countDown();
                        }
                    }
                });

                client.addListener(new TestListenerAdapter() {
                    @Override
                    public void onHandshakeCompleted(String peerName, String safetyNumber) {
                        clientHandshakeLatch.countDown();
                    }

                    @Override
                    public void onEncryptedAudioFrameReceived(long sequenceNumber, byte[] adpcmFrame) {
                        if (sequenceNumber == 1L) {
                            if (oneWayVoiceRef.compareAndSet(null, adpcmFrame)) {
                                clientReceivedOneWayFallbackVoice.countDown();
                            }
                        } else if (sequenceNumber >= 2L) {
                            if (clientPostHandoffVoiceRef.compareAndSet(null, adpcmFrame)) {
                                clientReceivedPostHandoffVoice.countDown();
                            }
                        }
                    }
                });

                InviteToken token = host.startHosting(
                        "HostAlice",
                        "",
                        Collections.singletonList("127.0.0.1"));
                host.simulateInboundTcpFirewallForTest();

                client.joinSession(token, "ClientBob", "");

                assertTrue(hostHandshakeLatch.await(6, TimeUnit.SECONDS));
                assertTrue(clientHandshakeLatch.await(6, TimeUnit.SECONDS));

                // Wait 250ms for Client's one-way UDP hole-punch packets to reach Host
                Thread.sleep(250);

                // 1. Even though Host received Client's UDP packets, Client has NOT received or ACKed Host's UDP!
                // Therefore Host MUST NOT falsely mark direct UDP as active!
                assertFalse("Host must not mark UDP active on a one-way UDP path without peer ACK",
                        host.isDirectUdpActive());
                assertFalse("Client must not mark UDP active when inbound UDP is blocked",
                        client.isDirectUdpActive());

                // 2. Host sends voice frame (seq=1) -> must automatically fall back to FRAME_AUDIO_TCP_FALLBACK
                // so Client still hears Host despite the one-way UDP block!
                AdpcmCodec codec = new AdpcmCodec();
                short[] pcm = new short[AdpcmCodec.SAMPLES_PER_FRAME];
                for (int i = 0; i < pcm.length; i++) {
                    pcm[i] = (short) (Math.cos(i * 0.2) * 9000);
                }
                byte[] voiceFrame1 = codec.encode(pcm, pcm.length);
                host.sendEncryptedAudioFrame(voiceFrame1, voiceFrame1.length);

                assertTrue("Client must receive Host's voice via control stream fallback under one-way UDP block",
                        clientReceivedOneWayFallbackVoice.await(5, TimeUnit.SECONDS));
                assertArrayEquals(voiceFrame1, oneWayVoiceRef.get());

                // 3. Now unblock Client's inbound UDP and trigger a Mid-Call Wi-Fi -> 5G Network Handoff on Client!
                int oldClientStunPort = client.getLocalStunEndpoint().getPublicPort();
                client.simulateOneWayInboundUdpBlockedForTest(false);
                client.notifyNetworkChangedOrHandoff();

                // Wait for Client to bind its new UDP socket, discover its new STUN port, advertise FRAME_UDP_CANDIDATES,
                // and complete the 3-way bidirectional UDP hole-punch verification with Host
                long handoffDeadline = System.currentTimeMillis() + 3500L;
                while (System.currentTimeMillis() < handoffDeadline
                        && (!host.isDirectUdpActive()
                        || !client.isDirectUdpActive()
                        || client.getLocalStunEndpoint() == null
                        || client.getLocalStunEndpoint().getPublicPort() == oldClientStunPort)) {
                    Thread.sleep(40);
                }

                assertNotNull(client.getLocalStunEndpoint());
                assertNotEquals("Client UDP port must change after mid-call network handoff",
                        oldClientStunPort, client.getLocalStunEndpoint().getPublicPort());
                assertTrue("Host must lock onto new bidirectional UDP pinhole after handoff",
                        host.isDirectUdpActive());
                assertTrue("Client must lock onto new bidirectional UDP pinhole after handoff",
                        client.isDirectUdpActive());

                // 4. Verify bidirectional voice frames flow over the newly hole-punched UDP pinhole
                byte[] voiceFrame2 = codec.encode(pcm, pcm.length);
                host.sendEncryptedAudioFrame(voiceFrame2, voiceFrame2.length);
                client.sendEncryptedAudioFrame(voiceFrame2, voiceFrame2.length);

                assertTrue("Client must receive voice over newly hole-punched UDP port after handoff",
                        clientReceivedPostHandoffVoice.await(5, TimeUnit.SECONDS));
                assertArrayEquals(voiceFrame2, clientPostHandoffVoiceRef.get());

                assertTrue("Host must receive voice over newly hole-punched UDP port after handoff",
                        hostReceivedPostHandoffVoice.await(5, TimeUnit.SECONDS));
                assertArrayEquals(voiceFrame2, hostPostHandoffVoiceRef.get());

            } finally {
                client.close();
                host.close();
            }
        }
    }

    @Test
    public void testRendezvousBatchedDatagramVoicePreventsHeadOfLineBlockingAndDeliversText()
            throws Exception {
        try (LocalMqttBroker localMqtt = new LocalMqttBroker()) {
            // Simulate a 4G / rate-limited public MQTT broker that drops every 5th PKT_DATAGRAM
            localMqtt.setDropPublishEveryN(5);

            List<ServerlessRendezvousChannel.BrokerEndpoint> brokers = Collections.singletonList(
                    new ServerlessRendezvousChannel.BrokerEndpoint("127.0.0.1", localMqtt.getPort(), false));

            P2PSessionManager host = new P2PSessionManager();
            host.setRendezvousBrokers(brokers);

            P2PSessionManager client = new P2PSessionManager();
            client.setRendezvousBrokers(brokers);

            try {
                CountDownLatch hostReady = new CountDownLatch(1);
                CountDownLatch clientReady = new CountDownLatch(1);
                CountDownLatch clientReceivedAllTexts = new CountDownLatch(10);
                CountDownLatch hostAckedAllTexts = new CountDownLatch(10);
                CountDownLatch hostReceivedAllTexts = new CountDownLatch(5);
                java.util.concurrent.atomic.AtomicInteger clientAudioFrames =
                        new java.util.concurrent.atomic.AtomicInteger();
                java.util.concurrent.atomic.AtomicInteger hostAudioFrames =
                        new java.util.concurrent.atomic.AtomicInteger();

                host.addListener(new TestListenerAdapter() {
                    @Override
                    public void onHandshakeCompleted(String peerName, String safetyNumber) {
                        hostReady.countDown();
                    }

                    @Override
                    public void onChatMessageReceived(ChatMessage message) {
                        if (message.getType() == ChatMessage.Type.TEXT) {
                            hostReceivedAllTexts.countDown();
                        }
                    }

                    @Override
                    public void onChatMessageUpdated(ChatMessage message) {
                        if (message.getType() == ChatMessage.Type.TEXT && message.isDelivered()) {
                            hostAckedAllTexts.countDown();
                        }
                    }

                    @Override
                    public void onEncryptedAudioFrameReceived(long sequenceNumber, byte[] adpcmFrame) {
                        hostAudioFrames.incrementAndGet();
                    }
                });

                client.addListener(new TestListenerAdapter() {
                    @Override
                    public void onHandshakeCompleted(String peerName, String safetyNumber) {
                        clientReady.countDown();
                    }

                    @Override
                    public void onChatMessageReceived(ChatMessage message) {
                        if (message.getType() == ChatMessage.Type.TEXT) {
                            clientReceivedAllTexts.countDown();
                        }
                    }

                    @Override
                    public void onEncryptedAudioFrameReceived(long sequenceNumber, byte[] adpcmFrame) {
                        clientAudioFrames.incrementAndGet();
                    }
                });

                InviteToken token = host.startHosting(
                        "WifiHost",
                        "",
                        Collections.singletonList("192.0.2.1"));
                host.simulateInboundTcpFirewallForTest();
                host.simulateSymmetricCgnatUdpBlockedForTest();
                client.simulateSymmetricCgnatUdpBlockedForTest();

                client.joinSession(token, "4GClient", "");
                assertTrue(hostReady.await(6, TimeUnit.SECONDS));
                assertTrue(clientReady.await(6, TimeUnit.SECONDS));

                host.simulateSymmetricCgnatUdpBlockedForTest();
                client.simulateSymmetricCgnatUdpBlockedForTest();

                AdpcmCodec codec = new AdpcmCodec();
                short[] pcm = new short[AdpcmCodec.SAMPLES_PER_FRAME];
                for (int i = 0; i < pcm.length; i++) {
                    pcm[i] = (short) (Math.sin(i * 0.25) * 9000);
                }
                byte[] adpcm = codec.encode(pcm, pcm.length);

                int publishesBeforeStream = localMqtt.getTotalPublishesRouted();

                // Stream 75 frames (1.5s at 50fps) bidirectionally while sending 10 + 5 text messages
                for (int i = 0; i < 75; i++) {
                    host.sendEncryptedAudioFrame(adpcm, adpcm.length);
                    client.sendEncryptedAudioFrame(adpcm, adpcm.length);
                    if (i % 7 == 0 && (i / 7) < 10) {
                        host.sendTextMessage("Host-msg-" + (i / 7));
                    }
                    if (i % 15 == 0 && (i / 15) < 5) {
                        client.sendTextMessage("Client-msg-" + (i / 15));
                    }
                    Thread.sleep(20);
                }

                assertTrue("All 10 host text messages must reach client without head-of-line blocking",
                        clientReceivedAllTexts.await(5, TimeUnit.SECONDS));
                assertTrue("All 10 host text delivery ACKs must return over Rendezvous",
                        hostAckedAllTexts.await(5, TimeUnit.SECONDS));
                assertTrue("All 5 client text messages must reach host without head-of-line blocking",
                        hostReceivedAllTexts.await(5, TimeUnit.SECONDS));

                // Wait briefly for trailing audio batch flush
                long deadline = System.currentTimeMillis() + 1500L;
                while (System.currentTimeMillis() < deadline
                        && (clientAudioFrames.get() < 40 || hostAudioFrames.get() < 40)) {
                    Thread.sleep(30);
                }
                assertTrue("Client must receive batched voice frames despite broker drops, got "
                        + clientAudioFrames.get(), clientAudioFrames.get() >= 40);
                assertTrue("Host must receive batched voice frames despite broker drops, got "
                        + hostAudioFrames.get(), hostAudioFrames.get() >= 40);

                // Verify batching drastically reduced MQTT publish count vs unbatched 50fps (~400+ with ACKs & retransmits)
                int publishesDuringStream = localMqtt.getTotalPublishesRouted() - publishesBeforeStream;
                assertTrue("Batched audio + chat must use < 180 total MQTT publishes (was "
                        + publishesDuringStream + ")", publishesDuringStream < 180);
            } finally {
                client.close();
                host.close();
            }
        }
    }

    @Test
    public void testRendezvousBatchedAudioFlushesTrailingPartialBatch() throws Exception {
        try (LocalMqttBroker localMqtt = new LocalMqttBroker()) {
            List<ServerlessRendezvousChannel.BrokerEndpoint> brokers = Collections.singletonList(
                    new ServerlessRendezvousChannel.BrokerEndpoint("127.0.0.1", localMqtt.getPort(), false));

            P2PSessionManager host = new P2PSessionManager();
            host.setRendezvousBrokers(brokers);

            P2PSessionManager client = new P2PSessionManager();
            client.setRendezvousBrokers(brokers);

            try {
                CountDownLatch hostReady = new CountDownLatch(1);
                CountDownLatch clientReady = new CountDownLatch(1);
                CountDownLatch clientGotFourFrames = new CountDownLatch(4);

                host.addListener(new TestListenerAdapter() {
                    @Override
                    public void onHandshakeCompleted(String peerName, String safetyNumber) {
                        hostReady.countDown();
                    }
                });
                client.addListener(new TestListenerAdapter() {
                    @Override
                    public void onHandshakeCompleted(String peerName, String safetyNumber) {
                        clientReady.countDown();
                    }

                    @Override
                    public void onEncryptedAudioFrameReceived(long sequenceNumber, byte[] adpcmFrame) {
                        clientGotFourFrames.countDown();
                    }
                });

                InviteToken token = host.startHosting(
                        "Host",
                        "",
                        Collections.singletonList("192.0.2.1"));
                host.simulateInboundTcpFirewallForTest();
                client.joinSession(token, "Client", "");

                assertTrue(hostReady.await(6, TimeUnit.SECONDS));
                assertTrue(clientReady.await(6, TimeUnit.SECONDS));

                host.simulateSymmetricCgnatUdpBlockedForTest();
                client.simulateSymmetricCgnatUdpBlockedForTest();

                byte[] adpcm = new AdpcmCodec().encode(new short[AdpcmCodec.SAMPLES_PER_FRAME], AdpcmCodec.SAMPLES_PER_FRAME);
                // Frame 1 flushes immediately; frames 2..4 (< max batch size 6) must flush via timer!
                host.sendEncryptedAudioFrame(adpcm, adpcm.length);
                Thread.sleep(20);
                host.sendEncryptedAudioFrame(adpcm, adpcm.length);
                Thread.sleep(20);
                host.sendEncryptedAudioFrame(adpcm, adpcm.length);
                Thread.sleep(20);
                host.sendEncryptedAudioFrame(adpcm, adpcm.length);

                assertTrue("Trailing partial audio batch must flush automatically within 2s",
                        clientGotFourFrames.await(2, TimeUnit.SECONDS));
            } finally {
                client.close();
                host.close();
            }
        }
    }

    @Test
    public void testClientHandoffDoesNotAdvertiseHostAddressAndHostRecoversLateStun() throws Exception {
        try (LocalMqttBroker localMqtt = new LocalMqttBroker();
             DatagramSocket unreachableStun = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"))) {

            List<ServerlessRendezvousChannel.BrokerEndpoint> brokers = Collections.singletonList(
                    new ServerlessRendezvousChannel.BrokerEndpoint("127.0.0.1", localMqtt.getPort(), false));

            // Host starts with an unreachable STUN port first so initial startHosting STUN times out
            List<InetSocketAddress> deadStun = Collections.singletonList(
                    new InetSocketAddress(InetAddress.getByName("127.0.0.1"), unreachableStun.getLocalPort()));

            P2PSessionManager host = new P2PSessionManager();
            host.setStunServers(deadStun);
            host.setRendezvousBrokers(brokers);

            P2PSessionManager client = new P2PSessionManager();
            client.setRendezvousBrokers(brokers);

            try (LocalStunServer lateStun = new LocalStunServer()) {
                CountDownLatch hostReady = new CountDownLatch(1);
                CountDownLatch clientReady = new CountDownLatch(1);

                host.addListener(new TestListenerAdapter() {
                    @Override
                    public void onHandshakeCompleted(String peerName, String safetyNumber) {
                        hostReady.countDown();
                    }
                });
                client.addListener(new TestListenerAdapter() {
                    @Override
                    public void onHandshakeCompleted(String peerName, String safetyNumber) {
                        clientReady.countDown();
                    }
                });

                InviteToken token = host.startHosting(
                        "WifiHost",
                        "",
                        Collections.singletonList("192.0.2.99"));
                assertNull("Initial STUN should have failed against blackhole", host.getLocalStunEndpoint());

                // Switch Host's STUN server to reachable before session establishes so async Host retry succeeds
                host.setStunServers(Collections.singletonList(
                        new InetSocketAddress(InetAddress.getByName("127.0.0.1"), lateStun.getPort())));
                host.simulateInboundTcpFirewallForTest();

                client.joinSession(token, "4GClient", "");
                assertTrue(hostReady.await(6, TimeUnit.SECONDS));
                assertTrue(clientReady.await(6, TimeUnit.SECONDS));

                // Host must recover its STUN endpoint asynchronously post-handshake
                long stunDeadline = System.currentTimeMillis() + 3000L;
                while (System.currentTimeMillis() < stunDeadline && host.getLocalStunEndpoint() == null) {
                    Thread.sleep(40);
                }
                assertNotNull("Host must asynchronously recover STUN endpoint post-handshake",
                        host.getLocalStunEndpoint());

                // Trigger client network handoff -> client must NOT advertise host's 192.0.2.99 in localUdpCandidates
                client.notifyNetworkChangedOrHandoff();
                Thread.sleep(250);
                for (InetSocketAddress candidate : client.getLocalUdpCandidates()) {
                    assertNotEquals("Client handoff must never advertise Host's InviteToken IP",
                            "192.0.2.99", candidate.getAddress().getHostAddress());
                }
            } finally {
                client.close();
                host.close();
            }
        }
    }

    @Test
    public void testRendezvousWinCancelsPendingDirectTcpWithoutFalseIntruderAlert() throws Exception {
        try (LocalMqttBroker localMqtt = new LocalMqttBroker()) {
            List<ServerlessRendezvousChannel.BrokerEndpoint> brokers = Collections.singletonList(
                    new ServerlessRendezvousChannel.BrokerEndpoint("127.0.0.1", localMqtt.getPort(), false));

            P2PSessionManager host = new P2PSessionManager();
            host.setRendezvousBrokers(brokers);

            P2PSessionManager client = new P2PSessionManager();
            client.setRendezvousBrokers(brokers);

            try {
                CountDownLatch hostReady = new CountDownLatch(1);
                CountDownLatch clientReady = new CountDownLatch(1);
                CountDownLatch clientTextLatch = new CountDownLatch(1);

                host.addListener(new TestListenerAdapter() {
                    @Override
                    public void onHandshakeCompleted(String peerName, String safetyNumber) {
                        hostReady.countDown();
                    }
                });
                client.addListener(new TestListenerAdapter() {
                    @Override
                    public void onHandshakeCompleted(String peerName, String safetyNumber) {
                        clientReady.countDown();
                    }

                    @Override
                    public void onChatMessageReceived(ChatMessage message) {
                        if (message.getType() == ChatMessage.Type.TEXT) {
                            clientTextLatch.countDown();
                        }
                    }
                });

                // Include unreachable blackhole IPs so TCP connect threads stay pending past 200ms while Rendezvous wins
                InviteToken token = host.startHosting(
                        "WifiHost",
                        "",
                        Arrays.asList("192.0.2.1", "198.51.100.1", "203.0.113.1"));

                long startMs = System.currentTimeMillis();
                client.joinSession(token, "4GClient", "");
                assertTrue(hostReady.await(5, TimeUnit.SECONDS));
                assertTrue(clientReady.await(5, TimeUnit.SECONDS));
                long connectElapsedMs = System.currentTimeMillis() - startMs;

                assertTrue("Rendezvous connection must complete promptly (<1500ms) while blackhole TCP sockets cancel, took "
                        + connectElapsedMs + "ms", connectElapsedMs < 1500L);
                assertEquals("Losing direct TCP candidates must not cause false intruder alerts on Host",
                        0, host.getBlockedIntruderAttempts());

                host.sendTextMessage("Post-handshake message after cancelled TCP race");
                assertTrue(clientTextLatch.await(3, TimeUnit.SECONDS));

                // Concurrent handoff + close must not throw RejectedExecutionException
                client.notifyNetworkChangedOrHandoff();
                client.close();
                client.notifyNetworkChangedOrHandoff();
            } finally {
                client.close();
                host.close();
            }
        }
    }

    @Test
    public void testMidCallNetworkSwitchRecoversHalfOpenMqttAndReverifiesUdp() throws Exception {
        try (LocalStunServer localStun = new LocalStunServer();
             LocalMqttBroker localMqtt = new LocalMqttBroker()) {

            List<InetSocketAddress> stunServers = Collections.singletonList(
                    new InetSocketAddress(InetAddress.getByName("127.0.0.1"), localStun.getPort()));
            List<ServerlessRendezvousChannel.BrokerEndpoint> brokers = Collections.singletonList(
                    new ServerlessRendezvousChannel.BrokerEndpoint("127.0.0.1", localMqtt.getPort(), false));

            P2PSessionManager host = new P2PSessionManager();
            host.setStunServers(stunServers);
            host.setRendezvousBrokers(brokers);

            P2PSessionManager client = new P2PSessionManager();
            client.setStunServers(stunServers);
            client.setRendezvousBrokers(brokers);

            try {
                CountDownLatch hostReady = new CountDownLatch(1);
                CountDownLatch clientReady = new CountDownLatch(1);
                CountDownLatch hostReceivedPostSwitchText = new CountDownLatch(1);
                CountDownLatch clientPostSwitchAck = new CountDownLatch(1);
                CountDownLatch hostReceivedPostSwitchVoice = new CountDownLatch(1);

                host.addListener(new TestListenerAdapter() {
                    @Override
                    public void onHandshakeCompleted(String peerName, String safetyNumber) {
                        hostReady.countDown();
                    }

                    @Override
                    public void onChatMessageReceived(ChatMessage message) {
                        if (message.getType() == ChatMessage.Type.TEXT
                                && "After Wi-Fi->4G switch".equals(message.getText())) {
                            hostReceivedPostSwitchText.countDown();
                        }
                    }

                    @Override
                    public void onEncryptedAudioFrameReceived(long sequenceNumber, byte[] adpcmFrame) {
                        if (sequenceNumber >= 2L) {
                            hostReceivedPostSwitchVoice.countDown();
                        }
                    }
                });

                client.addListener(new TestListenerAdapter() {
                    @Override
                    public void onHandshakeCompleted(String peerName, String safetyNumber) {
                        clientReady.countDown();
                    }

                    @Override
                    public void onChatMessageUpdated(ChatMessage message) {
                        if (message.getType() == ChatMessage.Type.TEXT
                                && message.isDelivered()
                                && "After Wi-Fi->4G switch".equals(message.getText())) {
                            clientPostSwitchAck.countDown();
                        }
                    }
                });

                InviteToken token = host.startHosting(
                        "WifiHost",
                        "",
                        Collections.singletonList("192.0.2.1"));
                host.simulateInboundTcpFirewallForTest();
                client.joinSession(token, "MobileClient", "");

                assertTrue(hostReady.await(6, TimeUnit.SECONDS));
                assertTrue(clientReady.await(6, TimeUnit.SECONDS));

                // Wait for direct UDP to lock before mid-call switch
                long udpDeadline = System.currentTimeMillis() + 3000L;
                while (System.currentTimeMillis() < udpDeadline
                        && (!host.isDirectUdpActive() || !client.isDirectUdpActive())) {
                    Thread.sleep(30);
                }
                assertTrue(host.isDirectUdpActive());
                assertTrue(client.isDirectUdpActive());

                byte[] adpcm = new AdpcmCodec().encode(
                        new short[AdpcmCodec.SAMPLES_PER_FRAME], AdpcmCodec.SAMPLES_PER_FRAME);
                client.sendEncryptedAudioFrame(adpcm, adpcm.length);

                // Blackhole ONLY client's current MQTT socket (simulating Wi-Fi interface dying silently
                // without TCP FIN/RST while Client switches to 4G)
                localMqtt.simulateHalfOpenBlackholeOnLatestClient();

                // Trigger mid-call network handoff on Client: must detect half-open MQTT socket via PINGREQ
                // in ~1.5s (not 45s SO_TIMEOUT!), reconnect, and re-verify bidirectional UDP
                long switchStart = System.currentTimeMillis();
                client.notifyNetworkChangedOrHandoff();
                client.sendTextMessage("After Wi-Fi->4G switch");

                assertTrue("Post-switch text must reach Host quickly after MQTT reconnect (< 6s)",
                        hostReceivedPostSwitchText.await(6, TimeUnit.SECONDS));
                assertTrue("Post-switch delivery ACK must return to Client (< 6s)",
                        clientPostSwitchAck.await(6, TimeUnit.SECONDS));
                long switchRecoveryMs = System.currentTimeMillis() - switchStart;
                assertTrue("Recovery must be fast (< 5000ms), took " + switchRecoveryMs + "ms",
                        switchRecoveryMs < 5000L);

                // Verify Host also re-locked UDP on Client's new port and receives post-switch voice
                long rePunchDeadline = System.currentTimeMillis() + 4000L;
                while (System.currentTimeMillis() < rePunchDeadline
                        && (!host.isDirectUdpActive() || !client.isDirectUdpActive())) {
                    Thread.sleep(30);
                }
                assertTrue("Host must re-verify direct UDP after peer handoff", host.isDirectUdpActive());
                assertTrue("Client must re-verify direct UDP after handoff", client.isDirectUdpActive());

                client.sendEncryptedAudioFrame(adpcm, adpcm.length);
                assertTrue("Host must receive post-switch voice frame",
                        hostReceivedPostSwitchVoice.await(4, TimeUnit.SECONDS));
            } finally {
                client.close();
                host.close();
            }
        }
    }

    @Test
    public void testStalledMqttWriteBufferDoesNotDeadlockNetworkChangeOrCloseAndJoinCloseHasNoUncaughtExceptions()
            throws Exception {
        // 1. Verify ServerlessRendezvousChannel.notifyNetworkChanged() and close() do not deadlock
        // when runWriteLoop() is blocked inside writeLock on a stalled/full TCP send buffer.
        try (LocalMqttBroker localMqtt = new LocalMqttBroker()) {
            List<ServerlessRendezvousChannel.BrokerEndpoint> brokers = Collections.singletonList(
                    new ServerlessRendezvousChannel.BrokerEndpoint("127.0.0.1", localMqtt.getPort(), false));

            byte[] secret = CryptoEngine.randomBytes(CryptoEngine.INVITE_SECRET_BYTES);
            ServerlessRendezvousChannel hostRv = new ServerlessRendezvousChannel("stalledSess", secret, true, brokers);
            ServerlessRendezvousChannel clientRv = new ServerlessRendezvousChannel("stalledSess", secret, false, brokers);
            ExecutorService pumpExecutor = Executors.newSingleThreadExecutor();
            try {
                CountDownLatch hostGotStream = new CountDownLatch(1);
                hostRv.startHost(stream -> hostGotStream.countDown());
                assertTrue(hostRv.awaitAtLeastOneBrokerReady(3000));

                ServerlessRendezvousChannel.RendezvousStream cs = clientRv.connectClientStream(4000);
                assertTrue(hostGotStream.await(3, TimeUnit.SECONDS));

                // Stop reading on client's broker socket and fill the TCP send buffer so runWriteLoop blocks in writeLock
                localMqtt.freezeReadsOnLatestClient();
                byte[] chunk = new byte[16 * 1024];
                pumpExecutor.submit(() -> {
                    try {
                        DataOutputStream dos = cs.getDataOutputStream();
                        for (int i = 0; i < 200; i++) {
                            dos.write(chunk);
                            dos.flush();
                        }
                    } catch (Exception ignored) {
                    }
                });
                Thread.sleep(250);

                long startMs = System.currentTimeMillis();
                clientRv.notifyNetworkChanged();
                long deadline = startMs + 3500L;
                while (System.currentTimeMillis() < deadline && clientRv.getConnectedBrokerCount() > 0) {
                    Thread.sleep(40);
                }
                assertEquals("Stalled broker socket must be force-closed within ~1.5s without writeLock deadlock",
                        0, clientRv.getConnectedBrokerCount());
                assertTrue("Recovery must finish in < 3500ms, took " + (System.currentTimeMillis() - startMs) + "ms",
                        (System.currentTimeMillis() - startMs) < 3500L);

                long closeStart = System.currentTimeMillis();
                clientRv.close();
                assertTrue("Channel close() must not hang on stalled writeLock",
                        (System.currentTimeMillis() - closeStart) < 1000L);
            } finally {
                pumpExecutor.shutdownNow();
                clientRv.close();
                hostRv.close();
            }
        }

        // 2. Verify rapid joinSession() + close() and concurrent notifyNetworkChangedOrHandoff() produce
        // zero uncaught RejectedExecutionExceptions and always end in State.DISCONNECTED.
        Thread.UncaughtExceptionHandler prevHandler = Thread.getDefaultUncaughtExceptionHandler();
        java.util.List<Throwable> uncaught = new java.util.concurrent.CopyOnWriteArrayList<>();
        Thread.setDefaultUncaughtExceptionHandler((t, e) -> uncaught.add(e));
        try {
            for (int iter = 0; iter < 15; iter++) {
                P2PSessionManager host = new P2PSessionManager();
                P2PSessionManager client = new P2PSessionManager();
                host.setRendezvousBrokers(Collections.singletonList(
                        new ServerlessRendezvousChannel.BrokerEndpoint("127.0.0.1", 1, false)));
                client.setRendezvousBrokers(Collections.singletonList(
                        new ServerlessRendezvousChannel.BrokerEndpoint("127.0.0.1", 1, false)));
                try {
                    InviteToken token = host.startHosting("H", "", Collections.singletonList("127.0.0.1"));
                    client.joinSession(token, "C", "");
                    if (iter % 2 == 0) {
                        Thread.sleep(20);
                        client.notifyNetworkChangedOrHandoff();
                        client.notifyNetworkChangedOrHandoff();
                    }
                } finally {
                    client.close();
                    host.close();
                }
                assertEquals(P2PSessionManager.State.DISCONNECTED, host.getCurrentState());
                assertEquals(P2PSessionManager.State.DISCONNECTED, client.getCurrentState());
            }
            Thread.sleep(100);
            assertTrue("Expected zero uncaught exceptions during close/handoff races, got: " + uncaught,
                    uncaught.isEmpty());
        } finally {
            Thread.setDefaultUncaughtExceptionHandler(prevHandler);
        }
    }

    @Test
    public void testStartHostingCloseRaceRemainsDisconnected() throws Exception {
        Thread.UncaughtExceptionHandler prevHandler = Thread.getDefaultUncaughtExceptionHandler();
        java.util.List<Throwable> uncaught = new java.util.concurrent.CopyOnWriteArrayList<>();
        Thread.setDefaultUncaughtExceptionHandler((t, e) -> uncaught.add(e));
        try (DatagramSocket blackholeStun = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"))) {
            List<InetSocketAddress> deadStun = Collections.singletonList(
                    new InetSocketAddress(InetAddress.getByName("127.0.0.1"), blackholeStun.getLocalPort()));
            for (int iter = 0; iter < 5; iter++) {
                P2PSessionManager host = new P2PSessionManager();
                host.setStunServers(deadStun);
                host.setRendezvousBrokers(Collections.singletonList(
                        new ServerlessRendezvousChannel.BrokerEndpoint("127.0.0.1", 1, false)));
                Thread closer = new Thread(() -> {
                    try {
                        Thread.sleep(40);
                    } catch (InterruptedException ignored) {
                    }
                    host.close();
                }, "TestHostCloser");
                closer.start();
                try {
                    host.startHosting("RaceHost", "", null);
                } catch (IOException ignored) {
                } finally {
                    closer.join(2000);
                    host.close();
                }
                assertEquals("Closed host session must remain DISCONNECTED after concurrent startHosting",
                        P2PSessionManager.State.DISCONNECTED, host.getCurrentState());
            }
            Thread.sleep(50);
            assertTrue("Expected zero uncaught exceptions during startHosting/close race, got: " + uncaught,
                    uncaught.isEmpty());
        } finally {
            Thread.setDefaultUncaughtExceptionHandler(prevHandler);
        }
    }

    /**
     * Minimal RFC 5389 STUN UDP Responder for deterministic local unit testing.
     */
    private static final class LocalStunServer implements AutoCloseable {
        private final DatagramSocket socket;
        private final AtomicBoolean closed = new AtomicBoolean(false);
        private final Thread worker;

        LocalStunServer() throws IOException {
            this.socket = new DatagramSocket(0, InetAddress.getByName("127.0.0.1"));
            this.worker = new Thread(this::serveLoop, "LocalStunServer");
            this.worker.setDaemon(true);
            this.worker.start();
        }

        int getPort() {
            return socket.getLocalPort();
        }

        private void serveLoop() {
            byte[] buf = new byte[512];
            while (!closed.get() && !socket.isClosed()) {
                try {
                    DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                    socket.receive(pkt);
                    if (pkt.getLength() < StunClient.STUN_HEADER_BYTES) {
                        continue;
                    }
                    ByteBuffer bb = ByteBuffer.wrap(pkt.getData(), pkt.getOffset(), pkt.getLength());
                    short msgType = bb.getShort();
                    bb.getShort(); // length
                    int cookie = bb.getInt();
                    if (msgType != StunClient.MSG_BINDING_REQUEST || cookie != StunClient.MAGIC_COOKIE) {
                        continue;
                    }
                    byte[] txId = new byte[StunClient.TRANSACTION_ID_BYTES];
                    bb.get(txId);

                    byte[] resp = StunClient.buildBindingResponse(
                            txId, pkt.getAddress(), pkt.getPort());
                    DatagramPacket respPkt = new DatagramPacket(
                            resp, resp.length, pkt.getAddress(), pkt.getPort());
                    socket.send(respPkt);
                } catch (IOException e) {
                    break;
                }
            }
        }

        @Override
        public void close() {
            closed.set(true);
            socket.close();
        }
    }

    /**
     * Lightweight embedded MQTT v3.1.1 broker for deterministic end-to-end rendezvous testing.
     */
    private static final class LocalMqttBroker implements AutoCloseable {
        private final ServerSocket serverSocket;
        private final AtomicBoolean closed = new AtomicBoolean(false);
        private final ExecutorService pool = Executors.newCachedThreadPool();
        private final Map<String, Set<ClientHandler>> topicSubscribers = new ConcurrentHashMap<>();
        private final List<ClientHandler> connectedHandlers = new java.util.concurrent.CopyOnWriteArrayList<>();
        private final java.util.concurrent.atomic.AtomicInteger totalPublishesRouted =
                new java.util.concurrent.atomic.AtomicInteger();
        private volatile int dropPublishEveryN = 0;

        LocalMqttBroker() throws IOException {
            this.serverSocket = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
            pool.execute(this::acceptLoop);
        }

        void simulateHalfOpenBlackholeOnLatestClient() {
            if (!connectedHandlers.isEmpty()) {
                ClientHandler target = connectedHandlers.get(connectedHandlers.size() - 1);
                target.setBlackhole(true);
            }
        }

        void freezeReadsOnLatestClient() {
            if (!connectedHandlers.isEmpty()) {
                ClientHandler target = connectedHandlers.get(connectedHandlers.size() - 1);
                target.setFreezeReads(true);
            }
        }

        void setDropPublishEveryN(int n) {
            this.dropPublishEveryN = n;
        }

        int getTotalPublishesRouted() {
            return totalPublishesRouted.get();
        }

        int getPort() {
            return serverSocket.getLocalPort();
        }

        private void acceptLoop() {
            while (!closed.get() && !serverSocket.isClosed()) {
                try {
                    Socket client = serverSocket.accept();
                    client.setTcpNoDelay(true);
                    ClientHandler handler = new ClientHandler(client);
                    connectedHandlers.add(handler);
                    pool.execute(handler);
                } catch (IOException e) {
                    break;
                }
            }
        }

        @Override
        public void close() {
            closed.set(true);
            try {
                serverSocket.close();
            } catch (IOException ignored) {
            }
            for (Set<ClientHandler> subs : topicSubscribers.values()) {
                for (ClientHandler h : subs) {
                    h.close();
                }
            }
            pool.shutdownNow();
        }

        private final class ClientHandler implements Runnable {
            private final Socket socket;
            private volatile boolean blackholed = false;
            private volatile boolean freezeReads = false;
            private DataInputStream in;
            private DataOutputStream out;

            ClientHandler(Socket socket) {
                this.socket = socket;
            }

            void setBlackhole(boolean blackholed) {
                this.blackholed = blackholed;
                for (Set<ClientHandler> subs : topicSubscribers.values()) {
                    subs.remove(this);
                }
            }

            void setFreezeReads(boolean freezeReads) {
                this.freezeReads = freezeReads;
                if (freezeReads) {
                    try {
                        socket.setReceiveBufferSize(2048);
                    } catch (IOException ignored) {
                    }
                    for (Set<ClientHandler> subs : topicSubscribers.values()) {
                        subs.remove(this);
                    }
                }
            }

            @Override
            public void run() {
                try {
                    in = new DataInputStream(socket.getInputStream());
                    out = new DataOutputStream(socket.getOutputStream());

                    while (!closed.get() && !socket.isClosed()) {
                        while (freezeReads && !closed.get() && !socket.isClosed()) {
                            Thread.sleep(50);
                        }
                        int hdr = in.readUnsignedByte();
                        int remLen = ServerlessRendezvousChannel.readRemainingLength(in);
                        byte[] body = new byte[remLen];
                        in.readFully(body);

                        if (blackholed) {
                            continue;
                        }

                        int pktType = hdr & 0xF0;
                        if (pktType == 0x10) { // CONNECT -> send CONNACK (0x20, len=2, 0x00, 0x00)
                            synchronized (this) {
                                out.writeByte(0x20);
                                out.writeByte(0x02);
                                out.writeByte(0x00);
                                out.writeByte(0x00);
                                out.flush();
                            }
                        } else if (pktType == 0x80) { // SUBSCRIBE -> register & send SUBACK (0x90)
                            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(body));
                            int pktId = dis.readUnsignedShort();
                            int topicLen = dis.readUnsignedShort();
                            byte[] topicBytes = new byte[topicLen];
                            dis.readFully(topicBytes);
                            String topic = new String(topicBytes, StandardCharsets.UTF_8);

                            topicSubscribers
                                    .computeIfAbsent(topic, k -> new CopyOnWriteArraySet<>())
                                    .add(this);

                            synchronized (this) {
                                out.writeByte(0x90);
                                out.writeByte(0x03);
                                out.writeShort(pktId);
                                out.writeByte(0x00); // Granted QoS 0
                                out.flush();
                            }
                        } else if (pktType == 0x30) { // PUBLISH -> route to topic subscribers
                            int qos = (hdr >> 1) & 0x03;
                            DataInputStream dis = new DataInputStream(new ByteArrayInputStream(body));
                            int topicLen = dis.readUnsignedShort();
                            byte[] topicBytes = new byte[topicLen];
                            dis.readFully(topicBytes);
                            String topic = new String(topicBytes, StandardCharsets.UTF_8);
                            int consumed = 2 + topicLen;
                            if (qos == 1 || qos == 2) {
                                int pktId = dis.readUnsignedShort();
                                consumed += 2;
                                if (qos == 1) {
                                    synchronized (this) {
                                        out.writeByte(0x40);
                                        out.writeByte(0x02);
                                        out.writeShort(pktId);
                                        out.flush();
                                    }
                                }
                            }
                            byte[] payload = Arrays.copyOfRange(body, consumed, body.length);
                            int seqCount = totalPublishesRouted.incrementAndGet();
                            int dropN = dropPublishEveryN;
                            if (dropN > 0 && seqCount > 8 && (seqCount % dropN) == 0) {
                                continue;
                            }
                            Set<ClientHandler> subs = topicSubscribers.get(topic);
                            if (subs != null) {
                                for (ClientHandler sub : subs) {
                                    sub.deliverPublish(topicBytes, payload);
                                }
                            }
                        } else if (pktType == 0xC0) { // PINGREQ -> PINGRESP
                            synchronized (this) {
                                out.writeByte(0xD0);
                                out.writeByte(0x00);
                                out.flush();
                            }
                        } else if (pktType == 0xE0) { // DISCONNECT
                            break;
                        }
                    }
                } catch (Exception ignored) {
                } finally {
                    close();
                }
            }

            synchronized void deliverPublish(byte[] topicBytes, byte[] payload) {
                try {
                    int remLen = 2 + topicBytes.length + payload.length;
                    out.writeByte(0x30);
                    ServerlessRendezvousChannel.writeRemainingLength(out, remLen);
                    out.writeShort(topicBytes.length);
                    out.write(topicBytes);
                    out.write(payload);
                    out.flush();
                } catch (IOException e) {
                    close();
                }
            }

            void close() {
                for (Set<ClientHandler> subs : topicSubscribers.values()) {
                    subs.remove(this);
                }
                try {
                    socket.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    private static class TestListenerAdapter implements P2PSessionManager.SessionListener {
        @Override
        public void onStateChanged(P2PSessionManager.State newState, String statusMessage) {}

        @Override
        public void onHandshakeCompleted(String peerDisplayName, String safetyNumber) {}

        @Override
        public void onChatMessageReceived(ChatMessage message) {}

        @Override
        public void onChatMessageUpdated(ChatMessage message) {}

        @Override
        public void onEncryptedAudioFrameReceived(long sequenceNumber, byte[] adpcmFrame) {}

        @Override
        public void onPeerMuteChanged(boolean peerMuted) {}

        @Override
        public void onLatencyUpdated(long rttMs) {}

        @Override
        public void onSecurityAlert(String alertMessage) {}
    }
}
