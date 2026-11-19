package com.pigeon.voice.net;

import com.pigeon.voice.audio.AdpcmCodec;
import com.pigeon.voice.contacts.ContactItem;
import com.pigeon.voice.crypto.CryptoEngine;
import com.pigeon.voice.token.InviteToken;

import org.junit.Test;

import java.util.Collections;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class P2PCallSessionIntegrationTest {

    @Test
    public void testFullEncryptedCallTextImageAndVoiceRoundtrip() throws Exception {
        P2PSessionManager host = new P2PSessionManager();
        P2PSessionManager client = new P2PSessionManager();

        try {
            CountDownLatch hostHandshakeLatch = new CountDownLatch(1);
            CountDownLatch clientHandshakeLatch = new CountDownLatch(1);
            CountDownLatch clientReceivedTextLatch = new CountDownLatch(1);
            CountDownLatch hostTextAckLatch = new CountDownLatch(1);
            CountDownLatch hostReceivedImageLatch = new CountDownLatch(1);
            CountDownLatch clientReceivedVoiceLatch = new CountDownLatch(1);

            AtomicReference<ChatMessage> receivedTextRef = new AtomicReference<>();
            AtomicReference<ChatMessage> receivedImageRef = new AtomicReference<>();
            AtomicReference<byte[]> receivedAudioRef = new AtomicReference<>();

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
                    if (receivedAudioRef.compareAndSet(null, adpcmFrame)) {
                        clientReceivedVoiceLatch.countDown();
                    }
                }
            });

            // 1. Host starts call server on 127.0.0.1 and generates shareable deep link
            InviteToken hostToken = host.startHosting(
                    "DaoudHost",
                    "",
                    Collections.singletonList("127.0.0.1"));
            String shareableDeepLink = hostToken.toShareableLink();

            // 2. Client parses deep link and connects directly to Host
            InviteToken parsedToken = InviteToken.fromTokenOrLink(shareableDeepLink);
            client.joinSession(parsedToken, "BobClient", "");

            assertTrue("Host handshake must complete", hostHandshakeLatch.await(5, TimeUnit.SECONDS));
            assertTrue("Client handshake must complete", clientHandshakeLatch.await(5, TimeUnit.SECONDS));

            assertEquals(P2PSessionManager.State.CONNECTED_SECURE, host.getCurrentState());
            assertEquals(P2PSessionManager.State.CONNECTED_SECURE, client.getCurrentState());
            assertTrue(host.isSessionLocked());
            assertTrue(client.isSessionLocked());
            assertEquals("SAS Safety Numbers must match", host.getSafetyNumber(), client.getSafetyNumber());
            assertEquals("BobClient", host.getPeerDisplayName());
            assertEquals("DaoudHost", client.getPeerDisplayName());

            // 3. Test encrypted text chat + delivery ACK
            host.sendTextMessage("Hello Bob, this call is end-to-end encrypted!");
            assertTrue("Client must receive encrypted text",
                    clientReceivedTextLatch.await(5, TimeUnit.SECONDS));
            assertNotNull(receivedTextRef.get());
            assertEquals("Hello Bob, this call is end-to-end encrypted!", receivedTextRef.get().getText());
            assertTrue("Host must receive encrypted delivery ACK",
                    hostTextAckLatch.await(5, TimeUnit.SECONDS));

            // 4. Test chunked encrypted image transfer (45 KB across 3 chunks of 16KB) with SHA-256 verification
            byte[] simulatedJpeg = CryptoEngine.randomBytes(45 * 1024);
            client.sendImage(simulatedJpeg);
            assertTrue("Host must receive & verify multi-chunk encrypted image",
                    hostReceivedImageLatch.await(5, TimeUnit.SECONDS));
            assertNotNull(receivedImageRef.get());
            assertArrayEquals("Reassembled image bytes must match SHA-256 verified original",
                    simulatedJpeg, receivedImageRef.get().getImageBytes());

            // 5. Test encrypted ADPCM voice frame streaming
            AdpcmCodec codec = new AdpcmCodec();
            short[] voicePcm = new short[AdpcmCodec.SAMPLES_PER_FRAME];
            for (int i = 0; i < voicePcm.length; i++) {
                voicePcm[i] = (short) (Math.sin(i * 0.2) * 12000);
            }
            byte[] encodedAdpcm = codec.encode(voicePcm, voicePcm.length);
            host.sendEncryptedAudioFrame(encodedAdpcm, encodedAdpcm.length);

            assertTrue("Client must receive encrypted ADPCM voice frame",
                    clientReceivedVoiceLatch.await(5, TimeUnit.SECONDS));
            assertArrayEquals(encodedAdpcm, receivedAudioRef.get());

        } finally {
            client.close();
            host.close();
        }
    }

    @Test
    public void testSinglePartyLockoutBlocksMultipleThirdPartyIntruders() throws Exception {
        P2PSessionManager host = new P2PSessionManager();
        P2PSessionManager peer1 = new P2PSessionManager();
        P2PSessionManager intruderPeer2 = new P2PSessionManager();
        P2PSessionManager intruderPeer3 = new P2PSessionManager();
        P2PSessionManager intruderPeer4 = new P2PSessionManager();

        try {
            CountDownLatch peer1Connected = new CountDownLatch(1);
            CountDownLatch intruder2Rejected = new CountDownLatch(1);
            CountDownLatch intruder3Rejected = new CountDownLatch(1);
            CountDownLatch intruder4Rejected = new CountDownLatch(1);
            CountDownLatch hostSecurityAlerts = new CountDownLatch(3);

            host.addListener(new TestListenerAdapter() {
                @Override
                public void onSecurityAlert(String alertMessage) {
                    hostSecurityAlerts.countDown();
                }
            });

            peer1.addListener(new TestListenerAdapter() {
                @Override
                public void onHandshakeCompleted(String peerName, String safetyNumber) {
                    peer1Connected.countDown();
                }
            });

            intruderPeer2.addListener(new TestListenerAdapter() {
                @Override
                public void onStateChanged(P2PSessionManager.State newState, String statusMessage) {
                    if (newState == P2PSessionManager.State.ERROR) {
                        intruder2Rejected.countDown();
                    }
                }
            });

            intruderPeer3.addListener(new TestListenerAdapter() {
                @Override
                public void onStateChanged(P2PSessionManager.State newState, String statusMessage) {
                    if (newState == P2PSessionManager.State.ERROR) {
                        intruder3Rejected.countDown();
                    }
                }
            });

            intruderPeer4.addListener(new TestListenerAdapter() {
                @Override
                public void onStateChanged(P2PSessionManager.State newState, String statusMessage) {
                    if (newState == P2PSessionManager.State.ERROR) {
                        intruder4Rejected.countDown();
                    }
                }
            });

            InviteToken token = host.startHosting(
                    "HostDevice",
                    "",
                    Collections.singletonList("127.0.0.1"));

            // Peer 1 joins legitimately
            peer1.joinSession(token, "ValidPeer1", "");
            assertTrue("Peer 1 must connect", peer1Connected.await(5, TimeUnit.SECONDS));
            assertTrue("Host session must now be locked", host.isSessionLocked());

            // Intruders 2, 3, and 4 attempt to join using the EXACT SAME token after Peer 1 joined
            intruderPeer2.joinSession(token, "Intruder2", "");
            assertTrue("Intruder 2 must be rejected", intruder2Rejected.await(3, TimeUnit.SECONDS));
            assertEquals(P2PSessionManager.State.ERROR, intruderPeer2.getCurrentState());

            intruderPeer3.joinSession(token, "Intruder3", "");
            intruderPeer4.joinSession(token, "Intruder4", "");
            assertTrue("Intruder 3 must be rejected", intruder3Rejected.await(3, TimeUnit.SECONDS));
            assertTrue("Intruder 4 must be rejected", intruder4Rejected.await(3, TimeUnit.SECONDS));
            assertEquals(P2PSessionManager.State.ERROR, intruderPeer3.getCurrentState());
            assertEquals(P2PSessionManager.State.ERROR, intruderPeer4.getCurrentState());

            assertTrue("Host must fire security alerts for all 3 intruders",
                    hostSecurityAlerts.await(3, TimeUnit.SECONDS));
            assertEquals("Host must record all 3 blocked intruder attempts",
                    3, host.getBlockedIntruderAttempts());

            // Verify Peer 1 and Host remain securely connected
            assertEquals(P2PSessionManager.State.CONNECTED_SECURE, host.getCurrentState());
            assertEquals(P2PSessionManager.State.CONNECTED_SECURE, peer1.getCurrentState());

        } finally {
            intruderPeer4.close();
            intruderPeer3.close();
            intruderPeer2.close();
            peer1.close();
            host.close();
        }
    }

    @Test
    public void testSpoofedUdpPacketCannotPoisonReplayWindowAndGracefulHangupDelivered() throws Exception {
        P2PSessionManager host = new P2PSessionManager();
        P2PSessionManager client = new P2PSessionManager();

        try {
            CountDownLatch hostReady = new CountDownLatch(1);
            CountDownLatch clientReady = new CountDownLatch(1);
            CountDownLatch hostReceivedVoiceAfterSpoof = new CountDownLatch(1);
            CountDownLatch hostReceivedGracefulHangup = new CountDownLatch(1);
            CountDownLatch hostReceivedMute = new CountDownLatch(1);

            host.addListener(new TestListenerAdapter() {
                @Override
                public void onHandshakeCompleted(String peerName, String safetyNumber) {
                    hostReady.countDown();
                }

                @Override
                public void onEncryptedAudioFrameReceived(long sequenceNumber, byte[] adpcmFrame) {
                    if (sequenceNumber == 1L) {
                        hostReceivedVoiceAfterSpoof.countDown();
                    }
                }

                @Override
                public void onPeerMuteChanged(boolean peerMuted) {
                    if (peerMuted) {
                        hostReceivedMute.countDown();
                    }
                }

                @Override
                public void onChatMessageReceived(ChatMessage message) {
                    if (message.getType() == ChatMessage.Type.SYSTEM
                            && message.getText().contains("hung up")) {
                        hostReceivedGracefulHangup.countDown();
                    }
                }
            });

            client.addListener(new TestListenerAdapter() {
                @Override
                public void onHandshakeCompleted(String peerName, String safetyNumber) {
                    clientReady.countDown();
                }
            });

            InviteToken token = host.startHosting(
                    "HostAlice",
                    "",
                    Collections.singletonList("127.0.0.1"));
            client.joinSession(token, "ClientBob", "");

            assertTrue(hostReady.await(5, TimeUnit.SECONDS));
            assertTrue(clientReady.await(5, TimeUnit.SECONDS));

            // 1. Send a forged/spoofed UDP packet with sequenceNumber = 999,999 and invalid GCM tag to Host's UDP port
            try (java.net.DatagramSocket attackerSocket = new java.net.DatagramSocket()) {
                byte[] forged = new byte[10 + 32];
                forged[0] = 0x50; // UDP_MAGIC
                forged[1] = CryptoEngine.CHANNEL_CLIENT_TO_HOST_AUDIO;
                java.nio.ByteBuffer.wrap(forged, 2, 8).putLong(999_999L);
                // Random unauthenticated ciphertext/tag
                byte[] garbage = CryptoEngine.randomBytes(32);
                System.arraycopy(garbage, 0, forged, 10, 32);

                java.net.DatagramPacket poisonAttempt = new java.net.DatagramPacket(
                        forged,
                        forged.length,
                        java.net.InetAddress.getByName("127.0.0.1"),
                        token.getUdpPort());
                attackerSocket.send(poisonAttempt);
            }

            // Small pause to ensure forged UDP datagram is processed by host's UDP reader loop first
            Thread.sleep(60);

            // 2. Now Client sends legitimate encrypted voice frame with seqNum = 1
            AdpcmCodec codec = new AdpcmCodec();
            short[] pcm = new short[AdpcmCodec.SAMPLES_PER_FRAME];
            byte[] adpcm = codec.encode(pcm, pcm.length);
            client.sendEncryptedAudioFrame(adpcm, adpcm.length);

            assertTrue("Host must accept legitimate seq=1 voice frame after spoofed seq=999999 attempt",
                    hostReceivedVoiceAfterSpoof.await(5, TimeUnit.SECONDS));

            // 3. Test encrypted mute state notification
            client.sendMuteState(true);
            assertTrue("Host must receive encrypted mute notification",
                    hostReceivedMute.await(3, TimeUnit.SECONDS));

            // 4. Client hangs up via close() -> Host must receive encrypted CTRL_END_CALL frame
            client.close();
            assertTrue("Host must receive encrypted CTRL_END_CALL hangup frame",
                    hostReceivedGracefulHangup.await(3, TimeUnit.SECONDS));

        } finally {
            client.close();
            host.close();
        }
    }

    @Test
    public void testContactRestrictedCallRejectsWrongContactAndAdmitsSelectedContact() throws Exception {
        P2PSessionManager host = new P2PSessionManager();
        P2PSessionManager unauthorizedCaller = new P2PSessionManager();
        P2PSessionManager authorizedAlice = new P2PSessionManager();

        try {
            String aliceHash = ContactItem.computeContactHash("+1 (555) 867-5309");
            InviteToken restrictedToken = host.startHosting(
                    "DaoudHost",
                    aliceHash,
                    Collections.singletonList("127.0.0.1"));

            CountDownLatch unauthorizedRejected = new CountDownLatch(1);
            unauthorizedCaller.addListener(new TestListenerAdapter() {
                @Override
                public void onStateChanged(P2PSessionManager.State newState, String statusMessage) {
                    if (newState == P2PSessionManager.State.ERROR) {
                        unauthorizedRejected.countDown();
                    }
                }
            });

            // 1. Mallory tries to join with wrong phone number (+1-555-000-1111)
            unauthorizedCaller.joinSession(restrictedToken, "Mallory", "+1-555-000-1111");
            assertTrue("Unauthorized contact must be rejected",
                    unauthorizedRejected.await(5, TimeUnit.SECONDS));
            assertEquals(P2PSessionManager.State.ERROR, unauthorizedCaller.getCurrentState());
            assertEquals("Host must record blocked attempt", 1, host.getBlockedIntruderAttempts());

            // 2. Now Alice joins with her matching phone number (formatted differently: 555-867-5309)
            CountDownLatch aliceConnected = new CountDownLatch(1);
            authorizedAlice.addListener(new TestListenerAdapter() {
                @Override
                public void onHandshakeCompleted(String peerName, String safetyNumber) {
                    aliceConnected.countDown();
                }
            });

            authorizedAlice.joinSession(restrictedToken, "Alice", "555-867-5309");
            assertTrue("Authorized contact Alice must connect",
                    aliceConnected.await(5, TimeUnit.SECONDS));
            assertEquals(P2PSessionManager.State.CONNECTED_SECURE, authorizedAlice.getCurrentState());
            assertEquals(P2PSessionManager.State.CONNECTED_SECURE, host.getCurrentState());

        } finally {
            unauthorizedCaller.close();
            authorizedAlice.close();
            host.close();
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
