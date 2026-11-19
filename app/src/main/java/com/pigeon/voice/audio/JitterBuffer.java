package com.pigeon.voice.audio;

import java.util.Arrays;
import java.util.TreeMap;

/**
 * Adaptive low-latency voice Jitter Buffer with Packet Loss Concealment (PLC).
 *
 * Reorders out-of-order UDP voice packets, prevents latency accumulation via adaptive queue
 * trimming, and synthesizes attenuated continuation frames during transient packet drops.
 */
public final class JitterBuffer {

    private final int samplesPerFrame;
    private final int minPrebufferFrames;
    private final int maxQueueFrames;

    private final TreeMap<Long, short[]> packetQueue = new TreeMap<>();
    private final short[] lastPlayedFrame;

    private boolean isPrimed = false;
    private long nextExpectedSeq = -1;
    private int consecutivePlcCount = 0;

    private long receivedCount = 0;
    private long lostCount = 0;
    private long duplicateOrLateCount = 0;
    private long trimmedCount = 0;

    public JitterBuffer(int samplesPerFrame, int minPrebufferFrames, int maxQueueFrames) {
        if (samplesPerFrame <= 0 || minPrebufferFrames < 1 || maxQueueFrames < minPrebufferFrames) {
            throw new IllegalArgumentException("Invalid JitterBuffer configuration");
        }
        this.samplesPerFrame = samplesPerFrame;
        this.minPrebufferFrames = minPrebufferFrames;
        this.maxQueueFrames = maxQueueFrames;
        this.lastPlayedFrame = new short[samplesPerFrame];
    }

    public JitterBuffer() {
        this(AdpcmCodec.SAMPLES_PER_FRAME, 2, 10);
    }

    /**
     * Pushes a decoded PCM frame with its sequence number into the jitter buffer.
     */
    public synchronized void pushFrame(long sequenceNumber, short[] pcmSamples) {
        if (sequenceNumber < 0 || pcmSamples == null || pcmSamples.length < samplesPerFrame) {
            return;
        }

        // Reject stale packets that already passed playout
        if (nextExpectedSeq != -1 && sequenceNumber < nextExpectedSeq) {
            duplicateOrLateCount++;
            return;
        }

        // Reject duplicate packets already in queue
        if (packetQueue.containsKey(sequenceNumber)) {
            duplicateOrLateCount++;
            return;
        }

        short[] copy = Arrays.copyOf(pcmSamples, samplesPerFrame);
        packetQueue.put(sequenceNumber, copy);
        receivedCount++;

        // Adaptive latency trimming: if burst exceeds maxQueueFrames, drop oldest frame(s)
        while (packetQueue.size() > maxQueueFrames) {
            Long droppedSeq = packetQueue.pollFirstEntry().getKey();
            trimmedCount++;
            if (nextExpectedSeq != -1 && droppedSeq >= nextExpectedSeq) {
                nextExpectedSeq = droppedSeq + 1;
            }
        }

        if (!isPrimed && packetQueue.size() >= minPrebufferFrames) {
            isPrimed = true;
            consecutivePlcCount = 0;
            long firstKey = packetQueue.firstKey();
            if (nextExpectedSeq == -1) {
                nextExpectedSeq = firstKey;
            } else if (firstKey > nextExpectedSeq) {
                lostCount += (firstKey - nextExpectedSeq);
                nextExpectedSeq = firstKey;
            }
        }
    }

    /**
     * Pushes a freshly-decoded PCM frame without allocating an extra copy when the caller
     * transfers ownership of an exact-sized array.
     */
    synchronized void pushDecodedFrameOwned(long sequenceNumber, short[] ownedPcmSamples) {
        if (sequenceNumber < 0 || ownedPcmSamples == null || ownedPcmSamples.length < samplesPerFrame) {
            return;
        }
        if (nextExpectedSeq != -1 && sequenceNumber < nextExpectedSeq) {
            duplicateOrLateCount++;
            return;
        }
        if (packetQueue.containsKey(sequenceNumber)) {
            duplicateOrLateCount++;
            return;
        }

        short[] stored = (ownedPcmSamples.length == samplesPerFrame)
                ? ownedPcmSamples
                : Arrays.copyOf(ownedPcmSamples, samplesPerFrame);
        packetQueue.put(sequenceNumber, stored);
        receivedCount++;

        while (packetQueue.size() > maxQueueFrames) {
            Long droppedSeq = packetQueue.pollFirstEntry().getKey();
            trimmedCount++;
            if (nextExpectedSeq != -1 && droppedSeq >= nextExpectedSeq) {
                nextExpectedSeq = droppedSeq + 1;
            }
        }

        if (!isPrimed && packetQueue.size() >= minPrebufferFrames) {
            isPrimed = true;
            consecutivePlcCount = 0;
            long firstKey = packetQueue.firstKey();
            if (nextExpectedSeq == -1) {
                nextExpectedSeq = firstKey;
            } else if (firstKey > nextExpectedSeq) {
                lostCount += (firstKey - nextExpectedSeq);
                nextExpectedSeq = firstKey;
            }
        }
    }

    /**
     * Pops the next 20ms PCM frame into outBuffer.
     * Always fills outBuffer with either the exact frame, a PLC concealed frame, or comfort silence.
     *
     * @return true if a real or PLC voice frame was produced, false if pre-buffering silence.
     */
    public synchronized boolean popFrame(short[] outBuffer) {
        if (outBuffer == null || outBuffer.length < samplesPerFrame) {
            throw new IllegalArgumentException("outBuffer too small");
        }

        if (!isPrimed) {
            Arrays.fill(outBuffer, 0, samplesPerFrame, (short) 0);
            return false;
        }

        if (packetQueue.isEmpty()) {
            // Queue underrun: perform PLC up to 3 consecutive frames (60ms), then re-prime
            if (consecutivePlcCount < 3) {
                generatePlcFrame(outBuffer, ++consecutivePlcCount);
                return true;
            } else {
                isPrimed = false;
                consecutivePlcCount = 0;
                Arrays.fill(outBuffer, 0, samplesPerFrame, (short) 0);
                Arrays.fill(lastPlayedFrame, (short) 0);
                return false;
            }
        }

        Long firstAvailableSeq = packetQueue.firstKey();
        if (nextExpectedSeq == -1) {
            nextExpectedSeq = firstAvailableSeq;
        }

        if (firstAvailableSeq.equals(nextExpectedSeq)) {
            // Exact in-order packet hit
            short[] frame = packetQueue.pollFirstEntry().getValue();
            System.arraycopy(frame, 0, outBuffer, 0, samplesPerFrame);
            System.arraycopy(frame, 0, lastPlayedFrame, 0, samplesPerFrame);
            nextExpectedSeq++;
            consecutivePlcCount = 0;
            return true;
        } else if (firstAvailableSeq > nextExpectedSeq) {
            // Gap detected (packet loss or out-of-order arrival still in flight)
            lostCount++;
            nextExpectedSeq++;
            if (consecutivePlcCount < 3) {
                generatePlcFrame(outBuffer, ++consecutivePlcCount);
            } else {
                // Jump forward to available packet if gap is large
                short[] frame = packetQueue.pollFirstEntry().getValue();
                System.arraycopy(frame, 0, outBuffer, 0, samplesPerFrame);
                System.arraycopy(frame, 0, lastPlayedFrame, 0, samplesPerFrame);
                nextExpectedSeq = firstAvailableSeq + 1;
                consecutivePlcCount = 0;
            }
            return true;
        } else {
            // Stale entry before nextExpectedSeq: discard and retry
            packetQueue.pollFirstEntry();
            return popFrame(outBuffer);
        }
    }

    private void generatePlcFrame(short[] outBuffer, int plcStep) {
        // Attenuate previous frame by 50%, 25%, 12.5% with subtle pitch smoothing
        int shift = Math.min(plcStep, 3);
        for (int i = 0; i < samplesPerFrame; i++) {
            short attenuated = (short) (lastPlayedFrame[i] >> shift);
            outBuffer[i] = attenuated;
        }
    }

    public synchronized void reset() {
        packetQueue.clear();
        Arrays.fill(lastPlayedFrame, (short) 0);
        isPrimed = false;
        nextExpectedSeq = -1;
        consecutivePlcCount = 0;
    }

    public synchronized int getBufferedFrameCount() {
        return packetQueue.size();
    }

    public synchronized long getReceivedCount() {
        return receivedCount;
    }

    public synchronized long getLostCount() {
        return lostCount;
    }

    public synchronized long getDuplicateOrLateCount() {
        return duplicateOrLateCount;
    }

    public synchronized long getTrimmedCount() {
        return trimmedCount;
    }

    public synchronized double getPacketLossPercentage() {
        long total = receivedCount + lostCount;
        if (total == 0) {
            return 0.0;
        }
        return (lostCount * 100.0) / total;
    }
}
