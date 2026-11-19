package com.pigeon.voice.audio;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class AudioCodecAndJitterTest {

    @Test
    public void testAdpcmCompressionRatioAndWaveformFidelity() {
        AdpcmCodec codec = new AdpcmCodec();
        short[] originalPcm = new short[AdpcmCodec.SAMPLES_PER_FRAME]; // 320 samples (640 bytes)

        // Generate a realistic composite speech-band waveform (400 Hz + 1100 Hz)
        for (int i = 0; i < originalPcm.length; i++) {
            double t = (double) i / AdpcmCodec.SAMPLE_RATE_HZ;
            double val = 10000.0 * Math.sin(2.0 * Math.PI * 400.0 * t)
                    + 5000.0 * Math.sin(2.0 * Math.PI * 1100.0 * t);
            originalPcm[i] = (short) Math.round(val);
        }

        byte[] compressed = codec.encode(originalPcm, originalPcm.length);
        assertEquals("ADPCM frame must be 164 bytes (4x compression over 640-byte PCM)",
                AdpcmCodec.ADPCM_BYTES_PER_FRAME, compressed.length);

        short[] decodedPcm = AdpcmCodec.decode(compressed);
        assertEquals(originalPcm.length, decodedPcm.length);

        // Verify waveform correlation / SNR after ADPCM roundtrip
        double dot = 0.0;
        double normOrig = 0.0;
        double normDec = 0.0;
        for (int i = 16; i < originalPcm.length; i++) { // skip initial step adaptation transient
            double a = originalPcm[i];
            double b = decodedPcm[i];
            dot += a * b;
            normOrig += a * a;
            normDec += b * b;
        }
        double correlation = dot / (Math.sqrt(normOrig) * Math.sqrt(normDec));
        assertTrue("Decoded voice waveform correlation must exceed 0.96, got " + correlation,
                correlation > 0.96);
    }

    @Test
    public void testNoiseGateLimiterAndLevelCalculation() {
        short[] quietNoise = new short[AdpcmCodec.SAMPLES_PER_FRAME];
        for (int i = 0; i < quietNoise.length; i++) {
            quietNoise[i] = (short) ((i % 2 == 0) ? 40 : -40);
        }

        assertFalse("Quiet hiss should not trigger VAD",
                AdpcmCodec.isVoiceActive(quietNoise, quietNoise.length, 150));
        AdpcmCodec.applyNoiseGateAndLimiter(quietNoise, quietNoise.length, 150);
        assertEquals("Noise gate must attenuate quiet hiss by 75%", 10, Math.abs(quietNoise[0]));

        short[] loudVoice = new short[AdpcmCodec.SAMPLES_PER_FRAME];
        for (int i = 0; i < loudVoice.length; i++) {
            loudVoice[i] = (short) ((i % 2 == 0) ? 16000 : -16000);
        }
        assertTrue("Loud voice must trigger VAD",
                AdpcmCodec.isVoiceActive(loudVoice, loudVoice.length, 150));
        int level = AdpcmCodec.calculateNormalizedLevel(loudVoice, loudVoice.length);
        assertTrue("Normalized level should be > 75 for high amplitude voice, got " + level, level > 75);
    }

    @Test
    public void testJitterBufferReorderingPlcAndAdaptiveTrimming() {
        int frameLen = 320;
        JitterBuffer jb = new JitterBuffer(frameLen, 2, 5);
        short[] out = new short[frameLen];

        // 1. Before pre-buffer (2 frames) is reached, popFrame returns false (comfort silence)
        jb.pushFrame(2L, filledFrame(frameLen, (short) 2000));
        assertFalse("Should still be pre-buffering with only 1 frame", jb.popFrame(out));

        // 2. Push frame 1 out-of-order: now 2 frames are buffered [1, 2]
        jb.pushFrame(1L, filledFrame(frameLen, (short) 1000));
        // Duplicate push of frame 1 must be ignored
        jb.pushFrame(1L, filledFrame(frameLen, (short) 9999));
        assertEquals(1L, jb.getDuplicateOrLateCount());

        // 3. Pop frame 1 and frame 2 in strict sequence order
        assertTrue(jb.popFrame(out));
        assertEquals(1000, out[0]);
        assertTrue(jb.popFrame(out));
        assertEquals(2000, out[0]);

        // 4. Simulate packet loss of sequence 3 (push sequence 4 directly)
        jb.pushFrame(4L, filledFrame(frameLen, (short) 4000));
        // Next pop expects seq 3 -> detects gap and synthesizes attenuated PLC frame (2000 >> 1 = 1000)
        assertTrue(jb.popFrame(out));
        assertEquals("PLC frame should be 50% attenuated continuation of frame 2", 1000, out[0]);
        assertEquals(1L, jb.getLostCount());

        // Next pop delivers seq 4
        assertTrue(jb.popFrame(out));
        assertEquals(4000, out[0]);

        // 5. Test adaptive latency trimming when queue exceeds maxQueueFrames (5)
        for (long seq = 5; seq <= 12; seq++) {
            jb.pushFrame(seq, filledFrame(frameLen, (short) (seq * 100)));
        }
        assertEquals("Queue must be trimmed to maxQueueFrames (5)", 5, jb.getBufferedFrameCount());
        assertTrue("Trimmed count must be > 0", jb.getTrimmedCount() > 0);
    }

    @Test
    public void testJitterBufferUnderrunReprimeResynchronizesSequence() {
        int frameLen = 320;
        JitterBuffer jb = new JitterBuffer(frameLen, 2, 6);
        short[] out = new short[frameLen];

        jb.pushFrame(1L, filledFrame(frameLen, (short) 1000));
        jb.pushFrame(2L, filledFrame(frameLen, (short) 2000));
        assertTrue(jb.popFrame(out));
        assertTrue(jb.popFrame(out));

        // Drain 3 PLC frames + 1 underrun frame to unprime the buffer
        assertTrue(jb.popFrame(out)); // PLC 1
        assertTrue(jb.popFrame(out)); // PLC 2
        assertTrue(jb.popFrame(out)); // PLC 3
        assertFalse("4th empty pop must unprime buffer", jb.popFrame(out));

        // Re-prime after a burst dropout (frames 3..19 lost; frames 20 and 21 arrive)
        jb.pushFrame(20L, filledFrame(frameLen, (short) 20000));
        jb.pushFrame(21L, filledFrame(frameLen, (short) 21000));

        // First pop after re-prime must immediately output frame 20 (not zeroed PLC)
        assertTrue(jb.popFrame(out));
        assertEquals("Must immediately play frame 20 after re-priming", 20000, out[0]);
        assertTrue(jb.popFrame(out));
        assertEquals(21000, out[0]);
        assertEquals("Lost frames 3..19 (17 frames) must be recorded", 17L, jb.getLostCount());
    }

    @Test
    public void testImageCompressorInSampleSizePanoramaAndInvalidBounds() {
        // Tall scrolling screenshot (1080 x 8000) -> must downsample (> 1) even though width is ~1024
        int tallSample = com.pigeon.voice.net.ImageCompressor.calculateInSampleSize(1080, 8000, 1024, 1024);
        assertTrue("Tall screenshot (1080x8000) must be downsampled, got " + tallSample, tallSample >= 4);

        // Wide panorama (8000 x 1080) -> must downsample (> 1)
        int wideSample = com.pigeon.voice.net.ImageCompressor.calculateInSampleSize(8000, 1080, 1024, 1024);
        assertTrue("Wide panorama (8000x1080) must be downsampled, got " + wideSample, wideSample >= 4);

        // Non-positive dimensions must safely return 1 without infinite loop or divide-by-zero
        assertEquals(1, com.pigeon.voice.net.ImageCompressor.calculateInSampleSize(0, 0, 1024, 1024));
        assertEquals(1, com.pigeon.voice.net.ImageCompressor.calculateInSampleSize(2000, 2000, 0, -5));
    }

    private static short[] filledFrame(int len, short val) {
        short[] arr = new short[len];
        for (int i = 0; i < len; i++) {
            arr[i] = val;
        }
        return arr;
    }
}
