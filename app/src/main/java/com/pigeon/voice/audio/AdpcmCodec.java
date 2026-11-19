package com.pigeon.voice.audio;

/**
 * High-performance IMA ADPCM 4-bit speech codec and voice DSP processor.
 *
 * Compresses 16-bit signed PCM audio (256 kbps @ 16 kHz mono) down to 4-bit IMA ADPCM
 * (65.6 kbps @ 16 kHz mono, 164 bytes per 20ms frame of 320 samples) with negligible CPU overhead
 * and zero heap allocation when using pre-allocated buffers.
 */
public final class AdpcmCodec {

    public static final int SAMPLE_RATE_HZ = 16000;
    public static final int FRAME_DURATION_MS = 20;
    public static final int SAMPLES_PER_FRAME = (SAMPLE_RATE_HZ * FRAME_DURATION_MS) / 1000; // 320 samples
    public static final int PCM_BYTES_PER_FRAME = SAMPLES_PER_FRAME * 2; // 640 bytes
    public static final int ADPCM_HEADER_BYTES = 4;
    public static final int ADPCM_BYTES_PER_FRAME = ADPCM_HEADER_BYTES + (SAMPLES_PER_FRAME / 2); // 164 bytes

    private static final int[] INDEX_TABLE = {
            -1, -1, -1, -1, 2, 4, 6, 8,
            -1, -1, -1, -1, 2, 4, 6, 8
    };

    private static final int[] STEP_TABLE = {
            7, 8, 9, 10, 11, 12, 13, 14, 16, 17,
            19, 21, 23, 25, 28, 31, 34, 37, 41, 45,
            50, 55, 60, 66, 73, 80, 88, 97, 107, 118,
            130, 143, 157, 173, 190, 209, 230, 253, 279, 307,
            337, 371, 408, 449, 494, 544, 598, 658, 724, 796,
            876, 963, 1060, 1166, 1282, 1411, 1552, 1707, 1878, 2066,
            2272, 2499, 2749, 3024, 3327, 3660, 4026, 4428, 4871, 5358,
            5894, 6484, 7132, 7845, 8630, 9493, 10442, 11487, 12635, 13899,
            15289, 16818, 18500, 20350, 22385, 24623, 27086, 29794, 32767
    };

    private int encodePredictor = 0;
    private int encodeStepIndex = 0;

    /**
     * Resets stateful encoder predictor/step index.
     */
    public void resetEncoder() {
        encodePredictor = 0;
        encodeStepIndex = 0;
    }

    /**
     * Encodes an even number of 16-bit PCM samples into a self-contained IMA ADPCM packet.
     * The first 4 bytes store the initial predictor (int16 LE), stepIndex (int8), and sampleCount/2.
     */
    public byte[] encode(short[] pcmSamples, int sampleCount) {
        if (pcmSamples == null || sampleCount <= 0 || (sampleCount % 2) != 0) {
            throw new IllegalArgumentException("sampleCount must be a positive even integer");
        }
        byte[] out = new byte[ADPCM_HEADER_BYTES + (sampleCount / 2)];
        encodeInto(pcmSamples, sampleCount, out);
        return out;
    }

    /**
     * Zero-allocation encode into a caller-provided output buffer of size 4 + (sampleCount / 2).
     */
    public void encodeInto(short[] pcmSamples, int sampleCount, byte[] outBuffer) {
        if (pcmSamples == null || sampleCount <= 0 || (sampleCount % 2) != 0) {
            throw new IllegalArgumentException("sampleCount must be a positive even integer");
        }
        int requiredLen = ADPCM_HEADER_BYTES + (sampleCount / 2);
        if (outBuffer == null || outBuffer.length < requiredLen) {
            throw new IllegalArgumentException("Output buffer too small");
        }

        int predictor = encodePredictor;
        int stepIndex = encodeStepIndex;

        // Write 4-byte state header so every UDP packet is independently decodable even after packet loss
        outBuffer[0] = (byte) (predictor & 0xFF);
        outBuffer[1] = (byte) ((predictor >> 8) & 0xFF);
        outBuffer[2] = (byte) (stepIndex & 0xFF);
        outBuffer[3] = 0;

        int outIdx = ADPCM_HEADER_BYTES;
        for (int i = 0; i < sampleCount; i += 2) {
            int nibbleLow = encodeSample(pcmSamples[i], predictor, stepIndex);
            predictor = tempPredictor;
            stepIndex = tempStepIndex;

            int nibbleHigh = encodeSample(pcmSamples[i + 1], predictor, stepIndex);
            predictor = tempPredictor;
            stepIndex = tempStepIndex;

            outBuffer[outIdx++] = (byte) ((nibbleLow & 0x0F) | ((nibbleHigh & 0x0F) << 4));
        }

        encodePredictor = predictor;
        encodeStepIndex = stepIndex;
    }

    private int tempPredictor;
    private int tempStepIndex;

    private int encodeSample(short sample, int predictor, int stepIndex) {
        int step = STEP_TABLE[stepIndex];
        int diff = sample - predictor;
        int nibble = 0;
        if (diff < 0) {
            nibble = 8;
            diff = -diff;
        }

        int vpdiff = step >> 3;
        if (diff >= step) {
            nibble |= 4;
            diff -= step;
            vpdiff += step;
        }
        step >>= 1;
        if (diff >= step) {
            nibble |= 2;
            diff -= step;
            vpdiff += step;
        }
        step >>= 1;
        if (diff >= step) {
            nibble |= 1;
            vpdiff += step;
        }

        if ((nibble & 8) != 0) {
            predictor -= vpdiff;
        } else {
            predictor += vpdiff;
        }

        if (predictor > 32767) {
            predictor = 32767;
        } else if (predictor < -32768) {
            predictor = -32768;
        }

        stepIndex += INDEX_TABLE[nibble];
        if (stepIndex < 0) {
            stepIndex = 0;
        } else if (stepIndex >= STEP_TABLE.length) {
            stepIndex = STEP_TABLE.length - 1;
        }

        tempPredictor = predictor;
        tempStepIndex = stepIndex;
        return nibble;
    }

    /**
     * Decodes a self-contained IMA ADPCM frame back into 16-bit PCM samples.
     */
    public static short[] decode(byte[] adpcmFrame) {
        if (adpcmFrame == null || adpcmFrame.length <= ADPCM_HEADER_BYTES) {
            throw new IllegalArgumentException("Invalid ADPCM frame");
        }
        int sampleCount = (adpcmFrame.length - ADPCM_HEADER_BYTES) * 2;
        short[] out = new short[sampleCount];
        decodeInto(adpcmFrame, adpcmFrame.length, out);
        return out;
    }

    /**
     * Zero-allocation decode into caller-provided PCM buffer. Returns number of decoded samples.
     */
    public static int decodeInto(byte[] adpcmFrame, int byteLength, short[] outPcm) {
        if (adpcmFrame == null || byteLength <= ADPCM_HEADER_BYTES) {
            throw new IllegalArgumentException("Invalid ADPCM frame length");
        }
        int sampleCount = (byteLength - ADPCM_HEADER_BYTES) * 2;
        if (outPcm == null || outPcm.length < sampleCount) {
            throw new IllegalArgumentException("Output PCM buffer too small");
        }

        int predictor = (short) ((adpcmFrame[0] & 0xFF) | (adpcmFrame[1] << 8));
        int stepIndex = adpcmFrame[2] & 0xFF;
        if (stepIndex >= STEP_TABLE.length) {
            stepIndex = STEP_TABLE.length - 1;
        }

        int pcmIdx = 0;
        for (int i = ADPCM_HEADER_BYTES; i < byteLength; i++) {
            int packed = adpcmFrame[i] & 0xFF;

            // Low nibble
            int nibble0 = packed & 0x0F;
            int step0 = STEP_TABLE[stepIndex];
            int vpdiff0 = step0 >> 3;
            if ((nibble0 & 4) != 0) vpdiff0 += step0;
            if ((nibble0 & 2) != 0) vpdiff0 += (step0 >> 1);
            if ((nibble0 & 1) != 0) vpdiff0 += (step0 >> 2);
            if ((nibble0 & 8) != 0) {
                predictor -= vpdiff0;
            } else {
                predictor += vpdiff0;
            }
            if (predictor > 32767) predictor = 32767;
            else if (predictor < -32768) predictor = -32768;
            stepIndex += INDEX_TABLE[nibble0];
            if (stepIndex < 0) stepIndex = 0;
            else if (stepIndex >= STEP_TABLE.length) stepIndex = STEP_TABLE.length - 1;
            outPcm[pcmIdx++] = (short) predictor;

            // High nibble
            int nibble1 = (packed >> 4) & 0x0F;
            int step1 = STEP_TABLE[stepIndex];
            int vpdiff1 = step1 >> 3;
            if ((nibble1 & 4) != 0) vpdiff1 += step1;
            if ((nibble1 & 2) != 0) vpdiff1 += (step1 >> 1);
            if ((nibble1 & 1) != 0) vpdiff1 += (step1 >> 2);
            if ((nibble1 & 8) != 0) {
                predictor -= vpdiff1;
            } else {
                predictor += vpdiff1;
            }
            if (predictor > 32767) predictor = 32767;
            else if (predictor < -32768) predictor = -32768;
            stepIndex += INDEX_TABLE[nibble1];
            if (stepIndex < 0) stepIndex = 0;
            else if (stepIndex >= STEP_TABLE.length) stepIndex = STEP_TABLE.length - 1;
            outPcm[pcmIdx++] = (short) predictor;
        }
        return sampleCount;
    }

    /**
     * Applies a soft noise gate (suppressing low-amplitude background hiss) and
     * soft limiter to prevent digital clipping.
     */
    public static void applyNoiseGateAndLimiter(short[] samples, int count, int gateThreshold) {
        if (samples == null || count <= 0) {
            return;
        }
        long sumSq = 0;
        for (int i = 0; i < count; i++) {
            int s = samples[i];
            sumSq += (long) s * s;
        }
        double rms = Math.sqrt((double) sumSq / count);

        // If frame RMS is below noise gate threshold, attenuate smoothly by 75%
        boolean gateActive = rms < gateThreshold;
        for (int i = 0; i < count; i++) {
            int s = samples[i];
            if (gateActive) {
                s >>= 2;
            } else if (s > 28000) {
                s = 28000 + ((s - 28000) >> 2);
            } else if (s < -28000) {
                s = -28000 + ((s + 28000) >> 2);
            }
            samples[i] = (short) Math.max(-32768, Math.min(32767, s));
        }
    }

    /**
     * Returns true if the audio frame contains active voice energy above the threshold.
     */
    public static boolean isVoiceActive(short[] samples, int count, int rmsThreshold) {
        if (samples == null || count <= 0) {
            return false;
        }
        long sumSq = 0;
        for (int i = 0; i < count; i++) {
            int s = samples[i];
            sumSq += (long) s * s;
        }
        double rms = Math.sqrt((double) sumSq / count);
        return rms >= rmsThreshold;
    }

    /**
     * Calculates a normalized 0..100 UI level meter reading from a PCM frame.
     */
    public static int calculateNormalizedLevel(short[] samples, int count) {
        if (samples == null || count <= 0) {
            return 0;
        }
        long sumSq = 0;
        for (int i = 0; i < count; i++) {
            int s = samples[i];
            sumSq += (long) s * s;
        }
        double rms = Math.sqrt((double) sumSq / count);
        if (rms < 20.0) {
            return 0;
        }
        double db = 20.0 * Math.log10(rms / 32768.0); // -96..0 dB
        int level = (int) Math.round(((db + 55.0) / 55.0) * 100.0);
        return Math.max(0, Math.min(100, level));
    }
}
