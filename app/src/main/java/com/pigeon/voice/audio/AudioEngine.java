package com.pigeon.voice.audio;

import android.annotation.SuppressLint;
import android.content.Context;
import android.media.AudioAttributes;
import android.media.AudioDeviceInfo;
import android.media.AudioFormat;
import android.media.AudioManager;
import android.media.AudioRecord;
import android.media.AudioTrack;
import android.media.MediaRecorder;
import android.media.audiofx.AcousticEchoCanceler;
import android.media.audiofx.AutomaticGainControl;
import android.media.audiofx.NoiseSuppressor;
import android.os.Build;
import android.os.Process;
import android.util.Log;

import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Low-latency Native Android Full-Duplex Voice Engine.
 *
 * - Captures 16 kHz wideband voice via AudioRecord (VOICE_COMMUNICATION source)
 * - Enables hardware AcousticEchoCanceler (AEC), NoiseSuppressor (NS), and AutomaticGainControl (AGC)
 * - Applies software noise gate & soft limiter, then compresses 640B PCM -> 164B IMA ADPCM
 * - Plays incoming frames through an adaptive JitterBuffer & low-latency AudioTrack
 */
public final class AudioEngine {

    private static final String TAG = "PigeonAudioEngine";
    private static final int NOISE_GATE_THRESHOLD = 110;

    public interface AudioEngineListener {
        void onOutboundAdpcmFrame(byte[] adpcmFrame, int length);
        void onAudioLevelsUpdated(int micLevel, int speakerLevel);
        void onAudioError(String message);
    }

    private final Context appContext;
    private final AudioEngineListener listener;
    private final AdpcmCodec outboundCodec = new AdpcmCodec();
    private final JitterBuffer jitterBuffer = new JitterBuffer(AdpcmCodec.SAMPLES_PER_FRAME, 2, 20);

    private final AtomicBoolean isRunning = new AtomicBoolean(false);
    private final AtomicBoolean isMuted = new AtomicBoolean(false);
    private final AtomicBoolean isSpeakerOn = new AtomicBoolean(false);

    private AudioManager audioManager;
    private AudioRecord audioRecord;
    private AudioTrack audioTrack;
    private AcousticEchoCanceler echoCanceler;
    private NoiseSuppressor noiseSuppressor;
    private AutomaticGainControl gainControl;

    private Thread captureThread;
    private Thread playbackThread;

    public AudioEngine(Context context, AudioEngineListener listener) {
        this.appContext = context.getApplicationContext();
        this.listener = listener;
        this.audioManager = (AudioManager) appContext.getSystemService(Context.AUDIO_SERVICE);
    }

    @SuppressLint("MissingPermission")
    public synchronized void start() {
        if (isRunning.get()) {
            return;
        }

        try {
            if (audioManager != null) {
                audioManager.setMode(AudioManager.MODE_IN_COMMUNICATION);
                applySpeakerphoneRouting(isSpeakerOn.get());
            }

            int minRecordBuf = AudioRecord.getMinBufferSize(
                    AdpcmCodec.SAMPLE_RATE_HZ,
                    AudioFormat.CHANNEL_IN_MONO,
                    AudioFormat.ENCODING_PCM_16BIT);
            int recordBufferSize = Math.max(minRecordBuf * 2, AdpcmCodec.PCM_BYTES_PER_FRAME * 4);

            audioRecord = new AudioRecord(
                    MediaRecorder.AudioSource.VOICE_COMMUNICATION,
                    AdpcmCodec.SAMPLE_RATE_HZ,
                    AudioFormat.CHANNEL_IN_MONO,
                    AudioFormat.ENCODING_PCM_16BIT,
                    recordBufferSize);

            if (audioRecord.getState() != AudioRecord.STATE_INITIALIZED) {
                throw new IllegalStateException("AudioRecord failed to initialize");
            }

            attachHardwareEffects(audioRecord.getAudioSessionId());

            int minTrackBuf = AudioTrack.getMinBufferSize(
                    AdpcmCodec.SAMPLE_RATE_HZ,
                    AudioFormat.CHANNEL_OUT_MONO,
                    AudioFormat.ENCODING_PCM_16BIT);
            int trackBufferSize = Math.max(minTrackBuf, AdpcmCodec.PCM_BYTES_PER_FRAME * 3);

            AudioAttributes attributes = new AudioAttributes.Builder()
                    .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
                    .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
                    .build();

            AudioFormat format = new AudioFormat.Builder()
                    .setSampleRate(AdpcmCodec.SAMPLE_RATE_HZ)
                    .setChannelMask(AudioFormat.CHANNEL_OUT_MONO)
                    .setEncoding(AudioFormat.ENCODING_PCM_16BIT)
                    .build();

            audioTrack = new AudioTrack.Builder()
                    .setAudioAttributes(attributes)
                    .setAudioFormat(format)
                    .setBufferSizeInBytes(trackBufferSize)
                    .setTransferMode(AudioTrack.MODE_STREAM)
                    .setPerformanceMode(AudioTrack.PERFORMANCE_MODE_LOW_LATENCY)
                    .build();

            outboundCodec.resetEncoder();
            jitterBuffer.reset();
            isRunning.set(true);

            captureThread = new Thread(this::runCaptureLoop, "Pigeon-AudioCapture");
            playbackThread = new Thread(this::runPlaybackLoop, "Pigeon-AudioPlayback");
            captureThread.start();
            playbackThread.start();
        } catch (Exception e) {
            Log.e(TAG, "Failed to start AudioEngine", e);
            stop();
            if (listener != null) {
                listener.onAudioError("Audio initialization error: " + e.getMessage());
            }
        }
    }

    private void attachHardwareEffects(int audioSessionId) {
        try {
            if (AcousticEchoCanceler.isAvailable()) {
                echoCanceler = AcousticEchoCanceler.create(audioSessionId);
                if (echoCanceler != null) {
                    echoCanceler.setEnabled(true);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "AEC unavailable", e);
        }

        try {
            if (NoiseSuppressor.isAvailable()) {
                noiseSuppressor = NoiseSuppressor.create(audioSessionId);
                if (noiseSuppressor != null) {
                    noiseSuppressor.setEnabled(true);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "NoiseSuppressor unavailable", e);
        }

        try {
            if (AutomaticGainControl.isAvailable()) {
                gainControl = AutomaticGainControl.create(audioSessionId);
                if (gainControl != null) {
                    gainControl.setEnabled(true);
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "AGC unavailable", e);
        }
    }

    private volatile int lastMicLevel = 0;
    private volatile int lastSpeakerLevel = 0;

    private void runCaptureLoop() {
        Process.setThreadPriority(Process.THREAD_PRIORITY_URGENT_AUDIO);
        final short[] pcmBuffer = new short[AdpcmCodec.SAMPLES_PER_FRAME];
        final byte[] adpcmBuffer = new byte[AdpcmCodec.ADPCM_BYTES_PER_FRAME];
        int levelTick = 0;

        try {
            audioRecord.startRecording();
            while (isRunning.get()) {
                int readOffset = 0;
                while (readOffset < AdpcmCodec.SAMPLES_PER_FRAME && isRunning.get()) {
                    int read = audioRecord.read(
                            pcmBuffer,
                            readOffset,
                            AdpcmCodec.SAMPLES_PER_FRAME - readOffset);
                    if (read <= 0) {
                        break;
                    }
                    readOffset += read;
                }

                if (readOffset < AdpcmCodec.SAMPLES_PER_FRAME) {
                    continue;
                }

                if (isMuted.get()) {
                    lastMicLevel = 0;
                    outboundCodec.resetEncoder();
                    levelTick++;
                    if ((levelTick & 3) == 0 && listener != null) {
                        listener.onAudioLevelsUpdated(0, lastSpeakerLevel);
                    }
                    continue;
                }

                // DSP processing: noise gate + soft limiter
                AdpcmCodec.applyNoiseGateAndLimiter(pcmBuffer, AdpcmCodec.SAMPLES_PER_FRAME, NOISE_GATE_THRESHOLD);

                // Compress 640 bytes PCM -> 164 bytes ADPCM
                outboundCodec.encodeInto(pcmBuffer, AdpcmCodec.SAMPLES_PER_FRAME, adpcmBuffer);

                if (listener != null) {
                    listener.onOutboundAdpcmFrame(adpcmBuffer, AdpcmCodec.ADPCM_BYTES_PER_FRAME);
                }

                levelTick++;
                if ((levelTick & 3) == 0) { // Every ~80ms update UI level meter
                    lastMicLevel = AdpcmCodec.calculateNormalizedLevel(pcmBuffer, AdpcmCodec.SAMPLES_PER_FRAME);
                    if (listener != null) {
                        listener.onAudioLevelsUpdated(lastMicLevel, lastSpeakerLevel);
                    }
                }
            }
        } catch (Exception e) {
            if (isRunning.get()) {
                Log.e(TAG, "Capture loop failed", e);
            }
        }
    }

    private void runPlaybackLoop() {
        Process.setThreadPriority(Process.THREAD_PRIORITY_URGENT_AUDIO);
        final short[] playBuffer = new short[AdpcmCodec.SAMPLES_PER_FRAME];
        int levelTick = 0;

        try {
            audioTrack.play();
            while (isRunning.get()) {
                boolean hasAudio = jitterBuffer.popFrame(playBuffer);
                if (hasAudio) {
                    audioTrack.write(playBuffer, 0, AdpcmCodec.SAMPLES_PER_FRAME);
                    levelTick++;
                    if ((levelTick & 3) == 0) {
                        lastSpeakerLevel = AdpcmCodec.calculateNormalizedLevel(
                                playBuffer, AdpcmCodec.SAMPLES_PER_FRAME);
                    }
                } else {
                    lastSpeakerLevel = 0;
                    // Write short silence slice to keep AudioTrack warm without adding latency
                    audioTrack.write(playBuffer, 0, AdpcmCodec.SAMPLES_PER_FRAME);
                }
            }
        } catch (Exception e) {
            if (isRunning.get()) {
                Log.e(TAG, "Playback loop failed", e);
            }
        }
    }

    /**
     * Feeds an incoming decrypted IMA ADPCM frame into the adaptive jitter buffer.
     */
    public void onInboundAdpcmFrame(long sequenceNumber, byte[] adpcmBytes, int length) {
        if (!isRunning.get() || adpcmBytes == null || length <= AdpcmCodec.ADPCM_HEADER_BYTES) {
            return;
        }
        try {
            int sampleCount = (length - AdpcmCodec.ADPCM_HEADER_BYTES) * 2;
            short[] decoded = new short[sampleCount];
            AdpcmCodec.decodeInto(adpcmBytes, length, decoded);
            jitterBuffer.pushDecodedFrameOwned(sequenceNumber, decoded);
        } catch (Exception e) {
            Log.w(TAG, "Dropped malformed ADPCM frame seq=" + sequenceNumber, e);
        }
    }

    public void setMuted(boolean muted) {
        isMuted.set(muted);
        if (muted) {
            lastMicLevel = 0;
            if (listener != null) {
                listener.onAudioLevelsUpdated(0, lastSpeakerLevel);
            }
        }
    }

    public boolean isMuted() {
        return isMuted.get();
    }

    public void setSpeakerphoneOn(boolean speakerOn) {
        isSpeakerOn.set(speakerOn);
        applySpeakerphoneRouting(speakerOn);
    }

    @SuppressWarnings("deprecation")
    private void applySpeakerphoneRouting(boolean speakerOn) {
        if (audioManager == null) {
            return;
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                if (speakerOn) {
                    List<AudioDeviceInfo> devices = audioManager.getAvailableCommunicationDevices();
                    for (AudioDeviceInfo device : devices) {
                        if (device.getType() == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER) {
                            audioManager.setCommunicationDevice(device);
                            return;
                        }
                    }
                } else {
                    audioManager.clearCommunicationDevice();
                    return;
                }
            }
            audioManager.setSpeakerphoneOn(speakerOn);
        } catch (Exception e) {
            Log.w(TAG, "Failed to toggle speakerphone", e);
        }
    }

    @SuppressWarnings("deprecation")
    private void resetAudioRouting() {
        if (audioManager == null) {
            return;
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                audioManager.clearCommunicationDevice();
            }
            audioManager.setSpeakerphoneOn(false);
            audioManager.setMode(AudioManager.MODE_NORMAL);
        } catch (Exception ignored) {
        }
    }

    public boolean isSpeakerphoneOn() {
        return isSpeakerOn.get();
    }

    public JitterBuffer getJitterBuffer() {
        return jitterBuffer;
    }

    public synchronized void stop() {
        isRunning.set(false);

        if (captureThread != null) {
            captureThread.interrupt();
            captureThread = null;
        }
        if (playbackThread != null) {
            playbackThread.interrupt();
            playbackThread = null;
        }

        if (echoCanceler != null) {
            try { echoCanceler.release(); } catch (Exception ignored) {}
            echoCanceler = null;
        }
        if (noiseSuppressor != null) {
            try { noiseSuppressor.release(); } catch (Exception ignored) {}
            noiseSuppressor = null;
        }
        if (gainControl != null) {
            try { gainControl.release(); } catch (Exception ignored) {}
            gainControl = null;
        }

        if (audioRecord != null) {
            try {
                if (audioRecord.getRecordingState() == AudioRecord.RECORDSTATE_RECORDING) {
                    audioRecord.stop();
                }
                audioRecord.release();
            } catch (Exception ignored) {}
            audioRecord = null;
        }

        if (audioTrack != null) {
            try {
                if (audioTrack.getPlayState() == AudioTrack.PLAYSTATE_PLAYING) {
                    audioTrack.stop();
                }
                audioTrack.release();
            } catch (Exception ignored) {}
            audioTrack = null;
        }

        resetAudioRouting();
    }
}
