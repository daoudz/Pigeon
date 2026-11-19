package com.pigeon.voice.ui;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.graphics.Bitmap;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.recyclerview.widget.LinearLayoutManager;
import androidx.recyclerview.widget.RecyclerView;

import com.google.android.material.button.MaterialButton;
import com.pigeon.voice.R;
import com.pigeon.voice.audio.AudioEngine;
import com.pigeon.voice.net.ActiveSessionRegistry;
import com.pigeon.voice.net.ChatMessage;
import com.pigeon.voice.net.ImageCompressor;
import com.pigeon.voice.net.P2PSessionManager;
import com.pigeon.voice.service.CallForegroundService;
import com.pigeon.voice.token.InviteToken;

import java.util.Locale;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Active Encrypted Voice Call, Text Chat & Image Sharing Room.
 */
public final class CallActivity extends AppCompatActivity implements P2PSessionManager.SessionListener {

    public static final String EXTRA_CONTACT_NAME = "extra_contact_name";
    public static final String EXTRA_CONTACT_PHONE = "extra_contact_phone";

    private final Handler uiHandler = new Handler(Looper.getMainLooper());
    private final ExecutorService imageExecutor = Executors.newSingleThreadExecutor();

    private P2PSessionManager session;
    private AudioEngine audioEngine;
    private ChatAdapter chatAdapter;

    private String invitedContactName;
    private String invitedContactPhone;

    private TextView tvCallPeerName;
    private TextView tvCallStatus;
    private TextView tvCallTimer;
    private TextView tvSafetyNumber;
    private TextView tvLockBadge;
    private TextView tvNetworkStats;
    private LinearLayout layoutInviteCard;
    private TextView tvInviteLinkPreview;
    private ProgressBar progressMicLevel;
    private ProgressBar progressSpeakerLevel;
    private MaterialButton btnToggleMute;
    private Button btnToggleSpeaker;
    private RecyclerView rvChatMessages;
    private EditText etChatMessage;

    private ActivityResultLauncher<String> imagePickerLauncher;

    private final Runnable timerRunnable = new Runnable() {
        @Override
        public void run() {
            updateCallTimerAndStats();
            uiHandler.postDelayed(this, 1000L);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_call);

        session = ActiveSessionRegistry.getActiveSession();
        if (session == null) {
            Toast.makeText(this, "No active call session", Toast.LENGTH_SHORT).show();
            finish();
            return;
        }

        invitedContactName = getIntent().getStringExtra(EXTRA_CONTACT_NAME);
        invitedContactPhone = getIntent().getStringExtra(EXTRA_CONTACT_PHONE);

        bindViews();
        setupImagePicker();
        setupAudioEngine();
        updateMuteButtonUi(audioEngine != null && audioEngine.isMuted());

        session.addListener(this);
        chatAdapter.setMessages(session.getChatHistory());
        scrollToBottom();

        syncUiWithSessionState(session.getCurrentState(), null);
        CallForegroundService.startOrUpdate(this, "Encrypted P2P session active");
        uiHandler.post(timerRunnable);
    }

    private void bindViews() {
        tvCallPeerName = findViewById(R.id.tvCallPeerName);
        tvCallStatus = findViewById(R.id.tvCallStatus);
        tvCallTimer = findViewById(R.id.tvCallTimer);
        tvSafetyNumber = findViewById(R.id.tvSafetyNumber);
        tvLockBadge = findViewById(R.id.tvLockBadge);
        tvNetworkStats = findViewById(R.id.tvNetworkStats);
        layoutInviteCard = findViewById(R.id.layoutInviteCard);
        tvInviteLinkPreview = findViewById(R.id.tvInviteLinkPreview);
        progressMicLevel = findViewById(R.id.progressMicLevel);
        progressSpeakerLevel = findViewById(R.id.progressSpeakerLevel);
        btnToggleMute = findViewById(R.id.btnToggleMute);
        btnToggleSpeaker = findViewById(R.id.btnToggleSpeaker);
        Button btnEndCall = findViewById(R.id.btnEndCall);
        Button btnCopyToken = findViewById(R.id.btnCopyToken);
        Button btnShareInvite = findViewById(R.id.btnShareInvite);
        rvChatMessages = findViewById(R.id.rvChatMessages);
        etChatMessage = findViewById(R.id.etChatMessage);
        ImageButton btnAttachImage = findViewById(R.id.btnAttachImage);
        ImageButton btnSendChat = findViewById(R.id.btnSendChat);

        chatAdapter = new ChatAdapter(this::showFullScreenImageDialog);
        LinearLayoutManager lm = new LinearLayoutManager(this);
        lm.setStackFromEnd(true);
        rvChatMessages.setLayoutManager(lm);
        rvChatMessages.setItemAnimator(null);
        rvChatMessages.setAdapter(chatAdapter);

        btnCopyToken.setOnClickListener(v -> copyInviteLinkToClipboard());
        btnShareInvite.setOnClickListener(v -> shareInviteToContact());
        btnToggleMute.setOnClickListener(v -> toggleMute());
        btnToggleSpeaker.setOnClickListener(v -> toggleSpeaker());
        btnEndCall.setOnClickListener(v -> endCallAndFinish());
        btnSendChat.setOnClickListener(v -> sendChatMessage());
        btnAttachImage.setOnClickListener(v -> pickImageToShare());
        tvSafetyNumber.setOnClickListener(v -> showSafetyNumberVerificationDialog());
        updateMuteButtonUi(false);
    }

    private void setupImagePicker() {
        imagePickerLauncher = registerForActivityResult(
                new ActivityResultContracts.GetContent(),
                uri -> {
                    if (uri != null) {
                        compressAndSendImage(uri);
                    }
                });
    }

    private void setupAudioEngine() {
        audioEngine = new AudioEngine(this, new AudioEngine.AudioEngineListener() {
            @Override
            public void onOutboundAdpcmFrame(byte[] adpcmFrame, int length) {
                if (session != null && session.getCurrentState() == P2PSessionManager.State.CONNECTED_SECURE) {
                    session.sendEncryptedAudioFrame(adpcmFrame, length);
                }
            }

            @Override
            public void onAudioLevelsUpdated(int micLevel, int speakerLevel) {
                uiHandler.post(() -> {
                    progressMicLevel.setProgress(micLevel);
                    progressSpeakerLevel.setProgress(speakerLevel);
                });
            }

            @Override
            public void onAudioError(String message) {
                uiHandler.post(() -> Toast.makeText(CallActivity.this, message, Toast.LENGTH_LONG).show());
            }
        });
    }

    private void syncUiWithSessionState(P2PSessionManager.State state, String customMessage) {
        InviteToken token = session.getActiveInviteToken();
        if (state == P2PSessionManager.State.HOSTING_WAITING && token != null) {
            layoutInviteCard.setVisibility(View.VISIBLE);
            tvInviteLinkPreview.setText(token.toShareableLink());
            String waitingTarget = (invitedContactName != null && !invitedContactName.isEmpty())
                    ? invitedContactName : "Invited Peer";
            tvCallPeerName.setText("Waiting for " + waitingTarget + "...");
            tvLockBadge.setText(token.isContactRestricted() ? "CONTACT-LOCKED (0/1)" : "OPEN TOKEN (0/1)");
        } else {
            layoutInviteCard.setVisibility(View.GONE);
        }

        if (state == P2PSessionManager.State.CONNECTED_SECURE) {
            tvCallPeerName.setText(session.getPeerDisplayName());
            tvSafetyNumber.setText("SAS: " + session.getSafetyNumber());
            int blocked = session.getBlockedIntruderAttempts();
            tvLockBadge.setText(blocked > 0 ? "LOCKED (" + blocked + " BLOCKED)" : "LOCKED (1/1 PEER)");
            tvLockBadge.setTextColor(getResources().getColor(R.color.pigeon_primary, getTheme()));
            audioEngine.start();
            CallForegroundService.startOrUpdate(
                    this,
                    "Connected with " + session.getPeerDisplayName() + " (SAS " + session.getSafetyNumber() + ")");
        } else if (state == P2PSessionManager.State.DISCONNECTED || state == P2PSessionManager.State.ERROR) {
            audioEngine.stop();
            CallForegroundService.stop(this);
            tvLockBadge.setText("ENDED");
        }

        if (customMessage != null && !customMessage.isEmpty()) {
            tvCallStatus.setText(customMessage);
        }
    }

    private void copyInviteLinkToClipboard() {
        if (session == null || session.getActiveInviteToken() == null) {
            return;
        }
        String shareText = session.getActiveInviteToken().toShareMessage(invitedContactName);
        ClipboardManager cm = (ClipboardManager) getSystemService(Context.CLIPBOARD_SERVICE);
        if (cm != null) {
            cm.setPrimaryClip(ClipData.newPlainText("Pigeon Encrypted Call Invite", shareText));
            Toast.makeText(this, "Copied one-time join link & token to clipboard", Toast.LENGTH_SHORT).show();
        }
    }

    private void shareInviteToContact() {
        if (session == null || session.getActiveInviteToken() == null) {
            return;
        }
        String message = session.getActiveInviteToken().toShareMessage(invitedContactName);

        // If a contact phone number was chosen, offer direct SMS or universal Share Sheet
        if (invitedContactPhone != null && !invitedContactPhone.trim().isEmpty()) {
            new AlertDialog.Builder(this)
                    .setTitle("Send Call Invite to " + invitedContactName)
                    .setItems(new String[]{
                            "Send via SMS to " + invitedContactPhone,
                            "Share via Other App (WhatsApp, Signal, etc.)"
                    }, (dialog, which) -> {
                        if (which == 0) {
                            Intent smsIntent = new Intent(
                                    Intent.ACTION_SENDTO,
                                    Uri.parse("smsto:" + Uri.encode(invitedContactPhone)));
                            smsIntent.putExtra("sms_body", message);
                            try {
                                startActivity(smsIntent);
                            } catch (Exception e) {
                                launchSystemShareSheet(message);
                            }
                        } else {
                            launchSystemShareSheet(message);
                        }
                    })
                    .show();
        } else {
            launchSystemShareSheet(message);
        }
    }

    private void launchSystemShareSheet(String message) {
        Intent sendIntent = new Intent(Intent.ACTION_SEND);
        sendIntent.setType("text/plain");
        sendIntent.putExtra(Intent.EXTRA_SUBJECT, "Pigeon Encrypted Voice Call Invite");
        sendIntent.putExtra(Intent.EXTRA_TEXT, message);
        startActivity(Intent.createChooser(sendIntent, "Send Pigeon One-Time Call Link"));
    }

    private void toggleMute() {
        if (audioEngine == null) {
            return;
        }
        boolean newMuted = !audioEngine.isMuted();
        audioEngine.setMuted(newMuted);
        if (newMuted) {
            progressMicLevel.setProgress(0);
        }
        updateMuteButtonUi(newMuted);
        if (session != null) {
            session.sendMuteState(newMuted);
        }
    }

    private void updateMuteButtonUi(boolean isMuted) {
        CharSequence currentText = btnToggleMute.getText();
        if (currentText != null && currentText.length() > 0) {
            btnToggleMute.setText("");
        }
        btnToggleMute.setIconResource(isMuted ? R.drawable.ic_mic_off : R.drawable.ic_mic_on);
        int iconColorRes = isMuted ? R.color.pigeon_danger : R.color.pigeon_text_primary;
        int strokeColorRes = isMuted ? R.color.pigeon_danger : R.color.pigeon_text_secondary;
        btnToggleMute.setIconTint(ContextCompat.getColorStateList(this, iconColorRes));
        btnToggleMute.setStrokeColor(ContextCompat.getColorStateList(this, strokeColorRes));
        btnToggleMute.setContentDescription(getString(isMuted ? R.string.unmute_mic : R.string.mute_mic));
    }

    private void toggleSpeaker() {
        if (audioEngine == null) {
            return;
        }
        boolean newSpeaker = !audioEngine.isSpeakerphoneOn();
        audioEngine.setSpeakerphoneOn(newSpeaker);
        btnToggleSpeaker.setText(newSpeaker ? "Speaker: On" : "Speaker: Off");
        btnToggleSpeaker.setTextColor(getResources().getColor(
                newSpeaker ? R.color.pigeon_primary : R.color.pigeon_text_primary,
                getTheme()));
    }

    private void sendChatMessage() {
        if (session == null || session.getCurrentState() != P2PSessionManager.State.CONNECTED_SECURE) {
            Toast.makeText(this, "Wait until peer joins and encryption is active", Toast.LENGTH_SHORT).show();
            return;
        }
        String text = etChatMessage.getText().toString().trim();
        if (text.isEmpty()) {
            return;
        }
        etChatMessage.setText("");
        ChatMessage sent = session.sendTextMessage(text);
        if (sent != null) {
            chatAdapter.addOrUpdateMessage(sent);
            scrollToBottom();
        }
    }

    private void pickImageToShare() {
        if (session == null || session.getCurrentState() != P2PSessionManager.State.CONNECTED_SECURE) {
            Toast.makeText(this, "Wait until peer joins before sharing encrypted images", Toast.LENGTH_SHORT).show();
            return;
        }
        imagePickerLauncher.launch("image/*");
    }

    private void compressAndSendImage(Uri uri) {
        Toast.makeText(this, "Compressing & encrypting image...", Toast.LENGTH_SHORT).show();
        imageExecutor.execute(() -> {
            try {
                byte[] jpegBytes = ImageCompressor.compressUriToJpeg(getApplicationContext(), uri);
                ChatMessage imgMsg = session.sendImage(jpegBytes);
                uiHandler.post(() -> {
                    chatAdapter.addOrUpdateMessage(imgMsg);
                    scrollToBottom();
                });
            } catch (Exception e) {
                uiHandler.post(() -> Toast.makeText(
                        CallActivity.this,
                        "Failed to share image: " + e.getMessage(),
                        Toast.LENGTH_LONG).show());
            }
        });
    }

    private void showFullScreenImageDialog(ChatMessage message, Bitmap bitmap) {
        ImageView imageView = new ImageView(this);
        imageView.setImageBitmap(bitmap);
        imageView.setAdjustViewBounds(true);
        int pad = (int) (12 * getResources().getDisplayMetrics().density);
        imageView.setPadding(pad, pad, pad, pad);

        new AlertDialog.Builder(this)
                .setTitle("Encrypted Image from " + (message.isOutgoing() ? "You" : message.getSenderName()))
                .setView(imageView)
                .setPositiveButton("Close", null)
                .show();
    }

    private void showSafetyNumberVerificationDialog() {
        if (session == null) {
            return;
        }
        String sas = session.getSafetyNumber();
        int blocked = session.getBlockedIntruderAttempts();
        String msg = "End-to-End Encryption Cipher:\n"
                + "• Key Agreement: Ephemeral ECDH (NIST P-256) + One-Time Token PSK\n"
                + "• KDF: RFC 5869 HKDF-SHA256\n"
                + "• Voice, Text & Image Cipher: AES-256-GCM (128-bit Auth Tag)\n\n"
                + "Safety Number (SAS): " + sas + "\n"
                + "Compare this 6-digit code with your peer over voice. If it matches, no man-in-the-middle exists.\n\n"
                + "Single-Peer Lockout: " + (session.isSessionLocked() ? "ACTIVE (1/1 Peer)" : "Waiting for peer")
                + "\nBlocked Third-Party Attempts: " + blocked;

        new AlertDialog.Builder(this)
                .setTitle("Cryptographic Call Security")
                .setMessage(msg)
                .setPositiveButton("OK", null)
                .show();
    }

    private void updateCallTimerAndStats() {
        if (session == null) {
            return;
        }
        long connectedSince = session.getConnectedSinceEpochMs();
        if (connectedSince > 0 && session.getCurrentState() == P2PSessionManager.State.CONNECTED_SECURE) {
            long elapsedSec = Math.max(0L, (System.currentTimeMillis() - connectedSince) / 1000L);
            long mins = elapsedSec / 60L;
            long secs = elapsedSec % 60L;
            tvCallTimer.setText(String.format(Locale.US, "%02d:%02d", mins, secs));

            long rtt = session.getLastRttMs();
            double loss = audioEngine != null ? audioEngine.getJitterBuffer().getPacketLossPercentage() : 0.0;
            String rttStr = rtt > 0 ? (rtt + " ms") : "<5 ms";
            tvNetworkStats.setText(String.format(Locale.US, "AES-256-GCM • %s • Loss %.1f%%", rttStr, loss));
        }
    }

    private void scrollToBottom() {
        if (chatAdapter.getItemCount() > 0) {
            rvChatMessages.scrollToPosition(chatAdapter.getItemCount() - 1);
        }
    }

    private void endCallAndFinish() {
        if (audioEngine != null) {
            audioEngine.stop();
        }
        CallForegroundService.stop(this);
        if (session != null) {
            session.removeListener(this);
            ActiveSessionRegistry.clearActiveSession(session);
        }
        finish();
    }

    @Override
    public void onStateChanged(P2PSessionManager.State newState, String statusMessage) {
        uiHandler.post(() -> syncUiWithSessionState(newState, statusMessage));
    }

    @Override
    public void onHandshakeCompleted(String peerDisplayName, String safetyNumber) {
        uiHandler.post(() -> {
            tvCallPeerName.setText(peerDisplayName);
            tvSafetyNumber.setText("SAS: " + safetyNumber);
            syncUiWithSessionState(P2PSessionManager.State.CONNECTED_SECURE,
                    "E2EE Voice & Chat Active with " + peerDisplayName);
        });
    }

    @Override
    public void onChatMessageReceived(ChatMessage message) {
        uiHandler.post(() -> {
            chatAdapter.addOrUpdateMessage(message);
            scrollToBottom();
        });
    }

    @Override
    public void onChatMessageUpdated(ChatMessage message) {
        uiHandler.post(() -> chatAdapter.addOrUpdateMessage(message));
    }

    @Override
    public void onEncryptedAudioFrameReceived(long sequenceNumber, byte[] adpcmFrame) {
        if (audioEngine != null) {
            audioEngine.onInboundAdpcmFrame(sequenceNumber, adpcmFrame, adpcmFrame.length);
        }
    }

    @Override
    public void onPeerMuteChanged(boolean peerMuted) {
        uiHandler.post(() -> {
            String status = peerMuted
                    ? (session.getPeerDisplayName() + " muted their microphone")
                    : ("E2EE Voice Active with " + session.getPeerDisplayName());
            tvCallStatus.setText(status);
        });
    }

    @Override
    public void onLatencyUpdated(long rttMs) {
        uiHandler.post(this::updateCallTimerAndStats);
    }

    @Override
    public void onSecurityAlert(String alertMessage) {
        uiHandler.post(() -> {
            int blocked = session != null ? session.getBlockedIntruderAttempts() : 0;
            if (blocked > 0) {
                tvLockBadge.setText("LOCKED (" + blocked + " BLOCKED)");
            }
            Toast.makeText(this, "Security Alert: " + alertMessage, Toast.LENGTH_LONG).show();
        });
    }

    @Override
    protected void onDestroy() {
        uiHandler.removeCallbacks(timerRunnable);
        imageExecutor.shutdownNow();
        if (session != null) {
            session.removeListener(this);
        }
        if (audioEngine != null) {
            audioEngine.stop();
        }
        if (isFinishing()) {
            CallForegroundService.stop(this);
            if (session != null) {
                ActiveSessionRegistry.clearActiveSession(session);
            }
        }
        super.onDestroy();
    }
}
