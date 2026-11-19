package com.pigeon.voice.service;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.wifi.WifiManager;
import android.os.Build;
import android.os.IBinder;
import android.os.PowerManager;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.core.app.NotificationCompat;

import com.pigeon.voice.R;
import com.pigeon.voice.net.ActiveSessionRegistry;
import com.pigeon.voice.net.P2PSessionManager;
import com.pigeon.voice.ui.CallActivity;

/**
 * Foreground Service keeping the serverless P2P encrypted voice call and Wi-Fi radio in
 * low-latency high-performance mode while the screen is off or the user switches apps.
 */
public final class CallForegroundService extends Service {

    private static final String CHANNEL_ID = "pigeon_encrypted_call_channel";
    private static final int NOTIFICATION_ID = 4101;
    private static final String EXTRA_STATUS_TEXT = "extra_status_text";

    private PowerManager.WakeLock wakeLock;
    private WifiManager.WifiLock wifiLock;
    private ConnectivityManager.NetworkCallback networkCallback;
    private volatile long lastNetworkHandle = -1L;

    public static void startOrUpdate(Context context, String statusText) {
        Intent intent = new Intent(context, CallForegroundService.class);
        intent.putExtra(EXTRA_STATUS_TEXT, statusText);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent);
        } else {
            context.startService(intent);
        }
    }

    public static void stop(Context context) {
        Intent intent = new Intent(context, CallForegroundService.class);
        context.stopService(intent);
    }

    @Override
    public void onCreate() {
        super.onCreate();
        createNotificationChannel();
        acquirePerformanceLocks();
        registerNetworkHandoffCallback();
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String statusText = (intent != null && intent.hasExtra(EXTRA_STATUS_TEXT))
                ? intent.getStringExtra(EXTRA_STATUS_TEXT)
                : "Encrypted P2P Voice Call Active";

        Notification notification = buildNotification(statusText);
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                startForeground(
                        NOTIFICATION_ID,
                        notification,
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE);
            } else {
                startForeground(NOTIFICATION_ID, notification);
            }
        } catch (Exception ignored) {
        }
        return START_NOT_STICKY;
    }

    private Notification buildNotification(String statusText) {
        Intent openIntent = new Intent(this, CallActivity.class);
        openIntent.setFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP | Intent.FLAG_ACTIVITY_CLEAR_TOP);
        PendingIntent pendingIntent = PendingIntent.getActivity(
                this,
                0,
                openIntent,
                PendingIntent.FLAG_UPDATE_CURRENT | PendingIntent.FLAG_IMMUTABLE);

        return new NotificationCompat.Builder(this, CHANNEL_ID)
                .setSmallIcon(R.drawable.ic_lock_shield)
                .setContentTitle(getString(R.string.app_name) + " • Secure P2P Call")
                .setContentText(statusText)
                .setOngoing(true)
                .setPriority(NotificationCompat.PRIORITY_LOW)
                .setCategory(NotificationCompat.CATEGORY_CALL)
                .setContentIntent(pendingIntent)
                .build();
    }

    private void createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            NotificationChannel channel = new NotificationChannel(
                    CHANNEL_ID,
                    "Pigeon Secure Calls",
                    NotificationManager.IMPORTANCE_LOW);
            channel.setDescription("Active end-to-end encrypted P2P voice call status");
            NotificationManager nm = getSystemService(NotificationManager.class);
            if (nm != null) {
                nm.createNotificationChannel(channel);
            }
        }
    }

    @SuppressWarnings("deprecation")
    private void acquirePerformanceLocks() {
        try {
            PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
            if (pm != null) {
                wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "Pigeon:EncryptedVoiceLock");
                wakeLock.setReferenceCounted(false);
                wakeLock.acquire(2 * 60 * 60 * 1000L); // Max 2 hours safety cap
            }
        } catch (Exception ignored) {
        }

        try {
            WifiManager wm = (WifiManager) getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wm != null) {
                int lockType = Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q
                        ? WifiManager.WIFI_MODE_FULL_LOW_LATENCY
                        : WifiManager.WIFI_MODE_FULL_HIGH_PERF;
                wifiLock = wm.createWifiLock(lockType, "Pigeon:LowLatencyVoiceWifiLock");
                wifiLock.setReferenceCounted(false);
                wifiLock.acquire();
            }
        } catch (Exception ignored) {
        }
    }

    private void releasePerformanceLocks() {
        if (wakeLock != null) {
            try {
                if (wakeLock.isHeld()) {
                    wakeLock.release();
                }
            } catch (Exception ignored) {}
            wakeLock = null;
        }
        if (wifiLock != null) {
            try {
                if (wifiLock.isHeld()) {
                    wifiLock.release();
                }
            } catch (Exception ignored) {}
            wifiLock = null;
        }
    }

    private void registerNetworkHandoffCallback() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.N) {
            return;
        }
        try {
            ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
            if (cm == null) {
                return;
            }
            ConnectivityManager.NetworkCallback cb = new ConnectivityManager.NetworkCallback() {
                @Override
                public void onAvailable(@NonNull Network network) {
                    long handle = network.getNetworkHandle();
                    long prev = lastNetworkHandle;
                    lastNetworkHandle = handle;
                    if (prev != -1L && prev != handle) {
                        P2PSessionManager active = ActiveSessionRegistry.getActiveSession();
                        if (active != null && active.getCurrentState() == P2PSessionManager.State.CONNECTED_SECURE) {
                            active.notifyNetworkChangedOrHandoff();
                        }
                    }
                }
            };
            cm.registerDefaultNetworkCallback(cb);
            this.networkCallback = cb;
        } catch (Exception ignored) {
        }
    }

    private void unregisterNetworkHandoffCallback() {
        if (networkCallback != null) {
            try {
                ConnectivityManager cm = (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
                if (cm != null) {
                    cm.unregisterNetworkCallback(networkCallback);
                }
            } catch (Exception ignored) {
            }
            networkCallback = null;
        }
    }

    @Override
    public void onDestroy() {
        unregisterNetworkHandoffCallback();
        releasePerformanceLocks();
        super.onDestroy();
    }

    @Nullable
    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}
