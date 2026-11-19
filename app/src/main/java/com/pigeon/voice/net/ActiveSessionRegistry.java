package com.pigeon.voice.net;

/**
 * Process-wide registry holding the active P2PSessionManager so Activities and
 * CallForegroundService can coordinate the live encrypted P2P sockets seamlessly.
 */
public final class ActiveSessionRegistry {

    private static volatile P2PSessionManager activeSession;

    private ActiveSessionRegistry() {
    }

    public static synchronized P2PSessionManager getActiveSession() {
        return activeSession;
    }

    public static synchronized void setActiveSession(P2PSessionManager session) {
        if (activeSession != null && activeSession != session) {
            activeSession.close();
        }
        activeSession = session;
    }

    public static synchronized void clearActiveSession(P2PSessionManager expected) {
        if (activeSession == expected) {
            activeSession.close();
            activeSession = null;
        }
    }

    public static synchronized void terminateAll() {
        if (activeSession != null) {
            activeSession.close();
            activeSession = null;
        }
    }
}
