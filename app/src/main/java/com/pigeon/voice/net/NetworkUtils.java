package com.pigeon.voice.net;

import java.net.Inet4Address;
import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;
import java.util.Locale;

/**
 * Discovers active Global Unicast IPv6 (5G/LTE/Dual-Stack Wi-Fi), local IPv4,
 * hotspot, and mesh-VPN addresses on the Android device so serverless P2P tokens
 * and UDP hole-punching can advertise all reachable endpoints.
 */
public final class NetworkUtils {

    private NetworkUtils() {
    }

    /**
     * Discovers all active non-loopback IPv4 addresses on the device, ordered by interface priority.
     */
    public static List<String> getLocalIpv4Addresses() {
        List<ScoredAddress> scored = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            if (interfaces != null) {
                while (interfaces.hasMoreElements()) {
                    NetworkInterface nif = interfaces.nextElement();
                    if (!nif.isUp() || nif.isLoopback()) {
                        continue;
                    }
                    String ifName = nif.getName() != null ? nif.getName().toLowerCase(Locale.US) : "";
                    Enumeration<InetAddress> addrs = nif.getInetAddresses();
                    while (addrs.hasMoreElements()) {
                        InetAddress addr = addrs.nextElement();
                        if (addr instanceof Inet4Address && !addr.isLoopbackAddress()) {
                            String ip = addr.getHostAddress();
                            if (ip != null && !ip.startsWith("169.254.")) {
                                int priority = scoreIpv4Interface(ifName, ip);
                                scored.add(new ScoredAddress(ip, priority));
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }

        Collections.sort(scored, (a, b) -> Integer.compare(b.priority, a.priority));
        List<String> result = new ArrayList<>();
        for (ScoredAddress sa : scored) {
            if (!result.contains(sa.ip)) {
                result.add(sa.ip);
            }
        }
        if (result.isEmpty()) {
            result.add("127.0.0.1");
        }
        return result;
    }

    /**
     * Discovers all active Global Unicast IPv6 addresses (2000::/3) across 5G/LTE cellular
     * and dual-stack Wi-Fi interfaces, excluding loopback (::1), link-local (fe80::/10),
     * site-local (fec0::/10), multicast (ff00::/8), and RFC 4193 ULA (fc00::/7),
     * and stripping any %zone interface scope suffixes.
     */
    public static List<String> getGlobalUnicastIpv6Addresses() {
        List<ScoredAddress> scored = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            if (interfaces != null) {
                while (interfaces.hasMoreElements()) {
                    NetworkInterface nif = interfaces.nextElement();
                    if (!nif.isUp() || nif.isLoopback()) {
                        continue;
                    }
                    String ifName = nif.getName() != null ? nif.getName().toLowerCase(Locale.US) : "";
                    Enumeration<InetAddress> addrs = nif.getInetAddresses();
                    while (addrs.hasMoreElements()) {
                        InetAddress addr = addrs.nextElement();
                        if (isGlobalUnicastIpv6(addr)) {
                            String cleanIpv6 = stripIpv6Zone(addr.getHostAddress());
                            if (cleanIpv6 != null && !cleanIpv6.isEmpty()) {
                                int priority = scoreIpv6Interface(ifName);
                                scored.add(new ScoredAddress(cleanIpv6, priority));
                            }
                        }
                    }
                }
            }
        } catch (Exception ignored) {
        }

        Collections.sort(scored, (a, b) -> Integer.compare(b.priority, a.priority));
        List<String> result = new ArrayList<>();
        for (ScoredAddress sa : scored) {
            if (!result.contains(sa.ip)) {
                result.add(sa.ip);
            }
        }
        return result;
    }

    /**
     * Returns true if and only if the address is a publicly routable Global Unicast IPv6
     * address in the IANA 2000::/3 block (first 3 bits == 001).
     */
    public static boolean isGlobalUnicastIpv6(InetAddress addr) {
        if (!(addr instanceof Inet6Address)) {
            return false;
        }
        if (addr.isLoopbackAddress()
                || addr.isLinkLocalAddress()
                || addr.isSiteLocalAddress()
                || addr.isMulticastAddress()) {
            return false;
        }
        byte[] raw = addr.getAddress();
        if (raw == null || raw.length != 16) {
            return false;
        }
        // Global Unicast IPv6 range 2000::/3 -> top 3 bits of first byte must be 001 (0x20..0x3F)
        return (raw[0] & 0xE0) == 0x20;
    }

    /**
     * Strips any IPv6 interface scope zone suffix (e.g. "2607:f8b0::1%rmnet_data0" -> "2607:f8b0::1")
     * and surrounding brackets if present.
     */
    public static String stripIpv6Zone(String hostAddress) {
        if (hostAddress == null) {
            return null;
        }
        String cleaned = hostAddress.trim();
        int pctIndex = cleaned.indexOf('%');
        if (pctIndex > 0) {
            cleaned = cleaned.substring(0, pctIndex).trim();
        }
        if (cleaned.startsWith("[")) {
            cleaned = cleaned.substring(1).trim();
        }
        if (cleaned.endsWith("]")) {
            cleaned = cleaned.substring(0, cleaned.length() - 1).trim();
        }
        return cleaned;
    }

    /**
     * Builds the complete priority-ordered candidate IP list for an InviteToken or UDP exchange:
     * 1. STUN NAT-translated external public IP (if discovered)
     * 2. Global Unicast IPv6 addresses (2000::/3 on 5G/LTE or Wi-Fi)
     * 3. Local / Hotspot / VPN IPv4 addresses
     */
    public static List<String> getCandidateHostAddresses(String stunPublicIp) {
        List<String> candidates = new ArrayList<>();

        if (stunPublicIp != null && !stunPublicIp.trim().isEmpty()) {
            String cleanStun = stripIpv6Zone(stunPublicIp);
            if (cleanStun != null && !cleanStun.isEmpty() && !"127.0.0.1".equals(cleanStun)) {
                candidates.add(cleanStun);
            }
        }

        for (String ipv6 : getGlobalUnicastIpv6Addresses()) {
            if (!candidates.contains(ipv6) && candidates.size() < 16) {
                candidates.add(ipv6);
            }
        }

        for (String ipv4 : getLocalIpv4Addresses()) {
            if ("127.0.0.1".equals(ipv4) && !candidates.isEmpty()) {
                continue;
            }
            if (!candidates.contains(ipv4) && candidates.size() < 16) {
                candidates.add(ipv4);
            }
        }

        if (candidates.isEmpty()) {
            candidates.add("127.0.0.1");
        }
        return candidates;
    }

    private static int scoreIpv4Interface(String ifName, String ip) {
        int score = 10;
        if (ifName.startsWith("wlan") || ifName.startsWith("ap") || ifName.startsWith("wifi")) {
            score += 50;
        } else if (ifName.startsWith("rndis") || ifName.startsWith("usb") || ifName.startsWith("eth")) {
            score += 40;
        } else if (ifName.startsWith("tun") || ifName.startsWith("wg") || ifName.startsWith("tailscale")) {
            score += 45;
        } else if (ifName.startsWith("rmnet") || ifName.startsWith("ccmni") || ifName.startsWith("pdp")) {
            score += 30;
        }
        if (ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.")) {
            score += 20;
        }
        return score;
    }

    private static int scoreIpv6Interface(String ifName) {
        int score = 40;
        if (ifName.startsWith("rmnet") || ifName.startsWith("ccmni") || ifName.startsWith("pdp")
                || ifName.startsWith("cell")) {
            // 5G/LTE mobile carrier global IPv6
            score += 45;
        } else if (ifName.startsWith("wlan") || ifName.startsWith("wifi") || ifName.startsWith("eth")) {
            score += 40;
        } else if (ifName.startsWith("tun") || ifName.startsWith("wg") || ifName.startsWith("tailscale")) {
            score += 35;
        }
        return score;
    }

    private static final class ScoredAddress {
        final String ip;
        final int priority;

        ScoredAddress(String ip, int priority) {
            this.ip = ip;
            this.priority = priority;
        }
    }
}
