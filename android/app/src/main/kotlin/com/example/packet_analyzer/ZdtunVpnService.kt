package com.example.packet_analyzer

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.util.Log
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap

/**
 * VPN Service using zdtun for proper packet forwarding
 * Based on PCAPdroid's architecture
 */
class ZdtunVpnService : VpnService() {
    companion object {
        private const val TAG = "ZdtunVpnService"
        private var methodChannel: MethodChannel? = null
        private var packetSink: EventChannel.EventSink? = null
        private var anomalySink: EventChannel.EventSink? = null
        private val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())

        fun setMethodChannel(channel: MethodChannel) {
            methodChannel = channel
        }

        fun setPacketSink(sink: EventChannel.EventSink?) {
            packetSink = sink
        }

        fun setAnomalySink(sink: EventChannel.EventSink?) {
            anomalySink = sink
            Log.i(TAG, "Anomaly sink set: ${if (sink != null) "active" else "inactive"}")
        }

        fun sendAnomalyToFlutter(anomaly: Map<String, Any>) {
            mainHandler.post {
                try {
                    anomalySink?.success(anomaly)
                    Log.i(TAG, "🚨 Anomaly sent to Flutter: ${anomaly["type"]}")
                } catch (e: Exception) {
                    Log.e(TAG, "Error sending anomaly to Flutter: ${e.message}")
                }
            }
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var zdtunInitialized = false
    private val instanceHandler = android.os.Handler(android.os.Looper.getMainLooper())

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "ZdtunVpnService created")
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        Log.i(TAG, "ZdtunVpnService onStartCommand: action=$action")

        when (action) {
            "STOP_VPN" -> {
                Log.i(TAG, "Received STOP_VPN command")
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                if (!isRunning) {
                    Log.i(TAG, "Starting VPN service")
                    startVpnService()
                } else {
                    Log.i(TAG, "VPN already running")
                }
                return START_STICKY
            }
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "andronet_capture",
                "AndroNet Capture",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "VPN packet capture service"
            }
            getSystemService(NotificationManager::class.java)
                .createNotificationChannel(channel)
        }
    }

    private fun buildNotification(): Notification {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, "andronet_capture")
                .setContentTitle("AndroNet VPN Active")
                .setContentText("Capturing network traffic")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .setOngoing(true)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("AndroNet VPN Active")
                .setContentText("Capturing network traffic")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .setOngoing(true)
                .build()
        }
    }

    private fun startVpnService() {
        // Must call startForeground() within 5 seconds on Android 8+ or the OS kills the service
        startForeground(1, buildNotification())

        try {
            // Establish VPN
            val builder = Builder()
                // IPv4 configuration
                .addAddress("10.0.0.2", 24)
                .addRoute("0.0.0.0", 0)

                // IPv6 configuration - capture IPv6 traffic too
                .addAddress("fd00::2", 64)
                .addRoute("::", 0)

                // DNS servers (both IPv4 and IPv6)
                .addDnsServer("8.8.8.8")
                .addDnsServer("8.8.4.4")
                .addDnsServer("2001:4860:4860::8888")  // Google DNS IPv6
                .addDnsServer("2001:4860:4860::8844")  // Google DNS IPv6

                .setSession("Andronet VPN")
                .setMtu(1500)  // Standard MTU
                .setBlocking(false)

            // Exclude this app from VPN to prevent capturing own traffic
            try {
                builder.addDisallowedApplication(packageName)
                Log.i(TAG, "✅ Excluded own app from VPN to prevent loops")
            } catch (e: Exception) {
                Log.w(TAG, "Could not exclude own app: ${e.message}")
            }

            vpnInterface = builder.establish()
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN")
                stopSelf()
                return
            }

            val tunFd = vpnInterface!!.fd
            Log.i(TAG, "VPN established with TUN fd: $tunFd")

            // Initialize zdtun
            if (!ZdtunVpn.nativeInit(this, tunFd)) {
                Log.e(TAG, "Failed to initialize zdtun")
                stopSelf()
                return
            }

            zdtunInitialized = true
            isRunning = true

            // Start PacketAnalysisManager for DPI and payload processing
            try {
                PacketAnalysisManager.getInstance().startAnalysis()
                Log.i(TAG, "✅ PacketAnalysisManager started")
            } catch (e: Exception) {
                Log.e(TAG, "❌ Failed to start PacketAnalysisManager: ${e.message}")
            }

            // Register anomaly listener to send anomalies to Flutter
            AnomalyDetector.addAnomalyListener { anomaly ->
                val anomalyMap = mapOf(
                    "type" to anomaly.type.name,
                    "severity" to anomaly.severity.name,
                    "description" to anomaly.description,
                    "sourceIp" to (anomaly.sourceIp ?: ""),
                    "destinationIp" to (anomaly.destinationIp ?: ""),
                    "timestamp" to anomaly.timestamp,
                    "details" to anomaly.details
                )
                sendAnomalyToFlutter(anomalyMap)
            }
            Log.i(TAG, "✅ Anomaly listener registered")

            // Start packet processing coroutines
            serviceScope.launch {
                readFromTun()
            }

            serviceScope.launch {
                processZdtunEvents()
            }

            Log.i(TAG, "ZdtunVpnService started successfully")

        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "❌ Native library load failure: ${e.message}", e)
            mainHandler.post {
                methodChannel?.invokeMethod(
                    "onNativeLibraryError",
                    mapOf("error" to (e.message ?: "Native library failed to load"))
                )
            }
            stopSelf()
        } catch (e: Exception) {
            Log.e(TAG, "❌ Error starting VPN: ${e.message}", e)
            mainHandler.post {
                methodChannel?.invokeMethod(
                    "onCaptureError",
                    mapOf("error" to (e.message ?: "Unknown error starting VPN"))
                )
            }
            stopSelf()
        }
    }

    /**
     * Read packets from TUN interface and forward to zdtun
     */
    private suspend fun readFromTun() = withContext(Dispatchers.IO) {
        val inputStream = FileInputStream(vpnInterface!!.fileDescriptor)
        val buffer = ByteBuffer.allocate(32767) // Max IP packet size

        Log.i(TAG, "Started reading from TUN")

        try {
            while (isRunning) {
                buffer.clear()
                val length = inputStream.read(buffer.array())

                if (length > 0) {
                    val packet = ByteArray(length)
                    System.arraycopy(buffer.array(), 0, packet, 0, length)

                    // Parse packet for logging/capturing
                    val packetInfo = parsePacket(packet, isOutgoing = true)
                    if (packetInfo != null) {
                        val protocol = packetInfo["protocol"]
                        val sourcePort = packetInfo["sourcePort"]
                        val destPort = packetInfo["destinationPort"]

                        // Per-packet diagnostic logging — debug builds only, avoids
                        // paying string-formatting cost and logcat spam in release.
                        if (BuildConfig.DEBUG) {
                            when (protocol) {
                                "SMTP", "IMAP", "IMAPS", "POP3", "POP3S", "ICMP" -> {
                                    Log.i(TAG, "🔍 EMAIL/ICMP PACKET: $protocol " +
                                            "${packetInfo["sourceIp"]}:$sourcePort → " +
                                            "${packetInfo["destinationIp"]}:$destPort")
                                }
                                "TCP" -> {
                                    when {
                                        destPort == 25 || sourcePort == 25 -> Log.i(TAG, "📧 SMTP (port 25) detected")
                                        destPort == 587 || sourcePort == 587 -> Log.i(TAG, "📧 SMTP (port 587) detected")
                                        destPort == 143 || sourcePort == 143 -> Log.i(TAG, "📧 IMAP (port 143) detected")
                                        destPort == 993 || sourcePort == 993 -> Log.i(TAG, "📧 IMAPS (port 993) detected")
                                        destPort == 110 || sourcePort == 110 -> Log.i(TAG, "📧 POP3 (port 110) detected")
                                        destPort == 995 || sourcePort == 995 -> Log.i(TAG, "📧 POP3S (port 995) detected")
                                    }
                                }
                            }

                            Log.d(TAG, "📤 TUN→zdtun: ${packetInfo["protocol"]} " +
                                    "${packetInfo["sourceIp"]}:${packetInfo["sourcePort"]} → " +
                                    "${packetInfo["destinationIp"]}:${packetInfo["destinationPort"]}")
                        }

                        // Send to Flutter for display (with raw packet for Phase 2 processing)
                        sendPacketToFlutter(packetInfo, packet)
                    }

                    // Forward packet to zdtun for processing
                    ZdtunVpn.nativeHandlePacket(packet)
                } else if (length < 0) {
                    Log.w(TAG, "TUN read returned $length, stopping")
                    break
                }

                // Yield to prevent blocking
                yield()
            }
        } catch (e: Exception) {
            if (isRunning) {
                Log.e(TAG, "Error reading from TUN: ${e.message}", e)
            }
        } finally {
            Log.i(TAG, "Stopped reading from TUN")
        }
    }

    /**
     * Process zdtun events (handles socket I/O, connections, etc.)
     */
    private suspend fun processZdtunEvents() = withContext(Dispatchers.IO) {
        Log.i(TAG, "Started processing zdtun events")

        try {
            while (isRunning) {
                // Handle zdtun events with 100ms timeout
                ZdtunVpn.nativeHandleEvents(100)

                // Yield to prevent blocking
                yield()
            }
        } catch (e: Exception) {
            if (isRunning) {
                Log.e(TAG, "Error processing zdtun events: ${e.message}", e)
            }
        } finally {
            Log.i(TAG, "Stopped processing zdtun events")
        }
    }

    /**
     * Called from native code to send packet back to VPN
     * This is the remote2vpn callback
     */
    @Suppress("unused")
    fun sendPacketToVpn(packet: ByteArray) {
        try {
            val outputStream = FileOutputStream(vpnInterface!!.fileDescriptor)
            outputStream.write(packet)

            // Parse for logging and display
            val packetInfo = parsePacket(packet, isOutgoing = false)
            if (packetInfo != null) {
                val protocol = packetInfo["protocol"]
                val sourcePort = packetInfo["sourcePort"]
                val destPort = packetInfo["destinationPort"]

                if (BuildConfig.DEBUG) {
                    when (protocol) {
                        "SMTP", "IMAP", "IMAPS", "POP3", "POP3S", "ICMP" -> {
                            Log.i(TAG, "🔍 EMAIL/ICMP PACKET (incoming): $protocol " +
                                    "${packetInfo["sourceIp"]}:$sourcePort → " +
                                    "${packetInfo["destinationIp"]}:$destPort")
                        }
                    }

                    Log.d(TAG, "📥 zdtun→TUN: ${packetInfo["protocol"]} " +
                            "${packetInfo["sourceIp"]}:${packetInfo["sourcePort"]} → " +
                            "${packetInfo["destinationIp"]}:${packetInfo["destinationPort"]}")
                }

                // Send to Flutter for display (with raw packet for Phase 2 processing)
                sendPacketToFlutter(packetInfo, packet)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error writing to TUN: ${e.message}")
        }
    }

    /**
     * Called from native code to protect sockets
     */
    @Suppress("unused")
    fun protectSocket(fd: Int): Boolean {
        val result = protect(fd)
        if (result) {
            Log.d(TAG, "✅ Socket protected: fd=$fd")
        } else {
            Log.w(TAG, "❌ Socket protection failed: fd=$fd")
        }
        return result
    }

    private fun parsePacket(packet: ByteArray, isOutgoing: Boolean = true): Map<String, Any>? {
        try {
            if (packet.size < 1) return null
            val version = (packet[0].toInt() shr 4) and 0x0F
            return when (version) {
                4 -> parseIpv4Packet(packet, isOutgoing)
                6 -> parseIpv6Packet(packet, isOutgoing)
                else -> null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error parsing packet: ${e.message}")
            return null
        }
    }

    // Cache of "protocol:localPort" -> resolved app label. getConnectionOwnerUid()
    // is a Binder IPC call to netd — expensive to do on every single packet, but
    // a given local (ephemeral) port belongs to the same app for the lifetime of
    // that socket, so this is safe to cache and cheap to keep bounded.
    private val owningAppCache = ConcurrentHashMap<String, String?>()

    /**
     * Resolves the installed app that owns a given TCP/UDP flow, using
     * ConnectivityManager.getConnectionOwnerUid (API 29+) — something desktop
     * Wireshark has no equivalent of, since it isn't running on the device
     * whose traffic it's inspecting. Returns null on API < 29, for flows we
     * can't attribute (e.g. system/kernel traffic), or for our own traffic.
     */
    private fun resolveOwningApp(
        transportProtocol: Int,
        isOutgoing: Boolean,
        sourceIP: String,
        sourcePort: Int,
        destIP: String,
        destPort: Int
    ): String? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return null
        if (sourcePort <= 0 || destPort <= 0) return null

        val localPort = if (isOutgoing) sourcePort else destPort
        val cacheKey = "$transportProtocol:$localPort"
        owningAppCache[cacheKey]?.let { return it }
        if (owningAppCache.containsKey(cacheKey)) return null // cached "unresolved"
        if (owningAppCache.size > 1000) owningAppCache.clear()

        val resolved = try {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            if (cm == null) {
                null
            } else {
                val local = if (isOutgoing) InetSocketAddress(sourceIP, sourcePort) else InetSocketAddress(destIP, destPort)
                val remote = if (isOutgoing) InetSocketAddress(destIP, destPort) else InetSocketAddress(sourceIP, sourcePort)
                val uid = cm.getConnectionOwnerUid(transportProtocol, local, remote)
                val packageName = if (uid <= 0 || uid == Process.myUid()) {
                    null
                } else {
                    packageManager.getPackagesForUid(uid)?.firstOrNull()
                }
                if (packageName == null) {
                    null
                } else {
                    val appInfo = packageManager.getApplicationInfo(packageName, 0)
                    packageManager.getApplicationLabel(appInfo).toString()
                }
            }
        } catch (e: Exception) {
            null
        }

        owningAppCache[cacheKey] = resolved
        return resolved
    }

    private fun parseIpv4Packet(packet: ByteArray, isOutgoing: Boolean): Map<String, Any>? {
        if (packet.size < 20) return null

        val protocol = packet[9].toInt() and 0xFF
        val sourceIP = "${packet[12].toInt() and 0xFF}.${packet[13].toInt() and 0xFF}." +
                "${packet[14].toInt() and 0xFF}.${packet[15].toInt() and 0xFF}"
        val destIP = "${packet[16].toInt() and 0xFF}.${packet[17].toInt() and 0xFF}." +
                "${packet[18].toInt() and 0xFF}.${packet[19].toInt() and 0xFF}"

        val ihl = (packet[0].toInt() and 0x0F) * 4
        // Validate IHL - must be at least 20 and within packet bounds
        if (ihl < 20 || ihl > packet.size) {
            return null
        }
        val protocolName: String
        var sourcePort = 0
        var destPort = 0
        var tcpFlags = ""

        if (ihl + 4 <= packet.size) {
            when (protocol) {
                6 -> {
                    protocolName = "TCP"
                    sourcePort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
                    destPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
                    tcpFlags = extractTcpFlags(packet, ihl)
                }
                17 -> {
                    protocolName = "UDP"
                    sourcePort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
                    destPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
                }
                1 -> protocolName = "ICMP"
                else -> protocolName = "Other($protocol)"
            }
        } else {
            protocolName = when (protocol) {
                6 -> "TCP"
                17 -> "UDP"
                1 -> "ICMP"
                else -> "Other($protocol)"
            }
        }

        // Determine application name based on port
        val appName = getApplicationName(protocolName, if (isOutgoing) destPort else sourcePort)
        val owningApp = if (protocol == 6 || protocol == 17) {
            resolveOwningApp(protocol, isOutgoing, sourceIP, sourcePort, destIP, destPort)
        } else null

        return mapOf(
            "protocol" to protocolName,
            "sourceIp" to sourceIP,
            "destinationIp" to destIP,
            "sourcePort" to sourcePort,
            "destinationPort" to destPort,
            "size" to packet.size,
            "timestamp" to System.currentTimeMillis(),
            "payload" to "",
            "direction" to if (isOutgoing) "outgoing" else "incoming",
            "appName" to appName,
            "flags" to tcpFlags,
            "owningApp" to (owningApp ?: "")
        )
    }

    /**
     * TCP flags live in a single byte 13 bytes into the TCP header (RFC 9293 §3.1):
     * bit 0=FIN, 1=SYN, 2=RST, 3=PSH, 4=ACK, 5=URG (bits 6-7 are ECE/CWR, not used
     * by any detector here). Space-separated names, matching the format the
     * libpcap-mode capture path (jni/libpcap_capture.c) already produces, since
     * AnomalyDetector/RuleEngine's flags.contains("SYN")-style checks are shared
     * across both capture modes.
     *
     * Previously this field was never populated on the VPN-mode path at all —
     * SYN-flood and connection-flood detection silently never fired for anyone
     * using unrooted/VPN mode (the default, zero-setup mode), despite the
     * detectors themselves being fully implemented and README-advertised as
     * working. Only rooted libpcap-mode users ever got real SYN/connection-flood
     * detection.
     */
    private fun extractTcpFlags(packet: ByteArray, tcpHeaderStart: Int): String {
        val flagsOffset = tcpHeaderStart + 13
        if (flagsOffset >= packet.size) return ""
        val flagsByte = packet[flagsOffset].toInt() and 0xFF
        return buildString {
            if (flagsByte and 0x02 != 0) append("SYN ")
            if (flagsByte and 0x10 != 0) append("ACK ")
            if (flagsByte and 0x01 != 0) append("FIN ")
            if (flagsByte and 0x04 != 0) append("RST ")
            if (flagsByte and 0x08 != 0) append("PSH ")
            if (flagsByte and 0x20 != 0) append("URG ")
        }
    }

    /**
     * IPv6 fixed header is always exactly 40 bytes (RFC 8200 §3):
     * version/traffic-class/flow-label (4) | payload length (2) | next header (1)
     * | hop limit (1) | source (16) | destination (16).
     *
     * Extension headers (hop-by-hop, routing, fragment, etc.) aren't walked here —
     * "next header" is treated as the transport protocol directly, which covers the
     * overwhelming majority of real traffic (plain TCP/UDP/ICMPv6). Previously this
     * whole packet class returned null here, so it was tunneled correctly by zdtun
     * but completely invisible to DPI/anomaly detection/PCAP logging.
     */
    private fun parseIpv6Packet(packet: ByteArray, isOutgoing: Boolean): Map<String, Any>? {
        if (packet.size < 40) return null

        val nextHeader = packet[6].toInt() and 0xFF
        val sourceIP = formatIpv6Address(packet, 8)
        val destIP = formatIpv6Address(packet, 24)

        val protocolName: String
        var sourcePort = 0
        var destPort = 0
        var tcpFlags = ""

        if (40 + 4 <= packet.size) {
            when (nextHeader) {
                6 -> {
                    protocolName = "TCP"
                    sourcePort = ((packet[40].toInt() and 0xFF) shl 8) or (packet[41].toInt() and 0xFF)
                    destPort = ((packet[42].toInt() and 0xFF) shl 8) or (packet[43].toInt() and 0xFF)
                    tcpFlags = extractTcpFlags(packet, 40)
                }
                17 -> {
                    protocolName = "UDP"
                    sourcePort = ((packet[40].toInt() and 0xFF) shl 8) or (packet[41].toInt() and 0xFF)
                    destPort = ((packet[42].toInt() and 0xFF) shl 8) or (packet[43].toInt() and 0xFF)
                }
                58 -> protocolName = "ICMPv6"
                else -> protocolName = "Other($nextHeader)"
            }
        } else {
            protocolName = when (nextHeader) {
                6 -> "TCP"
                17 -> "UDP"
                58 -> "ICMPv6"
                else -> "Other($nextHeader)"
            }
        }

        val appName = getApplicationName(protocolName, if (isOutgoing) destPort else sourcePort)
        val owningApp = if (nextHeader == 6 || nextHeader == 17) {
            resolveOwningApp(nextHeader, isOutgoing, sourceIP, sourcePort, destIP, destPort)
        } else null

        return mapOf(
            "protocol" to protocolName,
            "sourceIp" to sourceIP,
            "destinationIp" to destIP,
            "sourcePort" to sourcePort,
            "destinationPort" to destPort,
            "size" to packet.size,
            "timestamp" to System.currentTimeMillis(),
            "payload" to "",
            "direction" to if (isOutgoing) "outgoing" else "incoming",
            "appName" to appName,
            "flags" to tcpFlags,
            "owningApp" to (owningApp ?: "")
        )
    }

    /** Formats 16 raw bytes starting at [offset] as a zero-compressed IPv6 address string. */
    private fun formatIpv6Address(packet: ByteArray, offset: Int): String {
        val groups = IntArray(8) { i ->
            ((packet[offset + i * 2].toInt() and 0xFF) shl 8) or (packet[offset + i * 2 + 1].toInt() and 0xFF)
        }

        // Find the longest run of consecutive zero groups (min length 2) to compress with "::".
        var bestStart = -1
        var bestLen = 0
        var curStart = -1
        var curLen = 0
        for (i in 0..8) {
            val isZero = i < 8 && groups[i] == 0
            if (isZero) {
                if (curStart == -1) curStart = i
                curLen++
            } else {
                if (curLen > bestLen) {
                    bestStart = curStart
                    bestLen = curLen
                }
                curStart = -1
                curLen = 0
            }
        }
        if (bestLen < 2) bestStart = -1 // no worthwhile run to compress

        val sb = StringBuilder()
        var i = 0
        while (i < 8) {
            if (i == bestStart) {
                sb.append("::")
                i += bestLen
                continue
            }
            if (sb.isNotEmpty() && !sb.endsWith(":")) sb.append(':')
            sb.append(Integer.toHexString(groups[i]))
            i++
        }
        return sb.toString()
    }

    private fun getApplicationName(protocol: String, port: Int): String {
        return when {
            // Web protocols
            protocol == "TCP" && port == 443 -> "HTTPS"
            protocol == "TCP" && port == 80 -> "HTTP"
            protocol == "TCP" && port == 8080 -> "HTTP-Proxy"
            protocol == "TCP" && port == 8443 -> "HTTPS-Alt"

            // DNS
            protocol == "UDP" && port == 53 -> "DNS"
            protocol == "TCP" && port == 53 -> "DNS"
            protocol == "TCP" && port == 853 -> "DNS-over-TLS"
            protocol == "UDP" && port == 853 -> "DNS-over-TLS"

            // QUIC/HTTP3
            protocol == "UDP" && port == 443 -> "QUIC/HTTP3"

            // Email
            protocol == "TCP" && port == 25 -> "SMTP"
            protocol == "TCP" && port == 587 -> "SMTP-Secure"
            protocol == "TCP" && port == 465 -> "SMTPS"
            protocol == "TCP" && port == 110 -> "POP3"
            protocol == "TCP" && port == 995 -> "POP3S"
            protocol == "TCP" && port == 143 -> "IMAP"
            protocol == "TCP" && port == 993 -> "IMAPS"

            // File transfer
            protocol == "TCP" && port == 21 -> "FTP"
            protocol == "TCP" && port == 22 -> "SSH/SFTP"
            protocol == "TCP" && port == 990 -> "FTPS"

            // Remote access
            protocol == "TCP" && port == 23 -> "Telnet"
            protocol == "TCP" && port == 3389 -> "RDP"
            protocol == "TCP" && port == 5900 -> "VNC"

            // Database
            protocol == "TCP" && port == 3306 -> "MySQL"
            protocol == "TCP" && port == 5432 -> "PostgreSQL"
            protocol == "TCP" && port == 27017 -> "MongoDB"
            protocol == "TCP" && port == 6379 -> "Redis"

            // Messaging & VoIP
            protocol == "TCP" && port == 5222 -> "XMPP"
            protocol == "TCP" && port == 5223 -> "XMPP-SSL"
            protocol == "UDP" && port == 5060 -> "SIP"
            protocol == "TCP" && port == 5060 -> "SIP"
            protocol == "UDP" && (port in 10000..20000) -> "RTP/Media"

            // Gaming & Streaming
            protocol == "TCP" && port == 1935 -> "RTMP"
            protocol == "UDP" && port == 1935 -> "RTMP"

            // Other common services
            protocol == "TCP" && port == 119 -> "NNTP"
            protocol == "TCP" && port == 194 -> "IRC"
            protocol == "UDP" && port == 123 -> "NTP"
            protocol == "TCP" && port == 179 -> "BGP"
            protocol == "UDP" && port == 161 -> "SNMP"
            protocol == "UDP" && port == 162 -> "SNMP-Trap"

            // Default
            else -> protocol
        }
    }

    private fun sendPacketToFlutter(packetInfo: Map<String, Any>, rawPacket: ByteArray? = null) {
        try {
            // Phase 2: Process packet through PacketAnalysisManager
            val enrichedPacket = try {
                PacketAnalysisManager.getInstance().processPacket(packetInfo, rawPacket)
            } catch (e: Exception) {
                Log.w(TAG, "PacketAnalysisManager not available: ${e.message}")
                packetInfo
            }

            // EventChannel.EventSink must be called from main thread
            instanceHandler.post {
                try {
                    packetSink?.success(enrichedPacket)
                    Log.d(TAG, "✅ Packet sent to Flutter UI")
                } catch (e: Exception) {
                    Log.e(TAG, "Error in EventSink: ${e.message}")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error posting to main thread: ${e.message}")
        }
    }

    override fun onRevoke() {
        Log.w(TAG, "VPN permission revoked by system")
        try {
            isRunning = false
            serviceScope.cancel()
            if (zdtunInitialized) {
                ZdtunVpn.nativeCleanup()
                zdtunInitialized = false
            }
            vpnInterface?.close()
            vpnInterface = null
            stopForeground(true)
        } catch (e: Exception) {
            Log.e(TAG, "Error during revoke cleanup: ${e.message}", e)
        }
        super.onRevoke()
    }

    // Commit 13 — app swiped from recents while service is running
    override fun onTaskRemoved(rootIntent: Intent?) {
        Log.i(TAG, "Task removed — finalizing PCAP before death")
        try {
            PacketAnalysisManager.getInstance().finalizePcap()
        } catch (e: Exception) {
            Log.e(TAG, "Error finalizing PCAP on task removal: ${e.message}")
        }
        super.onTaskRemoved(rootIntent)
    }

    override fun onDestroy() {
        Log.i(TAG, "Stopping ZdtunVpnService")
        isRunning = false

        // Stop PacketAnalysisManager (internally calls finalizePcap)
        try {
            PacketAnalysisManager.getInstance().stopAnalysis()
            Log.i(TAG, "PacketAnalysisManager stopped")
        } catch (e: Exception) {
            Log.e(TAG, "Error stopping PacketAnalysisManager: ${e.message}")
        }

        serviceScope.cancel()

        if (zdtunInitialized) {
            ZdtunVpn.nativeCleanup()
            zdtunInitialized = false
        }

        vpnInterface?.close()
        vpnInterface = null

        super.onDestroy()
        Log.i(TAG, "ZdtunVpnService stopped")
    }
}
