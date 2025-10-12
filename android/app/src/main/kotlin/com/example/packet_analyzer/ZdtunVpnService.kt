package com.example.packet_analyzer

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

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

    private fun startVpnService() {
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

        } catch (e: Exception) {
            Log.e(TAG, "Error starting VPN: ${e.message}", e)
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

                        // Enhanced logging for email and ICMP protocols
                        when (protocol) {
                            "SMTP", "IMAP", "IMAPS", "POP3", "POP3S", "ICMP" -> {
                                Log.i(TAG, "🔍 EMAIL/ICMP PACKET: $protocol " +
                                        "${packetInfo["sourceIp"]}:$sourcePort → " +
                                        "${packetInfo["destinationIp"]}:$destPort")
                            }
                            "TCP" -> {
                                // Check if TCP is on email ports
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

                // Enhanced logging for email and ICMP protocols
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
            if (packet.size < 20) return null

            val version = (packet[0].toInt() shr 4) and 0x0F
            if (version != 4) return null

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

            if (ihl + 4 <= packet.size) {
                when (protocol) {
                    6 -> {
                        protocolName = "TCP"
                        sourcePort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
                        destPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
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
                "appName" to appName
            )
        } catch (e: Exception) {
            Log.e(TAG, "Error parsing packet: ${e.message}")
            return null
        }
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
            Log.d(TAG, "🚀 sendPacketToFlutter called with: $packetInfo")
            Log.d(TAG, "🚀 packetSink is: ${if (packetSink == null) "NULL" else "NOT NULL"}")

            // Phase 2: Process packet through PacketAnalysisManager
            val enrichedPacket = try {
                val result = PacketAnalysisManager.getInstance().processPacket(packetInfo, rawPacket)

                // Debug: Check if domain fields were added
                if (result.containsKey("domain")) {
                    Log.d(TAG, "✅ Domain added: ${result["domain"]} (${result["domainFriendly"]})")
                } else {
                    Log.d(TAG, "⚠️ No domain for ${result["destinationAddress"]}")
                }

                result
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

    override fun onDestroy() {
        Log.i(TAG, "Stopping ZdtunVpnService")
        isRunning = false

        // Stop PacketAnalysisManager
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
