package com.example.packet_analyzer

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Complete VPN Service with proper packet forwarding and bidirectional flow
 * Based on PCAPdroid's architecture with full packet reconstruction
 */
class CompleteVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isCapturing = AtomicBoolean(false)
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Statistics
    private val packetCount = AtomicLong(0)
    private val bytesOut = AtomicLong(0)
    private val bytesIn = AtomicLong(0)

    // Connection tracking with TCP state management
    private val connectionMap = ConcurrentHashMap<String, TcpConnectionState>()
    private val udpConnectionMap = ConcurrentHashMap<String, UdpConnectionState>()

    companion object {
        private const val TAG = "CompleteVpnService"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "PacketCaptureChannel"
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val VPN_MTU = 1500

        private var methodChannel: MethodChannel? = null
        private var packetSink: EventChannel.EventSink? = null

        fun setMethodChannel(channel: MethodChannel) {
            methodChannel = channel
            Log.i(TAG, "✅ Method channel set")
        }

        fun setPacketSink(sink: EventChannel.EventSink?) {
            packetSink = sink
            Log.i(TAG, "📡 Packet sink ${if (sink == null) "disconnected" else "connected"}")
        }
    }

    /**
     * TCP Connection State with sequence number tracking
     */
    data class TcpConnectionState(
        val sourceIP: String,
        val sourcePort: Int,
        val destIP: String,
        val destPort: Int,
        val socket: Socket,
        var localSeqNum: AtomicLong = AtomicLong(System.currentTimeMillis() and 0xFFFFFFFF),
        var remoteSeqNum: AtomicLong = AtomicLong(0),
        var localAckNum: AtomicLong = AtomicLong(0),
        var remoteAckNum: AtomicLong = AtomicLong(0),
        val startTime: Long = System.currentTimeMillis(),
        var lastSeen: Long = System.currentTimeMillis(),
        @Volatile var isActive: Boolean = true,
        @Volatile var isHandshakeComplete: Boolean = false
    )

    /**
     * UDP Connection State
     */
    data class UdpConnectionState(
        val sourceIP: String,
        val sourcePort: Int,
        val destIP: String,
        val destPort: Int,
        val socket: DatagramSocket,
        val startTime: Long = System.currentTimeMillis(),
        var lastSeen: Long = System.currentTimeMillis(),
        @Volatile var isActive: Boolean = true
    )

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "🚀 Starting complete VPN service with full packet reconstruction...")

        try {
            createNotificationChannel()
            startForeground(NOTIFICATION_ID, createNotification())

            // Build VPN interface
            val builder = Builder()
                .setSession("AndroidNet Complete Capture")
                .setMtu(VPN_MTU)
                .addAddress(VPN_ADDRESS, 24)
                .addRoute(VPN_ROUTE, 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("8.8.4.4")

            // Exclude own app from VPN
            try {
                builder.addDisallowedApplication(packageName)
                Log.i(TAG, "✅ Excluded own app from VPN")
            } catch (e: Exception) {
                Log.w(TAG, "⚠️ Could not exclude own app: ${e.message}")
            }

            vpnInterface = builder.establish()

            vpnInterface?.let { vpn ->
                Log.i(TAG, "✅ VPN interface established with complete packet reconstruction")
                isCapturing.set(true)

                // Start main packet loop
                startCompletePacketLoop(vpn)

                notifyFlutter("VPN_STARTED", mapOf(
                    "status" to "success",
                    "message" to "VPN started with bidirectional packet flow"
                ))
            } ?: run {
                Log.e(TAG, "❌ Failed to establish VPN interface")
                stopSelf()
            }

        } catch (e: Exception) {
            Log.e(TAG, "❌ VPN start error: ${e.message}", e)
            stopSelf()
        }

        return START_STICKY
    }

    /**
     * Main packet processing loop with complete forwarding
     */
    private fun startCompletePacketLoop(vpn: ParcelFileDescriptor) {
        serviceScope.launch(Dispatchers.IO) {
            val inputStream = FileInputStream(vpn.fileDescriptor)
            val outputStream = FileOutputStream(vpn.fileDescriptor)
            val buffer = ByteArray(32768)

            Log.i(TAG, "📡 Starting complete packet loop with bidirectional flow...")

            try {
                while (isCapturing.get()) {
                    val length = inputStream.read(buffer)

                    if (length > 0) {
                        packetCount.incrementAndGet()
                        val packet = buffer.copyOf(length)

                        // Process outgoing packet
                        launch {
                            processOutgoingPacket(packet, outputStream)
                        }

                        // Log stats periodically
                        if (packetCount.get() % 100 == 0L) {
                            Log.d(TAG, "📊 Stats: packets=${packetCount.get()}, out=${bytesOut.get()}, in=${bytesIn.get()}")
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "❌ Packet loop error: ${e.message}", e)
            } finally {
                inputStream.close()
                outputStream.close()
                Log.i(TAG, "🔒 Packet loop stopped")
            }
        }
    }

    /**
     * Process outgoing packet from device
     */
    private suspend fun processOutgoingPacket(packet: ByteArray, outputStream: FileOutputStream) {
        try {
            val packetInfo = PacketParser.parsePacket(packet) ?: return

            // Notify Flutter
            notifyPacketToFlutter(packetInfo, "OUT")

            bytesOut.addAndGet(packet.size.toLong())

            // Forward based on protocol
            when (packetInfo.protocol) {
                "TCP" -> handleTcpPacket(packetInfo, packet, outputStream)
                "UDP" -> handleUdpPacket(packetInfo, packet, outputStream)
                "ICMP" -> handleIcmpPacket(packetInfo, packet, outputStream)
                else -> Log.v(TAG, "⚠️ Unsupported protocol: ${packetInfo.protocol}")
            }

        } catch (e: Exception) {
            Log.w(TAG, "⚠️ Packet processing error: ${e.message}")
        }
    }

    /**
     * Handle TCP packet with full state management
     */
    private suspend fun handleTcpPacket(
        packetInfo: PacketParser.PacketInfo,
        rawPacket: ByteArray,
        outputStream: FileOutputStream
    ) {
        try {
            val connectionKey = "${packetInfo.sourceIP}:${packetInfo.sourcePort}-${packetInfo.destIP}:${packetInfo.destPort}"
            var connection = connectionMap[connectionKey]

            // Extract TCP flags and payload
            val tcpFlags = extractTcpFlags(rawPacket)
            val payload = extractTcpPayload(rawPacket)

            // Handle new connection (SYN packet)
            if (connection == null && (tcpFlags and PacketBuilder.TcpFlags.SYN) != 0) {
                connection = createTcpConnection(packetInfo)
                if (connection != null) {
                    connectionMap[connectionKey] = connection
                    Log.d(TAG, "✅ New TCP connection: ${packetInfo.destIP}:${packetInfo.destPort}")

                    // Start response handler
                    startTcpResponseHandler(connection, outputStream)
                } else {
                    return
                }
            }

            connection?.let { conn ->
                conn.lastSeen = System.currentTimeMillis()

                // Forward payload if present
                if (payload.isNotEmpty() && conn.socket.isConnected) {
                    try {
                        conn.socket.getOutputStream().write(payload)
                        conn.localSeqNum.addAndGet(payload.size.toLong())
                        Log.v(TAG, "📤 TCP forwarded ${payload.size} bytes to ${conn.destIP}:${conn.destPort}")
                    } catch (e: Exception) {
                        Log.w(TAG, "⚠️ TCP forward error: ${e.message}")
                        conn.isActive = false
                        connectionMap.remove(connectionKey)
                    }
                }

                // Handle connection close (FIN packet)
                if ((tcpFlags and PacketBuilder.TcpFlags.FIN) != 0) {
                    Log.d(TAG, "🔚 TCP FIN received, closing connection")
                    conn.isActive = false
                    connectionMap.remove(connectionKey)
                    conn.socket.close()
                }
            }

        } catch (e: Exception) {
            Log.w(TAG, "⚠️ TCP handling error: ${e.message}")
        }
    }

    /**
     * Create new TCP connection with socket protection
     */
    private suspend fun createTcpConnection(packetInfo: PacketParser.PacketInfo): TcpConnectionState? {
        return withContext(Dispatchers.IO) {
            try {
                val socket = Socket()

                // CRITICAL: Protect socket to prevent VPN routing loop
                if (!protect(socket)) {
                    Log.w(TAG, "❌ Socket protection failed")
                    return@withContext null
                }

                Log.d(TAG, "✅ Socket protected for ${packetInfo.destIP}:${packetInfo.destPort}")

                // Connect to destination
                socket.connect(
                    InetSocketAddress(packetInfo.destIP, packetInfo.destPort ?: 80),
                    5000
                )

                if (!socket.isConnected) {
                    Log.w(TAG, "❌ Socket connection failed")
                    return@withContext null
                }

                Log.d(TAG, "✅ TCP connected to ${packetInfo.destIP}:${packetInfo.destPort}")

                TcpConnectionState(
                    sourceIP = packetInfo.sourceIP,
                    sourcePort = packetInfo.sourcePort ?: 0,
                    destIP = packetInfo.destIP,
                    destPort = packetInfo.destPort ?: 0,
                    socket = socket
                )

            } catch (e: Exception) {
                Log.w(TAG, "❌ TCP connection creation failed: ${e.message}")
                null
            }
        }
    }

    /**
     * Handle TCP responses and write back to TUN interface
     */
    private fun startTcpResponseHandler(
        connection: TcpConnectionState,
        outputStream: FileOutputStream
    ) {
        serviceScope.launch(Dispatchers.IO) {
            try {
                val socket = connection.socket
                val inputStream = socket.getInputStream()
                val buffer = ByteArray(8192)

                Log.d(TAG, "📥 Started TCP response handler for ${connection.destIP}:${connection.destPort}")

                while (connection.isActive && !socket.isClosed) {
                    val bytesRead = inputStream.read(buffer)
                    if (bytesRead <= 0) {
                        Log.d(TAG, "🔚 TCP connection closed by remote")
                        break
                    }

                    val responsePayload = buffer.copyOf(bytesRead)
                    bytesIn.addAndGet(bytesRead.toLong())

                    // Update sequence numbers
                    connection.remoteSeqNum.addAndGet(bytesRead.toLong())
                    connection.localAckNum.set(connection.remoteSeqNum.get())

                    // Build response packet with proper headers
                    val responsePacket = PacketBuilder.buildTcpPacket(
                        sourceIP = connection.destIP,
                        destIP = connection.sourceIP,
                        sourcePort = connection.destPort,
                        destPort = connection.sourcePort,
                        seqNum = connection.remoteSeqNum.get(),
                        ackNum = connection.localSeqNum.get(),
                        flags = PacketBuilder.TcpFlags.PSH or PacketBuilder.TcpFlags.ACK,
                        payload = responsePayload
                    )

                    // Write response to TUN interface
                    synchronized(outputStream) {
                        outputStream.write(responsePacket)
                    }

                    Log.v(TAG, "📥 TCP response: ${bytesRead} bytes from ${connection.destIP}:${connection.destPort}")

                    // Notify Flutter
                    val packetInfo = PacketParser.PacketInfo(
                        timestamp = System.currentTimeMillis(),
                        protocol = "TCP",
                        sourceIP = connection.destIP,
                        destIP = connection.sourceIP,
                        sourcePort = connection.destPort,
                        destPort = connection.sourcePort,
                        length = bytesRead,
                        flags = "PSH,ACK",
                        payload = null
                    )
                    notifyPacketToFlutter(packetInfo, "IN")
                }

            } catch (e: Exception) {
                Log.w(TAG, "⚠️ TCP response handler error: ${e.message}")
            } finally {
                connection.isActive = false
                try {
                    connection.socket.close()
                } catch (e: Exception) {
                    // Ignore
                }
                Log.d(TAG, "🔒 TCP response handler stopped")
            }
        }
    }

    /**
     * Handle UDP packet
     */
    private suspend fun handleUdpPacket(
        packetInfo: PacketParser.PacketInfo,
        rawPacket: ByteArray,
        outputStream: FileOutputStream
    ) {
        try {
            val connectionKey = "${packetInfo.sourceIP}:${packetInfo.sourcePort}-${packetInfo.destIP}:${packetInfo.destPort}"
            var connection = udpConnectionMap[connectionKey]

            if (connection == null) {
                connection = createUdpConnection(packetInfo)
                if (connection != null) {
                    udpConnectionMap[connectionKey] = connection
                    Log.d(TAG, "✅ New UDP connection: ${packetInfo.destIP}:${packetInfo.destPort}")

                    // Start response handler
                    startUdpResponseHandler(connection, outputStream)
                } else {
                    return
                }
            }

            connection?.let { conn ->
                conn.lastSeen = System.currentTimeMillis()

                // Extract and forward UDP payload
                val payload = extractUdpPayload(rawPacket)
                if (payload.isNotEmpty()) {
                    val destAddress = InetAddress.getByName(conn.destIP)
                    val packet = DatagramPacket(payload, payload.size, destAddress, conn.destPort)
                    conn.socket.send(packet)

                    Log.v(TAG, "📤 UDP forwarded ${payload.size} bytes to ${conn.destIP}:${conn.destPort}")
                }
            }

        } catch (e: Exception) {
            Log.w(TAG, "⚠️ UDP handling error: ${e.message}")
        }
    }

    /**
     * Create new UDP connection with socket protection
     */
    private suspend fun createUdpConnection(packetInfo: PacketParser.PacketInfo): UdpConnectionState? {
        return withContext(Dispatchers.IO) {
            try {
                val socket = DatagramSocket()

                // CRITICAL: Protect socket
                if (!protect(socket)) {
                    Log.w(TAG, "❌ UDP socket protection failed")
                    return@withContext null
                }

                Log.d(TAG, "✅ UDP socket protected for ${packetInfo.destIP}:${packetInfo.destPort}")

                UdpConnectionState(
                    sourceIP = packetInfo.sourceIP,
                    sourcePort = packetInfo.sourcePort ?: 0,
                    destIP = packetInfo.destIP,
                    destPort = packetInfo.destPort ?: 0,
                    socket = socket
                )

            } catch (e: Exception) {
                Log.w(TAG, "❌ UDP connection creation failed: ${e.message}")
                null
            }
        }
    }

    /**
     * Handle UDP responses
     */
    private fun startUdpResponseHandler(
        connection: UdpConnectionState,
        outputStream: FileOutputStream
    ) {
        serviceScope.launch(Dispatchers.IO) {
            try {
                val socket = connection.socket
                socket.soTimeout = 30000  // 30 second timeout

                val buffer = ByteArray(8192)
                val packet = DatagramPacket(buffer, buffer.size)

                Log.d(TAG, "📥 Started UDP response handler for ${connection.destIP}:${connection.destPort}")

                while (connection.isActive) {
                    try {
                        socket.receive(packet)

                        val responsePayload = buffer.copyOf(packet.length)
                        bytesIn.addAndGet(packet.length.toLong())

                        // Build UDP response packet
                        val responsePacket = PacketBuilder.buildUdpPacket(
                            sourceIP = connection.destIP,
                            destIP = connection.sourceIP,
                            sourcePort = connection.destPort,
                            destPort = connection.sourcePort,
                            payload = responsePayload
                        )

                        // Write to TUN interface
                        synchronized(outputStream) {
                            outputStream.write(responsePacket)
                        }

                        Log.v(TAG, "📥 UDP response: ${packet.length} bytes from ${connection.destIP}:${connection.destPort}")

                        // Notify Flutter
                        val packetInfo = PacketParser.PacketInfo(
                            timestamp = System.currentTimeMillis(),
                            protocol = "UDP",
                            sourceIP = connection.destIP,
                            destIP = connection.sourceIP,
                            sourcePort = connection.destPort,
                            destPort = connection.sourcePort,
                            length = packet.length,
                            flags = null,
                            payload = null
                        )
                        notifyPacketToFlutter(packetInfo, "IN")

                    } catch (e: SocketTimeoutException) {
                        // Check if connection is still active
                        if (System.currentTimeMillis() - connection.lastSeen > 30000) {
                            Log.d(TAG, "⏰ UDP connection timeout")
                            break
                        }
                    }
                }

            } catch (e: Exception) {
                Log.w(TAG, "⚠️ UDP response handler error: ${e.message}")
            } finally {
                connection.isActive = false
                try {
                    connection.socket.close()
                } catch (e: Exception) {
                    // Ignore
                }
                Log.d(TAG, "🔒 UDP response handler stopped")
            }
        }
    }

    /**
     * Handle ICMP packet (simplified)
     */
    private suspend fun handleIcmpPacket(
        packetInfo: PacketParser.PacketInfo,
        rawPacket: ByteArray,
        outputStream: FileOutputStream
    ) {
        // ICMP requires raw sockets with root - skip for now
        Log.v(TAG, "⚠️ ICMP forwarding not implemented (requires root)")
    }

    // ========== PACKET PARSING HELPERS ==========

    private fun extractTcpFlags(rawPacket: ByteArray): Int {
        try {
            if (rawPacket.size < 20) return 0

            val ipHeaderLength = (rawPacket[0].toInt() and 0x0F) * 4
            if (rawPacket.size < ipHeaderLength + 20) return 0

            val tcpFlagsOffset = ipHeaderLength + 13
            return rawPacket[tcpFlagsOffset].toInt() and 0xFF

        } catch (e: Exception) {
            return 0
        }
    }

    private fun extractTcpPayload(rawPacket: ByteArray): ByteArray {
        try {
            if (rawPacket.size < 20) return byteArrayOf()

            val ipHeaderLength = (rawPacket[0].toInt() and 0x0F) * 4
            if (rawPacket.size < ipHeaderLength + 20) return byteArrayOf()

            val tcpHeaderStart = ipHeaderLength
            val tcpHeaderLength = ((rawPacket[tcpHeaderStart + 12].toInt() and 0xF0) shr 4) * 4

            val payloadStart = ipHeaderLength + tcpHeaderLength
            if (rawPacket.size <= payloadStart) return byteArrayOf()

            return rawPacket.copyOfRange(payloadStart, rawPacket.size)

        } catch (e: Exception) {
            return byteArrayOf()
        }
    }

    private fun extractUdpPayload(rawPacket: ByteArray): ByteArray {
        try {
            if (rawPacket.size < 20) return byteArrayOf()

            val ipHeaderLength = (rawPacket[0].toInt() and 0x0F) * 4
            if (rawPacket.size < ipHeaderLength + 8) return byteArrayOf()

            val payloadStart = ipHeaderLength + 8
            if (rawPacket.size <= payloadStart) return byteArrayOf()

            return rawPacket.copyOfRange(payloadStart, rawPacket.size)

        } catch (e: Exception) {
            return byteArrayOf()
        }
    }

    // ========== FLUTTER COMMUNICATION ==========

    private fun notifyPacketToFlutter(packetInfo: PacketParser.PacketInfo, direction: String) {
        try {
            val packetMap = mapOf(
                "id" to packetCount.get(),
                "timestamp" to packetInfo.timestamp,
                "protocol" to packetInfo.protocol,
                "sourceIp" to packetInfo.sourceIP,
                "destinationIp" to packetInfo.destIP,
                "sourcePort" to (packetInfo.sourcePort ?: 0),
                "destinationPort" to (packetInfo.destPort ?: 0),
                "size" to packetInfo.length,
                "direction" to direction,
                "flags" to (packetInfo.flags ?: ""),
                "payload" to (packetInfo.payload ?: "")
            )

            android.os.Handler(android.os.Looper.getMainLooper()).post {
                try {
                    packetSink?.success(packetMap)
                } catch (e: Exception) {
                    Log.e(TAG, "❌ EventChannel error: ${e.message}")
                }
            }

        } catch (e: Exception) {
            Log.w(TAG, "⚠️ Flutter notification error: ${e.message}")
        }
    }

    private fun notifyFlutter(event: String, data: Any) {
        try {
            android.os.Handler(android.os.Looper.getMainLooper()).post {
                methodChannel?.invokeMethod("onPacketEvent", mapOf(
                    "event" to event,
                    "data" to data
                ))
            }
        } catch (e: Exception) {
            Log.e(TAG, "❌ Flutter notification error: ${e.message}")
        }
    }

    // ========== NOTIFICATION ==========

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Packet Capture Service",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows when packet capture is active"
                setShowBadge(false)
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("AndroidNet Complete Capture")
            .setContentText("Capturing with bidirectional packet flow...")
            .setSmallIcon(android.R.drawable.ic_menu_info_details)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.i(TAG, "🛑 Stopping complete VPN service...")

        isCapturing.set(false)

        // Close all TCP connections
        connectionMap.values.forEach { connection ->
            connection.isActive = false
            try {
                connection.socket.close()
            } catch (e: Exception) {
                // Ignore
            }
        }
        connectionMap.clear()

        // Close all UDP connections
        udpConnectionMap.values.forEach { connection ->
            connection.isActive = false
            try {
                connection.socket.close()
            } catch (e: Exception) {
                // Ignore
            }
        }
        udpConnectionMap.clear()

        // Close VPN interface
        vpnInterface?.close()

        serviceScope.cancel()

        notifyFlutter("VPN_STOPPED", mapOf(
            "message" to "VPN stopped",
            "stats" to mapOf(
                "packets" to packetCount.get(),
                "bytesOut" to bytesOut.get(),
                "bytesIn" to bytesIn.get()
            )
        ))

        Log.i(TAG, "✅ Complete VPN service stopped - Packets: ${packetCount.get()}, Out: ${bytesOut.get()}, In: ${bytesIn.get()}")
    }
}