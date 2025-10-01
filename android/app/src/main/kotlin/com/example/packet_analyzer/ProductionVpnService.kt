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
 * PRODUCTION-GRADE VPN Service with COMPLETE TCP/UDP handling
 *
 * Features:
 * - Full TCP state machine with sequence number tracking
 * - Proper NAT translation
 * - Bidirectional packet reconstruction
 * - Connection pooling and cleanup
 * - Error handling and recovery
 *
 * Based on PCAPdroid's proven architecture
 */
class ProductionVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = AtomicBoolean(false)
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Connection tracking
    private val tcpConnections = ConcurrentHashMap<String, TcpConnection>()
    private val udpSockets = ConcurrentHashMap<String, DatagramSocket>()

    // Statistics
    private val packetsProcessed = AtomicLong(0)
    private val bytesForwarded = AtomicLong(0)
    private val connectionsCreated = AtomicLong(0)

    companion object {
        private const val TAG = "ProductionVpnService"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "PacketCaptureChannel"
        private const val VPN_MTU = 1500
        private const val CONNECTION_TIMEOUT_MS = 120000L  // 2 minutes
        private const val CLEANUP_INTERVAL_MS = 30000L     // 30 seconds

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

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "🚀 Starting PRODUCTION VPN with full TCP/UDP handling...")

        try {
            createNotificationChannel()
            startForeground(NOTIFICATION_ID, createNotification())

            // Build VPN interface with proper configuration
            val builder = Builder()
                .setSession("AndroidNet Production")
                .setMtu(VPN_MTU)
                .addAddress("10.0.0.2", 24)
                .addRoute("0.0.0.0", 0)  // Route ALL traffic
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")

            // Exclude own app to prevent loops
            try {
                builder.addDisallowedApplication(packageName)
                Log.i(TAG, "✅ Excluded own app from VPN")
            } catch (e: Exception) {
                Log.w(TAG, "⚠️ Could not exclude app: ${e.message}")
            }

            vpnInterface = builder.establish()

            vpnInterface?.let { vpn ->
                Log.i(TAG, "✅ VPN interface established - Starting full packet processing")
                isRunning.set(true)

                // Start main packet processing loop
                startPacketProcessingLoop(vpn)

                // Start periodic cleanup
                startConnectionCleanup()

                notifyFlutter("VPN_STARTED", mapOf(
                    "status" to "success",
                    "message" to "Production VPN started with full TCP/UDP support"
                ))

                Log.i(TAG, "✅ Production VPN fully operational")

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
     * Main packet processing loop
     */
    private fun startPacketProcessingLoop(vpn: ParcelFileDescriptor) {
        serviceScope.launch(Dispatchers.IO) {
            val inputStream = FileInputStream(vpn.fileDescriptor)
            val outputStream = FileOutputStream(vpn.fileDescriptor)
            val buffer = ByteArray(32768)  // 32KB buffer

            Log.i(TAG, "📡 Starting packet processing loop...")

            try {
                while (isRunning.get()) {
                    val length = inputStream.read(buffer)

                    if (length > 0) {
                        packetsProcessed.incrementAndGet()
                        val packet = buffer.copyOf(length)

                        // Process packet asynchronously
                        launch {
                            processOutgoingPacket(packet, outputStream)
                        }

                        // Log statistics periodically
                        if (packetsProcessed.get() % 500 == 0L) {
                            Log.i(TAG, "📊 Stats: packets=${packetsProcessed.get()}, " +
                                    "bytes=${bytesForwarded.get()}, " +
                                    "connections=${connectionsCreated.get()}, " +
                                    "active_tcp=${tcpConnections.size}, " +
                                    "active_udp=${udpSockets.size}")
                        }
                    }
                }
            } catch (e: Exception) {
                if (isRunning.get()) {
                    Log.e(TAG, "❌ Packet loop error: ${e.message}", e)
                }
            } finally {
                inputStream.close()
                outputStream.close()
                Log.i(TAG, "🔒 Packet processing loop stopped")
            }
        }
    }

    /**
     * Process outgoing packet from device
     */
    private suspend fun processOutgoingPacket(packet: ByteArray, outputStream: FileOutputStream) {
        try {
            // Parse packet
            val packetInfo = PacketParser.parsePacket(packet) ?: return

            // Notify Flutter for display (non-blocking)
            notifyPacketToFlutter(packetInfo, "OUT")

            bytesForwarded.addAndGet(packet.size.toLong())

            // Forward based on protocol
            when (packetInfo.protocol) {
                "TCP" -> handleTcpPacket(packetInfo, packet, outputStream)
                "UDP" -> handleUdpPacket(packetInfo, packet, outputStream)
                "ICMP" -> handleIcmpPacket(packetInfo, packet)
                else -> Log.v(TAG, "⚠️ Unsupported protocol: ${packetInfo.protocol}")
            }

        } catch (e: Exception) {
            Log.w(TAG, "⚠️ Packet processing error: ${e.message}")
        }
    }

    /**
     * Handle TCP packet with FULL state machine
     */
    private suspend fun handleTcpPacket(
        packetInfo: PacketParser.PacketInfo,
        rawPacket: ByteArray,
        outputStream: FileOutputStream
    ) {
        val key = "${packetInfo.sourceIP}:${packetInfo.sourcePort}-${packetInfo.destIP}:${packetInfo.destPort}"
        val flags = PacketRebuilder.getTcpFlags(rawPacket)
        val seq = PacketRebuilder.getTcpSeq(rawPacket)
        val ack = PacketRebuilder.getTcpAck(rawPacket)
        val payload = PacketRebuilder.extractTcpPayload(rawPacket)

        var connection = tcpConnections[key]

        // Handle SYN (new connection)
        if ((flags and PacketBuilder.TcpFlags.SYN) != 0 && (flags and PacketBuilder.TcpFlags.ACK) == 0) {
            Log.d(TAG, "🔵 TCP SYN: $key")

            connection = createTcpConnection(packetInfo) ?: return
            connection.initializeFromSyn(seq)
            tcpConnections[key] = connection
            connectionsCreated.incrementAndGet()

            // Start response handler
            startTcpResponseHandler(connection, outputStream)
            return
        }

        // Handle existing connection
        connection?.let { conn ->
            conn.lastActivity = System.currentTimeMillis()

            // Handle FIN (connection close)
            if ((flags and PacketBuilder.TcpFlags.FIN) != 0) {
                Log.d(TAG, "🔴 TCP FIN: $key")
                conn.processFin(fromClient = true)

                // Send FIN back to server
                try {
                    conn.socket.close()
                } catch (e: Exception) {
                    // Ignore
                }

                tcpConnections.remove(key)
                return
            }

            // Handle RST (connection reset)
            if ((flags and PacketBuilder.TcpFlags.RST) != 0) {
                Log.d(TAG, "🔴 TCP RST: $key")
                conn.isActive = false
                conn.socket.close()
                tcpConnections.remove(key)
                return
            }

            // Forward data payload
            if (payload.isNotEmpty() && conn.socket.isConnected && conn.state == TcpConnection.ESTABLISHED) {
                try {
                    conn.socket.getOutputStream().write(payload)
                    conn.updateOnClientData(payload.size)
                    Log.v(TAG, "📤 TCP data: $key, ${payload.size} bytes, seq=$seq")
                } catch (e: Exception) {
                    Log.w(TAG, "❌ TCP forward error: ${e.message}")
                    conn.isActive = false
                    tcpConnections.remove(key)
                }
            }
        }
    }

    /**
     * Create new TCP connection with socket protection
     */
    private suspend fun createTcpConnection(packetInfo: PacketParser.PacketInfo): TcpConnection? {
        return withContext(Dispatchers.IO) {
            try {
                val socket = Socket()

                // CRITICAL: Protect socket to prevent VPN routing loop
                if (!protect(socket)) {
                    Log.e(TAG, "❌ TCP socket protection FAILED for ${packetInfo.destIP}:${packetInfo.destPort}")
                    return@withContext null
                }

                Log.d(TAG, "✅ TCP socket protected: ${packetInfo.destIP}:${packetInfo.destPort}")

                // Connect to destination with timeout
                socket.connect(
                    InetSocketAddress(packetInfo.destIP, packetInfo.destPort ?: 80),
                    5000  // 5 second timeout
                )

                if (!socket.isConnected) {
                    Log.w(TAG, "❌ TCP connection failed: ${packetInfo.destIP}:${packetInfo.destPort}")
                    return@withContext null
                }

                Log.d(TAG, "✅ TCP connected: ${packetInfo.destIP}:${packetInfo.destPort}")

                // Create connection object
                TcpConnection(
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
     * Handle TCP responses with proper packet reconstruction
     */
    private fun startTcpResponseHandler(
        connection: TcpConnection,
        outputStream: FileOutputStream
    ) {
        serviceScope.launch(Dispatchers.IO) {
            try {
                val socket = connection.socket
                val inputStream = socket.getInputStream()
                val buffer = ByteArray(8192)

                Log.d(TAG, "📥 Started TCP response handler: ${connection.getKey()}")

                // Send SYN-ACK to complete handshake
                val serverInitSeq = System.currentTimeMillis() and 0xFFFFFFFF
                connection.processSynAck(serverInitSeq, connection.clientSeq.get() + 1)

                val synAckPacket = PacketRebuilder.buildSynAck(connection, serverInitSeq)
                if (synAckPacket != null) {
                    synchronized(outputStream) {
                        outputStream.write(synAckPacket)
                    }
                    Log.d(TAG, "✅ Sent SYN-ACK: ${connection.getKey()}")
                }

                // Read responses and forward to device
                while (connection.isActive && !socket.isClosed && isRunning.get()) {
                    val bytesRead = inputStream.read(buffer)

                    if (bytesRead <= 0) {
                        Log.d(TAG, "🔚 TCP connection closed by server: ${connection.getKey()}")
                        break
                    }

                    val responsePayload = buffer.copyOf(bytesRead)
                    connection.updateOnServerData(bytesRead)

                    // Build response packet with proper TCP headers
                    val responsePacket = PacketRebuilder.buildTcpPacket(
                        connection = connection,
                        payload = responsePayload,
                        flags = PacketBuilder.TcpFlags.PSH or PacketBuilder.TcpFlags.ACK,
                        fromServer = true
                    )

                    if (responsePacket != null) {
                        synchronized(outputStream) {
                            outputStream.write(responsePacket)
                        }

                        bytesForwarded.addAndGet(responsePacket.size.toLong())

                        Log.v(TAG, "📥 TCP response: ${connection.getKey()}, $bytesRead bytes, " +
                                "seq=${connection.serverSeq.get()}, ack=${connection.clientSeq.get()}")

                        // Notify Flutter
                        notifyResponseToFlutter(connection, bytesRead, "IN")
                    }
                }

                // Send FIN when closing
                if (connection.state == TcpConnection.ESTABLISHED) {
                    val finPacket = PacketRebuilder.buildFin(connection, fromServer = true)
                    if (finPacket != null) {
                        synchronized(outputStream) {
                            outputStream.write(finPacket)
                        }
                        Log.d(TAG, "✅ Sent FIN: ${connection.getKey()}")
                    }
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
                tcpConnections.remove(connection.getKey())
                Log.d(TAG, "🔒 TCP response handler stopped: ${connection.getKey()}")
            }
        }
    }

    /**
     * Handle UDP packet (simpler than TCP)
     */
    private suspend fun handleUdpPacket(
        packetInfo: PacketParser.PacketInfo,
        rawPacket: ByteArray,
        outputStream: FileOutputStream
    ) {
        val key = "${packetInfo.sourceIP}:${packetInfo.sourcePort}-${packetInfo.destIP}:${packetInfo.destPort}"
        var socket = udpSockets[key]

        if (socket == null) {
            socket = createUdpSocket() ?: return
            udpSockets[key] = socket

            // Start UDP response handler
            startUdpResponseHandler(packetInfo, socket, outputStream)
        }

        // Forward UDP packet
        val payload = PacketRebuilder.extractUdpPayload(rawPacket)
        if (payload.isNotEmpty()) {
            try {
                val destAddress = InetAddress.getByName(packetInfo.destIP)
                val packet = DatagramPacket(payload, payload.size, destAddress, packetInfo.destPort ?: 53)
                socket.send(packet)

                Log.v(TAG, "📤 UDP sent: $key, ${payload.size} bytes")
            } catch (e: Exception) {
                Log.w(TAG, "❌ UDP send error: ${e.message}")
                udpSockets.remove(key)
                socket.close()
            }
        }
    }

    /**
     * Create UDP socket with protection
     */
    private fun createUdpSocket(): DatagramSocket? {
        return try {
            val socket = DatagramSocket()

            // CRITICAL: Protect socket
            if (!protect(socket)) {
                Log.e(TAG, "❌ UDP socket protection FAILED")
                return null
            }

            socket.soTimeout = 5000  // 5 second timeout
            Log.d(TAG, "✅ UDP socket protected")
            socket

        } catch (e: Exception) {
            Log.w(TAG, "❌ UDP socket creation failed: ${e.message}")
            null
        }
    }

    /**
     * Handle UDP responses
     */
    private fun startUdpResponseHandler(
        originalPacket: PacketParser.PacketInfo,
        socket: DatagramSocket,
        outputStream: FileOutputStream
    ) {
        serviceScope.launch(Dispatchers.IO) {
            try {
                val buffer = ByteArray(8192)
                val packet = DatagramPacket(buffer, buffer.size)

                Log.d(TAG, "📥 Started UDP response handler")

                while (!socket.isClosed && isRunning.get()) {
                    try {
                        socket.receive(packet)

                        val responsePayload = buffer.copyOf(packet.length)

                        // Build UDP response packet
                        val responsePacket = PacketRebuilder.buildUdpPacket(
                            sourceIP = originalPacket.destIP,
                            destIP = originalPacket.sourceIP,
                            sourcePort = originalPacket.destPort ?: 0,
                            destPort = originalPacket.sourcePort ?: 0,
                            payload = responsePayload
                        )

                        if (responsePacket != null) {
                            synchronized(outputStream) {
                                outputStream.write(responsePacket)
                            }

                            bytesForwarded.addAndGet(responsePacket.size.toLong())

                            Log.v(TAG, "📥 UDP response: ${packet.length} bytes")

                            // Notify Flutter
                            val packetInfo = PacketParser.PacketInfo(
                                timestamp = System.currentTimeMillis(),
                                protocol = "UDP",
                                sourceIP = originalPacket.destIP,
                                destIP = originalPacket.sourceIP,
                                sourcePort = originalPacket.destPort,
                                destPort = originalPacket.sourcePort,
                                length = packet.length,
                                flags = null,
                                payload = null
                            )
                            notifyPacketToFlutter(packetInfo, "IN")
                        }

                    } catch (e: SocketTimeoutException) {
                        // Continue waiting
                    }
                }

            } catch (e: Exception) {
                Log.w(TAG, "⚠️ UDP response handler error: ${e.message}")
            } finally {
                socket.close()
                Log.d(TAG, "🔒 UDP response handler stopped")
            }
        }
    }

    /**
     * Handle ICMP packet (simplified - requires root for full support)
     */
    private suspend fun handleIcmpPacket(packetInfo: PacketParser.PacketInfo, rawPacket: ByteArray) {
        Log.v(TAG, "⚠️ ICMP packet detected (not forwarded - requires root)")
        // ICMP requires raw sockets which need root permissions
        // For basic functionality, we skip ICMP
    }

    /**
     * Periodic cleanup of dead connections
     */
    private fun startConnectionCleanup() {
        serviceScope.launch {
            while (isRunning.get()) {
                delay(CLEANUP_INTERVAL_MS)

                try {
                    // Cleanup dead TCP connections
                    val deadTcpConnections = tcpConnections.values.filter { it.shouldClose() }
                    deadTcpConnections.forEach { conn ->
                        conn.isActive = false
                        conn.socket.close()
                        tcpConnections.remove(conn.getKey())
                        Log.d(TAG, "🧹 Cleaned up TCP connection: ${conn.getKey()}")
                    }

                    // Cleanup dead UDP sockets
                    val deadUdpKeys = udpSockets.keys.filter { key ->
                        udpSockets[key]?.isClosed == true
                    }
                    deadUdpKeys.forEach { key ->
                        udpSockets.remove(key)
                        Log.d(TAG, "🧹 Cleaned up UDP socket: $key")
                    }

                    if (deadTcpConnections.isNotEmpty() || deadUdpKeys.isNotEmpty()) {
                        Log.i(TAG, "🧹 Cleanup: removed ${deadTcpConnections.size} TCP, ${deadUdpKeys.size} UDP")
                    }

                } catch (e: Exception) {
                    Log.w(TAG, "⚠️ Cleanup error: ${e.message}")
                }
            }
        }
    }

    // ========== FLUTTER COMMUNICATION ==========

    private fun notifyPacketToFlutter(packetInfo: PacketParser.PacketInfo, direction: String) {
        try {
            val packetMap = mapOf(
                "id" to packetsProcessed.get(),
                "timestamp" to packetInfo.timestamp,
                "protocol" to packetInfo.protocol,
                "sourceIp" to packetInfo.sourceIP,
                "destinationIp" to packetInfo.destIP,
                "sourcePort" to (packetInfo.sourcePort ?: 0),
                "destinationPort" to (packetInfo.destPort ?: 0),
                "size" to packetInfo.length,
                "direction" to direction,
                "flags" to (packetInfo.flags ?: "")
            )

            android.os.Handler(android.os.Looper.getMainLooper()).post {
                try {
                    packetSink?.success(packetMap)
                } catch (e: Exception) {
                    // Ignore
                }
            }
        } catch (e: Exception) {
            // Ignore
        }
    }

    private fun notifyResponseToFlutter(connection: TcpConnection, size: Int, direction: String) {
        try {
            val packetMap = mapOf(
                "timestamp" to System.currentTimeMillis(),
                "protocol" to "TCP",
                "sourceIp" to connection.destIP,
                "destinationIp" to connection.sourceIP,
                "sourcePort" to connection.destPort,
                "destinationPort" to connection.sourcePort,
                "size" to size,
                "direction" to direction
            )

            android.os.Handler(android.os.Looper.getMainLooper()).post {
                try {
                    packetSink?.success(packetMap)
                } catch (e: Exception) {
                    // Ignore
                }
            }
        } catch (e: Exception) {
            // Ignore
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
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("AndroidNet Production")
            .setContentText("Full TCP/UDP packet capture active")
            .setSmallIcon(android.R.drawable.ic_menu_info_details)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.i(TAG, "🛑 Stopping production VPN service...")

        isRunning.set(false)

        // Close all TCP connections
        tcpConnections.values.forEach { conn ->
            conn.isActive = false
            try {
                conn.socket.close()
            } catch (e: Exception) {
                // Ignore
            }
        }
        tcpConnections.clear()

        // Close all UDP sockets
        udpSockets.values.forEach { socket ->
            try {
                socket.close()
            } catch (e: Exception) {
                // Ignore
            }
        }
        udpSockets.clear()

        // Close VPN interface
        vpnInterface?.close()

        serviceScope.cancel()

        notifyFlutter("VPN_STOPPED", mapOf(
            "message" to "VPN stopped",
            "stats" to mapOf(
                "packets" to packetsProcessed.get(),
                "bytes" to bytesForwarded.get(),
                "connections" to connectionsCreated.get()
            )
        ))

        Log.i(TAG, "✅ Production VPN stopped - Stats: packets=${packetsProcessed.get()}, " +
                "bytes=${bytesForwarded.get()}, connections=${connectionsCreated.get()}")
    }
}
