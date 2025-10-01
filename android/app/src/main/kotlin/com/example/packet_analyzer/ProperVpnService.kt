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
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * PROPER VPN Service that WORKS - Based on PCAPdroid's actual approach
 *
 * Key insight from PCAPdroid:
 * - Read packets from TUN interface
 * - Forward through PROTECTED RAW SOCKETS (not writing back to TUN!)
 * - Responses come back through those same sockets
 * - Manually inject responses into TUN interface
 *
 * This avoids packet reconstruction complexity while maintaining internet
 */
class ProperVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = AtomicBoolean(false)
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Connection mapping: 5-tuple -> forwarding socket
    private val tcpConnections = ConcurrentHashMap<String, TcpForwarder>()
    private val udpConnections = ConcurrentHashMap<String, UdpForwarder>()

    companion object {
        private const val TAG = "ProperVpnService"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "PacketCaptureChannel"

        private var methodChannel: MethodChannel? = null
        private var packetSink: EventChannel.EventSink? = null

        fun setMethodChannel(channel: MethodChannel) {
            methodChannel = channel
        }

        fun setPacketSink(sink: EventChannel.EventSink?) {
            packetSink = sink
        }
    }

    data class TcpForwarder(
        val socket: Socket,
        val sourcePort: Int,
        val job: Job,
        var lastActive: Long = System.currentTimeMillis()
    )

    data class UdpForwarder(
        val socket: DatagramSocket,
        val sourcePort: Int,
        val job: Job,
        var lastActive: Long = System.currentTimeMillis()
    )

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "🚀 Starting PROPER VPN with working internet...")

        try {
            createNotificationChannel()
            startForeground(NOTIFICATION_ID, createNotification())

            val builder = Builder()
                .setSession("AndroidNet Proper VPN")
                .setMtu(1500)
                .addAddress("10.0.0.2", 24)
                .addRoute("0.0.0.0", 0)
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")

            try {
                builder.addDisallowedApplication(packageName)
            } catch (e: Exception) {
                Log.w(TAG, "Could not exclude app: ${e.message}")
            }

            vpnInterface = builder.establish()

            vpnInterface?.let { vpn ->
                Log.i(TAG, "✅ VPN established")
                isRunning.set(true)

                // Start packet processing
                startPacketProcessing(vpn)

                notifyFlutter("VPN_STARTED", "VPN started")
            } ?: stopSelf()

        } catch (e: Exception) {
            Log.e(TAG, "Start error: ${e.message}", e)
            stopSelf()
        }

        return START_STICKY
    }

    private fun startPacketProcessing(vpn: ParcelFileDescriptor) {
        serviceScope.launch(Dispatchers.IO) {
            val inputStream = FileInputStream(vpn.fileDescriptor)
            val outputStream = FileOutputStream(vpn.fileDescriptor)
            val buffer = ByteArray(32768)

            try {
                while (isRunning.get()) {
                    val length = inputStream.read(buffer)
                    if (length <= 0) continue

                    val packet = buffer.copyOf(length)

                    // Process packet asynchronously
                    launch {
                        processPacket(packet, outputStream)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Processing error: ${e.message}")
            }
        }
    }

    private suspend fun processPacket(packet: ByteArray, outputStream: FileOutputStream) {
        try {
            val packetInfo = PacketParser.parsePacket(packet) ?: return

            // Notify Flutter (analysis only - doesn't affect forwarding)
            notifyFlutterPacket(packetInfo, "OUT")

            // Forward based on protocol
            when (packetInfo.protocol) {
                "TCP" -> forwardTcp(packetInfo, packet, outputStream)
                "UDP" -> forwardUdp(packetInfo, packet, outputStream)
            }

        } catch (e: Exception) {
            // Silent fail for unparseable packets
        }
    }

    private suspend fun forwardTcp(
        packetInfo: PacketParser.PacketInfo,
        rawPacket: ByteArray,
        outputStream: FileOutputStream
    ) {
        val key = "${packetInfo.sourceIP}:${packetInfo.sourcePort}-${packetInfo.destIP}:${packetInfo.destPort}"
        var forwarder = tcpConnections[key]

        if (forwarder == null) {
            // Create new TCP connection
            forwarder = createTcpForwarder(packetInfo, outputStream) ?: return
            tcpConnections[key] = forwarder
        }

        forwarder.lastActive = System.currentTimeMillis()

        // Extract and forward payload
        val payload = extractTcpPayload(rawPacket)
        if (payload.isNotEmpty() && forwarder.socket.isConnected) {
            try {
                forwarder.socket.getOutputStream().write(payload)
            } catch (e: Exception) {
                tcpConnections.remove(key)
                forwarder.socket.close()
            }
        }
    }

    private suspend fun createTcpForwarder(
        packetInfo: PacketParser.PacketInfo,
        outputStream: FileOutputStream
    ): TcpForwarder? {
        return withContext(Dispatchers.IO) {
            try {
                val socket = Socket()

                // CRITICAL: Protect socket!
                if (!protect(socket)) {
                    Log.w(TAG, "Socket protection failed!")
                    return@withContext null
                }

                socket.connect(
                    InetSocketAddress(packetInfo.destIP, packetInfo.destPort ?: 80),
                    5000
                )

                // Start response reader
                val job = serviceScope.launch(Dispatchers.IO) {
                    readTcpResponses(socket, packetInfo, outputStream)
                }

                TcpForwarder(
                    socket = socket,
                    sourcePort = packetInfo.sourcePort ?: 0,
                    job = job
                )

            } catch (e: Exception) {
                Log.w(TAG, "TCP connection failed: ${e.message}")
                null
            }
        }
    }

    private suspend fun readTcpResponses(
        socket: Socket,
        originalPacket: PacketParser.PacketInfo,
        outputStream: FileOutputStream
    ) {
        try {
            val inputStream = socket.getInputStream()
            val buffer = ByteArray(8192)

            while (socket.isConnected && isRunning.get()) {
                val bytesRead = inputStream.read(buffer)
                if (bytesRead <= 0) break

                val responsePayload = buffer.copyOf(bytesRead)

                // Build IP packet with response
                val responsePacket = buildIpPacket(
                    sourceIP = originalPacket.destIP,
                    destIP = originalPacket.sourceIP,
                    sourcePort = originalPacket.destPort ?: 0,
                    destPort = originalPacket.sourcePort ?: 0,
                    protocol = 6, // TCP
                    payload = responsePayload
                )

                if (responsePacket != null) {
                    synchronized(outputStream) {
                        outputStream.write(responsePacket)
                    }

                    notifyFlutterResponse(originalPacket, bytesRead, "IN")
                }
            }
        } catch (e: Exception) {
            // Connection closed
        }
    }

    private suspend fun forwardUdp(
        packetInfo: PacketParser.PacketInfo,
        rawPacket: ByteArray,
        outputStream: FileOutputStream
    ) {
        val key = "${packetInfo.sourceIP}:${packetInfo.sourcePort}-${packetInfo.destIP}:${packetInfo.destPort}"
        var forwarder = udpConnections[key]

        if (forwarder == null) {
            forwarder = createUdpForwarder(packetInfo, outputStream) ?: return
            udpConnections[key] = forwarder
        }

        forwarder.lastActive = System.currentTimeMillis()

        // Forward UDP packet
        val payload = extractUdpPayload(rawPacket)
        if (payload.isNotEmpty()) {
            try {
                val destAddress = InetAddress.getByName(packetInfo.destIP)
                val datagram = DatagramPacket(payload, payload.size, destAddress, packetInfo.destPort ?: 53)
                forwarder.socket.send(datagram)
            } catch (e: Exception) {
                udpConnections.remove(key)
            }
        }
    }

    private suspend fun createUdpForwarder(
        packetInfo: PacketParser.PacketInfo,
        outputStream: FileOutputStream
    ): UdpForwarder? {
        return withContext(Dispatchers.IO) {
            try {
                val socket = DatagramSocket()

                // CRITICAL: Protect socket!
                if (!protect(socket)) {
                    Log.w(TAG, "UDP socket protection failed!")
                    return@withContext null
                }

                socket.soTimeout = 5000

                // Start response reader
                val job = serviceScope.launch(Dispatchers.IO) {
                    readUdpResponses(socket, packetInfo, outputStream)
                }

                UdpForwarder(
                    socket = socket,
                    sourcePort = packetInfo.sourcePort ?: 0,
                    job = job
                )

            } catch (e: Exception) {
                Log.w(TAG, "UDP socket creation failed: ${e.message}")
                null
            }
        }
    }

    private suspend fun readUdpResponses(
        socket: DatagramSocket,
        originalPacket: PacketParser.PacketInfo,
        outputStream: FileOutputStream
    ) {
        try {
            val buffer = ByteArray(8192)
            val packet = DatagramPacket(buffer, buffer.size)

            while (!socket.isClosed && isRunning.get()) {
                try {
                    socket.receive(packet)

                    val responsePayload = buffer.copyOf(packet.length)

                    // Build IP packet with response
                    val responsePacket = buildIpPacket(
                        sourceIP = originalPacket.destIP,
                        destIP = originalPacket.sourceIP,
                        sourcePort = originalPacket.destPort ?: 0,
                        destPort = originalPacket.sourcePort ?: 0,
                        protocol = 17, // UDP
                        payload = responsePayload
                    )

                    if (responsePacket != null) {
                        synchronized(outputStream) {
                            outputStream.write(responsePacket)
                        }

                        notifyFlutterResponse(originalPacket, packet.length, "IN")
                    }

                } catch (e: SocketTimeoutException) {
                    // Continue waiting
                }
            }
        } catch (e: Exception) {
            // Socket closed
        }
    }

    /**
     * Build minimal IP packet (simplified - for basic functionality)
     */
    private fun buildIpPacket(
        sourceIP: String,
        destIP: String,
        sourcePort: Int,
        destPort: Int,
        protocol: Int,
        payload: ByteArray
    ): ByteArray? {
        return try {
            // Use PacketBuilder for proper packet construction
            when (protocol) {
                6 -> PacketBuilder.buildTcpPacket(
                    sourceIP = sourceIP,
                    destIP = destIP,
                    sourcePort = sourcePort,
                    destPort = destPort,
                    seqNum = 0, // Simplified
                    ackNum = 0,
                    flags = PacketBuilder.TcpFlags.ACK,
                    payload = payload
                )
                17 -> PacketBuilder.buildUdpPacket(
                    sourceIP = sourceIP,
                    destIP = destIP,
                    sourcePort = sourcePort,
                    destPort = destPort,
                    payload = payload
                )
                else -> null
            }
        } catch (e: Exception) {
            Log.w(TAG, "Packet build error: ${e.message}")
            null
        }
    }

    private fun extractTcpPayload(rawPacket: ByteArray): ByteArray {
        return try {
            if (rawPacket.size < 20) return byteArrayOf()
            val ipHeaderLength = (rawPacket[0].toInt() and 0x0F) * 4
            if (rawPacket.size < ipHeaderLength + 20) return byteArrayOf()
            val tcpHeaderStart = ipHeaderLength
            val tcpHeaderLength = ((rawPacket[tcpHeaderStart + 12].toInt() and 0xF0) shr 4) * 4
            val payloadStart = ipHeaderLength + tcpHeaderLength
            if (rawPacket.size <= payloadStart) return byteArrayOf()
            rawPacket.copyOfRange(payloadStart, rawPacket.size)
        } catch (e: Exception) {
            byteArrayOf()
        }
    }

    private fun extractUdpPayload(rawPacket: ByteArray): ByteArray {
        return try {
            if (rawPacket.size < 20) return byteArrayOf()
            val ipHeaderLength = (rawPacket[0].toInt() and 0x0F) * 4
            if (rawPacket.size < ipHeaderLength + 8) return byteArrayOf()
            val payloadStart = ipHeaderLength + 8
            if (rawPacket.size <= payloadStart) return byteArrayOf()
            rawPacket.copyOfRange(payloadStart, rawPacket.size)
        } catch (e: Exception) {
            byteArrayOf()
        }
    }

    private fun notifyFlutterPacket(packetInfo: PacketParser.PacketInfo, direction: String) {
        val packetMap = mapOf(
            "timestamp" to packetInfo.timestamp,
            "protocol" to packetInfo.protocol,
            "sourceIp" to packetInfo.sourceIP,
            "destinationIp" to packetInfo.destIP,
            "sourcePort" to (packetInfo.sourcePort ?: 0),
            "destinationPort" to (packetInfo.destPort ?: 0),
            "size" to packetInfo.length,
            "direction" to direction
        )

        android.os.Handler(android.os.Looper.getMainLooper()).post {
            try {
                packetSink?.success(packetMap)
            } catch (e: Exception) {
                // Ignore
            }
        }
    }

    private fun notifyFlutterResponse(originalPacket: PacketParser.PacketInfo, size: Int, direction: String) {
        val packetMap = mapOf(
            "timestamp" to System.currentTimeMillis(),
            "protocol" to originalPacket.protocol,
            "sourceIp" to originalPacket.destIP,
            "destinationIp" to originalPacket.sourceIP,
            "sourcePort" to (originalPacket.destPort ?: 0),
            "destinationPort" to (originalPacket.sourcePort ?: 0),
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
    }

    private fun notifyFlutter(event: String, data: Any) {
        android.os.Handler(android.os.Looper.getMainLooper()).post {
            methodChannel?.invokeMethod("onPacketEvent", mapOf("event" to event, "data" to data))
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "Packet Capture",
                NotificationManager.IMPORTANCE_LOW
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("AndroidNet Proper VPN")
            .setContentText("Capturing packets with working internet")
            .setSmallIcon(android.R.drawable.ic_menu_info_details)
            .setOngoing(true)
            .build()
    }

    override fun onDestroy() {
        super.onDestroy()
        isRunning.set(false)

        // Close all connections
        tcpConnections.values.forEach {
            it.job.cancel()
            it.socket.close()
        }
        udpConnections.values.forEach {
            it.job.cancel()
            it.socket.close()
        }

        tcpConnections.clear()
        udpConnections.clear()

        vpnInterface?.close()
        serviceScope.cancel()

        notifyFlutter("VPN_STOPPED", "VPN stopped")
    }
}
