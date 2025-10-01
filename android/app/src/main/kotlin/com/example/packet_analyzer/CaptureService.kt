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
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class CaptureService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isCapturing = AtomicBoolean(false)
    private var captureJob: Job? = null
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Statistics
    private val packetsReceived = AtomicLong(0)
    private val bytesReceived = AtomicLong(0)
    private val connectionCount = AtomicLong(0)

    // Connection tracking
    private val connections = mutableMapOf<String, ConnectionInfo>()

    companion object {
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "PacketCaptureChannel"
        private var methodChannel: MethodChannel? = null

        fun setMethodChannel(channel: MethodChannel) {
            methodChannel = channel
        }
    }

    data class ConnectionInfo(
        val sourceIP: String,
        val destIP: String,
        val sourcePort: Int,
        val destPort: Int,
        val protocol: String,
        val startTime: Long,
        var lastSeen: Long,
        var bytesOut: Long = 0,
        var bytesIn: Long = 0,
        var packetsOut: Long = 0,
        var packetsIn: Long = 0
    )

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i("CaptureService", "🚀 Starting capture service...")

        when (intent?.action) {
            "START_CAPTURE" -> startCapture()
            "STOP_CAPTURE" -> stopCapture()
            else -> startCapture()
        }

        return START_STICKY
    }

    private fun startCapture() {
        if (isCapturing.get()) {
            Log.w("CaptureService", "Capture already running")
            return
        }

        try {
            createNotificationChannel()
            startForeground(NOTIFICATION_ID, createNotification())

            // Configure VPN with PCAPdroid-like settings
            val builder = Builder()
            builder.setSession("AndroidNet Packet Capture")
            builder.setMtu(1500)

            // Add local network range
            builder.addAddress("10.8.0.1", 32)

            // Route all traffic through VPN
            builder.addRoute("0.0.0.0", 0)

            // Add DNS servers
            builder.addDnsServer("8.8.8.8")
            builder.addDnsServer("8.8.4.4")

            // Block IPv6 to simplify packet handling
            builder.addRoute("::", 0)

            vpnInterface = builder.establish()

            if (vpnInterface != null) {
                Log.i("CaptureService", "✅ VPN interface established")
                isCapturing.set(true)
                startPacketLoop()
                notifyFlutter("CAPTURE_STARTED", mapOf(
                    "status" to "success",
                    "message" to "Packet capture started"
                ))
            } else {
                Log.e("CaptureService", "❌ Failed to establish VPN interface")
                stopSelf()
            }

        } catch (e: Exception) {
            Log.e("CaptureService", "Failed to start capture: ${e.message}", e)
            notifyFlutter("CAPTURE_ERROR", mapOf(
                "error" to e.message
            ))
            stopSelf()
        }
    }

    private fun startPacketLoop() {
        captureJob = serviceScope.launch {
            val vpn = vpnInterface ?: return@launch

            val inputStream = FileInputStream(vpn.fileDescriptor)
            val outputStream = FileOutputStream(vpn.fileDescriptor)

            // Use larger buffer for better performance
            val packet = ByteArray(32768)

            Log.i("CaptureService", "📡 Starting packet capture loop...")

            try {
                while (isCapturing.get() && !Thread.currentThread().isInterrupted) {
                    val length = inputStream.read(packet)

                    if (length > 0) {
                        // Update statistics
                        packetsReceived.incrementAndGet()
                        bytesReceived.addAndGet(length.toLong())

                        // Process packet in separate coroutine to avoid blocking
                        launch {
                            processPacket(packet.copyOf(length))
                        }

                        // Forward packet (implement NAT later)
                        forwardPacket(packet, length, outputStream)

                        // Send statistics update every 100 packets
                        if (packetsReceived.get() % 100 == 0L) {
                            sendStatisticsUpdate()
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e("CaptureService", "Packet loop error: ${e.message}", e)
                if (isCapturing.get()) {
                    notifyFlutter("CAPTURE_ERROR", mapOf(
                        "error" to "Packet capture failed: ${e.message}"
                    ))
                }
            }

            Log.i("CaptureService", "📡 Packet capture loop stopped")
        }
    }

    private suspend fun processPacket(packet: ByteArray) {
        try {
            val packetInfo = PacketParser.parsePacket(packet)
            if (packetInfo != null) {

                // Track connection
                val connectionKey = "${packetInfo.sourceIP}:${packetInfo.sourcePort}-${packetInfo.destIP}:${packetInfo.destPort}"
                val connection = connections.getOrPut(connectionKey) {
                    connectionCount.incrementAndGet()
                    ConnectionInfo(
                        sourceIP = packetInfo.sourceIP,
                        destIP = packetInfo.destIP,
                        sourcePort = packetInfo.sourcePort ?: 0,
                        destPort = packetInfo.destPort ?: 0,
                        protocol = packetInfo.protocol,
                        startTime = System.currentTimeMillis(),
                        lastSeen = System.currentTimeMillis()
                    )
                }

                // Update connection stats
                connection.lastSeen = System.currentTimeMillis()
                connection.packetsOut++
                connection.bytesOut += packetInfo.length

                // Convert to map for Flutter
                val packetData = mapOf(
                    "id" to packetsReceived.get(),
                    "timestamp" to packetInfo.timestamp,
                    "protocol" to packetInfo.protocol,
                    "sourceIP" to packetInfo.sourceIP,
                    "destIP" to packetInfo.destIP,
                    "sourcePort" to (packetInfo.sourcePort ?: 0),
                    "destPort" to (packetInfo.destPort ?: 0),
                    "length" to packetInfo.length,
                    "flags" to (packetInfo.flags ?: ""),
                    "payload" to (packetInfo.payload ?: ""),
                    "direction" to "OUT"
                )

                // Send to Flutter (throttle to prevent UI overload)
                if (packetsReceived.get() % 10 == 0L || packetInfo.protocol != "TCP") {
                    notifyFlutter("PACKET_CAPTURED", packetData)
                }
            }
        } catch (e: Exception) {
            Log.e("CaptureService", "Error processing packet: ${e.message}")
        }
    }

    private fun forwardPacket(packet: ByteArray, length: Int, outputStream: FileOutputStream) {
        try {
            // Simple forwarding - in real implementation, implement proper NAT
            // For now, just drop packets to avoid routing loops
            // outputStream.write(packet, 0, length)
        } catch (e: Exception) {
            Log.e("CaptureService", "Error forwarding packet: ${e.message}")
        }
    }

    private fun sendStatisticsUpdate() {
        val stats = mapOf(
            "packetsReceived" to packetsReceived.get(),
            "bytesReceived" to bytesReceived.get(),
            "connections" to connectionCount.get(),
            "uptime" to System.currentTimeMillis()
        )

        notifyFlutter("STATISTICS_UPDATE", stats)
    }

    private fun stopCapture() {
        Log.i("CaptureService", "🛑 Stopping capture service...")

        isCapturing.set(false)
        captureJob?.cancel()

        try {
            vpnInterface?.close()
            vpnInterface = null

            // Clear connections
            connections.clear()

            // Reset statistics
            packetsReceived.set(0)
            bytesReceived.set(0)
            connectionCount.set(0)

            notifyFlutter("CAPTURE_STOPPED", mapOf(
                "status" to "success",
                "message" to "Packet capture stopped"
            ))

            Log.i("CaptureService", "✅ Capture service stopped cleanly")

        } catch (e: Exception) {
            Log.e("CaptureService", "Error stopping capture: ${e.message}", e)
        }

        stopForeground(true)
        stopSelf()
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
            Log.e("CaptureService", "Flutter notification error: ${e.message}")
        }
    }

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
            .setContentTitle("AndroidNet Packet Capture")
            .setContentText("Capturing network packets...")
            .setSmallIcon(android.R.drawable.ic_menu_info_details)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    override fun onDestroy() {
        super.onDestroy()
        stopCapture()
        serviceScope.cancel()
    }
}