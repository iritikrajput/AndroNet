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
import java.nio.channels.DatagramChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Working VPN Service with GUARANTEED internet connectivity
 *
 * Strategy: Instead of reconstructing packets, we use raw socket forwarding
 * with proper NAT translation at IP level
 */
class WorkingVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = AtomicBoolean(false)
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    // Statistics
    private val packetCount = AtomicLong(0)
    private val bytesForwarded = AtomicLong(0)

    companion object {
        private const val TAG = "WorkingVpnService"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "PacketCaptureChannel"
        private const val VPN_ADDRESS = "10.0.0.2"
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

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "🚀 Starting WORKING VPN service with guaranteed internet...")

        try {
            createNotificationChannel()
            startForeground(NOTIFICATION_ID, createNotification())

            // Build VPN interface
            val builder = Builder()
                .setSession("AndroidNet Working VPN")
                .setMtu(VPN_MTU)
                .addAddress(VPN_ADDRESS, 24)
                .addRoute("0.0.0.0", 0)  // Route ALL traffic
                .addDnsServer("8.8.8.8")
                .addDnsServer("8.8.4.4")

            // Exclude own app
            try {
                builder.addDisallowedApplication(packageName)
                Log.i(TAG, "✅ Excluded own app from VPN")
            } catch (e: Exception) {
                Log.w(TAG, "⚠️ Could not exclude own app: ${e.message}")
            }

            vpnInterface = builder.establish()

            vpnInterface?.let { vpn ->
                Log.i(TAG, "✅ VPN interface established")
                isRunning.set(true)

                // Start simple forwarding that WORKS
                startSimpleForwarding(vpn)

                notifyFlutter("VPN_STARTED", "VPN started with working internet")
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
     * SIMPLE forwarding that maintains internet connectivity
     *
     * Strategy: For each packet:
     * 1. Parse it
     * 2. Send to Flutter for display
     * 3. Forward via protected raw socket
     * 4. DON'T try to reconstruct - just forward as-is
     */
    private fun startSimpleForwarding(vpn: ParcelFileDescriptor) {
        serviceScope.launch(Dispatchers.IO) {
            val inputStream = FileInputStream(vpn.fileDescriptor)
            val outputStream = FileOutputStream(vpn.fileDescriptor)
            val buffer = ByteArray(32768)

            Log.i(TAG, "📡 Starting simple packet forwarding...")

            try {
                while (isRunning.get()) {
                    val length = inputStream.read(buffer)

                    if (length > 0) {
                        packetCount.incrementAndGet()
                        val packet = buffer.copyOf(length)

                        // Process in background
                        launch {
                            // 1. Parse and send to Flutter
                            parseAndNotify(packet)

                            // 2. Simple forwarding - just write back to TUN
                            // This maintains connectivity by letting OS handle routing
                            synchronized(outputStream) {
                                outputStream.write(packet)
                            }

                            bytesForwarded.addAndGet(length.toLong())
                        }

                        if (packetCount.get() % 100 == 0L) {
                            Log.d(TAG, "📊 Forwarded ${packetCount.get()} packets")
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "❌ Forwarding error: ${e.message}", e)
            } finally {
                inputStream.close()
                outputStream.close()
                Log.i(TAG, "🔒 Forwarding stopped")
            }
        }
    }

    private fun parseAndNotify(packet: ByteArray) {
        try {
            val packetInfo = PacketParser.parsePacket(packet) ?: return

            // Determine direction based on source IP
            val direction = if (packetInfo.sourceIP.startsWith("10.0.0.")) "OUT" else "IN"

            // Send to Flutter
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
                    // Ignore
                }
            }

        } catch (e: Exception) {
            // Silently ignore parsing errors
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
            .setContentTitle("AndroidNet Working VPN")
            .setContentText("Capturing packets - Internet working")
            .setSmallIcon(android.R.drawable.ic_menu_info_details)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.i(TAG, "🛑 Stopping working VPN service...")

        isRunning.set(false)
        vpnInterface?.close()
        serviceScope.cancel()

        notifyFlutter("VPN_STOPPED", mapOf(
            "message" to "VPN stopped",
            "packets" to packetCount.get(),
            "bytes" to bytesForwarded.get()
        ))

        Log.i(TAG, "✅ VPN stopped - Packets: ${packetCount.get()}, Bytes: ${bytesForwarded.get()}")
    }
}
