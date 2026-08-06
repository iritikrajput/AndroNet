package com.example.packet_analyzer

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.Build
import android.os.IBinder
import android.util.Log
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel

/**
 * NetHunter Libpcap Service
 * Provides Wireshark-like packet capture on rooted devices using native libpcap
 */
class NetHunterService : Service() {

    private val TAG = "NetHunterService"
    private var isCapturing = false
    private val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())
    private var networkInterface = "any" // Default to capture on all interfaces

    companion object {
        private var methodChannel: MethodChannel? = null
        private var packetSink: EventChannel.EventSink? = null

        fun setMethodChannel(channel: MethodChannel) {
            methodChannel = channel
        }

        fun setPacketSink(sink: EventChannel.EventSink?) {
            packetSink = sink
        }
    }

    override fun onBind(intent: Intent): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        Log.i(TAG, "🚀 NetHunter Service created (Libpcap mode)")
        createNotificationChannel()
    }

    private fun isRooted(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec(arrayOf("su", "-c", "id"))
            val result = process.inputStream.bufferedReader().readLine() ?: ""
            process.destroy()
            result.contains("uid=0")
        } catch (e: Exception) {
            false
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action

        when (action) {
            "START_CAPTURE" -> {
                if (!isRooted()) {
                    Log.w(TAG, "Root not available — NetHunter mode unavailable")
                    onStatusUpdate("NetHunter mode requires root. Use VPN mode instead.")
                    stopSelf()
                    return START_NOT_STICKY
                }
                val iface = intent.getStringExtra("interface") ?: "any"
                startLibpcapCapture(iface)
            }
            "STOP_CAPTURE" -> stopLibpcapCapture()
        }

        return START_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "libpcap_channel",
                "Libpcap Packet Capture",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Wireshark-like deep packet inspection"
            }

            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }

    private fun startForeground() {
        val notification = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, "libpcap_channel")
                .setContentTitle("Libpcap Capture Active")
                .setContentText("Capturing packets on $networkInterface")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("Libpcap Capture Active")
                .setContentText("Capturing packets on $networkInterface")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .build()
        }

        startForeground(2, notification)
    }

    private fun startLibpcapCapture(interfaceName: String) {
        if (isCapturing) {
            Log.w(TAG, "Capture already running")
            return
        }

        Log.i(TAG, "🔍 Starting native libpcap capture on: $interfaceName")
        networkInterface = interfaceName

        try {
            // Initialize libpcap native bridge
            val success = LibpcapBridge.nativeInit(this, interfaceName)

            if (!success) {
                Log.e(TAG, "❌ Failed to initialize libpcap")
                onStatusUpdate("Failed to initialize libpcap - check root access")
                return
            }

            // Start capture
            val started = LibpcapBridge.nativeStartCapture()

            if (!started) {
                Log.e(TAG, "❌ Failed to start libpcap capture")
                onStatusUpdate("Failed to start capture")
                return
            }

            isCapturing = true
            startForeground()

            Log.i(TAG, "✅ Libpcap capture started successfully")
            onStatusUpdate("Libpcap capture started on $interfaceName")

        } catch (e: Exception) {
            Log.e(TAG, "❌ Libpcap capture error: ${e.message}", e)
            onStatusUpdate("Error: ${e.message}")
        }
    }

    private fun stopLibpcapCapture() {
        if (!isCapturing) {
            Log.w(TAG, "Capture not running")
            return
        }

        Log.i(TAG, "🛑 Stopping libpcap capture")

        try {
            LibpcapBridge.nativeStopCapture()
            LibpcapBridge.nativeCleanup()

            isCapturing = false
            stopForeground(true)

            Log.i(TAG, "✅ Libpcap capture stopped")
            onStatusUpdate("Capture stopped")

        } catch (e: Exception) {
            Log.e(TAG, "Error stopping capture: ${e.message}", e)
        }
    }

    /**
     * Called from native code when a packet is captured
     */
    @Suppress("unused")
    fun onPacketCaptured(packetInfo: Map<String, Any>) {
        try {
            mainHandler.post {
                try {
                    packetSink?.success(packetInfo)
                } catch (e: Exception) {
                    Log.e(TAG, "Error sending packet to Flutter: ${e.message}")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error in packet callback: ${e.message}")
        }
    }

    /**
     * Called from native code for status updates
     */
    @Suppress("unused")
    fun onStatusUpdate(status: String) {
        Log.i(TAG, "Status: $status")
        mainHandler.post {
            methodChannel?.invokeMethod("onLibpcapStatus", mapOf("status" to status))
        }
    }

    /**
     * Get list of available network interfaces (called from MainActivity)
     */
    fun getAvailableInterfaces(): List<String> {
        return try {
            LibpcapBridge.nativeGetInterfaces()?.toList() ?: listOf("any", "wlan0", "rmnet0")
        } catch (e: Exception) {
            Log.e(TAG, "Error getting interfaces: ${e.message}")
            listOf("any", "wlan0", "rmnet0") // Fallback defaults
        }
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
        super.onDestroy()
        Log.i(TAG, "NetHunter Service destroyed")
        try {
            PacketAnalysisManager.getInstance().finalizePcap()
        } catch (e: Exception) {
            Log.e(TAG, "Error finalizing PCAP: ${e.message}")
        }
        stopLibpcapCapture()
    }
}
