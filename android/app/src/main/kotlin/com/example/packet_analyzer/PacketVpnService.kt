package com.example.packet_analyzer

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.util.Log
import io.flutter.plugin.common.MethodChannel
import java.io.FileInputStream
import java.io.FileOutputStream

class PacketVpnService : VpnService() {
    
    companion object {
        private const val TAG = "PacketAnalyzer"
        private const val VPN_MTU = 1500
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val NOTIFICATION_ID = 1
        var methodChannel: MethodChannel? = null
    }
    
    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private var captureThread: Thread? = null
    private val mainHandler = Handler(Looper.getMainLooper())

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "VPN Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "Starting VPN service")
        
        if (!isRunning) {
            startVpnCapture()
        }
        
        return START_STICKY
    }

    private fun startVpnCapture() {
        val builder = Builder()
            .setMtu(VPN_MTU)
            .addAddress(VPN_ADDRESS, 32)
            .addRoute(VPN_ROUTE, 0)
            .addDnsServer("8.8.8.8")
            .setSession("Packet Analyzer")

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, createNotification())

        try {
            vpnInterface = builder.establish()
            Log.d(TAG, "VPN interface established")
            
            if (vpnInterface != null) {
                isRunning = true
                Log.d(TAG, "VPN capture initialized with FD: ${vpnInterface!!.fd}")
                startPacketProcessing()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN", e)
            stopSelf()
        }
    }

    private fun startPacketProcessing() {
        captureThread = Thread {
            Log.d(TAG, "Started VPN packet processing")
            
            val inputStream = FileInputStream(vpnInterface!!.fileDescriptor)
            val outputStream = FileOutputStream(vpnInterface!!.fileDescriptor)
            val buffer = ByteArray(VPN_MTU)

            try {
                while (isRunning) {
                    val length = inputStream.read(buffer)
                    if (length > 0) {
                        processPacket(buffer.copyOf(length), length)
                        outputStream.write(buffer, 0, length)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error in packet processing", e)
            }
            
            Log.d(TAG, "VPN packet processing thread stopped")
        }
        captureThread?.start()
    }

    private fun processPacket(buffer: ByteArray, length: Int) {
        try {
            // Basic IP packet validation
            if (length < 20) return
            
            // Check IP version - FIXED: Proper byte access
            val firstByte = buffer[0]
            val version = (firstByte.toInt() and 0xF0) shr 4
            if (version != 4) return
            
            // Get header length - FIXED: Proper byte handling
            val ihl = firstByte.toInt() and 0x0F
            val headerLength = ihl * 4
            if (length < headerLength) return
            
            // Extract protocol - FIXED: Direct byte access
            val protocolByte = buffer[11]
            val protocol = protocolByte.toInt() and 0xFF
            
            // FIXED: Correct IP address parsing
            val sourceIp = "${buffer[12].toInt() and 0xFF}.${buffer[13].toInt() and 0xFF}.${buffer[14].toInt() and 0xFF}.${buffer[15].toInt() and 0xFF}"
            val destIp = "${buffer[16].toInt() and 0xFF}.${buffer[17].toInt() and 0xFF}.${buffer[18].toInt() and 0xFF}.${buffer[19].toInt() and 0xFF}"
            
            var sourcePort = 0
            var destPort = 0
            var protocolName = "Unknown"
            
            // FIXED: Port parsing with proper bounds checking
            when (protocol) {
                6 -> { // TCP
                    protocolName = "TCP"
                    if (length >= headerLength + 4) {
                        sourcePort = ((buffer[headerLength].toInt() and 0xFF) shl 8) or 
                                    (buffer[headerLength + 1].toInt() and 0xFF)
                        destPort = ((buffer[headerLength + 2].toInt() and 0xFF) shl 8) or 
                                  (buffer[headerLength + 3].toInt() and 0xFF)
                    }
                }
                17 -> { // UDP
                    protocolName = "UDP"
                    if (length >= headerLength + 4) {
                        sourcePort = ((buffer[headerLength].toInt() and 0xFF) shl 8) or 
                                    (buffer[headerLength + 1].toInt() and 0xFF)
                        destPort = ((buffer[headerLength + 2].toInt() and 0xFF) shl 8) or 
                                  (buffer[headerLength + 3].toInt() and 0xFF)
                    }
                }
                1 -> protocolName = "ICMP"
                else -> protocolName = "Proto-$protocol"
            }
            
            // Create packet info
            val packetInfo = mapOf(
                "sourceIp" to sourceIp,
                "destinationIp" to destIp,
                "sourcePort" to sourcePort,
                "destinationPort" to destPort,
                "protocol" to protocolName,
                "size" to length,
                "timestamp" to System.currentTimeMillis().toString(),
                "payload" to ""
            )
            
            // Send to Flutter on main thread
            mainHandler.post {
                try {
                    methodChannel?.invokeMethod("onPacketReceived", packetInfo)
                    Log.d(TAG, "✅ Packet: $sourceIp:$sourcePort -> $destIp:$destPort ($protocolName, ${length}B)")
                } catch (e: Exception) {
                    Log.e(TAG, "❌ Failed to send packet to Flutter", e)
                }
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error processing packet", e)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "VPN_CHANNEL",
                "VPN Service",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, "VPN_CHANNEL")
                .setContentTitle("Packet Analyzer")
                .setContentText("Capturing network packets...")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentIntent(pendingIntent)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("Packet Analyzer")
                .setContentText("Capturing network packets...")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentIntent(pendingIntent)
                .build()
        }
    }

    override fun onDestroy() {
        Log.d(TAG, "Cleaning up native resources")
        isRunning = false
        
        captureThread?.interrupt()
        captureThread = null
        
        vpnInterface?.close()
        vpnInterface = null
        
        super.onDestroy()
    }
}
