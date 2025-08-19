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
            
            // Find the actual IP header start (handle VPN encapsulation)
            var ipHeaderStart = 0
            
            // Look for IPv4 header signature (version 4)
            for (i in 0 until minOf(length - 20, 10)) {
                val version = (buffer[i].toInt() and 0xF0) shr 4
                if (version == 4) {
                    ipHeaderStart = i
                    break
                }
            }
            
            // Verify we found a valid IP header
            if (ipHeaderStart + 20 > length) return
            
            // Check IP version
            val firstByte = buffer[ipHeaderStart]
            val version = (firstByte.toInt() and 0xF0) shr 4
            if (version != 4) return
            
            // Get header length (in 32-bit words)
            val ihl = firstByte.toInt() and 0x0F
            val headerLength = ihl * 4
            if (ipHeaderStart + headerLength > length) return
            
            // Extract protocol from byte 9 in IP header
            val protocol = buffer[ipHeaderStart + 9].toInt() and 0xFF
            
            // FIXED: Correct IP address parsing with proper offset
            val sourceIp = String.format("%d.%d.%d.%d",
                buffer[ipHeaderStart + 12].toInt() and 0xFF,
                buffer[ipHeaderStart + 13].toInt() and 0xFF,
                buffer[ipHeaderStart + 14].toInt() and 0xFF,
                buffer[ipHeaderStart + 15].toInt() and 0xFF
            )
            
            val destIp = String.format("%d.%d.%d.%d",
                buffer[ipHeaderStart + 16].toInt() and 0xFF,
                buffer[ipHeaderStart + 17].toInt() and 0xFF,
                buffer[ipHeaderStart + 18].toInt() and 0xFF,
                buffer[ipHeaderStart + 19].toInt() and 0xFF
            )
            
            var sourcePort = 0
            var destPort = 0
            var protocolName = "Unknown"
            
            val transportHeaderStart = ipHeaderStart + headerLength
            
            // Proper protocol identification and port extraction
            when (protocol) {
                6 -> { // TCP
                    protocolName = "TCP"
                    if (transportHeaderStart + 4 <= length) {
                        sourcePort = ((buffer[transportHeaderStart].toInt() and 0xFF) shl 8) or 
                                    (buffer[transportHeaderStart + 1].toInt() and 0xFF)
                        destPort = ((buffer[transportHeaderStart + 2].toInt() and 0xFF) shl 8) or 
                                  (buffer[transportHeaderStart + 3].toInt() and 0xFF)
                    }
                }
                17 -> { // UDP
                    protocolName = "UDP"
                    if (transportHeaderStart + 4 <= length) {
                        sourcePort = ((buffer[transportHeaderStart].toInt() and 0xFF) shl 8) or 
                                    (buffer[transportHeaderStart + 1].toInt() and 0xFF)
                        destPort = ((buffer[transportHeaderStart + 2].toInt() and 0xFF) shl 8) or 
                                  (buffer[transportHeaderStart + 3].toInt() and 0xFF)
                    }
                }
                1 -> { // ICMP
                    protocolName = "ICMP"
                    // ICMP doesn't have ports, leave as 0
                }
                else -> {
                    protocolName = "Proto-$protocol"
                }
            }
            
            // Enhanced protocol detection for common services
            if (protocol == 17 && (sourcePort == 53 || destPort == 53)) {
                protocolName = "DNS"
            } else if (protocol == 6 && (sourcePort == 443 || destPort == 443)) {
                protocolName = "HTTPS"
            } else if (protocol == 6 && (sourcePort == 80 || destPort == 80)) {
                protocolName = "HTTP"
            } else if (protocol == 6 && (sourcePort == 853 || destPort == 853)) {
                protocolName = "DNS-TLS"
            } else if (protocol == 6 && (sourcePort == 21 || destPort == 21)) {
                protocolName = "FTP"
            } else if (protocol == 6 && (sourcePort == 22 || destPort == 22)) {
                protocolName = "SSH"
            } else if (protocol == 6 && (sourcePort == 25 || destPort == 25)) {
                protocolName = "SMTP"
            } else if (protocol == 17 && (sourcePort == 123 || destPort == 123)) {
                protocolName = "NTP"
            } else if (protocol == 17 && (sourcePort == 67 || destPort == 67 || sourcePort == 68 || destPort == 68)) {
                protocolName = "DHCP"
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
