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
import java.net.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong

class PacketVpnService : VpnService() {

    companion object {
        private const val TAG = "PacketAnalyzer"
        private const val VPN_MTU = 1500
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val NOTIFICATION_ID = 1
        private const val LOG_THROTTLE_MS = 1000L
        var methodChannel: MethodChannel? = null
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private var captureThread: Thread? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    private val executorService: ExecutorService = Executors.newCachedThreadPool()
    private val tcpConnections = ConcurrentHashMap<String, Socket>()
    private var udpSocket: DatagramSocket? = null
    
    // Performance optimizations
    private val reusableBuffer = ByteArray(VPN_MTU)
    private val reusableResponseBuffer = ByteArray(VPN_MTU)
    private val lastLogTime = AtomicLong(0)
    private val packetCount = AtomicLong(0)

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "VPN Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "Starting VPN service")
        if (!isRunning) startVpnCapture()
        return START_STICKY
    }

    private fun startVpnCapture() {
        val builder = Builder()
            .setMtu(VPN_MTU)
            .addAddress(VPN_ADDRESS, 32)
            .addRoute(VPN_ROUTE, 0)
            .addDnsServer("8.8.8.8")
            .addDnsServer("8.8.4.4")
            .setSession("Packet Analyzer - Internet Active")

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, createNotification())

        try {
            vpnInterface = builder.establish()
            Log.d(TAG, "VPN interface established")
            if (vpnInterface != null) {
                isRunning = true
                Log.d(TAG, "VPN capture initialized with FD: ${vpnInterface!!.fd}")
                initializeForwarding()
                startPacketProcessing()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish VPN", e)
            stopSelf()
        }
    }

    private fun initializeForwarding() {
        try {
            udpSocket = DatagramSocket()
            Log.d(TAG, "UDP forwarding socket initialized")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to initialize UDP socket", e)
        }
    }

    private fun startPacketProcessing() {
        captureThread = Thread {
            Log.d(TAG, "Started VPN packet processing")
            val inputStream = FileInputStream(vpnInterface!!.fileDescriptor)
            val outputStream = FileOutputStream(vpnInterface!!.fileDescriptor)
            
            try {
                while (isRunning) {
                    val length = inputStream.read(reusableBuffer)
                    if (length > 0) {
                        val packetData = reusableBuffer.copyOf(length)
                        
                        executorService.execute { processPacketForDisplay(packetData, length) }
                        
                        // Direct forwarding to maintain internet
                        forwardPacketDirect(packetData, length, outputStream)
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error in packet processing", e)
            }
            Log.d(TAG, "VPN packet processing thread stopped")
        }
        captureThread?.start()
    }

    private fun processPacketForDisplay(buffer: ByteArray, length: Int) {
        try {
            if (length < 20) return
            
            val count = packetCount.incrementAndGet()
            val currentTime = System.currentTimeMillis()
            val shouldLog = currentTime - lastLogTime.get() > LOG_THROTTLE_MS
            
            var ipHeaderStart = 0
            for (i in 0 until minOf(length - 20, 10)) {
                val version = (buffer[i].toInt() and 0xF0) shr 4
                if (version == 4) {
                    ipHeaderStart = i
                    break
                }
            }
            if (ipHeaderStart + 20 > length) return
            
            val firstByte = buffer[ipHeaderStart]
            val version = (firstByte.toInt() and 0xF0) shr 4
            if (version != 4) return
            
            val ihl = firstByte.toInt() and 0x0F
            val headerLength = ihl * 4
            if (ipHeaderStart + headerLength > length) return
            
            val protocol = buffer[ipHeaderStart + 9].toInt() and 0xFF
            
            val sourceIp = buildString {
                append(buffer[ipHeaderStart + 12].toInt() and 0xFF)
                append('.')
                append(buffer[ipHeaderStart + 13].toInt() and 0xFF)
                append('.')
                append(buffer[ipHeaderStart + 14].toInt() and 0xFF)
                append('.')
                append(buffer[ipHeaderStart + 15].toInt() and 0xFF)
            }
            
            val destIp = buildString {
                append(buffer[ipHeaderStart + 16].toInt() and 0xFF)
                append('.')
                append(buffer[ipHeaderStart + 17].toInt() and 0xFF)
                append('.')
                append(buffer[ipHeaderStart + 18].toInt() and 0xFF)
                append('.')
                append(buffer[ipHeaderStart + 19].toInt() and 0xFF)
            }
            
            var sourcePort = 0
            var destPort = 0
            var protocolName = "Unknown"
            val transportHeaderStart = ipHeaderStart + headerLength
            
            when (protocol) {
                6 -> { // TCP
                    protocolName = "TCP"
                    if (transportHeaderStart + 4 <= length) {
                        sourcePort = ((buffer[transportHeaderStart].toInt() and 0xFF) shl 8) or (buffer[transportHeaderStart + 1].toInt() and 0xFF)
                        destPort = ((buffer[transportHeaderStart + 2].toInt() and 0xFF) shl 8) or (buffer[transportHeaderStart + 3].toInt() and 0xFF)
                    }
                }
                17 -> { // UDP
                    protocolName = "UDP"
                    if (transportHeaderStart + 4 <= length) {
                        sourcePort = ((buffer[transportHeaderStart].toInt() and 0xFF) shl 8) or (buffer[transportHeaderStart + 1].toInt() and 0xFF)
                        destPort = ((buffer[transportHeaderStart + 2].toInt() and 0xFF) shl 8) or (buffer[transportHeaderStart + 3].toInt() and 0xFF)
                    }
                }
                1 -> protocolName = "ICMP"
                else -> protocolName = "Proto-$protocol"
            }
            
            // Enhanced protocol detection
            when {
                protocol == 17 && (sourcePort == 53 || destPort == 53) -> protocolName = "DNS"
                protocol == 6 && (sourcePort == 443 || destPort == 443) -> protocolName = "HTTPS"
                protocol == 6 && (sourcePort == 80 || destPort == 80) -> protocolName = "HTTP"
                protocol == 6 && (sourcePort == 853 || destPort == 853) -> protocolName = "DNS-TLS"
            }
            
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
            
            mainHandler.post {
                try {
                    methodChannel?.invokeMethod("onPacketReceived", packetInfo)
                    
                    if (shouldLog) {
                        lastLogTime.set(currentTime)
                        Log.d(TAG, "✅ Packets captured: $count | Latest: $sourceIp:$sourcePort -> $destIp:$destPort ($protocolName, ${length}B)")
                    }
                } catch (e: Exception) {
                    if (shouldLog) {
                        Log.e(TAG, "❌ Failed to send packet to Flutter", e)
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing packet for display", e)
        }
    }

    // Direct forwarding to reduce thread overhead
    private fun forwardPacketDirect(buffer: ByteArray, length: Int, outputStream: FileOutputStream) {
        try {
            outputStream.write(buffer, 0, length)
            outputStream.flush()
        } catch (e: Exception) {
            // Minimal logging to reduce GC pressure
            if (System.currentTimeMillis() - lastLogTime.get() > LOG_THROTTLE_MS * 2) {
                Log.e(TAG, "Error in direct packet forwarding", e)
            }
        }
    }

    private fun forwardPacket(buffer: ByteArray, length: Int, outputStream: FileOutputStream) {
        try {
            if (length < 20) return
            val protocol = buffer[9].toInt() and 0xFF
            
            val destIp = InetAddress.getByAddress(buffer.sliceArray(16..19))
            
            when (protocol) {
                6 -> forwardTcpPacket(buffer, length, destIp, outputStream)
                17 -> forwardUdpPacket(buffer, length, destIp, outputStream)
                1 -> forwardIcmpPacket(buffer, length, outputStream)
                else -> {
                    outputStream.write(buffer, 0, length)
                    outputStream.flush()
                }
            }
        } catch (e: Exception) {
            // Minimal error logging
        }
    }

    private fun forwardTcpPacket(buffer: ByteArray, length: Int, destIp: InetAddress, outputStream: FileOutputStream) {
        try {
            if (length < 24) return
            
            // FIXED: Extract port bytes safely
            val portHighByte = buffer[22].toInt() and 0xFF
            val portLowByte = buffer[23].toInt() and 0xFF
            val destPort = (portHighByte shl 8) or portLowByte
            
            // Simplified forwarding for better performance
            outputStream.write(buffer, 0, length)
            outputStream.flush()
            
        } catch (e: Exception) {
            // Minimal error handling
        }
    }

    private fun forwardUdpPacket(buffer: ByteArray, length: Int, destIp: InetAddress, outputStream: FileOutputStream) {
        try {
            if (length < 28) return
            
            // FIXED: Extract port bytes safely
            val portHighByte = buffer[22].toInt() and 0xFF
            val portLowByte = buffer[23].toInt() and 0xFF
            val destPort = (portHighByte shl 8) or portLowByte
            
            // Simplified forwarding for better performance
            outputStream.write(buffer, 0, length)
            outputStream.flush()
            
        } catch (e: Exception) {
            // Minimal error handling
        }
    }

    private fun forwardIcmpPacket(buffer: ByteArray, length: Int, outputStream: FileOutputStream) {
        try {
            outputStream.write(buffer, 0, length)
            outputStream.flush()
        } catch (e: Exception) {
            // Minimal error handling
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel("VPN_CHANNEL", "VPN Service", NotificationManager.IMPORTANCE_LOW)
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, "VPN_CHANNEL")
                .setContentTitle("Packet Analyzer")
                .setContentText("Capturing packets - Internet Active ✅")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentIntent(pendingIntent)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("Packet Analyzer")
                .setContentText("Capturing packets - Internet Active ✅")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentIntent(pendingIntent)
                .build()
        }
    }

    override fun onDestroy() {
        Log.d(TAG, "Cleaning up VPN service - Total packets: ${packetCount.get()}")
        isRunning = false
        tcpConnections.values.forEach { try { it.close() } catch (e: Exception) {} }
        tcpConnections.clear()
        udpSocket?.close()
        udpSocket = null
        executorService.shutdown()
        captureThread?.interrupt()
        captureThread = null
        vpnInterface?.close()
        vpnInterface = null
        super.onDestroy()
    }
}
