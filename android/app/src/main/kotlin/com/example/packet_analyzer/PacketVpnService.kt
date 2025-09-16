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
import java.io.*
import java.net.*
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicLong
import java.util.zip.CRC32

class PacketVpnService : VpnService() {

    companion object {
        private const val TAG = "PacketAnalyzer"
        private const val VPN_MTU = 1500
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val NOTIFICATION_ID = 1
        private const val LOG_THROTTLE_MS = 1000L
        private const val SESSION_TIMEOUT_MS = 30000L
        private const val CLEANUP_INTERVAL_MS = 10000L
        var methodChannel: MethodChannel? = null
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    private var captureThread: Thread? = null
    private var cleanupThread: Thread? = null
    private val mainHandler = Handler(Looper.getMainLooper())
    private val executorService: ExecutorService = Executors.newCachedThreadPool()
    private val selector = Selector.open()
    
    // Session management for proper forwarding
    private val tcpSessions = ConcurrentHashMap<String, TcpSession>()
    private val udpSessions = ConcurrentHashMap<String, UdpSession>()
    private val lastLogTime = AtomicLong(0)
    private val packetCount = AtomicLong(0)

    // TCP Session class with proper state management
    private data class TcpSession(
        val sourceIp: InetAddress,
        val sourcePort: Int,
        val destIp: InetAddress,
        val destPort: Int,
        val socketChannel: SocketChannel,
        var lastActivity: Long = System.currentTimeMillis(),
        var sequenceNumber: Long = 0,
        var acknowledgmentNumber: Long = 0,
        var state: TcpState = TcpState.SYN_SENT
    ) {
        fun getKey(): String = "${sourceIp.hostAddress}:$sourcePort-${destIp.hostAddress}:$destPort"
        
        enum class TcpState {
            SYN_SENT, ESTABLISHED, FIN_WAIT, CLOSED
        }
    }

    // UDP Session class for state management
    private data class UdpSession(
        val sourceIp: InetAddress,
        val sourcePort: Int,
        val destIp: InetAddress,
        val destPort: Int,
        val datagramChannel: DatagramChannel,
        var lastActivity: Long = System.currentTimeMillis()
    ) {
        fun getKey(): String = "${sourceIp.hostAddress}:$sourcePort-${destIp.hostAddress}:$destPort"
    }

    override fun onCreate() {
        super.onCreate()
        Log.d(TAG, "Enhanced VPN Service created")
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.d(TAG, "Starting enhanced VPN service with full forwarding")
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
            .setSession("Enhanced Packet Analyzer - Full Forwarding")

        createNotificationChannel()
        startForeground(NOTIFICATION_ID, createNotification())

        try {
            vpnInterface = builder.establish()
            Log.d(TAG, "Enhanced VPN interface established")
            if (vpnInterface != null) {
                isRunning = true
                Log.d(TAG, "Enhanced VPN capture initialized with FD: ${vpnInterface!!.fd}")
                startPacketProcessing()
                startSessionCleanup()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to establish enhanced VPN", e)
            stopSelf()
        }
    }

    private fun startPacketProcessing() {
        captureThread = Thread {
            Log.d(TAG, "Started enhanced VPN packet processing with full TCP/UDP forwarding")
            
            val inputStream = FileInputStream(vpnInterface!!.fileDescriptor)
            val outputStream = FileOutputStream(vpnInterface!!.fileDescriptor)
            val buffer = ByteArray(VPN_MTU)
            
            try {
                while (isRunning) {
                    val length = inputStream.read(buffer)
                    if (length > 0) {
                        val packetData = buffer.copyOf(length)
                        
                        // Validate packet before processing
                        if (isValidPacket(packetData, length)) {
                            // Process for display (async)
                            executorService.execute { processPacketForDisplay(packetData, length) }
                            
                            // Forward with full TCP/UDP session management
                            executorService.execute { forwardPacketWithSessions(packetData, length, outputStream) }
                        }
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error in enhanced packet processing", e)
            } finally {
                try {
                    inputStream.close()
                    outputStream.close()
                } catch (e: Exception) {
                    Log.e(TAG, "Error closing streams", e)
                }
            }
            
            Log.d(TAG, "Enhanced VPN packet processing stopped")
        }
        captureThread?.start()
    }

    private fun isValidPacket(buffer: ByteArray, length: Int): Boolean {
        if (length < 20) return false // Minimum IP header size
        
        val version = (buffer[0].toInt() and 0xF0) shr 4
        if (version != 4) return false // Only IPv4 supported
        
        val ihl = buffer[0].toInt() and 0x0F
        val headerLength = ihl * 4
        if (headerLength < 20 || headerLength > length) return false
        
        return true
    }

    private fun processPacketForDisplay(buffer: ByteArray, length: Int) {
        try {
            val count = packetCount.incrementAndGet()
            val currentTime = System.currentTimeMillis()
            val shouldLog = currentTime - lastLogTime.get() > LOG_THROTTLE_MS
            
            val version = (buffer[0].toInt() and 0xF0) shr 4
            if (version != 4) return
            
            val ihl = buffer[0].toInt() and 0x0F
            val headerLength = ihl * 4
            if (headerLength > length) return
            
            val protocol = buffer[9].toInt() and 0xFF
            
            // Fixed IP address parsing
            val sourceIp = String.format("%d.%d.%d.%d",
                buffer[12].toInt() and 0xFF,
                buffer[13].toInt() and 0xFF,
                buffer[14].toInt() and 0xFF,
                buffer[15].toInt() and 0xFF
            )
            
            val destIp = String.format("%d.%d.%d.%d",
                buffer[16].toInt() and 0xFF,
                buffer[17].toInt() and 0xFF,
                buffer[18].toInt() and 0xFF,
                buffer[19].toInt() and 0xFF
            )
            
            var sourcePort = 0
            var destPort = 0
            var protocolName = "Unknown"
            val transportHeaderStart = headerLength
            
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
                1 -> protocolName = "ICMP"
                else -> protocolName = "Proto-$protocol"
            }
            
            // Enhanced protocol detection
            when {
                protocol == 17 && (sourcePort == 53 || destPort == 53) -> protocolName = "DNS"
                protocol == 6 && (sourcePort == 443 || destPort == 443) -> protocolName = "HTTPS"
                protocol == 6 && (sourcePort == 80 || destPort == 80) -> protocolName = "HTTP"
                protocol == 6 && (sourcePort == 853 || destPort == 853) -> protocolName = "DNS-TLS"
                protocol == 17 && (sourcePort == 123 || destPort == 123) -> protocolName = "NTP"
                protocol == 6 && (sourcePort == 22 || destPort == 22) -> protocolName = "SSH"
                protocol == 6 && (sourcePort == 25 || destPort == 25) -> protocolName = "SMTP"
                protocol == 6 && (sourcePort == 993 || destPort == 993) -> protocolName = "IMAPS"
                protocol == 6 && (sourcePort == 995 || destPort == 995) -> protocolName = "POP3S"
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
                        Log.d(TAG, "🚀 Packets: $count | Sessions: TCP=${tcpSessions.size}, UDP=${udpSessions.size} | Latest: $sourceIp:$sourcePort -> $destIp:$destPort ($protocolName, ${length}B)")
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

    private fun forwardPacketWithSessions(buffer: ByteArray, length: Int, outputStream: FileOutputStream) {
        try {
            if (!isValidPacket(buffer, length)) return
            
            val protocol = buffer[9].toInt() and 0xFF
            
            // Fixed IP address parsing
            val sourceIp = InetAddress.getByAddress(byteArrayOf(
                buffer[12], buffer[13], buffer[14], buffer[15]
            ))
            val destIp = InetAddress.getByAddress(byteArrayOf(
                buffer[16], buffer[17], buffer[18], buffer[19]
            ))
            
            when (protocol) {
                6 -> forwardTcpWithSession(buffer, length, sourceIp, destIp, outputStream)
                17 -> forwardUdpWithSession(buffer, length, sourceIp, destIp, outputStream)
                1 -> forwardIcmpDirect(buffer, length, outputStream)
                else -> forwardOtherProtocol(buffer, length, outputStream)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error in session-based forwarding", e)
        }
    }

    private fun forwardTcpWithSession(buffer: ByteArray, length: Int, sourceIp: InetAddress, destIp: InetAddress, outputStream: FileOutputStream) {
        try {
            val headerLength = (buffer[0].toInt() and 0x0F) * 4
            if (length < headerLength + 20) return // Need IP + TCP headers
            
            val sourcePort = ((buffer[headerLength].toInt() and 0xFF) shl 8) or 
                           (buffer[headerLength + 1].toInt() and 0xFF)
            val destPort = ((buffer[headerLength + 2].toInt() and 0xFF) shl 8) or 
                          (buffer[headerLength + 3].toInt() and 0xFF)
            val sessionKey = "${sourceIp.hostAddress}:$sourcePort-${destIp.hostAddress}:$destPort"
            
            var session = tcpSessions[sessionKey]
            
            if (session == null) {
                // Create new TCP session
                try {
                    val socketChannel = SocketChannel.open()
                    socketChannel.configureBlocking(false)
                    protect(socketChannel.socket())
                    
                    val connected = socketChannel.connect(InetSocketAddress(destIp, destPort))
                    if (!connected) {
                        // Register for connection completion
                        socketChannel.register(selector, SelectionKey.OP_CONNECT)
                        
                        // Wait for connection with timeout
                        var retries = 100
                        while (!socketChannel.finishConnect() && retries-- > 0) {
                            Thread.sleep(10)
                        }
                        
                        if (!socketChannel.isConnected()) {
                            socketChannel.close()
                            Log.w(TAG, "Failed to connect TCP session: $sessionKey")
                            return
                        }
                    }
                    
                    session = TcpSession(sourceIp, sourcePort, destIp, destPort, socketChannel)
                    tcpSessions[sessionKey] = session
                    
                    // Start reading responses from this session
                    executorService.execute { readTcpSession(session, outputStream) }
                    
                    Log.d(TAG, "📡 New TCP session: $sessionKey")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to create TCP session: $sessionKey", e)
                    return
                }
            }
            
            // Extract TCP payload and forward
            val tcpHeaderLen = ((buffer[headerLength + 12].toInt() and 0xF0) shr 4) * 4
            val payloadStart = headerLength + tcpHeaderLen
            if (payloadStart < length) {
                val payloadLength = length - payloadStart
                if (payloadLength > 0) {
                    val payload = ByteBuffer.wrap(buffer, payloadStart, payloadLength)
                    val written = session.socketChannel.write(payload)
                    if (written > 0) {
                        session.lastActivity = System.currentTimeMillis()
                        session.state = TcpSession.TcpState.ESTABLISHED
                    }
                }
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error in TCP session forwarding", e)
        }
    }

    private fun readTcpSession(session: TcpSession, outputStream: FileOutputStream) {
        try {
            val buffer = ByteBuffer.allocate(VPN_MTU - 40) // Leave space for headers
            
            while (isRunning && session.socketChannel.isConnected && session.state != TcpSession.TcpState.CLOSED) {
                try {
                    buffer.clear()
                    val bytesRead = session.socketChannel.read(buffer)
                    
                    if (bytesRead > 0) {
                        // Create TCP/IP response packet and write back
                        val responsePacket = buildTcpResponsePacket(session, buffer.array(), bytesRead)
                        synchronized(outputStream) {
                            outputStream.write(responsePacket)
                            outputStream.flush()
                        }
                        session.lastActivity = System.currentTimeMillis()
                    } else if (bytesRead == -1) {
                        // Connection closed by remote
                        session.state = TcpSession.TcpState.CLOSED
                        break
                    }
                } catch (e: IOException) {
                    Log.d(TAG, "TCP session read error (connection likely closed): ${session.getKey()}")
                    break
                }
                
                Thread.sleep(1) // Small delay to prevent busy waiting
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error reading TCP session: ${session.getKey()}", e)
        } finally {
            cleanupTcpSession(session)
        }
    }

    private fun cleanupTcpSession(session: TcpSession) {
        try {
            session.state = TcpSession.TcpState.CLOSED
            session.socketChannel.close()
            tcpSessions.remove(session.getKey())
        } catch (e: Exception) {
            Log.e(TAG, "Error closing TCP session: ${session.getKey()}", e)
        }
    }

    private fun forwardUdpWithSession(buffer: ByteArray, length: Int, sourceIp: InetAddress, destIp: InetAddress, outputStream: FileOutputStream) {
        try {
            val headerLength = (buffer[0].toInt() and 0x0F) * 4
            if (length < headerLength + 8) return // Need IP + UDP headers
            
            val sourcePort = ((buffer[headerLength].toInt() and 0xFF) shl 8) or 
                           (buffer[headerLength + 1].toInt() and 0xFF)
            val destPort = ((buffer[headerLength + 2].toInt() and 0xFF) shl 8) or 
                          (buffer[headerLength + 3].toInt() and 0xFF)
            val sessionKey = "${sourceIp.hostAddress}:$sourcePort-${destIp.hostAddress}:$destPort"
            
            var session = udpSessions[sessionKey]
            
            if (session == null) {
                // Create new UDP session
                try {
                    val datagramChannel = DatagramChannel.open()
                    datagramChannel.configureBlocking(false)
                    protect(datagramChannel.socket())
                    datagramChannel.connect(InetSocketAddress(destIp, destPort))
                    
                    session = UdpSession(sourceIp, sourcePort, destIp, destPort, datagramChannel)
                    udpSessions[sessionKey] = session
                    
                    // Start reading responses from this session
                    executorService.execute { readUdpSession(session, outputStream) }
                    
                    Log.d(TAG, "📡 New UDP session: $sessionKey")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to create UDP session: $sessionKey", e)
                    return
                }
            }
            
            // Extract UDP payload and forward
            val payloadStart = headerLength + 8 // IP header + UDP header
            if (payloadStart < length) {
                val payloadLength = length - payloadStart
                if (payloadLength > 0) {
                    val payload = ByteBuffer.wrap(buffer, payloadStart, payloadLength)
                    val written = session.datagramChannel.write(payload)
                    if (written > 0) {
                        session.lastActivity = System.currentTimeMillis()
                    }
                }
            }
            
        } catch (e: Exception) {
            Log.e(TAG, "Error in UDP session forwarding", e)
        }
    }

    private fun readUdpSession(session: UdpSession, outputStream: FileOutputStream) {
        try {
            val buffer = ByteBuffer.allocate(VPN_MTU - 28) // Leave space for IP + UDP headers
            
            while (isRunning && session.datagramChannel.isConnected) {
                try {
                    buffer.clear()
                    val bytesRead = session.datagramChannel.read(buffer)
                    
                    if (bytesRead > 0) {
                        // Create UDP/IP response packet and write back
                        val responsePacket = buildUdpResponsePacket(session, buffer.array(), bytesRead)
                        synchronized(outputStream) {
                            outputStream.write(responsePacket)
                            outputStream.flush()
                        }
                        session.lastActivity = System.currentTimeMillis()
                    }
                } catch (e: IOException) {
                    Log.d(TAG, "UDP session read completed: ${session.getKey()}")
                    break
                }
                
                Thread.sleep(1) // Small delay to prevent busy waiting
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error reading UDP session: ${session.getKey()}", e)
        } finally {
            cleanupUdpSession(session)
        }
    }

    private fun cleanupUdpSession(session: UdpSession) {
        try {
            session.datagramChannel.close()
            udpSessions.remove(session.getKey())
        } catch (e: Exception) {
            Log.e(TAG, "Error closing UDP session: ${session.getKey()}", e)
        }
    }

    private fun buildTcpResponsePacket(session: TcpSession, data: ByteArray, dataLength: Int): ByteArray {
        val totalLength = 20 + 20 + dataLength // IP header + TCP header + data
        val packet = ByteArray(totalLength)
        
        // IP Header (20 bytes)
        packet[0] = 0x45.toByte() // Version 4, IHL 5
        packet[1] = 0x00 // DSCP/ECN
        packet[2] = (totalLength shr 8).toByte() // Total Length
        packet[3] = totalLength.toByte()
        packet[4] = 0x00 // Identification
        packet[5] = 0x00
        packet[6] = 0x40 // Flags: Don't Fragment
        packet[7] = 0x00
        packet[8] = 0x40 // TTL: 64
        packet[9] = 6 // Protocol: TCP
        // Checksum will be calculated later (bytes 10-11)
        
        // Source IP (session destination becomes packet source)
        val sourceBytes = session.destIp.address
        System.arraycopy(sourceBytes, 0, packet, 12, 4)
        
        // Destination IP (session source becomes packet destination)
        val destBytes = session.sourceIp.address
        System.arraycopy(destBytes, 0, packet, 16, 4)
        
        // Calculate IP header checksum
        val ipChecksum = calculateChecksum(packet, 0, 20)
        packet[10] = (ipChecksum shr 8).toByte()
        packet[11] = ipChecksum.toByte()
        
        // TCP Header (20 bytes, starting at offset 20)
        packet[20] = (session.destPort shr 8).toByte() // Source port
        packet[21] = session.destPort.toByte()
        packet[22] = (session.sourcePort shr 8).toByte() // Destination port
        packet[23] = session.sourcePort.toByte()
        
        // Sequence and acknowledgment numbers (simplified)
        packet[24] = 0x00 // Sequence number
        packet[25] = 0x00
        packet[26] = 0x00
        packet[27] = 0x01
        packet[28] = 0x00 // Acknowledgment number
        packet[29] = 0x00
        packet[30] = 0x00
        packet[31] = 0x01
        
        packet[32] = 0x50 // Data offset: 5 words (20 bytes), reserved bits
        packet[33] = 0x18 // Flags: PSH + ACK
        packet[34] = 0xFF.toByte() // Window size
        packet[35] = 0xFF.toByte()
        // TCP checksum will be calculated (bytes 36-37)
        packet[38] = 0x00 // Urgent pointer
        packet[39] = 0x00
        
        // Copy data
        if (dataLength > 0) {
            System.arraycopy(data, 0, packet, 40, dataLength)
        }
        
        // Calculate TCP checksum (with pseudo header)
        val tcpChecksum = calculateTcpChecksum(packet, 12, 20, dataLength) // IP src/dst at offset 12
        packet[36] = (tcpChecksum shr 8).toByte()
        packet[37] = tcpChecksum.toByte()
        
        return packet
    }

    private fun buildUdpResponsePacket(session: UdpSession, data: ByteArray, dataLength: Int): ByteArray {
        val totalLength = 20 + 8 + dataLength // IP header + UDP header + data
        val packet = ByteArray(totalLength)
        
        // IP Header (20 bytes)
        packet[0] = 0x45.toByte() // Version 4, IHL 5
        packet[1] = 0x00 // DSCP/ECN
        packet[2] = (totalLength shr 8).toByte() // Total Length
        packet[3] = totalLength.toByte()
        packet[4] = 0x00 // Identification
        packet[5] = 0x00
        packet[6] = 0x40 // Flags: Don't Fragment
        packet[7] = 0x00
        packet[8] = 0x40 // TTL: 64
        packet[9] = 17 // Protocol: UDP
        // Checksum will be calculated later (bytes 10-11)
        
        // Source IP (session destination becomes packet source)
        val sourceBytes = session.destIp.address
        System.arraycopy(sourceBytes, 0, packet, 12, 4)
        
        // Destination IP (session source becomes packet destination)
        val destBytes = session.sourceIp.address
        System.arraycopy(destBytes, 0, packet, 16, 4)
        
        // Calculate IP header checksum
        val ipChecksum = calculateChecksum(packet, 0, 20)
        packet[10] = (ipChecksum shr 8).toByte()
        packet[11] = ipChecksum.toByte()
        
        // UDP Header (8 bytes, starting at offset 20)
        packet[20] = (session.destPort shr 8).toByte() // Source port
        packet[21] = session.destPort.toByte()
        packet[22] = (session.sourcePort shr 8).toByte() // Destination port
        packet[23] = session.sourcePort.toByte()
        
        val udpLength = 8 + dataLength
        packet[24] = (udpLength shr 8).toByte() // UDP length
        packet[25] = udpLength.toByte()
        // UDP checksum (bytes 26-27) - can be 0 for IPv4
        packet[26] = 0x00
        packet[27] = 0x00
        
        // Copy data
        if (dataLength > 0) {
            System.arraycopy(data, 0, packet, 28, dataLength)
        }
        
        return packet
    }

    private fun calculateChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        
        // Sum all 16-bit words
        while (i < offset + length - 1) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            i += 2
        }
        
        // Add odd byte if present
        if (i < offset + length) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }
        
        // Add carry bits
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        
        // One's complement
        return (sum xor 0xFFFF).toInt() and 0xFFFF
    }

    private fun calculateTcpChecksum(packet: ByteArray, ipOffset: Int, tcpOffset: Int, dataLength: Int): Int {
        // Create pseudo header + TCP header + data for checksum calculation
        val pseudoHeaderSize = 12
        val tcpHeaderSize = 20
        val totalSize = pseudoHeaderSize + tcpHeaderSize + dataLength
        val checksumData = ByteArray(totalSize)
        
        // Pseudo header
        System.arraycopy(packet, ipOffset, checksumData, 0, 8) // Source + Dest IP
        checksumData[8] = 0 // Reserved
        checksumData[9] = 6 // Protocol (TCP)
        val tcpLength = tcpHeaderSize + dataLength
        checksumData[10] = (tcpLength shr 8).toByte()
        checksumData[11] = tcpLength.toByte()
        
        // TCP header (clear checksum field first)
        System.arraycopy(packet, tcpOffset, checksumData, pseudoHeaderSize, tcpHeaderSize)
        checksumData[pseudoHeaderSize + 16] = 0 // Clear checksum field
        checksumData[pseudoHeaderSize + 17] = 0
        
        // TCP data
        if (dataLength > 0) {
            System.arraycopy(packet, tcpOffset + tcpHeaderSize, checksumData, pseudoHeaderSize + tcpHeaderSize, dataLength)
        }
        
        return calculateChecksum(checksumData, 0, totalSize)
    }

    private fun forwardIcmpDirect(buffer: ByteArray, length: Int, outputStream: FileOutputStream) {
        try {
            // For ICMP, we need to swap source and destination IPs for response
            val responsePacket = buffer.copyOf(length)
            
            // Swap source and destination IPs
            for (i in 0..3) {
                val temp = responsePacket[12 + i]
                responsePacket[12 + i] = responsePacket[16 + i]
                responsePacket[16 + i] = temp
            }
            
            // Recalculate IP header checksum
            responsePacket[10] = 0
            responsePacket[11] = 0
            val ipChecksum = calculateChecksum(responsePacket, 0, 20)
            responsePacket[10] = (ipChecksum shr 8).toByte()
            responsePacket[11] = ipChecksum.toByte()
            
            // Handle ICMP echo request -> echo reply
            val headerLength = (responsePacket[0].toInt() and 0x0F) * 4
            if (headerLength + 8 <= length && responsePacket[headerLength].toInt() == 8) { // Echo request
                responsePacket[headerLength] = 0 // Change to echo reply
                
                // Recalculate ICMP checksum
                responsePacket[headerLength + 2] = 0
                responsePacket[headerLength + 3] = 0
                val icmpChecksum = calculateChecksum(responsePacket, headerLength, length - headerLength)
                responsePacket[headerLength + 2] = (icmpChecksum shr 8).toByte()
                responsePacket[headerLength + 3] = icmpChecksum.toByte()
            }
            
            synchronized(outputStream) {
                outputStream.write(responsePacket)
                outputStream.flush()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error forwarding ICMP", e)
        }
    }

    private fun forwardOtherProtocol(buffer: ByteArray, length: Int, outputStream: FileOutputStream) {
        try {
            // For other protocols, attempt basic forwarding
            // This is a simplified approach - in production, you'd need protocol-specific handling
            Log.d(TAG, "Forwarding unsupported protocol: ${buffer[9].toInt() and 0xFF}")
        } catch (e: Exception) {
            Log.e(TAG, "Error forwarding other protocol", e)
        }
    }

    private fun startSessionCleanup() {
        cleanupThread = Thread {
            Log.d(TAG, "Started session cleanup thread")
            
            while (isRunning) {
                try {
                    val currentTime = System.currentTimeMillis()
                    
                    // Clean up old TCP sessions
                    val expiredTcpSessions = mutableListOf<String>()
                    tcpSessions.forEach { (key, session) ->
                        if (currentTime - session.lastActivity > SESSION_TIMEOUT_MS || 
                            session.state == TcpSession.TcpState.CLOSED) {
                            expiredTcpSessions.add(key)
                        }
                    }
                    
                    expiredTcpSessions.forEach { key ->
                        tcpSessions[key]?.let { session ->
                            cleanupTcpSession(session)
                            Log.d(TAG, "🧹 Cleaned up expired TCP session: $key")
                        }
                    }
                    
                    // Clean up old UDP sessions
                    val expiredUdpSessions = mutableListOf<String>()
                    udpSessions.forEach { (key, session) ->
                        if (currentTime - session.lastActivity > SESSION_TIMEOUT_MS) {
                            expiredUdpSessions.add(key)
                        }
                    }
                    
                    expiredUdpSessions.forEach { key ->
                        udpSessions[key]?.let { session ->
                            cleanupUdpSession(session)
                            Log.d(TAG, "🧹 Cleaned up expired UDP session: $key")
                        }
                    }
                    
                    if (expiredTcpSessions.isNotEmpty() || expiredUdpSessions.isNotEmpty()) {
                        Log.d(TAG, "Session cleanup: removed ${expiredTcpSessions.size} TCP, ${expiredUdpSessions.size} UDP sessions")
                    }
                    
                    Thread.sleep(CLEANUP_INTERVAL_MS)
                } catch (e: InterruptedException) {
                    Log.d(TAG, "Session cleanup thread interrupted")
                    break
                } catch (e: Exception) {
                    Log.e(TAG, "Error in session cleanup", e)
                }
            }
            
            Log.d(TAG, "Session cleanup thread stopped")
        }
        cleanupThread?.start()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "VPN_CHANNEL", 
                "Enhanced VPN Service", 
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Network packet analyzer with full forwarding"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_CLEAR_TASK
        }
        val pendingIntent = PendingIntent.getActivity(
            this, 
            0, 
            intent, 
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, "VPN_CHANNEL")
                .setContentTitle("Enhanced Packet Analyzer")
                .setContentText("Full TCP/UDP Forwarding Active 🚀")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .setShowWhen(false)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("Enhanced Packet Analyzer")
                .setContentText("Full TCP/UDP Forwarding Active 🚀")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .build()
        }
    }

    override fun onRevoke() {
        Log.d(TAG, "VPN permission revoked")
        stopVpnService()
        super.onRevoke()
    }

    private fun stopVpnService() {
        Log.d(TAG, "Stopping VPN service gracefully")
        isRunning = false
        
        // Stop threads
        captureThread?.interrupt()
        cleanupThread?.interrupt()
        
        // Close selector
        try {
            selector.close()
        } catch (e: Exception) {
            Log.e(TAG, "Error closing selector", e)
        }
        
        // Cleanup sessions
        cleanupAllSessions()
        
        // Shutdown executor
        try {
            executorService.shutdown()
            if (!executorService.awaitTermination(5, java.util.concurrent.TimeUnit.SECONDS)) {
                executorService.shutdownNow()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error shutting down executor", e)
            executorService.shutdownNow()
        }
        
        // Close VPN interface
        try {
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: Exception) {
            Log.e(TAG, "Error closing VPN interface", e)
        }
    }

    private fun cleanupAllSessions() {
        Log.d(TAG, "Cleaning up all sessions - TCP: ${tcpSessions.size}, UDP: ${udpSessions.size}")
        
        // Close all TCP sessions
        val tcpSessionsCopy = tcpSessions.values.toList()
        tcpSessionsCopy.forEach { session ->
            try {
                cleanupTcpSession(session)
            } catch (e: Exception) {
                Log.e(TAG, "Error cleaning up TCP session: ${session.getKey()}", e)
            }
        }
        tcpSessions.clear()
        
        // Close all UDP sessions
        val udpSessionsCopy = udpSessions.values.toList()
        udpSessionsCopy.forEach { session ->
            try {
                cleanupUdpSession(session)
            } catch (e: Exception) {
                Log.e(TAG, "Error cleaning up UDP session: ${session.getKey()}", e)
            }
        }
        udpSessions.clear()
        
        Log.d(TAG, "All sessions cleaned up")
    }

    override fun onDestroy() {
        val totalPackets = packetCount.get()
        Log.d(TAG, "VPN service destroyed - Total packets processed: $totalPackets")
        
        stopVpnService()
        super.onDestroy()
        
        Log.d(TAG, "VPN service cleanup complete")
    }

    // Public methods for external control
    fun getSessionStats(): Map<String, Any> {
        return mapOf(
            "tcpSessions" to tcpSessions.size,
            "udpSessions" to udpSessions.size,
            "totalPackets" to packetCount.get(),
            "isRunning" to isRunning
        )
    }

    fun getCurrentSessions(): Map<String, Any> {
        val tcpList = tcpSessions.values.map { session ->
            mapOf(
                "key" to session.getKey(),
                "state" to session.state.name,
                "lastActivity" to session.lastActivity,
                "connected" to session.socketChannel.isConnected
            )
        }
        
        val udpList = udpSessions.values.map { session ->
            mapOf(
                "key" to session.getKey(),
                "lastActivity" to session.lastActivity,
                "connected" to session.datagramChannel.isConnected
            )
        }
        
        return mapOf(
            "tcp" to tcpList,
            "udp" to udpList,
            "timestamp" to System.currentTimeMillis()
        )
    }
}