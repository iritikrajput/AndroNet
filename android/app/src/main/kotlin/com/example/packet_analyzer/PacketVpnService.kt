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
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodChannel
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.InetAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.DatagramChannel
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.math.min

/**
 * PacketVpnService.kt
 *
 * Session-based TCP/UDP forwarding VPN service for packet capture + real internet passthrough.
 *
 * Caveats:
 *  - Provides best-effort TCP forwarding; not a full TCP stack.
 *  - Should be tested thoroughly. Use DNS/UDP first, then HTTP.
 */

class PacketVpnService : VpnService() {

    companion object {
        private const val TAG = "PacketAnalyzer"
        private const val VPN_MTU = 1500
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val VPN_ROUTE = "0.0.0.0"
        private const val NOTIFICATION_ID = 1
        private const val SESSION_TIMEOUT_MS = 30_000L
        private const val CLEANUP_INTERVAL_SEC = 10L

        // Exposed by MainActivity
        var methodChannel: MethodChannel? = null
        var eventSink: EventChannel.EventSink? = null
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val isRunning = AtomicBoolean(false)
    private val executor = Executors.newCachedThreadPool()
    private val scheduled: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    private val tcpSessions = ConcurrentHashMap<String, TcpSession>()
    private val udpSessions = ConcurrentHashMap<String, UdpSession>()

    // Simple data classes for sessions
    private data class TcpSession(
        val srcIp: InetAddress, val srcPort: Int,
        val dstIp: InetAddress, val dstPort: Int,
        val channel: SocketChannel,
        var lastActivity: Long = System.currentTimeMillis()
    ) {
        fun key() = "${srcIp.hostAddress}:$srcPort-${dstIp.hostAddress}:$dstPort"
    }

    private data class UdpSession(
        val srcIp: InetAddress, val srcPort: Int,
        val dstIp: InetAddress, val dstPort: Int,
        val channel: DatagramChannel,
        var lastActivity: Long = System.currentTimeMillis()
    ) {
        fun key() = "${srcIp.hostAddress}:$srcPort-${dstIp.hostAddress}:$dstPort"
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (!isRunning.get()) startVpnCapture()
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
            if (vpnInterface == null) {
                Log.e(TAG, "Failed to establish VPN interface")
                stopSelf()
                return
            }
            isRunning.set(true)
            startPacketLoop()
            startSessionCleanup()
            Log.d(TAG, "VPN capture started")
        } catch (e: Exception) {
            Log.e(TAG, "Error establishing VPN", e)
            stopSelf()
        }
    }

    private fun startPacketLoop() {
        executor.execute {
            val input = FileInputStream(vpnInterface!!.fileDescriptor)
            val output = FileOutputStream(vpnInterface!!.fileDescriptor)
            val buffer = ByteArray(VPN_MTU)

            while (isRunning.get()) {
                try {
                    val len = input.read(buffer)
                    if (len > 0) {
                        val pkt = buffer.copyOf(len)
                        // 1) Send summary to Flutter (EventChannel)
                        processPacketForDisplay(pkt, len)
                        // 2) Forward to network using session forwarding
                        forwardPacketWithSessions(pkt, len, output)
                    }
                } catch (e: IOException) {
                    if (isRunning.get()) Log.e(TAG, "IO error in packet loop", e)
                    break
                } catch (e: Exception) {
                    Log.e(TAG, "Error in packet loop", e)
                }
            }

            try { input.close() } catch (_: Exception) {}
            try { output.close() } catch (_: Exception) {}
        }
    }

    private fun processPacketForDisplay(buffer: ByteArray, length: Int) {
        try {
            if (length < 20) return
            val version = (buffer[0].toInt() shr 4) and 0x0F
            if (version != 4) return
            val ihl = (buffer[0].toInt() and 0x0F) * 4
            if (ihl < 20 || ihl > length) return

            val protocol = buffer[9].toInt() and 0xFF
            val srcIp = "${buffer[12].toInt() and 0xFF}.${buffer[13].toInt() and 0xFF}.${buffer[14].toInt() and 0xFF}.${buffer[15].toInt() and 0xFF}"
            val dstIp = "${buffer[16].toInt() and 0xFF}.${buffer[17].toInt() and 0xFF}.${buffer[18].toInt() and 0xFF}.${buffer[19].toInt() and 0xFF}"

            var srcPort = 0
            var dstPort = 0
            var protoName = "IP-$protocol"
            if (protocol == 6 || protocol == 17) {
                if (length >= ihl + 4) {
                    srcPort = ((buffer[ihl].toInt() and 0xFF) shl 8) or (buffer[ihl + 1].toInt() and 0xFF)
                    dstPort = ((buffer[ihl + 2].toInt() and 0xFF) shl 8) or (buffer[ihl + 3].toInt() and 0xFF)
                    protoName = if (protocol == 6) "TCP" else "UDP"
                }
            } else if (protocol == 1) {
                protoName = "ICMP"
            }

            val packetInfo = mapOf(
                "sourceIp" to srcIp,
                "destinationIp" to dstIp,
                "sourcePort" to srcPort,
                "destinationPort" to dstPort,
                "protocol" to protoName,
                "size" to length,
                "timestamp" to System.currentTimeMillis().toString()
            )

            // Send to Flutter (EventChannel preferred; MethodChannel fallback)
            mainHandler.post {
                try { eventSink?.success(packetInfo) } catch (_: Exception) {}
                try { methodChannel?.invokeMethod("onPacketReceived", packetInfo) } catch (_: Exception) {}
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error processing packet for display", e)
        }
    }

    private fun forwardPacketWithSessions(buffer: ByteArray, length: Int, outputStream: FileOutputStream) {
        try {
            if (length < 20) return
            val protocol = buffer[9].toInt() and 0xFF
            val srcIp = InetAddress.getByAddress(byteArrayOf(buffer[12], buffer[13], buffer[14], buffer[15]))
            val dstIp = InetAddress.getByAddress(byteArrayOf(buffer[16], buffer[17], buffer[18], buffer[19]))

            when (protocol) {
                6 -> forwardTcp(buffer, length, srcIp, dstIp, outputStream)
                17 -> forwardUdp(buffer, length, srcIp, dstIp, outputStream)
                else -> {
                    // For unsupported protocols, do a quick passthrough (write same packet back)
                    synchronized(outputStream) {
                        outputStream.write(buffer, 0, length)
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error forwarding packet", e)
        }
    }

    // ---- TCP Forwarding ----
    private fun forwardTcp(buffer: ByteArray, length: Int, srcIp: InetAddress, dstIp: InetAddress, outputStream: FileOutputStream) {
        try {
            val ihl = (buffer[0].toInt() and 0x0F) * 4
            if (length < ihl + 20) return
            val srcPort = ((buffer[ihl].toInt() and 0xFF) shl 8) or (buffer[ihl + 1].toInt() and 0xFF)
            val dstPort = ((buffer[ihl + 2].toInt() and 0xFF) shl 8) or (buffer[ihl + 3].toInt() and 0xFF)
            val key = "${srcIp.hostAddress}:$srcPort-${dstIp.hostAddress}:$dstPort"

            var session = tcpSessions[key]
            if (session == null) {
                // Create non-blocking socket and protect it
                val sc = SocketChannel.open()
                sc.configureBlocking(false)
                protect(sc.socket()) // prevent VPN loop
                try {
                    sc.connect(InetSocketAddress(dstIp, dstPort))
                    // Wait shortly for connect
                    val start = System.currentTimeMillis()
                    val timeout = 2000L
                    while (!sc.finishConnect()) {
                        if (System.currentTimeMillis() - start > timeout) break
                        Thread.sleep(5)
                    }
                    if (!sc.isConnected) {
                        sc.close()
                        Log.w(TAG, "TCP connect timeout: $key")
                        return
                    }
                } catch (e: Exception) {
                    try { sc.close() } catch (_: Exception) {}
                    Log.e(TAG, "TCP connect error for $key", e)
                    return
                }

                session = TcpSession(srcIp, srcPort, dstIp, dstPort, sc)
                tcpSessions[key] = session
                // Start reading responses
                executor.execute { readTcpResponses(session, outputStream) }
                Log.d(TAG, "New TCP session: $key")
            }

            session.lastActivity = System.currentTimeMillis()

            // Extract TCP payload and write to remote socket
            val tcpHeaderLen = ((buffer[ihl + 12].toInt() and 0xF0) shr 4) * 4
            val payloadStart = ihl + tcpHeaderLen
            if (payloadStart < length) {
                val payloadLen = length - payloadStart
                val payload = ByteBuffer.wrap(buffer, payloadStart, payloadLen)
                // Non-blocking write; try until all bytes written or small retries
                var remain = payloadLen
                var attempts = 0
                while (remain > 0 && attempts < 100) {
                    val written = session.channel.write(payload)
                    if (written <= 0) {
                        Thread.sleep(1)
                        attempts++
                    } else {
                        remain -= written
                    }
                }
            } else {
                // it's likely a pure ACK or SYN; still nothing to send to remote
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error in forwardTcp", e)
        }
    }

    private fun readTcpResponses(session: TcpSession, outputStream: FileOutputStream) {
        val key = session.key()
        val buffer = ByteBuffer.allocate(VPN_MTU)
        try {
            while (isRunning.get() && session.channel.isOpen) {
                buffer.clear()
                val read = try { session.channel.read(buffer) } catch (e: IOException) { -1 }
                if (read > 0) {
                    val data = ByteArray(read)
                    buffer.flip()
                    buffer.get(data, 0, read)
                    // Build a synthetic IP/TCP packet from remote->local data
                    val packet = buildTcpResponsePacket(session, data, read)
                    synchronized(outputStream) {
                        try {
                            outputStream.write(packet)
                        } catch (e: IOException) {
                            Log.e(TAG, "Error writing TCP response to TUN", e)
                        }
                    }
                    session.lastActivity = System.currentTimeMillis()
                } else if (read == -1) {
                    break
                } else {
                    // no data; sleep briefly to avoid busy loop
                    Thread.sleep(2)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error in readTcpResponses for $key", e)
        } finally {
            cleanupTcpSession(session)
        }
    }

    private fun cleanupTcpSession(session: TcpSession) {
        try { session.channel.close() } catch (_: Exception) {}
        tcpSessions.remove(session.key())
        Log.d(TAG, "Cleaned TCP session: ${session.key()}")
    }

    // ---- UDP Forwarding ----
    private fun forwardUdp(buffer: ByteArray, length: Int, srcIp: InetAddress, dstIp: InetAddress, outputStream: FileOutputStream) {
        try {
            val ihl = (buffer[0].toInt() and 0x0F) * 4
            if (length < ihl + 8) return
            val srcPort = ((buffer[ihl].toInt() and 0xFF) shl 8) or (buffer[ihl + 1].toInt() and 0xFF)
            val dstPort = ((buffer[ihl + 2].toInt() and 0xFF) shl 8) or (buffer[ihl + 3].toInt() and 0xFF)
            val key = "${srcIp.hostAddress}:$srcPort-${dstIp.hostAddress}:$dstPort"

            var session = udpSessions[key]
            if (session == null) {
                try {
                    val dc = DatagramChannel.open()
                    protect(dc.socket())
                    dc.configureBlocking(false)
                    dc.connect(InetSocketAddress(dstIp, dstPort))
                    session = UdpSession(srcIp, srcPort, dstIp, dstPort, dc)
                    udpSessions[key] = session
                    executor.execute { readUdpResponses(session, outputStream) }
                    Log.d(TAG, "New UDP session: $key")
                } catch (e: Exception) {
                    Log.e(TAG, "Failed to create UDP session $key", e)
                    return
                }
            }

            session.lastActivity = System.currentTimeMillis()
            val payloadStart = ihl + 8
            if (payloadStart < length) {
                val payloadLen = length - payloadStart
                val payload = ByteBuffer.wrap(buffer, payloadStart, payloadLen)
                // write to datagram channel
                var attempts = 0
                while (payload.hasRemaining() && attempts < 10) {
                    val written = session.channel.write(payload)
                    if (written <= 0) {
                        Thread.sleep(1)
                        attempts++
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error in forwardUdp", e)
        }
    }

    private fun readUdpResponses(session: UdpSession, outputStream: FileOutputStream) {
        val key = session.key()
        val buffer = ByteBuffer.allocate(VPN_MTU)
        try {
            while (isRunning.get() && session.channel.isConnected) {
                buffer.clear()
                val read = try { session.channel.read(buffer) } catch (e: IOException) { -1 }
                if (read > 0) {
                    val data = ByteArray(read)
                    buffer.flip()
                    buffer.get(data, 0, read)
                    val packet = buildUdpResponsePacket(session, data, read)
                    synchronized(outputStream) {
                        try {
                            outputStream.write(packet)
                        } catch (e: IOException) {
                            Log.e(TAG, "Error writing UDP response to TUN", e)
                        }
                    }
                    session.lastActivity = System.currentTimeMillis()
                } else if (read == -1) {
                    break
                } else {
                    Thread.sleep(2)
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error in readUdpResponses for $key", e)
        } finally {
            cleanupUdpSession(session)
        }
    }

    private fun cleanupUdpSession(session: UdpSession) {
        try { session.channel.close() } catch (_: Exception) {}
        udpSessions.remove(session.key())
        Log.d(TAG, "Cleaned UDP session: ${session.key()}")
    }

    // ---- Packet builders (IP + TCP/UDP header + payload) ----
    // Note: simplified headers. For robust TCP behavior, full seq/ack handling is required.

    private fun buildTcpResponsePacket(session: TcpSession, data: ByteArray, dataLen: Int): ByteArray {
        // IP(20) + TCP(20) + data
        val ipLen = 20
        val tcpLen = 20
        val total = ipLen + tcpLen + dataLen
        val buf = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN)

        // IP header
        val versionIhl = (4 shl 4) or (ipLen / 4)
        buf.put(versionIhl.toByte()) // v + ihl
        buf.put(0.toByte()) // tos
        buf.putShort((total).toShort()) // total length
        buf.putShort(0.toShort()) // id
        buf.putShort(0.toShort()) // flags+frag
        buf.put(64.toByte()) // TTL
        buf.put(6.toByte()) // protocol TCP
        buf.putShort(0.toShort()) // checksum placeholder
        // source = remote server, dest = device VPN IP
        buf.put(session.dstIp.address)
        buf.put(session.srcIp.address)

        // compute IP checksum
        val ipArr = buf.array()
        val ipChecksum = calculateChecksum(ipArr, 0, ipLen)
        buf.putShort(10, ipChecksum)

        // TCP header
        buf.position(ipLen)
        buf.putShort(session.dstPort.toShort()) // source port (remote)
        buf.putShort(session.srcPort.toShort()) // dest port (device)
        buf.putInt(0) // seq (simplified)
        buf.putInt(0) // ack (simplified)
        // data offset (5) << 4, flags (PSH+ACK = 0x18)
        buf.putShort(((tcpLen / 4) shl 12 or 0x018).toShort())
        buf.putShort(8192.toShort()) // window
        buf.putShort(0.toShort()) // checksum placeholder
        buf.putShort(0.toShort()) // urgent pointer

        // data
        buf.put(data, 0, dataLen)

        // compute TCP checksum (pseudo-header)
        val tcpChecksum = calculateTcpChecksum(buf.array(), ipLen, tcpLen + dataLen)
        buf.putShort(ipLen + 16, tcpChecksum)

        return buf.array()
    }

    private fun buildUdpResponsePacket(session: UdpSession, data: ByteArray, dataLen: Int): ByteArray {
        val ipLen = 20
        val udpLen = 8
        val total = ipLen + udpLen + dataLen
        val buf = ByteBuffer.allocate(total).order(ByteOrder.BIG_ENDIAN)

        // IP header
        val versionIhl = (4 shl 4) or (ipLen / 4)
        buf.put(versionIhl.toByte())
        buf.put(0.toByte())
        buf.putShort(total.toShort())
        buf.putShort(0.toShort())
        buf.putShort(0.toShort())
        buf.put(64.toByte())
        buf.put(17.toByte()) // UDP
        buf.putShort(0.toShort())
        buf.put(session.dstIp.address)
        buf.put(session.srcIp.address)

        val ipArr = buf.array()
        val ipChecksum = calculateChecksum(ipArr, 0, ipLen)
        buf.putShort(10, ipChecksum)

        // UDP header
        buf.position(ipLen)
        buf.putShort(session.dstPort.toShort()) // source (remote)
        buf.putShort(session.srcPort.toShort()) // dest (device)
        buf.putShort((udpLen + dataLen).toShort())
        buf.putShort(0.toShort()) // checksum (optional in IPv4)

        // data
        buf.put(data, 0, dataLen)
        return buf.array()
    }

    // ---- Checksums ----
    private fun calculateChecksum(data: ByteArray, offset: Int, length: Int): Short {
        var sum = 0L
        var i = offset
        while (i < offset + length) {
            val hi = (data[i].toInt() and 0xFF)
            val lo = if (i + 1 < offset + length) (data[i + 1].toInt() and 0xFF) else 0
            sum += (hi shl 8) + lo
            i += 2
        }
        while (sum shr 16 > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        val checksum = sum.inv() and 0xFFFF
        return checksum.toShort()
    }

    private fun calculateTcpChecksum(packet: ByteArray, tcpOffset: Int, tcpLen: Int): Short {
        var sum = 0L
        // pseudo-header: src(4) + dst(4) + protocol(1) + tcpLen(2)
        // packet contains IP header in bytes 0..19
        // src ip bytes 12..15, dst ip 16..19
        sum += ((packet[12].toInt() and 0xFF) shl 8) + (packet[13].toInt() and 0xFF)
        sum += ((packet[14].toInt() and 0xFF) shl 8) + (packet[15].toInt() and 0xFF)
        sum += ((packet[16].toInt() and 0xFF) shl 8) + (packet[17].toInt() and 0xFF)
        sum += ((packet[18].toInt() and 0xFF) shl 8) + (packet[19].toInt() and 0xFF)
        sum += 6 // protocol number for TCP
        sum += tcpLen // tcp length

        var i = tcpOffset
        while (i < tcpOffset + tcpLen) {
            val hi = (packet[i].toInt() and 0xFF)
            val lo = if (i + 1 < tcpOffset + tcpLen) (packet[i + 1].toInt() and 0xFF) else 0
            sum += (hi shl 8) + lo
            i += 2
        }
        while (sum shr 16 > 0) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }
        val checksum = sum.inv() and 0xFFFF
        return checksum.toShort()
    }

    // ---- Session cleanup ----
    private fun startSessionCleanup() {
        scheduled.scheduleAtFixedRate({
            try {
                val now = System.currentTimeMillis()
                val tcpToRemove = tcpSessions.values.filter { now - it.lastActivity > SESSION_TIMEOUT_MS }
                for (s in tcpToRemove) cleanupTcpSession(s)
                val udpToRemove = udpSessions.values.filter { now - it.lastActivity > SESSION_TIMEOUT_MS }
                for (s in udpToRemove) cleanupUdpSession(s)
            } catch (e: Exception) {
                Log.e(TAG, "Error during session cleanup", e)
            }
        }, CLEANUP_INTERVAL_SEC, CLEANUP_INTERVAL_SEC, TimeUnit.SECONDS)
    }

    // ---- Notifications ----
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel("VPN_CHANNEL", "VPN Service", NotificationManager.IMPORTANCE_LOW)
            val manager = getSystemService(NotificationManager::class.java)
            manager?.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java)
        val pendingIntent = PendingIntent.getActivity(this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE)
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, "VPN_CHANNEL")
                .setContentTitle("Packet Analyzer Active")
                .setContentText("Monitoring network traffic")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .setContentIntent(pendingIntent)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("Packet Analyzer Active")
                .setContentText("Monitoring network traffic")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .setContentIntent(pendingIntent)
                .build()
        }
    }

    override fun onDestroy() {
        Log.d(TAG, "Stopping VPN service")
        isRunning.set(false)
        try { vpnInterface?.close() } catch (_: Exception) {}
        vpnInterface = null

        try { scheduled.shutdownNow() } catch (_: Exception) {}
        try { executor.shutdownNow() } catch (_: Exception) {}

        // Cleanup sessions
        tcpSessions.values.forEach { try { it.channel.close() } catch (_: Exception) {} }
        tcpSessions.clear()
        udpSessions.values.forEach { try { it.channel.close() } catch (_: Exception) {} }
        udpSessions.clear()

        super.onDestroy()
    }
}
