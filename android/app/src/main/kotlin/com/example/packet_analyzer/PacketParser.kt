package com.example.packet_analyzer

import android.util.Log
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.*

object PacketParser {

    data class PacketInfo(
        val timestamp: Long,
        val protocol: String,
        val sourceIP: String,
        val destIP: String,
        val sourcePort: Int?,
        val destPort: Int?,
        val length: Int,
        val flags: String?,
        val payload: String?
    )

    fun parsePacket(packet: ByteArray): PacketInfo? {
        try {
            if (packet.size < 20) {
                Log.d("PacketParser", "Packet too small: ${packet.size} bytes")
                return null
            }

            // Validate packet size is reasonable (not corrupted)
            if (packet.size > 65535) {
                Log.d("PacketParser", "Packet too large (possibly corrupted): ${packet.size} bytes")
                return null
            }

            val buffer = ByteBuffer.wrap(packet)

            // Parse IP header
            val versionAndIHL = buffer.get().toInt() and 0xFF
            val version = (versionAndIHL shr 4) and 0xF

            Log.d("PacketParser", "Parsing packet: ${packet.size} bytes, IP version: $version")

            // Handle both IPv4 and IPv6
            return when (version) {
                4 -> parseIPv4Packet(buffer, versionAndIHL)
                6 -> parseIPv6Packet(buffer, packet)
                else -> {
                    Log.d("PacketParser", "Unknown IP version: $version, first bytes: ${packet.take(8).joinToString(" ") { "%02x".format(it) }}")
                    null
                }
            }
        } catch (e: Exception) {
            Log.e("PacketParser", "Error parsing packet: ${e.message}")
            return null
        }
    }

    private fun parseIPv4Packet(buffer: ByteBuffer, versionAndIHL: Int): PacketInfo? {
        try {
            val ihl = (versionAndIHL and 0xF) * 4 // Internet Header Length in bytes

            buffer.get() // Type of Service
            val totalLength = buffer.short.toInt() and 0xFFFF
            buffer.short // Identification
            buffer.short // Flags and Fragment Offset
            buffer.get() // TTL
            val protocol = buffer.get().toInt() and 0xFF
            buffer.short // Header Checksum

            // Validate total length
            if (totalLength > 65535 || totalLength < ihl) {
                Log.d("PacketParser", "Invalid IPv4 total length: $totalLength (IHL: $ihl)")
                return null
            }

            // Source and Destination IP
            val sourceIPBytes = ByteArray(4)
            buffer.get(sourceIPBytes)
            val destIPBytes = ByteArray(4)
            buffer.get(destIPBytes)

            val sourceIP = InetAddress.getByAddress(sourceIPBytes).hostAddress
            val destIP = InetAddress.getByAddress(destIPBytes).hostAddress

            // DEBUG: Log IP addresses to identify zero IP issue
            Log.d("PacketParser", "🔍 IPv4 IPs: Source=${sourceIP}, Dest=${destIP}")
            Log.d("PacketParser", "🔍 Raw IP bytes: Source=${sourceIPBytes.joinToString(".") { (it.toInt() and 0xFF).toString() }}, Dest=${destIPBytes.joinToString(".") { (it.toInt() and 0xFF).toString() }}")

            // Skip IP options if present
            if (ihl > 20) {
                buffer.position(ihl)
            }

            val protocolName: String
            var sourcePort: Int? = null
            var destPort: Int? = null
            var flags: String? = null
            var payload: String? = null

            when (protocol) {
                1 -> { // ICMP
                    protocolName = "ICMP"
                    if (buffer.remaining() >= 8) {
                        val type = buffer.get().toInt() and 0xFF
                        val code = buffer.get().toInt() and 0xFF
                        flags = "Type:$type Code:$code"
                    }
                }
                6 -> { // TCP
                    if (buffer.remaining() >= 20) {
                        sourcePort = buffer.short.toInt() and 0xFFFF
                        destPort = buffer.short.toInt() and 0xFFFF
                        buffer.int // Sequence number
                        buffer.int // Acknowledgment number
                        val dataOffsetAndFlags = buffer.short.toInt() and 0xFFFF
                        val tcpFlags = dataOffsetAndFlags and 0x1FF

                        // Enhanced protocol detection based on port numbers
                        protocolName = when {
                            destPort == 80 || sourcePort == 80 -> "HTTP"
                            destPort == 443 || sourcePort == 443 -> "HTTPS"
                            destPort == 21 || sourcePort == 21 -> "FTP"
                            destPort == 22 || sourcePort == 22 -> "SSH"
                            destPort == 23 || sourcePort == 23 -> "Telnet"
                            destPort == 25 || sourcePort == 25 -> "SMTP"
                            destPort == 110 || sourcePort == 110 -> "POP3"
                            destPort == 143 || sourcePort == 143 -> "IMAP"
                            destPort == 993 || sourcePort == 993 -> "IMAPS"
                            destPort == 995 || sourcePort == 995 -> "POP3S"
                            destPort == 587 || sourcePort == 587 -> "SMTP"
                            destPort in 8000..8999 || sourcePort in 8000..8999 -> "HTTP-Alt"
                            else -> "TCP"
                        }

                        val flagsList = mutableListOf<String>()
                        if ((tcpFlags and 0x01) != 0) flagsList.add("FIN")
                        if ((tcpFlags and 0x02) != 0) flagsList.add("SYN")
                        if ((tcpFlags and 0x04) != 0) flagsList.add("RST")
                        if ((tcpFlags and 0x08) != 0) flagsList.add("PSH")
                        if ((tcpFlags and 0x10) != 0) flagsList.add("ACK")
                        if ((tcpFlags and 0x20) != 0) flagsList.add("URG")

                        flags = flagsList.joinToString("|")

                        // Extract payload for common ports
                        val dataOffset = ((dataOffsetAndFlags shr 12) and 0xF) * 4
                        if (buffer.remaining() >= dataOffset - 14) { // Adjust for already read bytes
                            buffer.position(buffer.position() + (dataOffset - 14))
                            if (buffer.remaining() > 0) {
                                val payloadSize = minOf(100, buffer.remaining()) // Limit payload size
                                val payloadBytes = ByteArray(payloadSize)
                                buffer.get(payloadBytes)
                                payload = extractReadablePayload(payloadBytes, destPort ?: 0)
                            }
                        }
                    } else {
                        protocolName = "TCP"
                    }
                }
                17 -> { // UDP
                    if (buffer.remaining() >= 8) {
                        sourcePort = buffer.short.toInt() and 0xFFFF
                        destPort = buffer.short.toInt() and 0xFFFF
                        val length = buffer.short.toInt() and 0xFFFF
                        buffer.short // Checksum

                        // Enhanced UDP protocol detection based on port numbers
                        protocolName = when {
                            destPort == 53 || sourcePort == 53 -> "DNS"
                            destPort == 67 || sourcePort == 67 -> "DHCP"
                            destPort == 68 || sourcePort == 68 -> "DHCP"
                            destPort == 123 || sourcePort == 123 -> "NTP"
                            destPort == 161 || sourcePort == 161 -> "SNMP"
                            destPort == 162 || sourcePort == 162 -> "SNMP-Trap"
                            destPort == 443 || sourcePort == 443 -> "QUIC/HTTP3"
                            destPort == 853 || sourcePort == 853 -> "DNS-over-TLS"
                            destPort == 1701 || sourcePort == 1701 -> "L2TP"
                            destPort == 1723 || sourcePort == 1723 -> "PPTP"
                            destPort == 4500 || sourcePort == 4500 -> "IPSec-NAT-T"
                            destPort == 5353 || sourcePort == 5353 -> "mDNS"
                            destPort in 3478..3479 || sourcePort in 3478..3479 -> "STUN"
                            destPort in 5060..5061 || sourcePort in 5060..5061 -> "SIP"
                            destPort in 27000..28000 || sourcePort in 27000..28000 -> "Gaming"
                            destPort in 6881..6999 || sourcePort in 6881..6999 -> "BitTorrent"
                            else -> "UDP"
                        }

                        // Extract payload for DNS and other protocols
                        if (buffer.remaining() > 0) {
                            val payloadSize = minOf(100, buffer.remaining())
                            val payloadBytes = ByteArray(payloadSize)
                            buffer.get(payloadBytes)
                            payload = extractReadablePayload(payloadBytes, destPort ?: 0)
                        }
                    } else {
                        protocolName = "UDP"
                    }
                }
                else -> {
                    protocolName = "Protocol:$protocol"
                }
            }

            val timestamp = System.currentTimeMillis()

            return PacketInfo(
                timestamp = timestamp,
                protocol = protocolName,
                sourceIP = sourceIP ?: "Unknown",
                destIP = destIP ?: "Unknown",
                sourcePort = sourcePort,
                destPort = destPort,
                length = totalLength,
                flags = flags,
                payload = payload
            )

        } catch (e: Exception) {
            Log.e("PacketParser", "Error parsing IPv4 packet: ${e.message}")
            return null
        }
    }

    private fun parseIPv6Packet(buffer: ByteBuffer, packet: ByteArray): PacketInfo? {
        try {
            if (packet.size < 40) return null // Minimum IPv6 header size

            // Reset buffer to start
            buffer.rewind()

            // Parse IPv6 header properly
            val versionAndTrafficClass = buffer.get().toInt() and 0xFF
            val version = (versionAndTrafficClass shr 4) and 0xF

            // Verify this is actually IPv6
            if (version != 6) {
                Log.d("PacketParser", "Invalid IPv6 version: $version")
                return null
            }

            // Read remaining header fields
            val trafficClassLowAndFlowLabelHigh = buffer.get().toInt() and 0xFF
            val flowLabelMid = buffer.get().toInt() and 0xFF
            val flowLabelLow = buffer.get().toInt() and 0xFF

            val payloadLength = buffer.short.toInt() and 0xFFFF
            val nextHeader = buffer.get().toInt() and 0xFF // Protocol
            val hopLimit = buffer.get().toInt() and 0xFF // TTL equivalent

            // Validate payload length
            if (payloadLength > 65535 || payloadLength < 0) {
                Log.d("PacketParser", "Invalid IPv6 payload length: $payloadLength")
                return null
            }

            // Source IPv6 address (16 bytes)
            val sourceIPBytes = ByteArray(16)
            buffer.get(sourceIPBytes)

            // Destination IPv6 address (16 bytes)
            val destIPBytes = ByteArray(16)
            buffer.get(destIPBytes)

            val sourceIP = try {
                InetAddress.getByAddress(sourceIPBytes).hostAddress
            } catch (e: Exception) {
                "invalid-ipv6-source"
            }

            val destIP = try {
                InetAddress.getByAddress(destIPBytes).hostAddress
            } catch (e: Exception) {
                "invalid-ipv6-dest"
            }

            // Parse protocol-specific data
            var protocolName = "IPv6"
            var sourcePort: Int? = null
            var destPort: Int? = null
            var flags: String? = null
            var payload: String? = null

            when (nextHeader) {
                6 -> { // TCP
                    protocolName = "TCP"
                    if (buffer.remaining() >= 20) {
                        sourcePort = buffer.short.toInt() and 0xFFFF
                        destPort = buffer.short.toInt() and 0xFFFF
                        buffer.int // Sequence number
                        buffer.int // Acknowledgment number
                        val dataOffsetAndFlags = buffer.short.toInt() and 0xFFFF
                        val tcpFlags = dataOffsetAndFlags and 0x1FF

                        val flagsList = mutableListOf<String>()
                        if ((tcpFlags and 0x01) != 0) flagsList.add("FIN")
                        if ((tcpFlags and 0x02) != 0) flagsList.add("SYN")
                        if ((tcpFlags and 0x04) != 0) flagsList.add("RST")
                        if ((tcpFlags and 0x08) != 0) flagsList.add("PSH")
                        if ((tcpFlags and 0x10) != 0) flagsList.add("ACK")
                        if ((tcpFlags and 0x20) != 0) flagsList.add("URG")

                        flags = flagsList.joinToString("|")
                    }
                }
                17 -> { // UDP
                    protocolName = "UDP"
                    if (buffer.remaining() >= 8) {
                        sourcePort = buffer.short.toInt() and 0xFFFF
                        destPort = buffer.short.toInt() and 0xFFFF
                        val length = buffer.short.toInt() and 0xFFFF
                        buffer.short // Checksum

                        if (buffer.remaining() > 0) {
                            val payloadSize = minOf(100, buffer.remaining())
                            val payloadBytes = ByteArray(payloadSize)
                            buffer.get(payloadBytes)
                            payload = extractReadablePayload(payloadBytes, destPort ?: 0)
                        }
                    }
                }
                58 -> { // ICMPv6
                    protocolName = "ICMPv6"
                    if (buffer.remaining() >= 4) {
                        val type = buffer.get().toInt() and 0xFF
                        val code = buffer.get().toInt() and 0xFF
                        flags = "Type:$type Code:$code"
                    }
                }
                else -> {
                    protocolName = "IPv6-$nextHeader"
                }
            }

            val timestamp = System.currentTimeMillis()

            return PacketInfo(
                timestamp = timestamp,
                protocol = protocolName,
                sourceIP = sourceIP ?: "Unknown",
                destIP = destIP ?: "Unknown",
                sourcePort = sourcePort,
                destPort = destPort,
                length = payloadLength + 40, // Add IPv6 header size
                flags = flags,
                payload = payload
            )

        } catch (e: Exception) {
            Log.e("PacketParser", "Error parsing IPv6 packet: ${e.message}")
            return null
        }
    }

    private fun extractReadablePayload(payloadBytes: ByteArray, port: Int): String? {
        return when (port) {
            // DNS (Domain Name System)
            53 -> { // DNS
                try {
                    if (payloadBytes.size >= 12) {
                        val transactionId = ((payloadBytes[0].toInt() and 0xFF) shl 8) or (payloadBytes[1].toInt() and 0xFF)
                        val flags = ((payloadBytes[2].toInt() and 0xFF) shl 8) or (payloadBytes[3].toInt() and 0xFF)
                        val isQuery = (flags and 0x8000) == 0
                        "DNS ${if (isQuery) "Query" else "Response"} (ID:$transactionId)"
                    } else null
                } catch (e: Exception) { null }
            }
            // HTTP (HyperText Transfer Protocol)
            80, 8080, 8000, 3000 -> { // HTTP
                try {
                    val payloadStr = String(payloadBytes, Charsets.UTF_8)
                    val lines = payloadStr.split("\r\n")
                    if (lines.isNotEmpty() && (lines[0].startsWith("GET") || lines[0].startsWith("POST") ||
                        lines[0].startsWith("PUT") || lines[0].startsWith("DELETE") || lines[0].startsWith("HTTP"))) {
                        "HTTP: ${lines[0].take(60)}${if (lines[0].length > 60) "..." else ""}"
                    } else null
                } catch (e: Exception) { null }
            }

            // HTTPS/TLS (HTTP Secure)
            443, 8443 -> { // HTTPS/TLS
                try {
                    if (payloadBytes.size >= 5 && payloadBytes[0] == 0x16.toByte()) {
                        "HTTPS TLS Handshake"
                    } else if (payloadBytes.size >= 5 && payloadBytes[0] == 0x17.toByte()) {
                        "HTTPS Application Data"
                    } else if (payloadBytes.size >= 5 && payloadBytes[0] == 0x15.toByte()) {
                        "HTTPS TLS Alert"
                    } else null
                } catch (e: Exception) { null }
            }

            // FTP (File Transfer Protocol)
            21 -> { // FTP Control
                try {
                    val payloadStr = String(payloadBytes, Charsets.UTF_8)
                    if (payloadStr.matches(Regex("^[0-9]{3} .*"))) {
                        "FTP Response: ${payloadStr.take(40)}${if (payloadStr.length > 40) "..." else ""}"
                    } else {
                        "FTP Command: ${payloadStr.take(40)}${if (payloadStr.length > 40) "..." else ""}"
                    }
                } catch (e: Exception) { null }
            }
            20 -> { // FTP Data
                "FTP Data Transfer"
            }

            // SSH (Secure Shell)
            22 -> { // SSH
                try {
                    val payloadStr = String(payloadBytes, Charsets.UTF_8)
                    when {
                        payloadStr.startsWith("SSH-") -> "SSH Protocol: ${payloadStr.take(30)}"
                        payloadBytes.size >= 4 -> "SSH Encrypted Data"
                        else -> null
                    }
                } catch (e: Exception) { "SSH Data" }
            }

            // SMTP (Simple Mail Transfer Protocol)
            25, 587 -> { // SMTP
                try {
                    val payloadStr = String(payloadBytes, Charsets.UTF_8)
                    when {
                        payloadStr.matches(Regex("^[0-9]{3} .*")) -> "SMTP Response: ${payloadStr.take(40)}"
                        payloadStr.startsWith("HELO") || payloadStr.startsWith("EHLO") -> "SMTP Handshake"
                        payloadStr.startsWith("MAIL FROM") -> "SMTP Mail From"
                        payloadStr.startsWith("RCPT TO") -> "SMTP Recipient"
                        payloadStr.startsWith("DATA") -> "SMTP Data"
                        else -> "SMTP: ${payloadStr.take(30)}"
                    }
                } catch (e: Exception) { "SMTP Data" }
            }

            // POP3 (Post Office Protocol)
            110, 995 -> { // POP3/POP3S
                try {
                    val payloadStr = String(payloadBytes, Charsets.UTF_8)
                    when {
                        payloadStr.startsWith("+OK") -> "POP3 OK: ${payloadStr.take(40)}"
                        payloadStr.startsWith("-ERR") -> "POP3 Error: ${payloadStr.take(40)}"
                        payloadStr.startsWith("USER") -> "POP3 Login"
                        payloadStr.startsWith("RETR") -> "POP3 Retrieve"
                        else -> "POP3: ${payloadStr.take(30)}"
                    }
                } catch (e: Exception) { if (port == 995) "POP3S Data" else "POP3 Data" }
            }

            // IMAP (Internet Message Access Protocol)
            143, 993 -> { // IMAP/IMAPS
                try {
                    val payloadStr = String(payloadBytes, Charsets.UTF_8)
                    when {
                        payloadStr.contains("* OK") -> "IMAP Server Ready"
                        payloadStr.contains("LOGIN") -> "IMAP Login"
                        payloadStr.contains("SELECT") -> "IMAP Select Folder"
                        payloadStr.contains("FETCH") -> "IMAP Fetch Messages"
                        else -> "IMAP: ${payloadStr.take(30)}"
                    }
                } catch (e: Exception) { if (port == 993) "IMAPS Data" else "IMAP Data" }
            }

            // SNMP (Simple Network Management Protocol)
            161, 162 -> { // SNMP
                "SNMP ${if (port == 161) "Request" else "Trap"}"
            }

            // NTP (Network Time Protocol)
            123 -> { // NTP
                "NTP Time Sync"
            }

            // DHCP (Dynamic Host Configuration Protocol)
            67, 68 -> { // DHCP
                "DHCP ${if (port == 67) "Server" else "Client"}"
            }

            // Telnet
            23 -> { // Telnet
                try {
                    val payloadStr = String(payloadBytes, Charsets.UTF_8)
                    "Telnet: ${payloadStr.take(30)}${if (payloadStr.length > 30) "..." else ""}"
                } catch (e: Exception) { "Telnet Data" }
            }

            // Gaming and VoIP protocols
            3478, 3479 -> "STUN/TURN" // WebRTC
            5060, 5061 -> "SIP ${if (port == 5061) "(Secure)" else ""}" // VoIP
            1935 -> "RTMP" // Streaming
            4444 -> "RTP/RTCP" // Media streaming
            else -> {
                // Try to extract readable ASCII text
                try {
                    val readable = payloadBytes.filter { it in 32..126 }.toByteArray()
                    if (readable.size >= 4) {
                        String(readable).take(30) + if (readable.size > 30) "..." else ""
                    } else null
                } catch (e: Exception) { null }
            }
        }
    }
}