package com.example.packet_analyzer

import android.util.Log
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets

/**
 * Deep Packet Inspection (DPI) - Protocol Dissectors
 * Parses payload data for HTTP, DNS, and other protocols
 */
object PacketDissector {
    private const val TAG = "PacketDissector"

    // File carving and payload analysis
    private val payloadAnalyzer = PayloadAnalyzer()

    /**
     * Dissect a packet and extract application-layer details
     */
    fun dissect(packetInfo: Map<String, Any>, payload: ByteArray?): Map<String, Any> {
        val protocol = packetInfo["protocol"] as? String ?: return packetInfo
        val destPort = (packetInfo["destinationPort"] as? Int) ?: 0
        val sourcePort = (packetInfo["sourcePort"] as? Int) ?: 0

        if (payload == null || payload.isEmpty()) {
            return packetInfo
        }

        val enrichedInfo = packetInfo.toMutableMap()

        try {
            when {
                // HTTP traffic
                protocol == "TCP" && (destPort == 80 || sourcePort == 80 ||
                                     destPort == 8080 || sourcePort == 8080) -> {
                    val httpData = parseHttp(payload)
                    if (httpData.isNotEmpty()) {
                        enrichedInfo["httpData"] = httpData
                        enrichedInfo["appName"] = "HTTP"
                    }
                }

                // HTTPS traffic (limited info - encrypted)
                protocol == "TCP" && (destPort == 443 || sourcePort == 443) -> {
                    val tlsData = parseTls(payload)
                    if (tlsData.isNotEmpty()) {
                        enrichedInfo["tlsData"] = tlsData
                    }
                }

                // DNS traffic
                protocol == "UDP" && (destPort == 53 || sourcePort == 53) -> {
                    val dnsData = parseDns(payload)
                    if (dnsData.isNotEmpty()) {
                        enrichedInfo["dnsData"] = dnsData
                        enrichedInfo["appName"] = "DNS"
                    }
                }

                // QUIC traffic (UDP port 443, 80 - HTTP/3 over QUIC)
                protocol == "UDP" && (destPort == 443 || sourcePort == 443 ||
                                     destPort == 80 || sourcePort == 80) -> {
                    val quicData = parseQuic(payload)
                    if (quicData.isNotEmpty()) {
                        enrichedInfo["quicData"] = quicData
                        enrichedInfo["appName"] = "QUIC"
                    }
                }

                // SIP traffic (VoIP)
                (protocol == "UDP" || protocol == "TCP") && (destPort == 5060 || sourcePort == 5060 ||
                                                               destPort == 5061 || sourcePort == 5061) -> {
                    val sipData = parseSip(payload)
                    if (sipData.isNotEmpty()) {
                        enrichedInfo["sipData"] = sipData
                        enrichedInfo["appName"] = "SIP"
                    }
                }

                // RTP traffic (Real-time Transport Protocol)
                protocol == "UDP" && isRtpPort(destPort) -> {
                    val rtpData = parseRtp(payload)
                    if (rtpData.isNotEmpty()) {
                        enrichedInfo["rtpData"] = rtpData
                        enrichedInfo["appName"] = "RTP"
                    }
                }

                // SMB traffic (Windows file sharing)
                protocol == "TCP" && (destPort == 445 || sourcePort == 445) -> {
                    val smbData = parseSmb(payload)
                    if (smbData.isNotEmpty()) {
                        enrichedInfo["smbData"] = smbData
                        enrichedInfo["appName"] = "SMB"
                    }
                }

                // NTP traffic (Network Time Protocol)
                protocol == "UDP" && (destPort == 123 || sourcePort == 123) -> {
                    val ntpData = parseNtp(payload)
                    if (ntpData.isNotEmpty()) {
                        enrichedInfo["ntpData"] = ntpData
                        enrichedInfo["appName"] = "NTP"
                    }
                }
            }

            // Analyze payload for files and security risks
            val payloadAnalysis = payloadAnalyzer.analyzePayload(payload, packetInfo)
            if (payloadAnalysis.isNotEmpty()) {
                enrichedInfo["payloadAnalysis"] = payloadAnalysis
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error dissecting packet: ${e.message}")
        }

        return enrichedInfo
    }

    /**
     * Parse HTTP request/response
     */
    private fun parseHttp(payload: ByteArray): Map<String, String> {
        try {
            val httpText = String(payload, StandardCharsets.UTF_8)
            val lines = httpText.split("\r\n", "\n")

            if (lines.isEmpty()) return emptyMap()

            val result = mutableMapOf<String, String>()
            val firstLine = lines[0]

            // Check if it's HTTP request or response
            if (firstLine.startsWith("HTTP/")) {
                // HTTP Response
                val parts = firstLine.split(" ", limit = 3)
                if (parts.size >= 3) {
                    result["type"] = "response"
                    result["version"] = parts[0]
                    result["statusCode"] = parts[1]
                    result["statusMessage"] = parts[2]
                }
            } else if (firstLine.contains("HTTP/")) {
                // HTTP Request
                val parts = firstLine.split(" ")
                if (parts.size >= 3) {
                    result["type"] = "request"
                    result["method"] = parts[0]
                    result["uri"] = parts[1]
                    result["version"] = parts[2]
                }
            } else {
                return emptyMap()
            }

            // Parse headers
            val headers = mutableMapOf<String, String>()
            for (i in 1 until lines.size) {
                val line = lines[i].trim()
                if (line.isEmpty()) break // End of headers

                val colonIndex = line.indexOf(':')
                if (colonIndex > 0) {
                    val key = line.substring(0, colonIndex).trim()
                    val value = line.substring(colonIndex + 1).trim()
                    headers[key] = value
                }
            }

            // Extract important headers
            headers["Host"]?.let { result["host"] = it }
            headers["User-Agent"]?.let { result["userAgent"] = it }
            headers["Content-Type"]?.let { result["contentType"] = it }
            headers["Content-Length"]?.let { result["contentLength"] = it }
            headers["Cookie"]?.let { result["hasCookies"] = "true" }
            headers["Authorization"]?.let { result["hasAuth"] = "true" }

            result["summary"] = when (result["type"]) {
                "request" -> "${result["method"]} ${result["uri"]}"
                "response" -> "HTTP ${result["statusCode"]} ${result["statusMessage"]}"
                else -> "HTTP Traffic"
            }

            return result

        } catch (e: Exception) {
            Log.e(TAG, "HTTP parse error: ${e.message}")
            return emptyMap()
        }
    }

    /**
     * Parse TLS/SSL handshake (limited - mostly encrypted)
     */
    private fun parseTls(payload: ByteArray): Map<String, String> {
        if (payload.size < 6) return emptyMap()

        try {
            val result = mutableMapOf<String, String>()

            // TLS record layer
            val contentType = payload[0].toInt() and 0xFF
            val majorVersion = payload[1].toInt() and 0xFF
            val minorVersion = payload[2].toInt() and 0xFF

            result["contentType"] = when (contentType) {
                20 -> "ChangeCipherSpec"
                21 -> "Alert"
                22 -> "Handshake"
                23 -> "Application"
                else -> "Unknown($contentType)"
            }

            result["version"] = when {
                majorVersion == 3 && minorVersion == 0 -> "SSL 3.0"
                majorVersion == 3 && minorVersion == 1 -> "TLS 1.0"
                majorVersion == 3 && minorVersion == 2 -> "TLS 1.1"
                majorVersion == 3 && minorVersion == 3 -> "TLS 1.2"
                majorVersion == 3 && minorVersion == 4 -> "TLS 1.3"
                else -> "Unknown"
            }

            // If it's a handshake, get handshake type
            if (contentType == 22 && payload.size > 5) {
                val handshakeType = payload[5].toInt() and 0xFF
                result["handshakeType"] = when (handshakeType) {
                    1 -> "ClientHello"
                    2 -> "ServerHello"
                    11 -> "Certificate"
                    12 -> "ServerKeyExchange"
                    14 -> "ServerHelloDone"
                    16 -> "ClientKeyExchange"
                    20 -> "Finished"
                    else -> "Unknown($handshakeType)"
                }
            }

            result["summary"] = "${result["version"]} ${result["contentType"]}"
            return result

        } catch (e: Exception) {
            Log.e(TAG, "TLS parse error: ${e.message}")
            return emptyMap()
        }
    }

    /**
     * Parse DNS query/response
     */
    private fun parseDns(payload: ByteArray): Map<String, String> {
        if (payload.size < 12) return emptyMap()

        try {
            val buffer = ByteBuffer.wrap(payload)
            val result = mutableMapOf<String, String>()

            // DNS Header
            val transactionId = buffer.getShort().toInt() and 0xFFFF
            val flags = buffer.getShort().toInt() and 0xFFFF

            val qr = (flags shr 15) and 0x1
            val opcode = (flags shr 11) and 0xF
            val aa = (flags shr 10) and 0x1
            val tc = (flags shr 9) and 0x1
            val rd = (flags shr 8) and 0x1
            val ra = (flags shr 7) and 0x1
            val rcode = flags and 0xF

            val qdCount = buffer.getShort().toInt() and 0xFFFF
            val anCount = buffer.getShort().toInt() and 0xFFFF
            val nsCount = buffer.getShort().toInt() and 0xFFFF
            val arCount = buffer.getShort().toInt() and 0xFFFF

            result["transactionId"] = transactionId.toString(16)
            result["type"] = if (qr == 0) "Query" else "Response"
            result["opcode"] = when (opcode) {
                0 -> "Standard Query"
                1 -> "Inverse Query"
                2 -> "Status"
                else -> "Unknown($opcode)"
            }

            result["responseCode"] = when (rcode) {
                0 -> "No Error"
                1 -> "Format Error"
                2 -> "Server Failure"
                3 -> "Name Error (NXDOMAIN)"
                4 -> "Not Implemented"
                5 -> "Refused"
                else -> "Unknown($rcode)"
            }

            result["questions"] = qdCount.toString()
            result["answers"] = anCount.toString()
            result["authorityRRs"] = nsCount.toString()
            result["additionalRRs"] = arCount.toString()

            // Parse query name
            if (qdCount > 0) {
                try {
                    val queryName = parseDnsName(buffer)
                    result["queryName"] = queryName

                    if (buffer.remaining() >= 4) {
                        val qType = buffer.getShort().toInt() and 0xFFFF
                        val qClass = buffer.getShort().toInt() and 0xFFFF

                        result["queryType"] = when (qType) {
                            1 -> "A (IPv4)"
                            2 -> "NS"
                            5 -> "CNAME"
                            6 -> "SOA"
                            12 -> "PTR"
                            15 -> "MX"
                            16 -> "TXT"
                            28 -> "AAAA (IPv6)"
                            33 -> "SRV"
                            else -> "Type $qType"
                        }

                        result["queryClass"] = if (qClass == 1) "IN (Internet)" else "Class $qClass"
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Could not parse DNS query name")
                }
            }

            result["summary"] = "${result["type"]}: ${result["queryName"] ?: "Unknown"} (${result["queryType"] ?: "?"})"
            return result

        } catch (e: Exception) {
            Log.e(TAG, "DNS parse error: ${e.message}")
            return emptyMap()
        }
    }

    /**
     * Parse DNS domain name from buffer
     */
    private fun parseDnsName(buffer: ByteBuffer): String {
        val parts = mutableListOf<String>()
        var maxLabels = 63 // Prevent infinite loops

        while (buffer.hasRemaining() && maxLabels-- > 0) {
            val length = buffer.get().toInt() and 0xFF

            if (length == 0) {
                break // End of name
            }

            if ((length and 0xC0) == 0xC0) {
                // Compression pointer - skip for now
                buffer.get() // Skip second byte of pointer
                break
            }

            if (buffer.remaining() < length) {
                break
            }

            val labelBytes = ByteArray(length)
            buffer.get(labelBytes)
            parts.add(String(labelBytes, StandardCharsets.UTF_8))
        }

        return if (parts.isEmpty()) "." else parts.joinToString(".")
    }

    /**
     * Parse DHCP packet
     */
    private fun parseDhcp(payload: ByteArray): Map<String, String> {
        if (payload.size < 240) return emptyMap()

        try {
            val result = mutableMapOf<String, String>()
            val buffer = ByteBuffer.wrap(payload)

            val op = buffer.get().toInt() and 0xFF
            result["messageType"] = if (op == 1) "Boot Request" else "Boot Reply"

            val htype = buffer.get().toInt() and 0xFF
            val hlen = buffer.get().toInt() and 0xFF
            val hops = buffer.get().toInt() and 0xFF

            val xid = buffer.getInt()
            result["transactionId"] = String.format("%08x", xid)

            // Skip secs, flags
            buffer.getShort()
            buffer.getShort()

            // IP addresses
            val ciaddr = readIpAddress(buffer)
            val yiaddr = readIpAddress(buffer)
            val siaddr = readIpAddress(buffer)
            val giaddr = readIpAddress(buffer)

            if (ciaddr != "0.0.0.0") result["clientIP"] = ciaddr
            if (yiaddr != "0.0.0.0") result["yourIP"] = yiaddr
            if (siaddr != "0.0.0.0") result["serverIP"] = siaddr
            if (giaddr != "0.0.0.0") result["gatewayIP"] = giaddr

            // Skip hardware address and server name
            buffer.position(buffer.position() + 16 + 64 + 128)

            // Check for magic cookie
            val magic = buffer.getInt()
            if (magic == 0x63825363) {
                result["hasMagicCookie"] = "true"
            }

            result["summary"] = result["messageType"] ?: "DHCP"
            return result

        } catch (e: Exception) {
            Log.e(TAG, "DHCP parse error: ${e.message}")
            return emptyMap()
        }
    }

    private fun readIpAddress(buffer: ByteBuffer): String {
        val bytes = ByteArray(4)
        buffer.get(bytes)
        return bytes.joinToString(".") { (it.toInt() and 0xFF).toString() }
    }

    /**
     * Check if port is in RTP range (5004, 10000-65535)
     */
    private fun isRtpPort(port: Int): Boolean {
        return port == 5004 || port in 10000..65535
    }

    /**
     * Parse QUIC (HTTP/3) packet
     */
    private fun parseQuic(payload: ByteArray): Map<String, String> {
        if (payload.size < 9) return emptyMap()

        try {
            val result = mutableMapOf<String, String>()
            val buffer = ByteBuffer.wrap(payload)

            // QUIC Long Header format (initial packets)
            val firstByte = buffer.get().toInt() and 0xFF
            val isLongHeader = (firstByte and 0x80) != 0

            if (isLongHeader) {
                val version = buffer.getInt()
                result["version"] = String.format("%08x", version)

                // Destination Connection ID Length
                val dcil = buffer.get().toInt() and 0xFF
                result["destinationConnectionIdLength"] = dcil.toString()

                if (buffer.remaining() >= dcil) {
                    val dcid = ByteArray(dcil)
                    buffer.get(dcid)
                    result["destinationConnectionId"] = dcid.joinToString("") { "%02x".format(it) }
                }

                // Source Connection ID Length
                val scil = buffer.get().toInt() and 0xFF
                result["sourceConnectionIdLength"] = scil.toString()

                if (buffer.remaining() >= scil) {
                    val scid = ByteArray(scil)
                    buffer.get(scid)
                    result["sourceConnectionId"] = scid.joinToString("") { "%02x".format(it) }
                }
            } else {
                result["headerType"] = "Short Header"
            }

            result["summary"] = "QUIC ${result["version"] ?: "Unknown"}"
            return result

        } catch (e: Exception) {
            Log.e(TAG, "QUIC parse error: ${e.message}")
            return emptyMap()
        }
    }

    /**
     * Parse SIP (Session Initiation Protocol) packet
     */
    private fun parseSip(payload: ByteArray): Map<String, String> {
        try {
            val sipText = String(payload, StandardCharsets.UTF_8)
            val lines = sipText.split("\r\n", "\n")

            if (lines.isEmpty()) return emptyMap()

            val result = mutableMapOf<String, String>()
            val firstLine = lines[0].trim()

            // Parse SIP request line (e.g., "INVITE sip:user@domain SIP/2.0")
            if (firstLine.contains("SIP/2.0")) {
                val parts = firstLine.split(" ")
                if (parts.size >= 3) {
                    result["method"] = parts[0]
                    result["requestUri"] = parts[1]
                    result["version"] = parts[2]
                    result["type"] = "request"
                }
            } else if (firstLine.startsWith("SIP/2.0")) {
                // SIP response line (e.g., "SIP/2.0 200 OK")
                val parts = firstLine.split(" ", limit = 3)
                if (parts.size >= 3) {
                    result["version"] = parts[0]
                    result["statusCode"] = parts[1]
                    result["reasonPhrase"] = parts[2]
                    result["type"] = "response"
                }
            }

            // Parse important headers
            for (i in 1 until lines.size) {
                val line = lines[i].trim()
                if (line.isEmpty()) break

                val colonIndex = line.indexOf(':')
                if (colonIndex > 0) {
                    val key = line.substring(0, colonIndex).trim()
                    val value = line.substring(colonIndex + 1).trim()

                    when (key.lowercase()) {
                        "from" -> result["from"] = value
                        "to" -> result["to"] = value
                        "call-id" -> result["callId"] = value
                        "cseq" -> result["cseq"] = value
                        "contact" -> result["contact"] = value
                        "user-agent" -> result["userAgent"] = value
                        "content-type" -> result["contentType"] = value
                        "content-length" -> result["contentLength"] = value
                    }
                }
            }

            result["summary"] = when (result["type"]) {
                "request" -> "${result["method"]} ${result["requestUri"]}"
                "response" -> "SIP ${result["statusCode"]} ${result["reasonPhrase"]}"
                else -> "SIP Traffic"
            }

            return result

        } catch (e: Exception) {
            Log.e(TAG, "SIP parse error: ${e.message}")
            return emptyMap()
        }
    }

    /**
     * Parse RTP (Real-time Transport Protocol) packet
     */
    private fun parseRtp(payload: ByteArray): Map<String, String> {
        if (payload.size < 12) return emptyMap()

        try {
            val result = mutableMapOf<String, String>()
            val buffer = ByteBuffer.wrap(payload)

            // RTP Header
            val firstByte = buffer.get().toInt() and 0xFF
            val secondByte = buffer.get().toInt() and 0xFF

            val version = (firstByte shr 6) and 0x3
            val padding = (firstByte shr 5) and 0x1
            val extension = (firstByte shr 4) and 0x1
            val csrcCount = firstByte and 0xF

            val marker = (secondByte shr 7) and 0x1
            val payloadType = secondByte and 0x7F

            result["version"] = version.toString()
            result["padding"] = (padding == 1).toString()
            result["extension"] = (extension == 1).toString()
            result["csrcCount"] = csrcCount.toString()
            result["marker"] = (marker == 1).toString()
            result["payloadType"] = payloadType.toString()

            val sequenceNumber = buffer.getShort().toInt() and 0xFFFF
            val timestamp = buffer.getInt()
            val ssrc = buffer.getInt()

            result["sequenceNumber"] = sequenceNumber.toString()
            result["timestamp"] = timestamp.toString()
            result["ssrc"] = String.format("%08x", ssrc)

            // Parse CSRC identifiers if present
            if (csrcCount > 0) {
                val csrcList = mutableListOf<String>()
                repeat(csrcCount) {
                    if (buffer.remaining() >= 4) {
                        val csrc = buffer.getInt()
                        csrcList.add(String.format("%08x", csrc))
                    }
                }
                result["csrcIdentifiers"] = csrcList.joinToString(", ")
            }

            result["summary"] = "RTP PT=$payloadType Seq=$sequenceNumber"
            return result

        } catch (e: Exception) {
            Log.e(TAG, "RTP parse error: ${e.message}")
            return emptyMap()
        }
    }

    /**
     * Parse SMB (Server Message Block) packet
     */
    private fun parseSmb(payload: ByteArray): Map<String, String> {
        if (payload.size < 4) return emptyMap()

        try {
            val result = mutableMapOf<String, String>()
            val buffer = ByteBuffer.wrap(payload)

            // SMB1/SMB2 header
            val protocolId = payload.copyOfRange(0, 4)
            val protocolString = String(protocolId, StandardCharsets.UTF_8)

            if (protocolString == "\u00FFSMB") {
                // SMB1
                result["version"] = "SMB1"
                if (payload.size >= 36) {
                    val command = payload[4].toInt() and 0xFF
                    result["command"] = when (command) {
                        0x00 -> "Create Directory"
                        0x01 -> "Delete Directory"
                        0x02 -> "Open"
                        0x03 -> "Create"
                        0x04 -> "Close"
                        0x05 -> "Flush"
                        0x06 -> "Delete"
                        0x07 -> "Rename"
                        0x08 -> "Query Information"
                        0x09 -> "Set Information"
                        0x0A -> "Read"
                        0x0B -> "Write"
                        0x0C -> "Lock Byte Range"
                        0x0D -> "Unlock Byte Range"
                        0x0E -> "Create Temporary"
                        0x0F -> "Create New"
                        0x10 -> "Check Directory"
                        0x11 -> "Process Exit"
                        0x12 -> "Seek"
                        0x13 -> "Lock And Read"
                        0x14 -> "Write And Unlock"
                        0x15 -> "Read Raw"
                        0x16 -> "Read Mpx"
                        0x17 -> "Read Mpx Secondary"
                        0x18 -> "Write Raw"
                        0x19 -> "Write Mpx"
                        0x1A -> "Write Mpx Secondary"
                        0x1B -> "Write Complete"
                        0x1C -> "Query Server"
                        0x1D -> "Set Server Information2"
                        0x1E -> "IOCTL"
                        0x1F -> "IOCTL Secondary"
                        0x20 -> "Copy"
                        0x21 -> "Move"
                        0x22 -> "Echo"
                        0x23 -> "Write And Close"
                        0x24 -> "Open Andx"
                        0x25 -> "Read Andx"
                        0x26 -> "Write Andx"
                        0x27 -> "New File Size"
                        0x28 -> "Close Andx"
                        0x29 -> "Transaction"
                        0x2A -> "Transaction Secondary"
                        0x2B -> "IOCTL Andx"
                        0x2C -> "Find Close2"
                        0x2D -> "Find Notify Close"
                        0x2E -> "Tree Connect"
                        0x2F -> "Tree Disconnect"
                        0x30 -> "Negotiate"
                        0x31 -> "Session Setup Andx"
                        0x32 -> "Logout Andx"
                        0x33 -> "Tree Connect Andx"
                        0x34 -> "Security Package Andx"
                        0x35 -> "Query Information Disk"
                        0x36 -> "Search"
                        0x37 -> "Find"
                        0x38 -> "Find Unique"
                        0x39 -> "Find Close"
                        0x3A -> "NT Transact"
                        0x3B -> "NT Transact Secondary"
                        0x3C -> "NT Create Andx"
                        0x3D -> "NT Cancel"
                        0x3E -> "NT Rename"
                        0x3F -> "Open Print File"
                        0x40 -> "Write Print File"
                        0x41 -> "Close Print File"
                        0x42 -> "Get Print Queue"
                        0x43 -> "Transaction2"
                        0x44 -> "Transaction2 Secondary"
                        0x45 -> "Find First2"
                        0x46 -> "Find Next2"
                        0x47 -> "Query Fs Information"
                        0x48 -> "Set Fs Information"
                        0x49 -> "Query Path Information"
                        0x4A -> "Set Path Information"
                        0x4B -> "Query File Information"
                        0x4C -> "Set File Information"
                        0x4D -> "Fs Information"
                        0x4E -> "Dump Data"
                        0x4F -> "NT Transact Notif List"
                        else -> "Command $command"
                    }
                }
                // SMB2/SMB3 - check for SMB2 header
                val smb2Signature = payload.copyOfRange(4, 8)
                if (smb2Signature[0] == 0xFE.toByte() && smb2Signature[1] == 'S'.toByte() &&
                    smb2Signature[2] == 'M'.toByte() && smb2Signature[3] == 'B'.toByte()) {
                    result["version"] = "SMB2/3"
                    if (payload.size >= 68) {
                        val command = payload.copyOfRange(12, 14).let {
                            ((it[1].toInt() and 0xFF) shl 8) or (it[0].toInt() and 0xFF)
                        }
                        result["command"] = when (command) {
                            0x0000 -> "Negotiate"
                            0x0001 -> "Session Setup"
                            0x0002 -> "Logoff"
                            0x0003 -> "Tree Connect"
                            0x0004 -> "Tree Disconnect"
                            0x0005 -> "Create"
                            0x0006 -> "Close"
                            0x0007 -> "Flush"
                            0x0008 -> "Read"
                            0x0009 -> "Write"
                            0x000A -> "Lock"
                            0x000B -> "IOCTL"
                            0x000C -> "Cancel"
                            0x000D -> "Echo"
                            0x000E -> "Query Directory"
                            0x000F -> "Change Notify"
                            0x0010 -> "Query Info"
                            0x0011 -> "Set Info"
                            0x0012 -> "Oplock Break"
                            else -> "Command $command"
                        }
                    }
                }

            result["summary"] = "${result["version"]} ${result["command"] ?: "Traffic"}"
            return result

        } catch (e: Exception) {
            Log.e(TAG, "SMB parse error: ${e.message}")
            return emptyMap()
        }
    }

    /**
     * Parse NTP (Network Time Protocol) packet
     */
    private fun parseNtp(payload: ByteArray): Map<String, String> {
        if (payload.size < 48) return emptyMap()

        try {
            val result = mutableMapOf<String, String>()
            val buffer = ByteBuffer.wrap(payload)

            // NTP Header
            val firstByte = buffer.get().toInt() and 0xFF
            val secondByte = buffer.get().toInt() and 0xFF

            val leapIndicator = (firstByte shr 6) and 0x3
            val versionNumber = (firstByte shr 3) and 0x7
            val mode = firstByte and 0x7

            result["leapIndicator"] = when (leapIndicator) {
                0 -> "No Warning"
                1 -> "Last Minute has 61 seconds"
                2 -> "Last Minute has 59 seconds"
                3 -> "Alarm Condition (Clock Not Synchronized)"
                else -> "Unknown($leapIndicator)"
            }

            result["version"] = (versionNumber + 1).toString()

            result["mode"] = when (mode) {
                1 -> "Symmetric Active"
                2 -> "Symmetric Passive"
                3 -> "Client"
                4 -> "Server"
                5 -> "Broadcast"
                6 -> "NTP Control Message"
                7 -> "Private Use"
                else -> "Reserved($mode)"
            }

            val stratum = buffer.get().toInt() and 0xFF
            result["stratum"] = when (stratum) {
                0 -> "Unspecified or Unavailable"
                1 -> "Primary Reference"
                in 2..15 -> "Secondary Reference"
                16 -> "Reserved"
                in 17..255 -> "Reserved for Private Use"
                else -> stratum.toString()
            }

            val pollInterval = buffer.get().toInt() and 0xFF
            val precision = buffer.get().toInt() and 0xFF

            result["pollInterval"] = "${1 shl pollInterval} seconds"
            result["precision"] = "${1.0 / (1 shl precision)} seconds"

            // Skip root delay, root dispersion, reference ID
            buffer.position(buffer.position() + 12)

            // Reference timestamp
            val refTimestamp = buffer.getLong()
            result["referenceTimestamp"] = refTimestamp.toString()

            // Skip originate, receive, transmit timestamps for basic parsing
            buffer.position(buffer.position() + 24)

            result["summary"] = "NTP v${result["version"]} ${result["mode"]}"
            return result

        } catch (e: Exception) {
            Log.e(TAG, "NTP parse error: ${e.message}")
            return emptyMap()
        }
    }
}
