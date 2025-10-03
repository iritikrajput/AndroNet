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

                // DHCP traffic
                protocol == "UDP" && (destPort == 67 || destPort == 68 ||
                                     sourcePort == 67 || sourcePort == 68) -> {
                    val dhcpData = parseDhcp(payload)
                    if (dhcpData.isNotEmpty()) {
                        enrichedInfo["dhcpData"] = dhcpData
                        enrichedInfo["appName"] = "DHCP"
                    }
                }
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
}
