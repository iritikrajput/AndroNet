package com.example.packet_analyzer

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Packet construction utilities for building IP/TCP/UDP packets
 * Based on PCAPdroid's packet handling approach
 */
object PacketBuilder {

    /**
     * Build complete IPv4 + TCP packet with payload
     */
    fun buildTcpPacket(
        sourceIP: String,
        destIP: String,
        sourcePort: Int,
        destPort: Int,
        seqNum: Long,
        ackNum: Long,
        flags: Int,
        payload: ByteArray = byteArrayOf()
    ): ByteArray {
        val ipHeader = buildIpv4Header(
            sourceIP = sourceIP,
            destIP = destIP,
            protocol = 6,  // TCP
            totalLength = 20 + 20 + payload.size  // IP header + TCP header + payload
        )

        val tcpHeader = buildTcpHeader(
            sourcePort = sourcePort,
            destPort = destPort,
            seqNum = seqNum,
            ackNum = ackNum,
            flags = flags,
            payloadLength = payload.size
        )

        // Calculate TCP checksum with pseudo-header
        val tcpChecksum = calculateTcpChecksum(
            sourceIP = sourceIP,
            destIP = destIP,
            tcpHeader = tcpHeader,
            payload = payload
        )

        // Insert checksum into TCP header
        tcpHeader[16] = (tcpChecksum shr 8).toByte()
        tcpHeader[17] = (tcpChecksum and 0xFF).toByte()

        // Calculate IP checksum
        val ipChecksum = calculateChecksum(ipHeader, 0, 20)
        ipHeader[10] = (ipChecksum shr 8).toByte()
        ipHeader[11] = (ipChecksum and 0xFF).toByte()

        // Combine all parts
        return ipHeader + tcpHeader + payload
    }

    /**
     * Build complete IPv4 + UDP packet with payload
     */
    fun buildUdpPacket(
        sourceIP: String,
        destIP: String,
        sourcePort: Int,
        destPort: Int,
        payload: ByteArray
    ): ByteArray {
        val ipHeader = buildIpv4Header(
            sourceIP = sourceIP,
            destIP = destIP,
            protocol = 17,  // UDP
            totalLength = 20 + 8 + payload.size  // IP header + UDP header + payload
        )

        val udpHeader = buildUdpHeader(
            sourcePort = sourcePort,
            destPort = destPort,
            length = 8 + payload.size
        )

        // Calculate UDP checksum with pseudo-header
        val udpChecksum = calculateUdpChecksum(
            sourceIP = sourceIP,
            destIP = destIP,
            udpHeader = udpHeader,
            payload = payload
        )

        // Insert checksum into UDP header
        udpHeader[6] = (udpChecksum shr 8).toByte()
        udpHeader[7] = (udpChecksum and 0xFF).toByte()

        // Calculate IP checksum
        val ipChecksum = calculateChecksum(ipHeader, 0, 20)
        ipHeader[10] = (ipChecksum shr 8).toByte()
        ipHeader[11] = (ipChecksum and 0xFF).toByte()

        // Combine all parts
        return ipHeader + udpHeader + payload
    }

    /**
     * Build IPv4 header (20 bytes)
     */
    private fun buildIpv4Header(
        sourceIP: String,
        destIP: String,
        protocol: Int,
        totalLength: Int
    ): ByteArray {
        val header = ByteArray(20)
        val buffer = ByteBuffer.wrap(header)

        // Version (4) + IHL (5) = 0x45
        buffer.put(0x45.toByte())

        // Type of Service
        buffer.put(0x00.toByte())

        // Total Length
        buffer.putShort(totalLength.toShort())

        // Identification
        buffer.putShort(0x0000.toShort())

        // Flags + Fragment Offset
        buffer.putShort(0x4000.toShort())  // Don't Fragment

        // TTL
        buffer.put(64.toByte())

        // Protocol
        buffer.put(protocol.toByte())

        // Header Checksum (will be calculated later)
        buffer.putShort(0x0000.toShort())

        // Source IP
        val srcIP = ipStringToBytes(sourceIP)
        buffer.put(srcIP)

        // Destination IP
        val dstIP = ipStringToBytes(destIP)
        buffer.put(dstIP)

        return header
    }

    /**
     * Build TCP header (20 bytes minimum)
     */
    private fun buildTcpHeader(
        sourcePort: Int,
        destPort: Int,
        seqNum: Long,
        ackNum: Long,
        flags: Int,
        payloadLength: Int
    ): ByteArray {
        val header = ByteArray(20)
        val buffer = ByteBuffer.wrap(header)

        // Source Port
        buffer.putShort(sourcePort.toShort())

        // Destination Port
        buffer.putShort(destPort.toShort())

        // Sequence Number
        buffer.putInt(seqNum.toInt())

        // Acknowledgment Number
        buffer.putInt(ackNum.toInt())

        // Data Offset (5 = 20 bytes) + Reserved + Flags
        val dataOffsetAndFlags = (5 shl 12) or flags
        buffer.putShort(dataOffsetAndFlags.toShort())

        // Window Size
        buffer.putShort(8192.toShort())  // 8KB window

        // Checksum (will be calculated later)
        buffer.putShort(0x0000.toShort())

        // Urgent Pointer
        buffer.putShort(0x0000.toShort())

        return header
    }

    /**
     * Build UDP header (8 bytes)
     */
    private fun buildUdpHeader(
        sourcePort: Int,
        destPort: Int,
        length: Int
    ): ByteArray {
        val header = ByteArray(8)
        val buffer = ByteBuffer.wrap(header)

        // Source Port
        buffer.putShort(sourcePort.toShort())

        // Destination Port
        buffer.putShort(destPort.toShort())

        // Length
        buffer.putShort(length.toShort())

        // Checksum (will be calculated later)
        buffer.putShort(0x0000.toShort())

        return header
    }

    /**
     * Calculate TCP checksum including pseudo-header
     */
    private fun calculateTcpChecksum(
        sourceIP: String,
        destIP: String,
        tcpHeader: ByteArray,
        payload: ByteArray
    ): Int {
        // Build pseudo-header
        val pseudoHeader = ByteArray(12)
        val buffer = ByteBuffer.wrap(pseudoHeader)

        buffer.put(ipStringToBytes(sourceIP))
        buffer.put(ipStringToBytes(destIP))
        buffer.put(0x00.toByte())
        buffer.put(6.toByte())  // TCP protocol
        buffer.putShort((tcpHeader.size + payload.size).toShort())

        // Combine pseudo-header + TCP header + payload
        val combined = pseudoHeader + tcpHeader + payload

        return calculateChecksum(combined, 0, combined.size)
    }

    /**
     * Calculate UDP checksum including pseudo-header
     */
    private fun calculateUdpChecksum(
        sourceIP: String,
        destIP: String,
        udpHeader: ByteArray,
        payload: ByteArray
    ): Int {
        // Build pseudo-header
        val pseudoHeader = ByteArray(12)
        val buffer = ByteBuffer.wrap(pseudoHeader)

        buffer.put(ipStringToBytes(sourceIP))
        buffer.put(ipStringToBytes(destIP))
        buffer.put(0x00.toByte())
        buffer.put(17.toByte())  // UDP protocol
        buffer.putShort((udpHeader.size + payload.size).toShort())

        // Combine pseudo-header + UDP header + payload
        val combined = pseudoHeader + udpHeader + payload

        return calculateChecksum(combined, 0, combined.size)
    }

    /**
     * Calculate Internet checksum (RFC 1071)
     */
    private fun calculateChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset

        // Add 16-bit words
        while (i < offset + length - 1) {
            val word = ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum += word
            i += 2
        }

        // Add remaining byte if odd length
        if (i < offset + length) {
            sum += (data[i].toInt() and 0xFF) shl 8
        }

        // Fold 32-bit sum to 16 bits
        while (sum shr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum shr 16)
        }

        // One's complement
        return (sum.inv() and 0xFFFF).toInt()
    }

    /**
     * Convert IP string to bytes
     */
    private fun ipStringToBytes(ip: String): ByteArray {
        val parts = ip.split(".")
        return ByteArray(4) { i ->
            parts.getOrNull(i)?.toIntOrNull()?.toByte() ?: 0
        }
    }

    /**
     * TCP Flags
     */
    object TcpFlags {
        const val FIN = 0x01
        const val SYN = 0x02
        const val RST = 0x04
        const val PSH = 0x08
        const val ACK = 0x10
        const val URG = 0x20
    }
}