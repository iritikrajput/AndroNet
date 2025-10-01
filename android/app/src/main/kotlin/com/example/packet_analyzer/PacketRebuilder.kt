package com.example.packet_analyzer

import android.util.Log
import java.nio.ByteBuffer

/**
 * Advanced packet reconstruction with proper headers and checksums
 * Handles complete IP/TCP/UDP packet building
 */
object PacketRebuilder {

    private const val TAG = "PacketRebuilder"

    /**
     * Build complete TCP packet with proper state tracking
     */
    fun buildTcpPacket(
        connection: TcpConnection,
        payload: ByteArray,
        flags: Int = PacketBuilder.TcpFlags.PSH or PacketBuilder.TcpFlags.ACK,
        fromServer: Boolean = true
    ): ByteArray? {
        return try {
            if (fromServer) {
                // Server -> Client
                PacketBuilder.buildTcpPacket(
                    sourceIP = connection.destIP,
                    destIP = connection.sourceIP,
                    sourcePort = connection.destPort,
                    destPort = connection.sourcePort,
                    seqNum = connection.serverSeq.get(),
                    ackNum = connection.clientSeq.get(),
                    flags = flags,
                    payload = payload
                )
            } else {
                // Client -> Server
                PacketBuilder.buildTcpPacket(
                    sourceIP = connection.sourceIP,
                    destIP = connection.destIP,
                    sourcePort = connection.sourcePort,
                    destPort = connection.destPort,
                    seqNum = connection.clientSeq.get(),
                    ackNum = connection.serverAck.get(),
                    flags = flags,
                    payload = payload
                )
            }

        } catch (e: Exception) {
            Log.e(TAG, "TCP packet build error: ${e.message}")
            null
        }
    }

    /**
     * Build TCP handshake packets
     */
    fun buildSynAck(
        connection: TcpConnection,
        serverInitSeq: Long
    ): ByteArray? {
        return try {
            PacketBuilder.buildTcpPacket(
                sourceIP = connection.destIP,
                destIP = connection.sourceIP,
                sourcePort = connection.destPort,
                destPort = connection.sourcePort,
                seqNum = serverInitSeq,
                ackNum = connection.clientSeq.get() + 1,
                flags = PacketBuilder.TcpFlags.SYN or PacketBuilder.TcpFlags.ACK,
                payload = byteArrayOf()
            )
        } catch (e: Exception) {
            Log.e(TAG, "SYN-ACK build error: ${e.message}")
            null
        }
    }

    fun buildAck(
        connection: TcpConnection,
        fromServer: Boolean = true
    ): ByteArray? {
        return try {
            if (fromServer) {
                PacketBuilder.buildTcpPacket(
                    sourceIP = connection.destIP,
                    destIP = connection.sourceIP,
                    sourcePort = connection.destPort,
                    destPort = connection.sourcePort,
                    seqNum = connection.serverSeq.get(),
                    ackNum = connection.clientSeq.get(),
                    flags = PacketBuilder.TcpFlags.ACK,
                    payload = byteArrayOf()
                )
            } else {
                PacketBuilder.buildTcpPacket(
                    sourceIP = connection.sourceIP,
                    destIP = connection.destIP,
                    sourcePort = connection.sourcePort,
                    destPort = connection.destPort,
                    seqNum = connection.clientSeq.get(),
                    ackNum = connection.serverAck.get(),
                    flags = PacketBuilder.TcpFlags.ACK,
                    payload = byteArrayOf()
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "ACK build error: ${e.message}")
            null
        }
    }

    fun buildFin(
        connection: TcpConnection,
        fromServer: Boolean = true
    ): ByteArray? {
        return try {
            if (fromServer) {
                PacketBuilder.buildTcpPacket(
                    sourceIP = connection.destIP,
                    destIP = connection.sourceIP,
                    sourcePort = connection.destPort,
                    destPort = connection.sourcePort,
                    seqNum = connection.serverSeq.get(),
                    ackNum = connection.clientSeq.get(),
                    flags = PacketBuilder.TcpFlags.FIN or PacketBuilder.TcpFlags.ACK,
                    payload = byteArrayOf()
                )
            } else {
                PacketBuilder.buildTcpPacket(
                    sourceIP = connection.sourceIP,
                    destIP = connection.destIP,
                    sourcePort = connection.sourcePort,
                    destPort = connection.destPort,
                    seqNum = connection.clientSeq.get(),
                    ackNum = connection.serverAck.get(),
                    flags = PacketBuilder.TcpFlags.FIN or PacketBuilder.TcpFlags.ACK,
                    payload = byteArrayOf()
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "FIN build error: ${e.message}")
            null
        }
    }

    /**
     * Build UDP packet (simpler than TCP)
     */
    fun buildUdpPacket(
        sourceIP: String,
        destIP: String,
        sourcePort: Int,
        destPort: Int,
        payload: ByteArray
    ): ByteArray? {
        return try {
            PacketBuilder.buildUdpPacket(
                sourceIP = sourceIP,
                destIP = destIP,
                sourcePort = sourcePort,
                destPort = destPort,
                payload = payload
            )
        } catch (e: Exception) {
            Log.e(TAG, "UDP packet build error: ${e.message}")
            null
        }
    }

    /**
     * Parse TCP flags from raw packet
     */
    fun getTcpFlags(rawPacket: ByteArray): Int {
        return try {
            if (rawPacket.size < 20) return 0
            val ipHeaderLength = (rawPacket[0].toInt() and 0x0F) * 4
            if (rawPacket.size < ipHeaderLength + 20) return 0
            val tcpFlagsOffset = ipHeaderLength + 13
            rawPacket[tcpFlagsOffset].toInt() and 0xFF
        } catch (e: Exception) {
            0
        }
    }

    /**
     * Parse TCP sequence number from raw packet
     */
    fun getTcpSeq(rawPacket: ByteArray): Long {
        return try {
            if (rawPacket.size < 20) return 0
            val ipHeaderLength = (rawPacket[0].toInt() and 0x0F) * 4
            if (rawPacket.size < ipHeaderLength + 20) return 0

            val seqOffset = ipHeaderLength + 4
            val buffer = ByteBuffer.wrap(rawPacket, seqOffset, 4)
            buffer.int.toLong() and 0xFFFFFFFF
        } catch (e: Exception) {
            0
        }
    }

    /**
     * Parse TCP acknowledgment number from raw packet
     */
    fun getTcpAck(rawPacket: ByteArray): Long {
        return try {
            if (rawPacket.size < 20) return 0
            val ipHeaderLength = (rawPacket[0].toInt() and 0x0F) * 4
            if (rawPacket.size < ipHeaderLength + 20) return 0

            val ackOffset = ipHeaderLength + 8
            val buffer = ByteBuffer.wrap(rawPacket, ackOffset, 4)
            buffer.int.toLong() and 0xFFFFFFFF
        } catch (e: Exception) {
            0
        }
    }

    /**
     * Extract TCP payload from raw packet
     */
    fun extractTcpPayload(rawPacket: ByteArray): ByteArray {
        return try {
            if (rawPacket.size < 20) return byteArrayOf()
            val ipHeaderLength = (rawPacket[0].toInt() and 0x0F) * 4
            if (rawPacket.size < ipHeaderLength + 20) return byteArrayOf()

            val tcpHeaderStart = ipHeaderLength
            val tcpHeaderLength = ((rawPacket[tcpHeaderStart + 12].toInt() and 0xF0) shr 4) * 4

            val payloadStart = ipHeaderLength + tcpHeaderLength
            if (rawPacket.size <= payloadStart) return byteArrayOf()

            rawPacket.copyOfRange(payloadStart, rawPacket.size)
        } catch (e: Exception) {
            byteArrayOf()
        }
    }

    /**
     * Extract UDP payload from raw packet
     */
    fun extractUdpPayload(rawPacket: ByteArray): ByteArray {
        return try {
            if (rawPacket.size < 20) return byteArrayOf()
            val ipHeaderLength = (rawPacket[0].toInt() and 0x0F) * 4
            if (rawPacket.size < ipHeaderLength + 8) return byteArrayOf()

            val payloadStart = ipHeaderLength + 8
            if (rawPacket.size <= payloadStart) return byteArrayOf()

            rawPacket.copyOfRange(payloadStart, rawPacket.size)
        } catch (e: Exception) {
            byteArrayOf()
        }
    }
}
