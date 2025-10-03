package com.example.packet_analyzer

import android.util.Log
import java.io.File

/**
 * PCAP File Writer
 * Exports captured packets to .pcap format for Wireshark analysis
 */
object PcapWriter {
    private const val TAG = "PcapWriter"
    private var isWriting = false

    init {
        try {
            System.loadLibrary("pcap_writer")
            Log.i(TAG, "✅ PCAP writer native library loaded")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "❌ Failed to load pcap_writer: ${e.message}")
        }
    }

    /**
     * Initialize PCAP file for writing
     * @param filepath Absolute path to output .pcap file
     * @param linktype Link layer type (1=Ethernet, 101=Raw IP)
     * @return true if successful
     */
    external fun nativeInit(filepath: String, linktype: Int = 101): Boolean

    /**
     * Write a packet to the PCAP file
     * @param packetData Raw packet bytes
     * @param timestampMs Timestamp in milliseconds
     * @return true if successful
     */
    external fun nativeWritePacket(packetData: ByteArray, timestampMs: Long): Boolean

    /**
     * Get writing statistics
     * @return Map with packetCount, totalBytes, filepath
     */
    external fun nativeGetStats(): Map<String, Any>

    /**
     * Close the PCAP file
     */
    external fun nativeClose()

    /**
     * Start writing packets to PCAP file
     */
    fun startCapture(outputPath: String, linktype: Int = 101): Boolean {
        if (isWriting) {
            Log.w(TAG, "Already writing to PCAP file")
            return false
        }

        val file = File(outputPath)

        // Create parent directories if needed
        file.parentFile?.mkdirs()

        val success = nativeInit(outputPath, linktype)
        if (success) {
            isWriting = true
            Log.i(TAG, "📝 Started writing to: $outputPath")
        } else {
            Log.e(TAG, "❌ Failed to initialize PCAP writer")
        }

        return success
    }

    /**
     * Write a packet to the active PCAP file
     */
    fun writePacket(packetData: ByteArray, timestampMs: Long = System.currentTimeMillis()): Boolean {
        if (!isWriting) {
            return false
        }

        return try {
            nativeWritePacket(packetData, timestampMs)
        } catch (e: Exception) {
            Log.e(TAG, "Error writing packet: ${e.message}")
            false
        }
    }

    /**
     * Get current capture statistics
     */
    fun getStats(): Map<String, Any> {
        return try {
            nativeGetStats()
        } catch (e: Exception) {
            Log.e(TAG, "Error getting stats: ${e.message}")
            emptyMap()
        }
    }

    /**
     * Stop writing and close the PCAP file
     */
    fun stopCapture(): Map<String, Any> {
        if (!isWriting) {
            return emptyMap()
        }

        val stats = getStats()
        nativeClose()
        isWriting = false

        Log.i(TAG, "✅ PCAP capture stopped: ${stats["packetCount"]} packets, ${stats["totalBytes"]} bytes")
        return stats
    }

    /**
     * Check if currently writing to PCAP
     */
    fun isActive(): Boolean = isWriting

    /**
     * Generate a timestamped filename for PCAP export
     */
    fun generateFilename(prefix: String = "andronet"): String {
        val timestamp = java.text.SimpleDateFormat("yyyyMMdd_HHmmss", java.util.Locale.US)
            .format(java.util.Date())
        return "${prefix}_${timestamp}.pcap"
    }
}
