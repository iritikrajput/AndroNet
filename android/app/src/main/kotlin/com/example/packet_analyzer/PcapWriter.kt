package com.example.packet_analyzer

import android.util.Log
import java.io.File

object PcapWriter {
    private const val TAG = "PcapWriter"
    private var isWriting = false

    init {
        try {
            System.loadLibrary("pcap_writer")
            Log.i(TAG, "PCAP writer native library loaded")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load pcap_writer: ${e.message}")
        }
    }

    // ── Core write path ───────────────────────────────────────────────────────

    external fun nativeInit(filepath: String, linktype: Int = 101): Boolean

    external fun nativeWritePacket(packetData: ByteArray, timestampMs: Long): Boolean

    /** Write a packet with an anomaly annotation stored as EPB option 2988. */
    external fun nativeWriteAnnotatedPacket(
        packetData: ByteArray,
        timestampMs: Long,
        annotation: String
    ): Boolean

    external fun nativeGetStats(): Map<String, Any>

    external fun nativeClose()

    // ── Configuration ─────────────────────────────────────────────────────────

    /**
     * Set file-rotation thresholds.
     * @param maxSizeBytes  Rotate when file exceeds this size (default 50 MB = 52_428_800).
     * @param maxAgeSeconds Rotate when file age exceeds this value (default 3600).
     * @param maxFiles      Maximum number of rotation files to keep (default 10).
     */
    external fun nativeSetRotationSettings(
        maxSizeBytes: Long,
        maxAgeSeconds: Long,
        maxFiles: Int
    )

    /**
     * Tell the C layer which interface is being captured and its link-layer type.
     * Must be called before nativeInit so the IDB option is written correctly.
     * @param ifName   Interface name, e.g. "tun0" or "wlan0".
     * @param linktype pcap link-layer type (1 = Ethernet, 101 = Raw IP).
     */
    external fun nativeSetInterfaceInfo(ifName: String, linktype: Int)

    /** Validate the block structure of a pcapng file. Returns true if intact. */
    external fun nativeValidatePcapFile(filepath: String): Boolean

    // ── Kotlin helpers ────────────────────────────────────────────────────────

    /**
     * Start writing to a pcapng file.
     * @param outputPath Absolute path to the output file.
     * @param linktype   Link-layer type (1 = Ethernet, 101 = Raw IP).
     * @param ifName     Interface name for IDB metadata (empty = omit).
     */
    fun startCapture(
        outputPath: String,
        linktype: Int = 101,
        ifName: String = ""
    ): Boolean {
        if (isWriting) {
            Log.w(TAG, "Already writing to PCAP file")
            return false
        }

        File(outputPath).parentFile?.mkdirs()

        if (ifName.isNotEmpty()) {
            nativeSetInterfaceInfo(ifName, linktype)
        }

        val success = nativeInit(outputPath, linktype)
        if (success) {
            isWriting = true
            Log.i(TAG, "Started writing to: $outputPath")
        } else {
            Log.e(TAG, "Failed to initialize PCAP writer")
        }
        return success
    }

    fun writePacket(
        packetData: ByteArray,
        timestampMs: Long = System.currentTimeMillis()
    ): Boolean {
        if (!isWriting) return false
        return try {
            nativeWritePacket(packetData, timestampMs)
        } catch (e: Exception) {
            Log.e(TAG, "Error writing packet: ${e.message}")
            false
        }
    }

    fun writeAnnotatedPacket(
        packetData: ByteArray,
        timestampMs: Long = System.currentTimeMillis(),
        annotation: String
    ): Boolean {
        if (!isWriting) return false
        return try {
            nativeWriteAnnotatedPacket(packetData, timestampMs, annotation)
        } catch (e: Exception) {
            Log.e(TAG, "Error writing annotated packet: ${e.message}")
            false
        }
    }

    fun getStats(): Map<String, Any> {
        return try {
            nativeGetStats()
        } catch (e: Exception) {
            Log.e(TAG, "Error getting stats: ${e.message}")
            emptyMap()
        }
    }

    fun stopCapture(): Map<String, Any> {
        if (!isWriting) return emptyMap()
        val stats = getStats()
        nativeClose()
        isWriting = false
        Log.i(TAG, "PCAP capture stopped: ${stats["packetCount"]} packets, ${stats["totalBytes"]} bytes")
        return stats
    }

    fun isActive(): Boolean = isWriting

    fun generateFilename(prefix: String = "andronet"): String {
        val timestamp = java.text.SimpleDateFormat("yyyyMMdd_HHmmss", java.util.Locale.US)
            .format(java.util.Date())
        return "${prefix}_${timestamp}.pcapng"
    }
}
