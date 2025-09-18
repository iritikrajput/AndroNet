package com.example.packet_analyzer

import io.flutter.plugin.common.MethodChannel
import android.util.Log
import java.io.File

object NativeInterface {
    private const val TAG = "NativeInterface"

    init {
        try {
            System.loadLibrary("packet_analyzer")
            Log.d(TAG, "Native library loaded successfully")
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "Native library not found: ${e.message}")
        }
    }

    // Flutter method channel
    private var methodChannel: MethodChannel? = null

    fun setMethodChannel(channel: MethodChannel) {
        methodChannel = channel
        Log.d(TAG, "Method channel set")
    }

    // ---- Called from native (via JNI) ----
    @JvmStatic
    fun sendPacketToFlutter(
        sourceIp: String,
        destIp: String,
        sourcePort: Int,
        destPort: Int,
        protocol: String,
        size: Int,
        timestamp: String,
        payload: String
    ) {
        val packetData = mapOf(
            "sourceIp" to sourceIp,
            "destinationIp" to destIp,
            "sourcePort" to sourcePort,
            "destinationPort" to destPort,
            "protocol" to protocol,
            "size" to size,
            "timestamp" to timestamp,
            "payload" to payload
        )

        try {
            methodChannel?.invokeMethod("onPacketReceived", packetData)
            Log.d(TAG, "Packet sent to Flutter: $sourceIp:$sourcePort -> $destIp:$destPort")
        } catch (e: Exception) {
            Log.e(TAG, "Error sending packet to Flutter", e)
        }
    }

    @JvmStatic
    fun sendStatsToFlutter(statsJson: String) {
        try {
            methodChannel?.invokeMethod("onStatsUpdated", statsJson)
            Log.d(TAG, "Stats sent to Flutter")
        } catch (e: Exception) {
            Log.e(TAG, "Error sending stats to Flutter", e)
        }
    }

    @JvmStatic
    fun sendStatusUpdate(isCapturing: Boolean, mode: String) {
        val statusData = mapOf(
            "isCapturing" to isCapturing,
            "mode" to mode,
            "totalPackets" to 0,
            "totalBytes" to 0,
            "startTime" to if (isCapturing) System.currentTimeMillis() else null
        )

        try {
            methodChannel?.invokeMethod("onStatusChanged", statusData)
            Log.d(TAG, "Status update sent: capturing=$isCapturing, mode=$mode")
        } catch (e: Exception) {
            Log.e(TAG, "Error sending status update", e)
        }
    }

    // ---- Native method declarations ----
    external fun nativeInitializeVpnCapture(fd: Int): Boolean
    external fun nativeProcessPacket(packet: ByteArray, length: Int): Boolean
    external fun nativeStartRootedCapture(): Boolean
    external fun nativeStopRootedCapture(): Boolean
    external fun nativeCleanup()
    external fun nativeClearPackets()
    external fun nativePauseCapture()
    external fun nativeResumeCapture()
    external fun nativeExportPackets(): String?
}
