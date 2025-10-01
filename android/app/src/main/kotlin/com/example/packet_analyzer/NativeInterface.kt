package com.example.packet_analyzer

import android.content.Context
import android.os.Environment
import android.util.Log
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.io.FileOutputStream
import java.net.NetworkInterface

class NativeInterface {
    companion object {
        private const val TAG = "NativeInterface"

        // Native library loading removed - using tun2socks AAR instead

        private lateinit var methodChannel: MethodChannel

        @JvmStatic
        fun setMethodChannel(channel: MethodChannel) {
            methodChannel = channel
        }

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
            methodChannel.invokeMethod("onPacketReceived", packetData)
        }

        @JvmStatic
        fun sendStatsToFlutter(statsJson: String) {
            methodChannel.invokeMethod("onStatsUpdated", statsJson)
        }

        @JvmStatic
        fun sendStatusUpdate(isCapturing: Boolean, mode: String) {
            val statusData = mapOf(
                "status" to if (isCapturing) "Capturing ($mode)" else "Stopped",
                "isCapturing" to isCapturing,
                "mode" to mode
            )
            methodChannel.invokeMethod("onStatusChanged", statusData)
        }

        @JvmStatic
        fun isDeviceRooted(): Boolean {
            val buildTags = android.os.Build.TAGS
            if (buildTags != null && buildTags.contains("test-keys")) return true

            val paths = arrayOf(
                "/system/app/Superuser.apk",
                "/sbin/su",
                "/system/bin/su",
                "/system/xbin/su",
                "/data/local/xbin/su",
                "/data/local/bin/su",
                "/system/sd/xbin/su",
                "/system/bin/failsafe/su",
                "/data/local/su",
                "/su/bin/su"
            )
            if (paths.any { File(it).exists() }) return true

            return try {
                Runtime.getRuntime().exec("su")
                true
            } catch (e: Exception) {
                false
            }
        }

        @JvmStatic
        fun getAvailableInterfaces(): List<String> {
            return try {
                NetworkInterface.getNetworkInterfaces()
                    .toList()
                    .map { it.name }
            } catch (e: Exception) {
                emptyList()
            }
        }

        // ---- Native JNI functions (commented out - using tun2socks AAR instead) ----
        // @JvmStatic external fun nativeStartRootedCapture(): Boolean
        // @JvmStatic external fun nativeStopRootedCapture(): Boolean
        // @JvmStatic external fun nativeCleanup()
        // @JvmStatic external fun nativeClearPackets()
        // @JvmStatic external fun nativePauseCapture()
        // @JvmStatic external fun nativeResumeCapture()
        // @JvmStatic external fun nativeExportPackets(): ByteArray?

        // ---- Export Packets to Downloads ----
        @JvmStatic
        fun exportPackets(context: Context): String? {
            return try {
                // TODO: Implement export functionality using tun2socks data
                Log.w(TAG, "Export function not yet implemented with tun2socks AAR")
                null
            } catch (e: Exception) {
                Log.e(TAG, "Export failed", e)
                null
            }
        }
    }
}
