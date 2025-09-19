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

        init {
            try {
                System.loadLibrary("packet_analyzer")
                Log.d(TAG, "Native library loaded successfully")
            } catch (e: UnsatisfiedLinkError) {
                Log.w(TAG, "Native library not found: ${e.message}")
            }
        }

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

        // ---- Native JNI functions ----
        @JvmStatic external fun nativeStartRootedCapture(): Boolean
        @JvmStatic external fun nativeStopRootedCapture(): Boolean
        @JvmStatic external fun nativeCleanup()
        @JvmStatic external fun nativeClearPackets()
        @JvmStatic external fun nativePauseCapture()
        @JvmStatic external fun nativeResumeCapture()
        @JvmStatic external fun nativeExportPackets(): ByteArray?

        // ---- Export Packets to Downloads ----
        @JvmStatic
        fun exportPackets(context: Context): String? {
            return try {
                val data = nativeExportPackets() ?: return null
                val downloads =
                    Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
                if (!downloads.exists()) downloads.mkdirs()

                val file = File(downloads, "capture_${System.currentTimeMillis()}.pcap")
                FileOutputStream(file).use { it.write(data) }

                Log.d(TAG, "Exported PCAP to: ${file.absolutePath}")
                file.absolutePath
            } catch (e: Exception) {
                Log.e(TAG, "Export failed", e)
                null
            }
        }
    }
}
