package com.example.packet_analyzer

import io.flutter.plugin.common.MethodChannel
import java.io.File

class NativeInterface {
    
    companion object {
        init {
            System.loadLibrary("packet_analyzer")
        }
        
        // Use a private variable to avoid setter conflicts
        private var _methodChannel: MethodChannel? = null
        
        fun setMethodChannel(channel: MethodChannel) {
            _methodChannel = channel
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
            
            _methodChannel?.invokeMethod("onPacketReceived", packetData)
        }
        
        @JvmStatic
        fun sendStatsToFlutter(statsJson: String) {
            _methodChannel?.invokeMethod("onStatsUpdated", statsJson)
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
            _methodChannel?.invokeMethod("onStatusChanged", statusData)
        }
    }

    // Native method declarations
    external fun initializeVpnCapture(fd: Int): Boolean
    external fun processPacket(packet: ByteArray, length: Int): Boolean
    external fun startRootedCapture(): Boolean
    external fun stopRootedCapture(): Boolean
    external fun cleanup()
    external fun clearPackets()
    external fun pauseCapture()
    external fun resumeCapture()
    external fun exportPackets(): String?
    
    fun isDeviceRooted(): Boolean {
        return checkRootMethod1() || checkRootMethod2() || checkRootMethod3()
    }
    
    private fun checkRootMethod1(): Boolean {
        val buildTags = android.os.Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }
    
    private fun checkRootMethod2(): Boolean {
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
        
        for (path in paths) {
            if (File(path).exists()) return true
        }
        return false
    }
    
    private fun checkRootMethod3(): Boolean {
        return try {
            Runtime.getRuntime().exec("su")
            true
        } catch (e: Exception) {
            false
        }
    }
}
