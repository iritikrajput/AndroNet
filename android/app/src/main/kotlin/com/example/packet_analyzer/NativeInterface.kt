package com.example.packet_analyzer

import io.flutter.plugin.common.MethodChannel
import android.util.Log
import java.io.File

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
        
        // Use a private variable to avoid setter conflicts
        private var _methodChannel: MethodChannel? = null
        
        fun setMethodChannel(channel: MethodChannel) {
            _methodChannel = channel
            Log.d(TAG, "Method channel set")
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
            
            try {
                _methodChannel?.invokeMethod("onPacketReceived", packetData)
                Log.d(TAG, "Packet sent to Flutter: $sourceIp:$sourcePort -> $destIp:$destPort")
            } catch (e: Exception) {
                Log.e(TAG, "Error sending packet to Flutter", e)
            }
        }
        
        @JvmStatic
        fun sendStatsToFlutter(statsJson: String) {
            try {
                _methodChannel?.invokeMethod("onStatsUpdated", statsJson)
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
                _methodChannel?.invokeMethod("onStatusChanged", statusData)
                Log.d(TAG, "Status update sent: capturing=$isCapturing, mode=$mode")
            } catch (e: Exception) {
                Log.e(TAG, "Error sending status update", e)
            }
        }
    }
    
    // Native method declarations with safe fallbacks
    fun initializeVpnCapture(fd: Int): Boolean {
        return try {
            nativeInitializeVpnCapture(fd)
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "Native initializeVpnCapture not available")
            true // Return true for VPN-based capture fallback
        }
    }
    
    fun processPacket(packet: ByteArray, length: Int): Boolean {
        return try {
            nativeProcessPacket(packet, length)
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "Native processPacket not available")
            false
        }
    }
    
    fun startRootedCapture(): Boolean {
        return try {
            nativeStartRootedCapture()
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "Native startRootedCapture not available")
            false
        }
    }
    
    fun stopRootedCapture(): Boolean {
        return try {
            nativeStopRootedCapture()
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "Native stopRootedCapture not available")
            true
        }
    }
    
    fun cleanup() {
        try {
            nativeCleanup()
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "Native cleanup not available")
        }
    }
    
    fun clearPackets() {
        try {
            nativeClearPackets()
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "Native clearPackets not available")
        }
    }
    
    fun pauseCapture() {
        try {
            nativePauseCapture()
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "Native pauseCapture not available")
        }
    }
    
    fun resumeCapture() {
        try {
            nativeResumeCapture()
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "Native resumeCapture not available")
        }
    }
    
    fun exportPackets(): String? {
        return try {
            nativeExportPackets()
        } catch (e: UnsatisfiedLinkError) {
            Log.w(TAG, "Native exportPackets not available")
            null
        }
    }
    
    fun isDeviceRooted(): Boolean {
        val rooted = checkRootMethod1() || checkRootMethod2() || checkRootMethod3()
        Log.d(TAG, "Device root status: $rooted")
        return rooted
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
    
    // External native method declarations
    private external fun nativeInitializeVpnCapture(fd: Int): Boolean
    private external fun nativeProcessPacket(packet: ByteArray, length: Int): Boolean
    private external fun nativeStartRootedCapture(): Boolean
    private external fun nativeStopRootedCapture(): Boolean
    private external fun nativeCleanup()
    private external fun nativeClearPackets()
    private external fun nativePauseCapture()
    private external fun nativeResumeCapture()
    private external fun nativeExportPackets(): String?
}
