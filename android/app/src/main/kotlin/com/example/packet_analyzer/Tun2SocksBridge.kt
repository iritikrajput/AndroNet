package com.example.packet_analyzer

import tun2socks.Tun2socks

object Tun2SocksBridge {
    // Private listener property - accessible within the object
    private var packetListener: PacketListener? = null
    private var isInitialized = false

    init {
        try {
            // Use the AAR library directly
            Tun2socks.touch()  // Initialize the Go library
            android.util.Log.i("Tun2SocksBridge", "✅ Tun2socks library initialized successfully")
            isInitialized = true
        } catch (e: Exception) {
            android.util.Log.e("Tun2SocksBridge", "❌ Failed to initialize Tun2socks library: ${e.message}")
            isInitialized = false
        }
    }

    // Simple interface for packet listening
    interface PacketListener {
        fun onPacket(jsonStr: String)
    }

    // Use the real Go tun2socks library
    fun startTun2Socks(
        fd: Long,
        socksServer: String,
        socksPort: Long,
        dnsServer: String,
        enableIPv6: Boolean
    ) {
        try {
            if (!isInitialized) {
                android.util.Log.e("Tun2SocksBridge", "❌ Tun2socks library not initialized")
                return
            }

            android.util.Log.i("Tun2SocksBridge", "🚀 Starting real tun2socks")
            android.util.Log.i("Tun2SocksBridge", "📋 Config: fd=$fd, socks=$socksServer:$socksPort, dns=$dnsServer, ipv6=$enableIPv6")

            // Call the real Go implementation
            Tun2socks.startTun2Socks(fd, socksServer, socksPort, dnsServer, enableIPv6)
            android.util.Log.i("Tun2SocksBridge", "✅ Real tun2socks started successfully")
        } catch (e: Exception) {
            android.util.Log.e("Tun2SocksBridge", "❌ StartTun2Socks error: ${e.message}")
            e.printStackTrace()
        }
    }

    fun setPacketListener(listener: PacketListener) {
        android.util.Log.i("Tun2SocksBridge", "📡 PacketListener set")
        // Store listener for fallback method
        packetListener = listener

        // Test packets disabled - using only real packets now
        // simulatePacketCapture()
    }

    fun stopTun2Socks() {
        try {
            if (isInitialized) {
                android.util.Log.i("Tun2SocksBridge", "🛑 Stopping real tun2socks")
                Tun2socks.stopTun2Socks()
                android.util.Log.i("Tun2SocksBridge", "✅ Real tun2socks stopped")
            } else {
                android.util.Log.w("Tun2SocksBridge", "⚠️ Tun2socks not initialized, nothing to stop")
            }
        } catch (e: Exception) {
            android.util.Log.e("Tun2SocksBridge", "❌ Error stopping tun2socks: ${e.message}")
        }
    }

    // All simulation functions removed - using only real packet capture
}
