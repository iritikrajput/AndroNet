package com.example.packet_analyzer

import android.util.Log

/**
 * JNI bridge to zdtun native library
 */
object ZdtunVpn {
    private const val TAG = "ZdtunVpn"

    init {
        try {
            System.loadLibrary("zdtun_vpn")
            Log.i(TAG, "Native library loaded successfully")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load native library: ${e.message}")
            throw e
        }
    }

    /**
     * Initialize zdtun with VPN service and TUN file descriptor
     */
    external fun nativeInit(vpnService: Any, tunFd: Int): Boolean

    /**
     * Handle a packet from TUN interface
     */
    external fun nativeHandlePacket(packet: ByteArray)

    /**
     * Handle zdtun events (socket I/O processing)
     */
    external fun nativeHandleEvents(timeoutMs: Int)

    /**
     * Cleanup zdtun resources
     */
    external fun nativeCleanup()
}
