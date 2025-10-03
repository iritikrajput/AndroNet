package com.example.packet_analyzer

import android.util.Log

/**
 * JNI Bridge for libpcap packet capture
 * Used for rooted devices (Kali NetHunter) to provide Wireshark-like capabilities
 */
object LibpcapBridge {
    private const val TAG = "LibpcapBridge"

    init {
        try {
            System.loadLibrary("pcap_capture")
            Log.i(TAG, "✅ libpcap_capture native library loaded")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "❌ Failed to load libpcap_capture: ${e.message}")
        }
    }

    /**
     * Initialize libpcap capture on specified network interface
     * @param serviceObj The service instance with callback methods
     * @param interfaceName Network interface (e.g., "wlan0", "eth0", "any")
     * @return true if successful
     */
    external fun nativeInit(serviceObj: Any, interfaceName: String): Boolean

    /**
     * Start packet capture
     * @return true if successful
     */
    external fun nativeStartCapture(): Boolean

    /**
     * Stop packet capture
     */
    external fun nativeStopCapture()

    /**
     * Cleanup libpcap resources
     */
    external fun nativeCleanup()

    /**
     * Get list of available network interfaces
     * @return Array of interface names
     */
    external fun nativeGetInterfaces(): Array<String>?
}
