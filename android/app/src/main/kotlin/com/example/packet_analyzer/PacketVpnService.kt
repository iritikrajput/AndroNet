package com.example.packet_analyzer

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import io.flutter.plugin.common.MethodChannel
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

class PacketVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private var nativeInterface: NativeInterface? = null
    private var isRunning = false
    private lateinit var packetThread: Thread

    companion object {
        var methodChannel: MethodChannel? = null
    }

    override fun onCreate() {
        super.onCreate()
        nativeInterface = NativeInterface()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startVpn()
        return START_STICKY
    }

    private fun startVpn() {
        val builder = Builder()
            .setSession("PacketAnalyzer")
            .addAddress("10.0.0.2", 32)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("8.8.8.8")
            .setMtu(1500)

        vpnInterface = builder.establish()
        
        if (vpnInterface != null) {
            isRunning = true
            startForeground(1, createNotification())
            
            // Initialize native packet processing
            nativeInterface?.initializeVpnCapture(vpnInterface!!.fd)
            
            // Start packet processing thread
            packetThread = Thread {
                processPackets()
            }
            packetThread.start()
        }
    }

    private fun processPackets() {
        val input = FileInputStream(vpnInterface!!.fileDescriptor)
        val output = FileOutputStream(vpnInterface!!.fileDescriptor)
        val packet = ByteBuffer.allocate(32767)

        while (isRunning) {
            try {
                val length = input.read(packet.array())
                if (length > 0) {
                    packet.limit(length)
                    // Process packet through native code
                    nativeInterface?.processPacket(packet.array(), length)
                    packet.clear()
                }
            } catch (e: Exception) {
                if (isRunning) {
                    e.printStackTrace()
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        isRunning = false
        
        nativeInterface?.cleanup()
        
        vpnInterface?.close()
        vpnInterface = null
        
        if (::packetThread.isInitialized) {
            packetThread.interrupt()
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "PACKET_ANALYZER_CHANNEL",
                "Packet Analyzer Service",
                NotificationManager.IMPORTANCE_LOW
            )
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, "PACKET_ANALYZER_CHANNEL")
                .setContentTitle("Packet Analyzer")
                .setContentText("VPN Service is running")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("Packet Analyzer")
                .setContentText("VPN Service is running")
                .setSmallIcon(android.R.drawable.ic_menu_info_details)
                .build()
        }
    }
}
