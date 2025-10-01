package com.example.packet_analyzer

import android.app.Service
import android.content.Intent
import android.os.IBinder
import android.util.Log
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.InputStreamReader
import java.text.SimpleDateFormat
import java.util.*

class NetHunterService : Service() {

    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var captureJob: Job? = null
    private var tcpdumpProcess: Process? = null

    companion object {
        private var methodChannel: MethodChannel? = null

        fun setMethodChannel(channel: MethodChannel) {
            methodChannel = channel
        }
    }

    override fun onBind(intent: Intent): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action

        when (action) {
            "START_CAPTURE" -> startLibpcapCapture()
            "STOP_CAPTURE" -> stopLibpcapCapture()
        }

        return START_STICKY
    }

    private fun startLibpcapCapture() {
        Log.i("NetHunterService", "Starting libpcap capture...")

        captureJob = serviceScope.launch {
            try {
                // Use tcpdump with libpcap for packet capture
                val command = arrayOf(
                    "su", "-c",
                    "tcpdump -i any -l -n -s 0 -X 2>/dev/null"
                )

                tcpdumpProcess = Runtime.getRuntime().exec(command)
                val reader = BufferedReader(InputStreamReader(tcpdumpProcess!!.inputStream))

                notifyFlutter("LIBPCAP_STARTED", "NetHunter capture started")

                var line: String?
                while (reader.readLine().also { line = it } != null && !Thread.currentThread().isInterrupted) {
                    line?.let { parseTcpdumpOutput(it) }
                }

            } catch (e: Exception) {
                Log.e("NetHunterService", "Libpcap capture error: ${e.message}")
                notifyFlutter("LIBPCAP_ERROR", "Capture failed: ${e.message}")
            }
        }
    }

    private fun stopLibpcapCapture() {
        Log.i("NetHunterService", "Stopping libpcap capture...")

        captureJob?.cancel()
        tcpdumpProcess?.destroy()
        tcpdumpProcess = null

        notifyFlutter("LIBPCAP_STOPPED", "NetHunter capture stopped")
    }

    private fun parseTcpdumpOutput(line: String) {
        try {
            // Parse tcpdump output format
            // Example: "12:34:56.789012 IP 192.168.1.1.80 > 192.168.1.100.54321: Flags [P.], seq 1:100, ack 1, win 65535, length 99"

            if (line.contains("IP ") && line.contains(" > ")) {
                val packetInfo = parseTcpdumpLine(line)
                if (packetInfo != null) {
                    notifyFlutter("PACKET_CAPTURED", packetInfo)
                }
            }
        } catch (e: Exception) {
            Log.e("NetHunterService", "Error parsing tcpdump line: ${e.message}")
        }
    }

    private fun parseTcpdumpLine(line: String): Map<String, Any>? {
        try {
            val parts = line.split(" ")
            if (parts.size < 4) return null

            val timestamp = parts[0]
            val protocol = if (line.contains("IP ")) "IP" else "Unknown"

            // Extract source and destination
            val connectionPart = parts.find { it.contains(" > ") }
            if (connectionPart == null) return null

            val connection = connectionPart.split(" > ")
            if (connection.size != 2) return null

            val sourceInfo = parseAddressPort(connection[0])
            val destInfo = parseAddressPort(connection[1].substringBefore(":"))

            // Extract flags and additional info
            val flags = extractFlags(line)
            val length = extractLength(line)

            return mapOf(
                "timestamp" to timestamp,
                "protocol" to protocol,
                "sourceIP" to (sourceInfo.first ?: "Unknown"),
                "destIP" to (destInfo.first ?: "Unknown"),
                "sourcePort" to (sourceInfo.second ?: 0),
                "destPort" to (destInfo.second ?: 0),
                "length" to (length ?: 0),
                "flags" to (flags ?: ""),
                "payload" to "", // tcpdump doesn't provide payload by default
                "captureMode" to "libpcap"
            )

        } catch (e: Exception) {
            Log.e("NetHunterService", "Error parsing tcpdump line: ${e.message}")
            return null
        }
    }

    private fun parseAddressPort(addressPort: String): Pair<String?, Int?> {
        try {
            val lastDotIndex = addressPort.lastIndexOf('.')
            if (lastDotIndex == -1) return Pair(addressPort, null)

            val address = addressPort.substring(0, lastDotIndex)
            val portStr = addressPort.substring(lastDotIndex + 1)

            val port = try {
                portStr.toInt()
            } catch (e: NumberFormatException) {
                null
            }

            return Pair(address, port)
        } catch (e: Exception) {
            return Pair(null, null)
        }
    }

    private fun extractFlags(line: String): String? {
        return try {
            val flagsRegex = "Flags \\[([^\\]]+)\\]".toRegex()
            val match = flagsRegex.find(line)
            match?.groupValues?.get(1)
        } catch (e: Exception) {
            null
        }
    }

    private fun extractLength(line: String): Int? {
        return try {
            val lengthRegex = "length (\\d+)".toRegex()
            val match = lengthRegex.find(line)
            match?.groupValues?.get(1)?.toInt()
        } catch (e: Exception) {
            null
        }
    }

    private fun notifyFlutter(event: String, data: Any) {
        try {
            android.os.Handler(android.os.Looper.getMainLooper()).post {
                methodChannel?.invokeMethod("onPacketEvent", mapOf(
                    "event" to event,
                    "data" to data
                ))
            }
        } catch (e: Exception) {
            Log.e("NetHunterService", "Flutter notification error: ${e.message}")
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        stopLibpcapCapture()
        serviceScope.cancel()
    }
}