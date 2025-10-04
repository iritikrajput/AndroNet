package com.example.packet_analyzer

import android.content.Context
import android.os.Environment
import android.util.Log
import io.flutter.plugin.common.MethodChannel
import kotlinx.coroutines.*
import java.io.File

/**
 * Packet Analysis Manager - Phase 2 Integration
 * Coordinates PCAP export, DPI, anomaly detection, and statistics
 */
class PacketAnalysisManager(private val context: Context) {
    private val TAG = "PacketAnalysisManager"

    private var isAnalyzing = false
    private var isPcapExporting = false
    private val managerScope = CoroutineScope(Dispatchers.Default + SupervisorJob())

    // Statistics tracking
    private var lastStatsUpdate = 0L
    private var packetsLastSecond = 0
    private var bytesLastSecond = 0L

    private val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())

    companion object {
        private var methodChannel: MethodChannel? = null

        fun setMethodChannel(channel: MethodChannel) {
            methodChannel = channel
        }
    }

    /**
     * Start analyzing packets (called when capture starts)
     */
    fun startAnalysis() {
        if (isAnalyzing) {
            Log.w(TAG, "Analysis already running")
            return
        }

        isAnalyzing = true
        Log.i(TAG, "🔍 Starting packet analysis...")

        // Reset statistics
        TrafficStatistics.reset()
        AnomalyDetector.reset()

        // Register anomaly listener
        AnomalyDetector.addAnomalyListener { anomaly ->
            handleAnomaly(anomaly)
        }

        // Start periodic stats update
        managerScope.launch {
            runPeriodicStatsUpdate()
        }

        // Start periodic cleanup
        managerScope.launch {
            runPeriodicCleanup()
        }
    }

    /**
     * Stop analyzing packets (called when capture stops)
     */
    fun stopAnalysis() {
        if (!isAnalyzing) {
            return
        }

        isAnalyzing = false
        Log.i(TAG, "🛑 Stopping packet analysis...")

        // Stop PCAP export if running
        if (isPcapExporting) {
            stopPcapExport()
        }

        managerScope.cancel()
    }

    /**
     * Process a captured packet through all Phase 2 systems
     */
    fun processPacket(packetInfo: Map<String, Any>, rawPacket: ByteArray? = null) {
        if (!isAnalyzing) return

        try {
            // 1. Update traffic statistics
            TrafficStatistics.updateStats(packetInfo)

            // 2. Deep packet inspection (if payload available)
            val enrichedPacket = if (rawPacket != null && rawPacket.isNotEmpty()) {
                // Extract payload from raw packet
                val payload = extractPayload(rawPacket, packetInfo)
                PacketDissector.dissect(packetInfo, payload)
            } else {
                packetInfo
            }

            // 3. Anomaly detection
            val payload = extractPayload(rawPacket, packetInfo)
            AnomalyDetector.analyzePacket(enrichedPacket, payload)

            // 4. PCAP export (if active)
            if (isPcapExporting && rawPacket != null) {
                val timestamp = (packetInfo["timestamp"] as? Long) ?: System.currentTimeMillis()
                PcapWriter.writePacket(rawPacket, timestamp)
            }

            // 5. Track for bandwidth calculation
            val size = (packetInfo["size"] as? Int)?.toLong() ?: 0L
            packetsLastSecond++
            bytesLastSecond += size

        } catch (e: Exception) {
            Log.e(TAG, "Error processing packet: ${e.message}")
        }
    }

    /**
     * Start exporting packets to PCAP file
     */
    fun startPcapExport(filename: String? = null): Boolean {
        if (isPcapExporting) {
            Log.w(TAG, "PCAP export already running")
            return false
        }

        try {
            // Use Downloads directory for easy access
            val downloadsDir = Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS)
            val andronetDir = File(downloadsDir, "AndroNet")
            andronetDir.mkdirs()

            val pcapFilename = filename ?: PcapWriter.generateFilename()
            val outputPath = File(andronetDir, pcapFilename).absolutePath

            val success = PcapWriter.startCapture(outputPath, linktype = 101) // Raw IP

            if (success) {
                isPcapExporting = true
                Log.i(TAG, "📝 PCAP export started: $outputPath")
                notifyFlutter("pcapExportStarted", mapOf("path" to outputPath))
            } else {
                Log.e(TAG, "❌ Failed to start PCAP export")
                notifyFlutter("pcapExportFailed", mapOf("error" to "Failed to initialize"))
            }

            return success

        } catch (e: Exception) {
            Log.e(TAG, "Error starting PCAP export: ${e.message}", e)
            notifyFlutter("pcapExportFailed", mapOf("error" to e.message))
            return false
        }
    }

    /**
     * Stop PCAP export
     */
    fun stopPcapExport(): Map<String, Any> {
        if (!isPcapExporting) {
            return emptyMap()
        }

        val stats = PcapWriter.stopCapture()
        isPcapExporting = false

        Log.i(TAG, "✅ PCAP export stopped: ${stats["packetCount"]} packets")
        notifyFlutter("pcapExportStopped", stats)

        return stats
    }

    /**
     * Get current PCAP export status
     */
    fun getPcapExportStatus(): Map<String, Any> {
        return if (isPcapExporting) {
            PcapWriter.getStats().toMutableMap().apply {
                put("isExporting", true)
            }
        } else {
            mapOf("isExporting" to false)
        }
    }

    /**
     * Get traffic statistics
     */
    fun getStatistics(): Map<String, Any> {
        return TrafficStatistics.getDashboardData()
    }

    /**
     * Get anomaly detection stats
     */
    fun getAnomalyStats(): Map<String, Any> {
        return AnomalyDetector.getStatistics()
    }

    /**
     * Handle detected anomaly
     */
    private fun handleAnomaly(anomaly: AnomalyDetector.Anomaly) {
        Log.w(TAG, "🚨 ANOMALY: ${anomaly.type} - ${anomaly.description}")

        val anomalyData = mapOf(
            "type" to anomaly.type.name,
            "severity" to anomaly.severity.name,
            "description" to anomaly.description,
            "sourceIp" to (anomaly.sourceIp ?: ""),
            "destinationIp" to (anomaly.destinationIp ?: ""),
            "timestamp" to anomaly.timestamp,
            "details" to anomaly.details
        )

        notifyFlutter("anomalyDetected", anomalyData)
    }

    /**
     * Periodic statistics update (every second)
     */
    private suspend fun runPeriodicStatsUpdate() {
        while (isAnalyzing) {
            delay(1000)

            try {
                // Record bandwidth and packet rate samples
                TrafficStatistics.recordBandwidthSample(bytesLastSecond)
                TrafficStatistics.recordPacketRateSample(packetsLastSecond)

                // Reset counters
                packetsLastSecond = 0
                bytesLastSecond = 0

                // Send periodic stats update to Flutter (every 5 seconds)
                if (System.currentTimeMillis() - lastStatsUpdate > 5000) {
                    val stats = TrafficStatistics.getSummary()
                    notifyFlutter("statsUpdate", stats)
                    lastStatsUpdate = System.currentTimeMillis()
                }

            } catch (e: Exception) {
                Log.e(TAG, "Error in stats update: ${e.message}")
            }
        }
    }

    /**
     * Periodic cleanup of old data (every minute)
     */
    private suspend fun runPeriodicCleanup() {
        while (isAnalyzing) {
            delay(60000) // 1 minute

            try {
                TrafficStatistics.cleanup()
                AnomalyDetector.cleanup()
                Log.d(TAG, "Performed periodic cleanup")

            } catch (e: Exception) {
                Log.e(TAG, "Error in cleanup: ${e.message}")
            }
        }
    }

    /**
     * Extract payload from raw packet
     */
    private fun extractPayload(packet: ByteArray, packetInfo: Map<String, Any>): ByteArray? {
        try {
            if (packet.size < 20) return null

            // Get IP header length
            val ihl = (packet[0].toInt() and 0x0F) * 4

            val protocol = packetInfo["protocol"] as? String ?: return null

            val payloadStart = when (protocol) {
                "TCP" -> {
                    // TCP header is at least 20 bytes
                    if (packet.size < ihl + 20) return null
                    val tcpHeaderLen = ((packet[ihl + 12].toInt() and 0xFF) shr 4) * 4
                    ihl + tcpHeaderLen
                }
                "UDP" -> {
                    // UDP header is 8 bytes
                    ihl + 8
                }
                "ICMP" -> {
                    // ICMP header is at least 8 bytes
                    ihl + 8
                }
                else -> return null
            }

            if (payloadStart >= packet.size) return null

            return packet.copyOfRange(payloadStart, packet.size)

        } catch (e: Exception) {
            Log.e(TAG, "Error extracting payload: ${e.message}")
            return null
        }
    }

    /**
     * Notify Flutter of events
     */
    private fun notifyFlutter(event: String, data: Any) {
        mainHandler.post {
            try {
                methodChannel?.invokeMethod("onAnalysisEvent", mapOf(
                    "event" to event,
                    "data" to data
                ))
            } catch (e: Exception) {
                Log.e(TAG, "Error notifying Flutter: ${e.message}")
            }
        }
    }
}
