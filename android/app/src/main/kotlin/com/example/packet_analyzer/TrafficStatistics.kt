package com.example.packet_analyzer

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Real-time Traffic Statistics Tracker
 * Provides analytics data for dashboard visualization
 */
object TrafficStatistics {
    private const val TAG = "TrafficStatistics"
    private const val STATS_WINDOW_MS = 60000L // 1 minute rolling window

    // Protocol distribution
    private val protocolCounts = ConcurrentHashMap<String, Long>()
    private val protocolBytes = ConcurrentHashMap<String, Long>()

    // Top talkers (IP addresses)
    private val ipTraffic = ConcurrentHashMap<String, IpStats>()

    // Bandwidth tracking
    private val bandwidthSamples = CopyOnWriteArrayList<BandwidthSample>()

    // Connection tracking
    private val activeConnections = ConcurrentHashMap<String, ConnectionInfo>()

    // Time-series data
    private val packetRateHistory = CopyOnWriteArrayList<RateSample>()

    private var totalPackets = 0L
    private var totalBytes = 0L
    private var captureStartTime = 0L

    data class IpStats(
        var bytesSent: Long = 0,
        var bytesReceived: Long = 0,
        var packetsSent: Long = 0,
        var packetsReceived: Long = 0,
        var lastSeen: Long = System.currentTimeMillis()
    )

    data class BandwidthSample(
        val timestamp: Long,
        val bytesPerSecond: Long
    )

    data class RateSample(
        val timestamp: Long,
        val packetsPerSecond: Int
    )

    data class ConnectionInfo(
        val sourceIp: String,
        val destIp: String,
        val sourcePort: Int,
        val destPort: Int,
        val protocol: String,
        val startTime: Long = System.currentTimeMillis(),
        var lastSeen: Long = System.currentTimeMillis(),
        var bytesSent: Long = 0,
        var bytesReceived: Long = 0
    )

    /**
     * Update statistics with a new packet
     */
    fun updateStats(packetInfo: Map<String, Any>) {
        try {
            if (captureStartTime == 0L) {
                captureStartTime = System.currentTimeMillis()
            }

            val protocol = packetInfo["protocol"] as? String ?: "Unknown"
            val appName = packetInfo["appName"] as? String ?: protocol
            val size = (packetInfo["size"] as? Int)?.toLong() ?: 0L
            val sourceIp = packetInfo["sourceIp"] as? String ?: ""
            val destIp = packetInfo["destinationIp"] as? String ?: ""
            val sourcePort = (packetInfo["sourcePort"] as? Int) ?: 0
            val destPort = (packetInfo["destinationPort"] as? Int) ?: 0
            val direction = packetInfo["direction"] as? String ?: "outgoing"

            // Update total counters
            totalPackets++
            totalBytes += size

            // Update protocol statistics
            protocolCounts.merge(appName, 1L, Long::plus)
            protocolBytes.merge(appName, size, Long::plus)

            // Update IP statistics
            if (sourceIp.isNotEmpty()) {
                val sourceStats = ipTraffic.getOrPut(sourceIp) { IpStats() }
                if (direction == "outgoing") {
                    sourceStats.bytesSent += size
                    sourceStats.packetsSent++
                } else {
                    sourceStats.bytesReceived += size
                    sourceStats.packetsReceived++
                }
                sourceStats.lastSeen = System.currentTimeMillis()
            }

            if (destIp.isNotEmpty() && destIp != sourceIp) {
                val destStats = ipTraffic.getOrPut(destIp) { IpStats() }
                if (direction == "outgoing") {
                    destStats.bytesReceived += size
                    destStats.packetsReceived++
                } else {
                    destStats.bytesSent += size
                    destStats.packetsSent++
                }
                destStats.lastSeen = System.currentTimeMillis()
            }

            // Track connection
            if (protocol == "TCP" || protocol == "UDP") {
                val connKey = "$sourceIp:$sourcePort-$destIp:$destPort"
                val connection = activeConnections.getOrPut(connKey) {
                    ConnectionInfo(sourceIp, destIp, sourcePort, destPort, protocol)
                }
                connection.lastSeen = System.currentTimeMillis()
                if (direction == "outgoing") {
                    connection.bytesSent += size
                } else {
                    connection.bytesReceived += size
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error updating stats: ${e.message}")
        }
    }

    /**
     * Record bandwidth sample (call periodically, e.g., every second)
     */
    fun recordBandwidthSample(bytesInLastSecond: Long) {
        val sample = BandwidthSample(System.currentTimeMillis(), bytesInLastSecond)
        bandwidthSamples.add(sample)

        // Keep only last minute of samples
        val cutoff = System.currentTimeMillis() - STATS_WINDOW_MS
        bandwidthSamples.removeAll { it.timestamp < cutoff }
    }

    /**
     * Record packet rate sample
     */
    fun recordPacketRateSample(packetsInLastSecond: Int) {
        val sample = RateSample(System.currentTimeMillis(), packetsInLastSecond)
        packetRateHistory.add(sample)

        // Keep only last minute of samples
        val cutoff = System.currentTimeMillis() - STATS_WINDOW_MS
        packetRateHistory.removeAll { it.timestamp < cutoff }
    }

    /**
     * Get protocol distribution for pie chart
     */
    fun getProtocolDistribution(): Map<String, Long> {
        return protocolCounts.toMap().toList()
            .sortedByDescending { it.second }
            .take(10)
            .toMap()
    }

    /**
     * Get protocol distribution by bytes
     */
    fun getProtocolDistributionByBytes(): Map<String, Long> {
        return protocolBytes.toMap().toList()
            .sortedByDescending { it.second }
            .take(10)
            .toMap()
    }

    /**
     * Get top talkers (most active IPs)
     */
    fun getTopTalkers(limit: Int = 10): List<Pair<String, IpStats>> {
        return ipTraffic.toList()
            .sortedByDescending { (_, stats) -> stats.bytesSent + stats.bytesReceived }
            .take(limit)
    }

    /**
     * Get bandwidth time series (for line chart)
     */
    fun getBandwidthTimeSeries(): List<BandwidthSample> {
        return bandwidthSamples.toList()
    }

    /**
     * Get packet rate time series
     */
    fun getPacketRateTimeSeries(): List<RateSample> {
        return packetRateHistory.toList()
    }

    /**
     * Get active connections
     */
    fun getActiveConnections(limit: Int = 20): List<ConnectionInfo> {
        val now = System.currentTimeMillis()
        return activeConnections.values
            .filter { now - it.lastSeen < 30000 } // Active in last 30 seconds
            .sortedByDescending { it.lastSeen }
            .take(limit)
    }

    /**
     * Get overall statistics summary
     */
    fun getSummary(): Map<String, Any> {
        val now = System.currentTimeMillis()
        val uptime = if (captureStartTime > 0) now - captureStartTime else 0

        val activeConns = activeConnections.values.count { now - it.lastSeen < 30000 }

        return mapOf(
            "totalPackets" to totalPackets,
            "totalBytes" to totalBytes,
            "uptimeMs" to uptime,
            "uptimeSeconds" to (uptime / 1000),
            "protocolCount" to protocolCounts.size,
            "uniqueIPs" to ipTraffic.size,
            "activeConnections" to activeConns,
            "packetsPerSecond" to if (uptime > 0) (totalPackets * 1000 / uptime) else 0,
            "bytesPerSecond" to if (uptime > 0) (totalBytes * 1000 / uptime) else 0,
            "avgPacketSize" to if (totalPackets > 0) (totalBytes / totalPackets) else 0
        )
    }

    /**
     * Get comprehensive dashboard data
     */
    fun getDashboardData(): Map<String, Any> {
        return mapOf(
            "summary" to getSummary(),
            "protocolDistribution" to getProtocolDistribution(),
            "protocolDistributionByBytes" to getProtocolDistributionByBytes(),
            "topTalkers" to getTopTalkers().map { (ip, stats) ->
                mapOf(
                    "ip" to ip,
                    "totalBytes" to (stats.bytesSent + stats.bytesReceived),
                    "totalPackets" to (stats.packetsSent + stats.packetsReceived),
                    "bytesSent" to stats.bytesSent,
                    "bytesReceived" to stats.bytesReceived
                )
            },
            "bandwidthTimeSeries" to getBandwidthTimeSeries().map { sample ->
                mapOf("timestamp" to sample.timestamp, "bps" to sample.bytesPerSecond)
            },
            "packetRateTimeSeries" to getPacketRateTimeSeries().map { sample ->
                mapOf("timestamp" to sample.timestamp, "pps" to sample.packetsPerSecond)
            },
            "activeConnections" to getActiveConnections().map { conn ->
                mapOf(
                    "source" to "${conn.sourceIp}:${conn.sourcePort}",
                    "destination" to "${conn.destIp}:${conn.destPort}",
                    "protocol" to conn.protocol,
                    "duration" to (System.currentTimeMillis() - conn.startTime),
                    "totalBytes" to (conn.bytesSent + conn.bytesReceived)
                )
            }
        )
    }

    /**
     * Reset all statistics
     */
    fun reset() {
        totalPackets = 0
        totalBytes = 0
        captureStartTime = 0
        protocolCounts.clear()
        protocolBytes.clear()
        ipTraffic.clear()
        bandwidthSamples.clear()
        packetRateHistory.clear()
        activeConnections.clear()
        Log.i(TAG, "Statistics reset")
    }

    /**
     * Cleanup old data (call periodically)
     */
    fun cleanup() {
        val now = System.currentTimeMillis()
        val cutoff = now - STATS_WINDOW_MS

        // Remove old bandwidth samples
        bandwidthSamples.removeAll { it.timestamp < cutoff }

        // Remove old packet rate samples
        packetRateHistory.removeAll { it.timestamp < cutoff }

        // Remove inactive connections (> 5 minutes)
        activeConnections.entries.removeAll { (_, conn) ->
            now - conn.lastSeen > 300000
        }

        // Remove inactive IPs (> 10 minutes)
        ipTraffic.entries.removeAll { (_, stats) ->
            now - stats.lastSeen > 600000
        }
    }
}
