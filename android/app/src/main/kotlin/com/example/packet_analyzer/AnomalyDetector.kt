package com.example.packet_analyzer

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Network Anomaly Detection System
 * Detects port scans, ARP spoofing, DDoS attacks, and other suspicious activities
 */
object AnomalyDetector {
    private const val TAG = "AnomalyDetector"

    // Detection thresholds
    private const val PORT_SCAN_THRESHOLD = 20 // ports per source IP in time window
    private const val PORT_SCAN_WINDOW_MS = 10000L // 10 seconds
    private const val SYN_FLOOD_THRESHOLD = 100 // SYN packets per second
    private const val CONNECTION_RATE_THRESHOLD = 50 // new connections per second
    private const val DNS_QUERY_THRESHOLD = 30 // DNS queries per second (possible DNS tunneling)

    // Data structures for tracking
    private val portScans = ConcurrentHashMap<String, PortScanTracker>()
    private val synFloodTracker = ConcurrentHashMap<String, SynFloodTracker>()
    private val connectionTracker = ConcurrentHashMap<String, ConnectionRateTracker>()
    private val dnsQueryTracker = DnsQueryTracker()
    private val arpCache = ConcurrentHashMap<String, String>() // IP -> MAC mapping

    // Anomaly listeners
    private val anomalyListeners = CopyOnWriteArrayList<(Anomaly) -> Unit>()

    data class Anomaly(
        val type: AnomalyType,
        val severity: Severity,
        val description: String,
        val sourceIp: String? = null,
        val destinationIp: String? = null,
        val details: Map<String, Any> = emptyMap(),
        val timestamp: Long = System.currentTimeMillis()
    )

    enum class AnomalyType {
        PORT_SCAN,
        SYN_FLOOD,
        ARP_SPOOFING,
        DNS_TUNNELING,
        CONNECTION_FLOOD,
        UNUSUAL_TRAFFIC,
        MALFORMED_PACKET
    }

    enum class Severity {
        LOW, MEDIUM, HIGH, CRITICAL
    }

    private data class PortScanTracker(
        var ports: MutableSet<Int> = mutableSetOf(),
        var firstSeen: Long = System.currentTimeMillis(),
        var lastSeen: Long = System.currentTimeMillis()
    )

    private data class SynFloodTracker(
        var synCount: Int = 0,
        var windowStart: Long = System.currentTimeMillis()
    )

    private data class ConnectionRateTracker(
        var connections: Int = 0,
        var windowStart: Long = System.currentTimeMillis()
    )

    private data class DnsQueryTracker(
        var queries: Int = 0,
        var windowStart: Long = System.currentTimeMillis(),
        var domains: MutableSet<String> = mutableSetOf()
    )

    /**
     * Register anomaly listener
     */
    fun addAnomalyListener(listener: (Anomaly) -> Unit) {
        anomalyListeners.add(listener)
    }

    /**
     * Remove anomaly listener
     */
    fun removeAnomalyListener(listener: (Anomaly) -> Unit) {
        anomalyListeners.remove(listener)
    }

    /**
     * Analyze a packet for anomalies
     */
    fun analyzePacket(packetInfo: Map<String, Any>) {
        try {
            val sourceIp = packetInfo["sourceIp"] as? String ?: return
            val destIp = packetInfo["destinationIp"] as? String ?: return
            val protocol = packetInfo["protocol"] as? String ?: return
            val destPort = (packetInfo["destinationPort"] as? Int) ?: 0
            val flags = packetInfo["flags"] as? String ?: ""

            // Port scan detection
            if (protocol == "TCP" && destPort > 0) {
                detectPortScan(sourceIp, destPort, destIp)
            }

            // SYN flood detection
            if (protocol == "TCP" && flags.contains("SYN") && !flags.contains("ACK")) {
                detectSynFlood(destIp)
            }

            // Connection flood detection
            if (protocol == "TCP" && flags.contains("SYN")) {
                detectConnectionFlood(sourceIp)
            }

            // DNS tunneling detection
            if (protocol == "UDP" && destPort == 53) {
                val dnsData = packetInfo["dnsData"] as? Map<String, String>
                val queryName = dnsData?.get("queryName") ?: ""
                detectDnsTunneling(queryName)
            }

            // ARP spoofing detection (requires raw packets with ARP protocol)
            if (protocol == "ARP") {
                detectArpSpoofing(packetInfo)
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error analyzing packet: ${e.message}")
        }
    }

    /**
     * Detect port scanning activity
     */
    private fun detectPortScan(sourceIp: String, port: Int, destIp: String) {
        val now = System.currentTimeMillis()

        val tracker = portScans.getOrPut(sourceIp) { PortScanTracker() }

        // Reset if window expired
        if (now - tracker.firstSeen > PORT_SCAN_WINDOW_MS) {
            tracker.ports.clear()
            tracker.firstSeen = now
        }

        tracker.ports.add(port)
        tracker.lastSeen = now

        // Check if threshold exceeded
        if (tracker.ports.size >= PORT_SCAN_THRESHOLD) {
            val anomaly = Anomaly(
                type = AnomalyType.PORT_SCAN,
                severity = Severity.HIGH,
                description = "Port scan detected: ${tracker.ports.size} ports scanned in ${(now - tracker.firstSeen) / 1000}s",
                sourceIp = sourceIp,
                destinationIp = destIp,
                details = mapOf(
                    "portsScanned" to tracker.ports.size,
                    "timeWindowMs" to (now - tracker.firstSeen),
                    "ports" to tracker.ports.take(20).joinToString(", ")
                )
            )
            reportAnomaly(anomaly)

            // Reset to avoid duplicate alerts
            tracker.ports.clear()
            tracker.firstSeen = now
        }
    }

    /**
     * Detect SYN flood attacks
     */
    private fun detectSynFlood(targetIp: String) {
        val now = System.currentTimeMillis()

        val tracker = synFloodTracker.getOrPut(targetIp) { SynFloodTracker() }

        // Reset counter every second
        if (now - tracker.windowStart > 1000) {
            tracker.synCount = 0
            tracker.windowStart = now
        }

        tracker.synCount++

        if (tracker.synCount >= SYN_FLOOD_THRESHOLD) {
            val anomaly = Anomaly(
                type = AnomalyType.SYN_FLOOD,
                severity = Severity.CRITICAL,
                description = "Possible SYN flood attack: ${tracker.synCount} SYN packets/second",
                destinationIp = targetIp,
                details = mapOf(
                    "synPacketsPerSecond" to tracker.synCount
                )
            )
            reportAnomaly(anomaly)

            // Reset to avoid spam
            tracker.synCount = 0
            tracker.windowStart = now
        }
    }

    /**
     * Detect connection flooding
     */
    private fun detectConnectionFlood(sourceIp: String) {
        val now = System.currentTimeMillis()

        val tracker = connectionTracker.getOrPut(sourceIp) { ConnectionRateTracker() }

        // Reset counter every second
        if (now - tracker.windowStart > 1000) {
            tracker.connections = 0
            tracker.windowStart = now
        }

        tracker.connections++

        if (tracker.connections >= CONNECTION_RATE_THRESHOLD) {
            val anomaly = Anomaly(
                type = AnomalyType.CONNECTION_FLOOD,
                severity = Severity.HIGH,
                description = "Excessive connection rate: ${tracker.connections} connections/second",
                sourceIp = sourceIp,
                details = mapOf(
                    "connectionsPerSecond" to tracker.connections
                )
            )
            reportAnomaly(anomaly)

            tracker.connections = 0
            tracker.windowStart = now
        }
    }

    /**
     * Detect DNS tunneling (data exfiltration via DNS)
     */
    private fun detectDnsTunneling(queryName: String) {
        if (queryName.isEmpty()) return

        val now = System.currentTimeMillis()

        // Reset counter every second
        if (now - dnsQueryTracker.windowStart > 1000) {
            dnsQueryTracker.queries = 0
            dnsQueryTracker.domains.clear()
            dnsQueryTracker.windowStart = now
        }

        dnsQueryTracker.queries++
        dnsQueryTracker.domains.add(queryName)

        // Check for excessive DNS queries
        if (dnsQueryTracker.queries >= DNS_QUERY_THRESHOLD) {
            val anomaly = Anomaly(
                type = AnomalyType.DNS_TUNNELING,
                severity = Severity.MEDIUM,
                description = "Possible DNS tunneling: ${dnsQueryTracker.queries} queries/second",
                details = mapOf(
                    "queriesPerSecond" to dnsQueryTracker.queries,
                    "uniqueDomains" to dnsQueryTracker.domains.size,
                    "sampleDomains" to dnsQueryTracker.domains.take(5).joinToString(", ")
                )
            )
            reportAnomaly(anomaly)

            dnsQueryTracker.queries = 0
            dnsQueryTracker.domains.clear()
            dnsQueryTracker.windowStart = now
        }

        // Check for suspiciously long domain names (common in DNS tunneling)
        if (queryName.length > 50) {
            val anomaly = Anomaly(
                type = AnomalyType.DNS_TUNNELING,
                severity = Severity.MEDIUM,
                description = "Suspicious DNS query: unusually long domain name (${queryName.length} chars)",
                details = mapOf(
                    "queryName" to queryName,
                    "length" to queryName.length
                )
            )
            reportAnomaly(anomaly)
        }
    }

    /**
     * Detect ARP spoofing
     */
    private fun detectArpSpoofing(packetInfo: Map<String, Any>) {
        // Note: This requires ARP packet support in capture
        val senderIp = packetInfo["senderIp"] as? String ?: return
        val senderMac = packetInfo["senderMac"] as? String ?: return

        val cachedMac = arpCache[senderIp]

        if (cachedMac != null && cachedMac != senderMac) {
            // IP address is now associated with a different MAC - possible spoofing
            val anomaly = Anomaly(
                type = AnomalyType.ARP_SPOOFING,
                severity = Severity.CRITICAL,
                description = "Possible ARP spoofing: IP $senderIp changed MAC from $cachedMac to $senderMac",
                sourceIp = senderIp,
                details = mapOf(
                    "oldMac" to cachedMac,
                    "newMac" to senderMac
                )
            )
            reportAnomaly(anomaly)
        }

        // Update cache
        arpCache[senderIp] = senderMac
    }

    /**
     * Report an anomaly to all listeners
     */
    private fun reportAnomaly(anomaly: Anomaly) {
        Log.w(TAG, "🚨 ANOMALY DETECTED: ${anomaly.type} - ${anomaly.description}")

        for (listener in anomalyListeners) {
            try {
                listener(anomaly)
            } catch (e: Exception) {
                Log.e(TAG, "Error in anomaly listener: ${e.message}")
            }
        }
    }

    /**
     * Get current detection statistics
     */
    fun getStatistics(): Map<String, Any> {
        return mapOf(
            "activePortScans" to portScans.size,
            "activeSynFloodTargets" to synFloodTracker.size,
            "activeConnectionFlooders" to connectionTracker.size,
            "arpCacheEntries" to arpCache.size,
            "dnsQueriesPerSecond" to dnsQueryTracker.queries
        )
    }

    /**
     * Clear all tracking data
     */
    fun reset() {
        portScans.clear()
        synFloodTracker.clear()
        connectionTracker.clear()
        arpCache.clear()
        dnsQueryTracker.queries = 0
        dnsQueryTracker.domains.clear()
        Log.i(TAG, "Anomaly detector reset")
    }

    /**
     * Cleanup old entries (call periodically)
     */
    fun cleanup() {
        val now = System.currentTimeMillis()

        // Remove old port scan trackers
        portScans.entries.removeAll { (_, tracker) ->
            now - tracker.lastSeen > PORT_SCAN_WINDOW_MS * 2
        }

        // Remove old SYN flood trackers
        synFloodTracker.entries.removeAll { (_, tracker) ->
            now - tracker.windowStart > 10000
        }

        // Remove old connection trackers
        connectionTracker.entries.removeAll { (_, tracker) ->
            now - tracker.windowStart > 10000
        }
    }
}
