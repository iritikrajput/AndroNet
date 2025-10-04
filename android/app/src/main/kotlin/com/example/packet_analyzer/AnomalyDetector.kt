package com.example.packet_analyzer

import kotlin.math.abs
import kotlin.math.log2
import kotlin.math.sqrt
import kotlin.collections.MutableList
import kotlin.collections.mutableMapOf

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

    // ML-based anomaly detection data structures
    private val trafficStats = TrafficStatistics()
    private val behavioralAnalyzer = BehavioralAnalyzer()
    private val entropyAnalyzer = EntropyAnalyzer()
    private val connectionPatternAnalyzer = ConnectionPatternAnalyzer()

    // Adaptive thresholds (updated based on learned behavior)
    private var adaptivePortScanThreshold = PORT_SCAN_THRESHOLD.toDouble()
    private var adaptiveSynFloodThreshold = SYN_FLOOD_THRESHOLD.toDouble()
    private var adaptiveConnectionRateThreshold = CONNECTION_RATE_THRESHOLD.toDouble()

    // Statistical models
    private data class StatisticalModel(
        var mean: Double = 0.0,
        var variance: Double = 0.0,
        var count: Int = 0,
        var lastUpdate: Long = System.currentTimeMillis()
    )

    private data class TrafficStatistics(
        val packetSizeStats: StatisticalModel = StatisticalModel(),
        val interPacketTimeStats: StatisticalModel = StatisticalModel(),
        val connectionDurationStats: StatisticalModel = StatisticalModel()
    )

    private data class BehavioralAnalyzer(
        val ipActivityMap: MutableMap<String, MutableList<Long>> = mutableMapOf(), // IP -> list of timestamps
        val protocolUsageMap: MutableMap<String, MutableList<Long>> = mutableMapOf(), // Protocol -> usage timestamps
        val portActivityMap: MutableMap<Int, MutableList<Long>> = mutableMapOf() // Port -> access timestamps
    )

    private data class EntropyAnalyzer(
        val payloadEntropyMap: MutableMap<String, MutableList<Double>> = mutableMapOf(), // IP -> entropy values
        val averageEntropy: Double = 4.5 // Typical entropy for normal traffic
    )

    private data class ConnectionPatternAnalyzer(
        val connectionSequences: MutableMap<String, MutableList<String>> = mutableMapOf(), // IP -> sequence of ports
        val timingPatterns: MutableMap<String, MutableList<Long>> = mutableMapOf() // IP -> connection timing intervals
    )

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
    fun analyzePacket(packetInfo: Map<String, Any>, payload: ByteArray? = null) {
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

            // ML-based anomaly detection
            detectStatisticalAnomalies(packetInfo, payload)
            detectBehavioralAnomalies(packetInfo)
            detectEntropyAnomalies(packetInfo, payload)
            detectConnectionPatternAnomalies(packetInfo)

            // Update learning models
            updateTrafficStatistics(packetInfo, payload)
            updateBehavioralModels(packetInfo)
            updateAdaptiveThresholds()

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
            "dnsQueriesPerSecond" to dnsQueryTracker.queries,

            // ML-based statistics
            "mlStatistics" to mapOf(
                "packetSizeMean" to trafficStats.packetSizeStats.mean,
                "packetSizeVariance" to trafficStats.packetSizeStats.variance,
                "packetSizeCount" to trafficStats.packetSizeStats.count,
                "trackedIps" to behavioralAnalyzer.ipActivityMap.size,
                "trackedProtocols" to behavioralAnalyzer.protocolUsageMap.size,
                "trackedPorts" to behavioralAnalyzer.portActivityMap.size,
                "entropyTracking" to entropyAnalyzer.payloadEntropyMap.size,
                "connectionPatterns" to connectionPatternAnalyzer.connectionSequences.size,
                "timingPatterns" to connectionPatternAnalyzer.timingPatterns.size
            ),

            // Adaptive thresholds
            "adaptiveThresholds" to mapOf(
                "portScanThreshold" to adaptivePortScanThreshold,
                "synFloodThreshold" to adaptiveSynFloodThreshold,
                "connectionRateThreshold" to adaptiveConnectionRateThreshold
            )
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

        // Reset ML-based analyzers
        trafficStats.packetSizeStats.mean = 0.0
        trafficStats.packetSizeStats.variance = 0.0
        trafficStats.packetSizeStats.count = 0

        behavioralAnalyzer.ipActivityMap.clear()
        behavioralAnalyzer.protocolUsageMap.clear()
        behavioralAnalyzer.portActivityMap.clear()

        entropyAnalyzer.payloadEntropyMap.clear()

        connectionPatternAnalyzer.connectionSequences.clear()
        connectionPatternAnalyzer.timingPatterns.clear()

        // Reset adaptive thresholds
        adaptivePortScanThreshold = PORT_SCAN_THRESHOLD.toDouble()
        adaptiveSynFloodThreshold = SYN_FLOOD_THRESHOLD.toDouble()
        adaptiveConnectionRateThreshold = CONNECTION_RATE_THRESHOLD.toDouble()

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

        // Cleanup ML-based analyzers
        cleanupOldEntries(behavioralAnalyzer.ipActivityMap, 3600000)
        cleanupOldEntries(behavioralAnalyzer.protocolUsageMap, 3600000)
        cleanupOldEntries(behavioralAnalyzer.portActivityMap, 3600000)
        cleanupOldEntries(connectionPatternAnalyzer.connectionSequences, 3600000)
        cleanupOldEntries(connectionPatternAnalyzer.timingPatterns, 3600000)
        cleanupOldEntries(entropyAnalyzer.payloadEntropyMap, 3600000)
    }

    /**
     * Detect behavioral anomalies by analyzing traffic patterns
     */
    private fun detectBehavioralAnomalies(packetInfo: Map<String, Any>) {
        val sourceIp = packetInfo["sourceIp"] as? String ?: return
        val protocol = packetInfo["protocol"] as? String ?: return
        val destPort = (packetInfo["destinationPort"] as? Int) ?: 0

        val now = System.currentTimeMillis()

        // Check unusual IP activity patterns
        val ipActivity = behavioralAnalyzer.ipActivityMap.getOrPut(sourceIp) { mutableListOf() }
        ipActivity.add(now)

        // Keep only last 1000 timestamps per IP
        if (ipActivity.size > 1000) {
            ipActivity.removeAt(0)
        }

        // Detect burst activity (more than 50 packets in 1 second)
        val recentActivity = ipActivity.filter { now - it < 1000 }
        if (recentActivity.size > 50) {
            val anomaly = Anomaly(
                type = AnomalyType.UNUSUAL_TRAFFIC,
                severity = Severity.HIGH,
                description = "Unusual burst activity from $sourceIp: ${recentActivity.size} packets in 1 second",
                sourceIp = sourceIp,
                details = mapOf(
                    "packetCount" to recentActivity.size,
                    "timeWindow" to 1000
                )
            )
            reportAnomaly(anomaly)
        }

        // Check unusual port activity
        if (destPort > 0) {
            val portActivity = behavioralAnalyzer.portActivityMap.getOrPut(destPort) { mutableListOf() }
            portActivity.add(now)

            // Keep only last 500 timestamps per port
            if (portActivity.size > 500) {
                portActivity.removeAt(0)
            }

            // Detect unusual port scanning patterns
            val portRecentActivity = portActivity.filter { now - it < 5000 } // 5 seconds
            if (portRecentActivity.size > 10) {
                // Check if this IP is accessing this port unusually frequently
                val ipPortActivity = portActivity.filter { it in recentActivity }
                if (ipPortActivity.size > 5) {
                    val anomaly = Anomaly(
                        type = AnomalyType.PORT_SCAN,
                        severity = Severity.MEDIUM,
                        description = "Unusual port activity pattern: $sourceIp accessing port $destPort ${ipPortActivity.size} times in 5 seconds",
                        sourceIp = sourceIp,
                        details = mapOf(
                            "port" to destPort,
                            "accessCount" to ipPortActivity.size,
                            "timeWindow" to 5000
                        )
                    )
                    reportAnomaly(anomaly)
                }
            }
        }
    }

    /**
     * Detect entropy-based anomalies in payload data
     */
    private fun detectEntropyAnomalies(packetInfo: Map<String, Any>, payload: ByteArray?) {
        val sourceIp = packetInfo["sourceIp"] as? String ?: return

        if (payload == null || payload.isEmpty()) return

        val entropy = calculateEntropy(payload)

        // Track entropy for this IP
        val entropyList = entropyAnalyzer.payloadEntropyMap.getOrPut(sourceIp) { mutableListOf() }
        entropyList.add(entropy)

        // Keep only last 100 entropy values per IP
        if (entropyList.size > 100) {
            entropyList.removeAt(0)
        }

        // Check for anomalous entropy (too high or too low suggests encoded/malformed data)
        val averageEntropy = entropyList.average()
        val entropyDeviation = abs(entropy - entropyAnalyzer.averageEntropy)

        if (entropyDeviation > 2.0) { // Significant deviation from normal entropy
            val anomaly = Anomaly(
                type = AnomalyType.UNUSUAL_TRAFFIC,
                severity = if (entropyDeviation > 3.0) Severity.HIGH else Severity.MEDIUM,
                description = "Unusual payload entropy from $sourceIp: ${"%.2f".format(entropy)} (deviation: ${"%.2f".format(entropyDeviation)})",
                sourceIp = sourceIp,
                details = mapOf(
                    "entropy" to entropy,
                    "averageEntropy" to averageEntropy,
                    "deviation" to entropyDeviation,
                    "expectedRange" to "${entropyAnalyzer.averageEntropy - 1.5} - ${entropyAnalyzer.averageEntropy + 1.5}"
                )
            )
            reportAnomaly(anomaly)
        }
    }

    /**
     * Detect anomalous connection patterns and timing
     */
    private fun detectConnectionPatternAnomalies(packetInfo: Map<String, Any>) {
        val sourceIp = packetInfo["sourceIp"] as? String ?: return
        val protocol = packetInfo["protocol"] as? String ?: return
        val destPort = (packetInfo["destinationPort"] as? Int) ?: 0

        if (protocol != "TCP") return

        val now = System.currentTimeMillis()

        // Track connection patterns
        val connectionSeq = connectionPatternAnalyzer.connectionSequences.getOrPut(sourceIp) { mutableListOf() }
        connectionSeq.add("$destPort")

        // Keep only last 50 connections per IP
        if (connectionSeq.size > 50) {
            connectionSeq.removeAt(0)
        }

        // Track timing patterns
        val timingList = connectionPatternAnalyzer.timingPatterns.getOrPut(sourceIp) { mutableListOf() }
        if (timingList.isNotEmpty()) {
            val lastConnection = timingList.last()
            val interval = now - lastConnection
            timingList.add(now)

            // Keep only last 100 timing intervals
            if (timingList.size > 100) {
                timingList.removeAt(0)
            }

            // Detect unusual connection timing (very regular or very irregular)
            if (timingList.size > 10) {
                val intervals = timingList.zipWithNext { a, b -> b - a }
                val avgInterval = intervals.average()
                val intervalVariance = intervals.map { (it - avgInterval) * (it - avgInterval) }.average()

                // Very regular timing (low variance) might indicate automated behavior
                if (intervalVariance < 100 && avgInterval < 1000) { // Less than 1 second average, very regular
                    val anomaly = Anomaly(
                        type = AnomalyType.UNUSUAL_TRAFFIC,
                        severity = Severity.LOW,
                        description = "Unusual connection timing pattern from $sourceIp: very regular intervals (${"%.0f".format(avgInterval)}ms)",
                        sourceIp = sourceIp,
                        details = mapOf(
                            "averageInterval" to avgInterval,
                            "intervalVariance" to intervalVariance,
                            "connectionCount" to timingList.size
                        )
                    )
                    reportAnomaly(anomaly)
                }
            }
        } else {
            timingList.add(now)
        }

        // Detect sequential port access patterns (potential scanning)
        if (connectionSeq.size >= 5) {
            val recentPorts = connectionSeq.takeLast(5)
            val uniquePorts = recentPorts.distinct().size

            // If accessing many different ports in sequence, likely scanning
            if (uniquePorts >= 4) {
                val anomaly = Anomaly(
                    type = AnomalyType.PORT_SCAN,
                    severity = Severity.MEDIUM,
                    description = "Sequential port access pattern from $sourceIp: ${uniquePorts} different ports in sequence",
                    sourceIp = sourceIp,
                    details = mapOf(
                        "portsAccessed" to recentPorts,
                        "uniquePorts" to uniquePorts,
                        "sequenceLength" to recentPorts.size
                    )
                )
                reportAnomaly(anomaly)
            }
        }
    }

    /**
     * Update traffic statistics for ML models
     */
    private fun updateTrafficStatistics(packetInfo: Map<String, Any>, payload: ByteArray?) {
        val packetSize = payload?.size ?: 0

        if (packetSize > 0) {
            updateStatisticalModel(trafficStats.packetSizeStats, packetSize.toDouble())
        }
    }

    /**
     * Update behavioral models with new packet data
     */
    private fun updateBehavioralModels(packetInfo: Map<String, Any>) {
        val sourceIp = packetInfo["sourceIp"] as? String ?: return
        val protocol = packetInfo["protocol"] as? String ?: return
        val destPort = (packetInfo["destinationPort"] as? Int) ?: 0

        val now = System.currentTimeMillis()

        // Update IP activity
        behavioralAnalyzer.ipActivityMap.getOrPut(sourceIp) { mutableListOf() }.add(now)

        // Update protocol usage
        behavioralAnalyzer.protocolUsageMap.getOrPut(protocol) { mutableListOf() }.add(now)

        // Update port activity
        if (destPort > 0) {
            behavioralAnalyzer.portActivityMap.getOrPut(destPort) { mutableListOf() }.add(now)
        }

        // Cleanup old entries (older than 1 hour)
        cleanupOldEntries(behavioralAnalyzer.ipActivityMap, 3600000)
        cleanupOldEntries(behavioralAnalyzer.protocolUsageMap, 3600000)
        cleanupOldEntries(behavioralAnalyzer.portActivityMap, 3600000)
    }

    /**
     * Update adaptive thresholds based on learned behavior
     */
    private fun updateAdaptiveThresholds() {
        val now = System.currentTimeMillis()

        // Update thresholds based on traffic patterns
        if (trafficStats.packetSizeStats.count > 100) {
            // Adjust port scan threshold based on observed activity
            val avgPacketRate = behavioralAnalyzer.ipActivityMap.values.sumOf { it.size } / behavioralAnalyzer.ipActivityMap.size.toDouble()
            adaptivePortScanThreshold = maxOf(15.0, minOf(50.0, avgPacketRate * 0.5))

            // Adjust SYN flood threshold based on observed connection rates
            val totalConnections = connectionTracker.values.sumOf { it.connections }
            if (totalConnections > 0) {
                adaptiveSynFloodThreshold = maxOf(50.0, minOf(200.0, totalConnections * 1.5))
            }
        }
    }

    /**
     * Calculate Shannon entropy of byte array
     */
    private fun calculateEntropy(data: ByteArray): Double {
        if (data.isEmpty()) return 0.0

        val byteCounts = IntArray(256) { 0 }
        data.forEach { byteCounts[it.toInt() and 0xFF]++ }

        var entropy = 0.0
        val dataLength = data.size.toDouble()

        for (count in byteCounts) {
            if (count > 0) {
                val probability = count / dataLength
                entropy -= probability * log2(probability)
            }
        }

        return entropy
    }

    /**
     * Calculate z-score for statistical anomaly detection
     */
    private fun calculateZScore(value: Double, model: StatisticalModel): Double {
        if (model.count < 2) return 0.0

        val standardDeviation = sqrt(model.variance)
        if (standardDeviation == 0.0) return 0.0

        return (value - model.mean) / standardDeviation
    }

    /**
     * Update statistical model with new value using online algorithm
     */
    private fun updateStatisticalModel(model: StatisticalModel, value: Double) {
        model.count++
        val delta = value - model.mean
        model.mean += delta / model.count
        val delta2 = value - model.mean
        model.variance += delta * delta2
        model.lastUpdate = System.currentTimeMillis()
    }

    /**
     * Cleanup old entries from behavioral maps
     */
    private fun cleanupOldEntries(map: MutableMap<String, MutableList<Long>>, maxAge: Long) {
        val now = System.currentTimeMillis()
        val keysToRemove = mutableListOf<String>()

        for ((key, timestamps) in map) {
            timestamps.removeAll { now - it > maxAge }
            if (timestamps.isEmpty()) {
                keysToRemove.add(key)
            }
        }

        keysToRemove.forEach { map.remove(it) }
    }
