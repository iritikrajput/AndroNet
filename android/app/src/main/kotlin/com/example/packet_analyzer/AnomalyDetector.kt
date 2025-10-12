package com.example.packet_analyzer

import android.util.Log
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.math.abs
import kotlin.math.log2
import kotlin.math.sqrt

/**
 * Network Anomaly Detection System
 * Detects port scans, ARP spoofing, DDoS attacks, and other suspicious activities
 */
object AnomalyDetector {
    private const val TAG = "AnomalyDetector"

    // Detection thresholds
    private const val PORT_SCAN_THRESHOLD = 20
    private const val PORT_SCAN_WINDOW_MS = 10000L
    private const val SYN_FLOOD_THRESHOLD = 100
    private const val CONNECTION_RATE_THRESHOLD = 50
    private const val DNS_QUERY_THRESHOLD = 30

    // ML-based data structures
    private val trafficStats = TrafficStatistics()
    private val behavioralAnalyzer = BehavioralAnalyzer()
    private val entropyAnalyzer = EntropyAnalyzer()
    private val connectionPatternAnalyzer = ConnectionPatternAnalyzer()

    // Adaptive thresholds
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
        val packetSizeStats: StatisticalModel = StatisticalModel()
    )

    private data class BehavioralAnalyzer(
        val ipActivityMap: MutableMap<String, MutableList<Long>> = mutableMapOf(),
        val protocolUsageMap: MutableMap<String, MutableList<Long>> = mutableMapOf(),
        val portActivityMap: MutableMap<Int, MutableList<Long>> = mutableMapOf()
    )

    private data class EntropyAnalyzer(
        val payloadEntropyMap: MutableMap<String, MutableList<Double>> = mutableMapOf(),
        val averageEntropy: Double = 4.5
    )

    private data class ConnectionPatternAnalyzer(
        val connectionSequences: MutableMap<String, MutableList<String>> = mutableMapOf(),
        val timingPatterns: MutableMap<String, MutableList<Long>> = mutableMapOf()
    )

    // Trackers
    private val anomalyListeners = CopyOnWriteArrayList<(Anomaly) -> Unit>()
    private val portScans = mutableMapOf<String, PortScanTracker>()
    private val synFloodTracker = mutableMapOf<String, SynFloodTracker>()
    private val connectionTracker = mutableMapOf<String, ConnectionRateTracker>()
    private val arpCache = mutableMapOf<String, String>()
    private val dnsQueryTracker = DnsQueryTracker()

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
        PORT_SCAN, SYN_FLOOD, ARP_SPOOFING, DNS_TUNNELING, CONNECTION_FLOOD,
        UNUSUAL_TRAFFIC, MALFORMED_PACKET
    }

    enum class Severity { LOW, MEDIUM, HIGH, CRITICAL }

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

    // === Listeners ===
    fun addAnomalyListener(listener: (Anomaly) -> Unit) {
        anomalyListeners.add(listener)
    }

    fun removeAnomalyListener(listener: (Anomaly) -> Unit) {
        anomalyListeners.remove(listener)
    }

    // === Core Analysis ===
    fun analyzePacket(packetInfo: Map<String, Any>, payload: ByteArray? = null) {
        try {
            val sourceIp = packetInfo["sourceIp"] as? String ?: return
            val destIp = packetInfo["destinationIp"] as? String ?: return
            val protocol = packetInfo["protocol"] as? String ?: return
            val destPort = (packetInfo["destinationPort"] as? Int) ?: 0
            val flags = packetInfo["flags"] as? String ?: ""

            // === 1. Basic Rule-Based Detection ===
            if (protocol == "TCP" && destPort > 0) detectPortScan(sourceIp, destPort, destIp)
            if (protocol == "TCP" && flags.contains("SYN") && !flags.contains("ACK")) detectSynFlood(destIp)
            if (protocol == "TCP" && flags.contains("SYN")) detectConnectionFlood(sourceIp)
            if (protocol == "UDP" && destPort == 53) {
                val dnsData = packetInfo["dnsData"] as? Map<String, String>
                detectDnsTunneling(dnsData?.get("queryName") ?: "")
            }
            if (protocol == "ARP") detectArpSpoofing(packetInfo)

            // === 2. Signature-Based Detection ===
            val signatureMatches = SignatureDatabase.matchSignatures(packetInfo, payload)
            for (match in signatureMatches) {
                reportAnomaly(
                    Anomaly(
                        type = when (match.signature.category) {
                            SignatureDatabase.Category.MALWARE -> AnomalyType.UNUSUAL_TRAFFIC
                            SignatureDatabase.Category.EXPLOIT -> AnomalyType.UNUSUAL_TRAFFIC
                            SignatureDatabase.Category.RECONNAISSANCE -> AnomalyType.PORT_SCAN
                            SignatureDatabase.Category.COMMAND_CONTROL -> AnomalyType.UNUSUAL_TRAFFIC
                            SignatureDatabase.Category.DATA_EXFILTRATION -> AnomalyType.DNS_TUNNELING
                            SignatureDatabase.Category.BRUTE_FORCE -> AnomalyType.CONNECTION_FLOOD
                            SignatureDatabase.Category.WEB_ATTACK -> AnomalyType.UNUSUAL_TRAFFIC
                            SignatureDatabase.Category.NETWORK_ATTACK -> AnomalyType.SYN_FLOOD
                        },
                        severity = match.signature.severity,
                        description = "[${match.signature.id}] ${match.signature.name}: ${match.signature.description}",
                        sourceIp = sourceIp,
                        destinationIp = destIp,
                        details = mapOf(
                            "signatureId" to match.signature.id,
                            "category" to match.signature.category.name
                        )
                    )
                )
            }

            // === 3. Rule Engine Detection ===
            val ruleMatches = RuleEngine.evaluateRules(packetInfo, payload)
            for (match in ruleMatches) {
                reportAnomaly(
                    Anomaly(
                        type = when (match.rule.category) {
                            "RECONNAISSANCE" -> AnomalyType.PORT_SCAN
                            "WEB_ATTACK" -> AnomalyType.UNUSUAL_TRAFFIC
                            "MALWARE" -> AnomalyType.UNUSUAL_TRAFFIC
                            "EXFILTRATION" -> AnomalyType.DNS_TUNNELING
                            "BRUTE_FORCE" -> AnomalyType.CONNECTION_FLOOD
                            "EXPLOIT" -> AnomalyType.UNUSUAL_TRAFFIC
                            else -> AnomalyType.UNUSUAL_TRAFFIC
                        },
                        severity = match.rule.severity,
                        description = "[${match.rule.id}] ${match.rule.name}: ${match.rule.description}",
                        sourceIp = sourceIp,
                        destinationIp = destIp,
                        details = match.details
                    )
                )
            }

            // === 4. ML-Based Detection (Stubs) ===
            detectBehavioralAnomalies(packetInfo)
            detectEntropyAnomalies(packetInfo, payload)
            detectConnectionPatternAnomalies(packetInfo)
            updateTrafficStatistics(packetInfo, payload)
            updateBehavioralModels(packetInfo)
            updateAdaptiveThresholds()

        } catch (e: Exception) {
            Log.e(TAG, "Error analyzing packet: ${e.message}")
        }
    }

    // === Basic Detection Functions ===
    private fun detectPortScan(sourceIp: String, port: Int, destIp: String) {
        val now = System.currentTimeMillis()
        val tracker = portScans.getOrPut(sourceIp) { PortScanTracker() }

        if (now - tracker.firstSeen > PORT_SCAN_WINDOW_MS) {
            tracker.ports.clear()
            tracker.firstSeen = now
        }
        tracker.ports.add(port)
        tracker.lastSeen = now

        if (tracker.ports.size >= PORT_SCAN_THRESHOLD) {
            reportAnomaly(
                Anomaly(
                    AnomalyType.PORT_SCAN, Severity.HIGH,
                    "Port scan detected from $sourceIp",
                    sourceIp, destIp
                )
            )
            tracker.ports.clear()
        }
    }

    private fun detectSynFlood(targetIp: String) {
        val now = System.currentTimeMillis()
        val tracker = synFloodTracker.getOrPut(targetIp) { SynFloodTracker() }

        if (now - tracker.windowStart > 1000) {
            tracker.synCount = 0
            tracker.windowStart = now
        }
        tracker.synCount++
        if (tracker.synCount >= SYN_FLOOD_THRESHOLD) {
            reportAnomaly(
                Anomaly(AnomalyType.SYN_FLOOD, Severity.CRITICAL, "Possible SYN flood", destinationIp = targetIp)
            )
            tracker.synCount = 0
        }
    }

    private fun detectConnectionFlood(sourceIp: String) {
        val now = System.currentTimeMillis()
        val tracker = connectionTracker.getOrPut(sourceIp) { ConnectionRateTracker() }

        if (now - tracker.windowStart > 1000) {
            tracker.connections = 0
            tracker.windowStart = now
        }
        tracker.connections++
        if (tracker.connections >= CONNECTION_RATE_THRESHOLD) {
            reportAnomaly(
                Anomaly(AnomalyType.CONNECTION_FLOOD, Severity.HIGH, "Connection flood detected", sourceIp = sourceIp)
            )
            tracker.connections = 0
        }
    }

    private fun detectDnsTunneling(queryName: String) {
        if (queryName.isEmpty()) return
        if (queryName.length > 50) {
            reportAnomaly(
                Anomaly(AnomalyType.DNS_TUNNELING, Severity.MEDIUM, "Suspicious DNS query: $queryName")
            )
        }
    }

    private fun detectArpSpoofing(packetInfo: Map<String, Any>) {
        val senderIp = packetInfo["senderIp"] as? String ?: return
        val senderMac = packetInfo["senderMac"] as? String ?: return
        val cached = arpCache[senderIp]
        if (cached != null && cached != senderMac) {
            reportAnomaly(
                Anomaly(AnomalyType.ARP_SPOOFING, Severity.CRITICAL, "ARP spoofing from $senderIp")
            )
        }
        arpCache[senderIp] = senderMac
    }

    // === Utility ===
    private fun reportAnomaly(anomaly: Anomaly) {
        Log.w(TAG, "🚨 Anomaly detected: ${anomaly.description}")
        for (listener in anomalyListeners) listener(anomaly)
    }

    // === Dummy Functional Replacements (to fix missing references) ===
    private fun detectBehavioralAnomalies(packetInfo: Map<String, Any>) {}
    private fun detectEntropyAnomalies(packetInfo: Map<String, Any>, payload: ByteArray?) {}
    private fun detectConnectionPatternAnomalies(packetInfo: Map<String, Any>) {}
    private fun updateTrafficStatistics(packetInfo: Map<String, Any>, payload: ByteArray?) {}
    private fun updateBehavioralModels(packetInfo: Map<String, Any>) {}
    private fun updateAdaptiveThresholds() {}

    // === Stats and Maintenance ===
    fun reset() {
        portScans.clear()
        synFloodTracker.clear()
        connectionTracker.clear()
        arpCache.clear()
        dnsQueryTracker.domains.clear()
        Log.i(TAG, "AnomalyDetector reset complete")
    }

    fun getStatistics(): Map<String, Any> = mapOf(
        "activePortScans" to portScans.size,
        "activeSynFloods" to synFloodTracker.size,
        "activeConnections" to connectionTracker.size
    )

    // === Cleanup ===
    fun cleanup() {
        val now = System.currentTimeMillis()
        portScans.entries.removeAll { now - it.value.lastSeen > 20000 }
        synFloodTracker.entries.removeAll { now - it.value.windowStart > 10000 }
        connectionTracker.entries.removeAll { now - it.value.windowStart > 10000 }
    }
}
