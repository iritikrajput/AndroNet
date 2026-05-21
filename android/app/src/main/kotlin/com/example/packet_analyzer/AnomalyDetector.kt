package com.example.packet_analyzer

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.log2

/**
 * Network Anomaly Detection System
 * Detects port scans, ARP spoofing, DDoS attacks, and other suspicious activities
 */
object AnomalyDetector {
    private const val TAG = "AnomalyDetector"

    // Detection threshold floor values — adaptive values take precedence at runtime
    private const val FLOOR_PORT_SCAN = 20
    private const val PORT_SCAN_WINDOW_MS = 10000L
    private const val FLOOR_SYN_FLOOD = 100
    private const val FLOOR_CONNECTION_RATE = 50
    private const val DNS_QUERY_THRESHOLD = 30

    // Entropy analysis thresholds
    // COMMIT 1: raised to reduce false positives from compressed media and modern compression
    private const val ENTROPY_THRESHOLD_HIGH = 7.6
    private const val ENTROPY_THRESHOLD_SUSPICIOUS = 7.2
    private const val ENTROPY_THRESHOLD_DNS_TUNNEL = 6.2
    private const val MIN_PAYLOAD_SIZE_FOR_ENTROPY = 64

    // COMMIT 1: protocol allowlist — these always produce high entropy legitimately
    private val ENTROPY_ALLOWLIST = setOf(
        "TLS", "QUIC", "HTTPS", "SSL",
        "DTLS",
        "WireGuard",
        "IPSec",
        "SSH",
        "SFTP",
        "FTPS",
        "SMTPS",
        "IMAPS",
        "POP3S",
        "DoT",
        "DoH",
        "SRTP",
        "ZRTP"
    )

    // COMMIT 2: cooldown — prevents the same source IP from flooding the alert log
    private val entropyAlertCooldown = ConcurrentHashMap<String, Long>()
    private const val ENTROPY_COOLDOWN_MS = 30_000L

    // COMMIT 3: consecutive high-entropy packet counters — one-off packets are not evidence
    private val highEntropyPacketCount = ConcurrentHashMap<String, Int>()
    private val dnsHighEntropyCount = ConcurrentHashMap<String, Int>()
    private const val ENTROPY_CONSECUTIVE_THRESHOLD = 5
    private const val DNS_ENTROPY_CONSECUTIVE_THRESHOLD = 3

    // COMMIT 2: packet counter drives periodic cooldown map cleanup
    private val packetCount = AtomicInteger(0)

    // COMMIT 7: adaptive thresholds replace all hard-coded comparison values
    val adaptiveThresholds = AdaptiveThresholdManager()

    // ML-based data structures
    private val trafficStats = TrafficStatistics()
    private val behavioralAnalyzer = BehavioralAnalyzer()
    private val entropyAnalyzer = EntropyAnalyzer()
    private val connectionPatternAnalyzer = ConnectionPatternAnalyzer()

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

    // Trackers — ConcurrentHashMap because analyzePacket runs on IO/Default coroutines
    private val anomalyListeners = CopyOnWriteArrayList<(Anomaly) -> Unit>()
    private val portScans = ConcurrentHashMap<String, PortScanTracker>()
    private val synFloodTracker = ConcurrentHashMap<String, SynFloodTracker>()
    private val connectionTracker = ConcurrentHashMap<String, ConnectionRateTracker>()
    private val arpCache = ConcurrentHashMap<String, String>()
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
        UNUSUAL_TRAFFIC, MALFORMED_PACKET, HIGH_ENTROPY_PAYLOAD, COVERT_CHANNEL
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

    fun calculateEntropy(payload: ByteArray): Double {
        if (payload.isEmpty()) return 0.0
        val frequency = IntArray(256)
        for (byte in payload) frequency[byte.toInt() and 0xFF]++
        val size = payload.size.toDouble()
        return frequency.fold(0.0) { entropy, count ->
            if (count == 0) entropy
            else {
                val p = count / size
                entropy - p * log2(p)
            }
        }
    }

    fun calculateAnomalyScore(packetInfo: Map<String, Any>): Double {
        val sourceIp = packetInfo["sourceIp"] as? String ?: ""
        val destIp = (packetInfo["destinationIp"] ?: packetInfo["destinationAddress"]) as? String ?: ""

        val portScanScore = portScans[sourceIp]?.let {
            (it.ports.size.toDouble() / adaptiveThresholds.portScanThreshold).coerceIn(0.0, 1.0)
        } ?: 0.0

        val synFloodScore = synFloodTracker[destIp]?.let {
            (it.synCount.toDouble() / adaptiveThresholds.synFloodThreshold).coerceIn(0.0, 1.0)
        } ?: 0.0

        val connectionScore = connectionTracker[sourceIp]?.let {
            (it.connections.toDouble() / adaptiveThresholds.connectionRateThreshold).coerceIn(0.0, 1.0)
        } ?: 0.0

        return (portScanScore * 0.3 + synFloodScore * 0.4 + connectionScore * 0.3).coerceIn(0.0, 1.0)
    }

    // === Core Analysis ===
    fun analyzePacket(packetInfo: Map<String, Any>, payload: ByteArray? = null) {
        try {
            // COMMIT 10: during the 60-second learning period only record observations,
            // never fire alerts — prevents the first-minute false positive flood
            if (adaptiveThresholds.isInLearningPeriod()) {
                recordObservationsOnly(packetInfo)
                return
            }

            // COMMIT 2: periodic cleanup of the cooldown map to prevent unbounded growth
            if (packetCount.incrementAndGet() % 1000 == 0) clearStaleEntropyCooldowns()

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

            // === 4. Entropy-Based Detection ===
            if (payload != null && payload.size >= MIN_PAYLOAD_SIZE_FOR_ENTROPY) {
                val appName = packetInfo["appName"] as? String
                checkDnsTunneling(payload, protocol, sourceIp, destIp)
                checkHighEntropyPayload(payload, protocol, appName, sourceIp, destIp)
                (packetInfo as? MutableMap<String, Any>)?.put("entropyScore", calculateEntropy(payload))
            }

            // === 5. ML-Based Detection (Stubs) ===
            detectBehavioralAnomalies(packetInfo)
            detectConnectionPatternAnomalies(packetInfo)
            updateTrafficStatistics(packetInfo, payload)
            updateBehavioralModels(packetInfo)
            updateAdaptiveThresholds()

            // === 6. Record adaptive baseline observations (COMMIT 8) ===
            adaptiveThresholds.recordObservation(
                portScans = getCurrentPortScanRate(),
                synRate = getCurrentSynRate(),
                connectionRate = getCurrentConnectionRate(),
                dnsRate = getCurrentDnsRate(),
                arpRate = getCurrentArpRate()
            )

        } catch (e: Exception) {
            Log.e(TAG, "Error analyzing packet: ${e.message}")
        }
    }

    // COMMIT 10: record observations without running any detection logic
    private fun recordObservationsOnly(packetInfo: Map<String, Any>) {
        adaptiveThresholds.recordObservation(
            portScans = getCurrentPortScanRate(),
            synRate = getCurrentSynRate(),
            connectionRate = getCurrentConnectionRate(),
            dnsRate = getCurrentDnsRate(),
            arpRate = getCurrentArpRate()
        )
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

        // COMMIT 7: use adaptive threshold instead of hard-coded constant
        if (tracker.ports.size >= adaptiveThresholds.portScanThreshold) {
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
        // COMMIT 7: use adaptive threshold
        if (tracker.synCount >= adaptiveThresholds.synFloodThreshold) {
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
        // COMMIT 7: use adaptive threshold
        if (tracker.connections >= adaptiveThresholds.connectionRateThreshold) {
            reportAnomaly(
                Anomaly(AnomalyType.CONNECTION_FLOOD, Severity.HIGH, "Connection flood detected", sourceIp = sourceIp)
            )
            tracker.connections = 0
        }
    }

    private fun checkHighEntropyPayload(
        payload: ByteArray,
        protocol: String,
        appName: String?,
        sourceIp: String,
        destinationIp: String
    ) {
        if (payload.size < MIN_PAYLOAD_SIZE_FOR_ENTROPY) return
        if (protocol.isEmpty()) return
        // COMMIT 4: skip known compressed/encrypted binary formats
        if (isKnownCompressedFormat(payload)) return
        // COMMIT 1: skip protocols that legitimately always produce high entropy
        if (protocol.uppercase() in ENTROPY_ALLOWLIST) return

        val entropy = calculateEntropy(payload)

        // Determine whether this packet's entropy would qualify for any alert
        val wouldAlert = when {
            protocol == "ICMP" && entropy > 6.0 -> true
            (protocol == "HTTP" || protocol == "DNS") && entropy > ENTROPY_THRESHOLD_SUSPICIOUS -> true
            entropy > ENTROPY_THRESHOLD_HIGH -> true
            else -> false
        }

        // COMMIT 3: require 5 consecutive high-entropy packets before alerting;
        // a single outlier packet is not evidence of tunneling
        if (wouldAlert) {
            highEntropyPacketCount[sourceIp] = (highEntropyPacketCount[sourceIp] ?: 0) + 1
            if ((highEntropyPacketCount[sourceIp] ?: 0) < ENTROPY_CONSECUTIVE_THRESHOLD) return
        } else {
            highEntropyPacketCount[sourceIp] = 0
            return
        }

        // COMMIT 2: cooldown — same source suppressed for 30 s after an alert
        val now = System.currentTimeMillis()
        val lastAlert = entropyAlertCooldown[sourceIp] ?: 0L
        if (now - lastAlert < ENTROPY_COOLDOWN_MS) return
        entropyAlertCooldown[sourceIp] = now

        when {
            protocol == "ICMP" && entropy > 6.0 -> reportAnomaly(
                Anomaly(
                    type = AnomalyType.COVERT_CHANNEL,
                    severity = Severity.CRITICAL,
                    description = "ICMP payload entropy ${"%.2f".format(entropy)} — possible icmptunnel/ptunnel covert channel",
                    sourceIp = sourceIp,
                    destinationIp = destinationIp
                )
            )
            (protocol == "HTTP" || protocol == "DNS") && entropy > ENTROPY_THRESHOLD_HIGH -> reportAnomaly(
                Anomaly(
                    type = AnomalyType.HIGH_ENTROPY_PAYLOAD,
                    severity = Severity.HIGH,
                    description = "High entropy ${"%.2f".format(entropy)} in $protocol payload — possible exfiltration",
                    sourceIp = sourceIp,
                    destinationIp = destinationIp
                )
            )
            (protocol == "HTTP" || protocol == "DNS") && entropy > ENTROPY_THRESHOLD_SUSPICIOUS -> reportAnomaly(
                Anomaly(
                    type = AnomalyType.HIGH_ENTROPY_PAYLOAD,
                    severity = Severity.MEDIUM,
                    description = "Suspicious entropy ${"%.2f".format(entropy)} in $protocol payload",
                    sourceIp = sourceIp,
                    destinationIp = destinationIp
                )
            )
            entropy > ENTROPY_THRESHOLD_HIGH -> reportAnomaly(
                Anomaly(
                    type = AnomalyType.HIGH_ENTROPY_PAYLOAD,
                    severity = Severity.MEDIUM,
                    description = "Unexpected high entropy ${"%.2f".format(entropy)} in $protocol — investigate",
                    sourceIp = sourceIp,
                    destinationIp = destinationIp
                )
            )
        }
    }

    private fun checkDnsTunneling(payload: ByteArray, protocol: String, sourceIp: String, destinationIp: String) {
        if (protocol != "DNS") return
        if (payload.size < MIN_PAYLOAD_SIZE_FOR_ENTROPY) return
        val entropy = calculateEntropy(payload)

        // COMMIT 3: require 3 consecutive high-entropy DNS packets; real tunneling is a stream
        if (entropy > ENTROPY_THRESHOLD_DNS_TUNNEL) {
            dnsHighEntropyCount[sourceIp] = (dnsHighEntropyCount[sourceIp] ?: 0) + 1
            if ((dnsHighEntropyCount[sourceIp] ?: 0) < DNS_ENTROPY_CONSECUTIVE_THRESHOLD) return
        } else {
            dnsHighEntropyCount[sourceIp] = 0
            return
        }

        // COMMIT 2: cooldown check
        val now = System.currentTimeMillis()
        val lastAlert = entropyAlertCooldown[sourceIp] ?: 0L
        if (now - lastAlert < ENTROPY_COOLDOWN_MS) return
        entropyAlertCooldown[sourceIp] = now

        reportAnomaly(
            Anomaly(
                type = AnomalyType.DNS_TUNNELING,
                severity = Severity.HIGH,
                description = "DNS query entropy ${"%.2f".format(entropy)} suggests tunneling tool (dnscat2/iodine)",
                sourceIp = sourceIp,
                destinationIp = destinationIp
            )
        )
    }

    // COMMIT 4: magic-byte pre-filter — skip known compressed/media formats before
    // computing entropy, as these legitimately produce high entropy values
    internal fun isKnownCompressedFormat(payload: ByteArray): Boolean {
        if (payload.size < 4) return false
        val b = payload
        return when {
            b[0] == 0xFF.toByte() && b[1] == 0xD8.toByte() -> true  // JPEG
            b[0] == 0x89.toByte() && b[1] == 0x50.toByte() -> true  // PNG
            b[0] == 0x47.toByte() && b[1] == 0x49.toByte() -> true  // GIF
            b[0] == 0x50.toByte() && b[1] == 0x4B.toByte() -> true  // ZIP/APK/JAR
            b[0] == 0x1F.toByte() && b[1] == 0x8B.toByte() -> true  // GZIP
            b[0] == 0x42.toByte() && b[1] == 0x5A.toByte() -> true  // BZIP2
            b[0] == 0xFD.toByte() && b[1] == 0x37.toByte() -> true  // XZ
            b[0] == 0x52.toByte() && b[1] == 0x61.toByte() -> true  // RAR
            b[0] == 0x37.toByte() && b[1] == 0x7A.toByte() -> true  // 7ZIP
            b[0] == 0x00.toByte() && b[1] == 0x00.toByte()
                && b[2] == 0x00.toByte() -> true                     // MP4/MOV
            b[0] == 0x1A.toByte() && b[1] == 0x45.toByte() -> true  // WebM/MKV
            else -> false
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

    // === COMMIT 8: Rate extraction — feed the adaptive threshold manager ===

    private fun getCurrentPortScanRate(): Int =
        portScans.values.maxOfOrNull { it.ports.size } ?: 0

    private fun getCurrentSynRate(): Int =
        synFloodTracker.values.maxOfOrNull { it.synCount } ?: 0

    private fun getCurrentConnectionRate(): Int =
        connectionTracker.values.maxOfOrNull { it.connections } ?: 0

    private fun getCurrentDnsRate(): Int = dnsQueryTracker.queries

    // No per-window ARP rate counter exists; return 0 so the adaptive manager
    // keeps the floor value for ARP thresholds
    private fun getCurrentArpRate(): Int = 0

    // === COMMIT 2: Entropy cooldown maintenance ===
    private fun clearStaleEntropyCooldowns() {
        val cutoff = System.currentTimeMillis() - 300_000L
        entropyAlertCooldown.entries.removeIf { it.value < cutoff }
    }

    // === Utility ===
    private fun reportAnomaly(anomaly: Anomaly) {
        for (listener in anomalyListeners) listener(anomaly)
    }

    // === Stubs for future ML-based detection ===
    private fun detectBehavioralAnomalies(packetInfo: Map<String, Any>) {}
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
        highEntropyPacketCount.clear()
        dnsHighEntropyCount.clear()
        entropyAlertCooldown.clear()
        packetCount.set(0)
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
