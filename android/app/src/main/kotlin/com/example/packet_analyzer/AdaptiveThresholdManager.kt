package com.example.packet_analyzer

/**
 * Adaptive Threshold Manager
 *
 * Learns normal traffic rates during a 60-second baseline period, then sets
 * detection thresholds proportional to that baseline.  Hard floor values
 * prevent baseline-poisoning attacks; a ceiling multiplier prevents thresholds
 * from drifting so high that real attacks are missed.
 */
class AdaptiveThresholdManager {

    companion object {
        const val LEARNING_PERIOD_MS = 60_000L  // 60-second learning window
        const val ALPHA_SLOW = 0.05             // slow EMA for stable networks
        const val ALPHA_FAST = 0.15             // fast EMA for volatile networks

        // Absolute floor values — thresholds can never fall below these,
        // regardless of how quiet the observed baseline is
        const val FLOOR_PORT_SCAN = 8
        const val FLOOR_SYN_FLOOD = 30
        const val FLOOR_CONNECTION_RATE = 15
        const val FLOOR_DNS_QUERY_RATE = 10
        const val FLOOR_ARP_RATE = 3

        // Threshold ceiling = baseline * CEILING_MULTIPLIER
        // Prevents thresholds from drifting so high that real attacks are missed
        const val CEILING_MULTIPLIER = 4.0
    }

    // Current adaptive threshold values exposed to AnomalyDetector
    var portScanThreshold: Int = 20
        private set
    var synFloodThreshold: Int = 100
        private set
    var connectionRateThreshold: Int = 50
        private set
    var dnsQueryRateThreshold: Int = 30
        private set
    var arpRateThreshold: Int = 10
        private set

    // Learning period state
    private var learningStartTime: Long = 0L
    private var isLearning: Boolean = false
    private var learningComplete: Boolean = false

    // Observations collected during the learning window
    private val observedPortScansPerWindow = mutableListOf<Int>()
    private val observedSynRates = mutableListOf<Int>()
    private val observedConnectionRates = mutableListOf<Int>()
    private val observedDnsRates = mutableListOf<Int>()
    private val observedArpRates = mutableListOf<Int>()

    // EMA baseline values updated continuously after learning completes
    private var baselinePortScan = 0.0
    private var baselineSynFlood = 0.0
    private var baselineConnectionRate = 0.0
    private var baselineDnsRate = 0.0
    private var baselineArpRate = 0.0

    fun startLearning() {
        learningStartTime = System.currentTimeMillis()
        isLearning = true
        learningComplete = false
        observedPortScansPerWindow.clear()
        observedSynRates.clear()
        observedConnectionRates.clear()
        observedDnsRates.clear()
        observedArpRates.clear()
    }

    fun isInLearningPeriod(): Boolean {
        if (!isLearning) return false
        return System.currentTimeMillis() - learningStartTime < LEARNING_PERIOD_MS
    }

    fun recordObservation(
        portScans: Int,
        synRate: Int,
        connectionRate: Int,
        dnsRate: Int,
        arpRate: Int
    ) {
        when {
            isInLearningPeriod() -> {
                observedPortScansPerWindow.add(portScans)
                observedSynRates.add(synRate)
                observedConnectionRates.add(connectionRate)
                observedDnsRates.add(dnsRate)
                observedArpRates.add(arpRate)
            }
            isLearning && !learningComplete -> finalizeLearning()
            learningComplete -> updateEMA(portScans, synRate, connectionRate, dnsRate, arpRate)
        }
    }

    private fun finalizeLearning() {
        isLearning = false
        learningComplete = true

        // 90th-percentile baseline avoids skewing from isolated spikes during learning
        baselinePortScan = percentile90(observedPortScansPerWindow)
        baselineSynFlood = percentile90(observedSynRates)
        baselineConnectionRate = percentile90(observedConnectionRates)
        baselineDnsRate = percentile90(observedDnsRates)
        baselineArpRate = percentile90(observedArpRates)

        recalculateThresholds()
    }

    private fun updateEMA(
        portScans: Int,
        synRate: Int,
        connectionRate: Int,
        dnsRate: Int,
        arpRate: Int
    ) {
        baselinePortScan = ALPHA_SLOW * portScans + (1 - ALPHA_SLOW) * baselinePortScan
        baselineSynFlood = ALPHA_SLOW * synRate + (1 - ALPHA_SLOW) * baselineSynFlood
        baselineConnectionRate = ALPHA_SLOW * connectionRate + (1 - ALPHA_SLOW) * baselineConnectionRate
        baselineDnsRate = ALPHA_SLOW * dnsRate + (1 - ALPHA_SLOW) * baselineDnsRate
        baselineArpRate = ALPHA_SLOW * arpRate + (1 - ALPHA_SLOW) * baselineArpRate

        recalculateThresholds()
    }

    private fun recalculateThresholds() {
        portScanThreshold = clamp(
            (baselinePortScan * 2.5).toInt(),
            FLOOR_PORT_SCAN,
            (baselinePortScan * CEILING_MULTIPLIER).toInt().coerceAtLeast(FLOOR_PORT_SCAN * 2)
        )
        synFloodThreshold = clamp(
            (baselineSynFlood * 2.5).toInt(),
            FLOOR_SYN_FLOOD,
            (baselineSynFlood * CEILING_MULTIPLIER).toInt().coerceAtLeast(FLOOR_SYN_FLOOD * 2)
        )
        connectionRateThreshold = clamp(
            (baselineConnectionRate * 2.5).toInt(),
            FLOOR_CONNECTION_RATE,
            (baselineConnectionRate * CEILING_MULTIPLIER).toInt().coerceAtLeast(FLOOR_CONNECTION_RATE * 2)
        )
        dnsQueryRateThreshold = clamp(
            (baselineDnsRate * 2.5).toInt(),
            FLOOR_DNS_QUERY_RATE,
            (baselineDnsRate * CEILING_MULTIPLIER).toInt().coerceAtLeast(FLOOR_DNS_QUERY_RATE * 2)
        )
        arpRateThreshold = clamp(
            (baselineArpRate * 2.5).toInt(),
            FLOOR_ARP_RATE,
            (baselineArpRate * CEILING_MULTIPLIER).toInt().coerceAtLeast(FLOOR_ARP_RATE * 2)
        )
    }

    internal fun percentile90(values: List<Int>): Double {
        if (values.isEmpty()) return 0.0
        val sorted = values.sorted()
        val index = (sorted.size * 0.90).toInt().coerceAtMost(sorted.size - 1)
        return sorted[index].toDouble()
    }

    private fun clamp(value: Int, min: Int, max: Int): Int = value.coerceIn(min, max)

    fun getStatus(): Map<String, Any> {
        return mapOf(
            "isLearning" to isInLearningPeriod(),
            "learningComplete" to learningComplete,
            "thresholds" to mapOf(
                "portScan" to portScanThreshold,
                "synFlood" to synFloodThreshold,
                "connectionRate" to connectionRateThreshold,
                "dnsQueryRate" to dnsQueryRateThreshold,
                "arpRate" to arpRateThreshold
            ),
            "baselines" to mapOf(
                "portScan" to baselinePortScan,
                "synFlood" to baselineSynFlood,
                "connectionRate" to baselineConnectionRate,
                "dnsRate" to baselineDnsRate,
                "arpRate" to baselineArpRate
            )
        )
    }

    fun reset() {
        portScanThreshold = 20
        synFloodThreshold = 100
        connectionRateThreshold = 50
        dnsQueryRateThreshold = 30
        arpRateThreshold = 10
        baselinePortScan = 0.0
        baselineSynFlood = 0.0
        baselineConnectionRate = 0.0
        baselineDnsRate = 0.0
        baselineArpRate = 0.0
        isLearning = false
        learningComplete = false
    }
}
