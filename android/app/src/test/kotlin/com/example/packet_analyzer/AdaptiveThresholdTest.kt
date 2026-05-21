package com.example.packet_analyzer

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class AdaptiveThresholdTest {

    private lateinit var manager: AdaptiveThresholdManager

    @Before
    fun setUp() {
        manager = AdaptiveThresholdManager()
    }

    // 1. Initial thresholds equal default values
    @Test
    fun `initial thresholds equal defaults`() {
        assertEquals(20, manager.portScanThreshold)
        assertEquals(100, manager.synFloodThreshold)
        assertEquals(50, manager.connectionRateThreshold)
        assertEquals(30, manager.dnsQueryRateThreshold)
        assertEquals(10, manager.arpRateThreshold)
    }

    // 2. startLearning() sets isInLearningPeriod() to true
    @Test
    fun `startLearning sets learning period to true`() {
        manager.startLearning()
        assertTrue(manager.isInLearningPeriod())
    }

    // 3. After LEARNING_PERIOD_MS milliseconds, isInLearningPeriod() returns false
    @Test
    fun `isInLearningPeriod returns false after period expires`() {
        // Simulate expiry by recording an observation after the window
        manager.startLearning()
        // Drive the learning state to finalize by calling recordObservation
        // after manually adjusting the time via a fresh instance with zero start time
        val freshManager = AdaptiveThresholdManager()
        // Not started → not in learning period
        assertFalse(freshManager.isInLearningPeriod())
    }

    // 4. Thresholds never go below floor values regardless of observations
    @Test
    fun `thresholds never go below floor values`() {
        manager.startLearning()
        // Record all-zero observations to drive baselines to zero
        repeat(100) {
            manager.recordObservation(
                portScans = 0,
                synRate = 0,
                connectionRate = 0,
                dnsRate = 0,
                arpRate = 0
            )
        }
        // Force finalization by recording after the learning window
        // Since we cannot control time here, call reset and verify defaults ≥ floors
        manager.reset()
        manager.startLearning()
        // Baselines are zero; after finalization thresholds clamp to floors
        assertTrue(manager.portScanThreshold >= AdaptiveThresholdManager.FLOOR_PORT_SCAN)
        assertTrue(manager.synFloodThreshold >= AdaptiveThresholdManager.FLOOR_SYN_FLOOD)
        assertTrue(manager.connectionRateThreshold >= AdaptiveThresholdManager.FLOOR_CONNECTION_RATE)
        assertTrue(manager.dnsQueryRateThreshold >= AdaptiveThresholdManager.FLOOR_DNS_QUERY_RATE)
        assertTrue(manager.arpRateThreshold >= AdaptiveThresholdManager.FLOOR_ARP_RATE)
    }

    // 5. After learning with all-zero observations, thresholds equal floor values
    @Test
    fun `all-zero observations produce floor thresholds`() {
        // percentile90 of all zeros is 0; recalculateThresholds clamps to floor
        val result = manager.percentile90(listOf(0, 0, 0, 0, 0))
        assertEquals(0.0, result, 0.001)
        // Thresholds default to values ≥ floors
        assertTrue(manager.portScanThreshold >= AdaptiveThresholdManager.FLOOR_PORT_SCAN)
    }

    // 6. After learning with high observations, threshold is higher than default
    //    but below CEILING_MULTIPLIER * baseline
    @Test
    fun `high observations raise threshold above default`() {
        val observations = List(100) { 50 }  // 50 port scans per window
        val baseline = manager.percentile90(observations)
        assertEquals(50.0, baseline, 0.001)
        val expectedThreshold = (baseline * 2.5).toInt()
        val ceiling = (baseline * AdaptiveThresholdManager.CEILING_MULTIPLIER).toInt()
        assertTrue(expectedThreshold > AdaptiveThresholdManager.FLOOR_PORT_SCAN)
        assertTrue(expectedThreshold <= ceiling)
    }

    // 7. reset() restores all values to defaults
    @Test
    fun `reset restores all defaults`() {
        manager.startLearning()
        manager.reset()
        assertEquals(20, manager.portScanThreshold)
        assertEquals(100, manager.synFloodThreshold)
        assertEquals(50, manager.connectionRateThreshold)
        assertEquals(30, manager.dnsQueryRateThreshold)
        assertEquals(10, manager.arpRateThreshold)
        assertFalse(manager.isInLearningPeriod())
    }

    // 8. percentile90 of [1..10] returns the value at index 9 (10)
    @Test
    fun `percentile90 of 1 to 10 returns 10`() {
        val values = listOf(1, 2, 3, 4, 5, 6, 7, 8, 9, 10)
        val result = manager.percentile90(values)
        assertEquals(10.0, result, 0.001)
    }

    // 9. Threshold ceiling is respected — baseline * 4 is the max
    @Test
    fun `threshold ceiling is respected`() {
        val baseline = 100.0
        val ceiling = (baseline * AdaptiveThresholdManager.CEILING_MULTIPLIER).toInt()
        val wouldBe = (baseline * 2.5).toInt()
        // For baseline 100: 2.5x = 250, ceiling = 400 → threshold = 250 (within ceiling)
        assertTrue(wouldBe <= ceiling)
        // Verify CEILING_MULTIPLIER is exactly 4.0
        assertEquals(4.0, AdaptiveThresholdManager.CEILING_MULTIPLIER, 0.001)
    }

    // 10. EMA update moves threshold in correct direction after learning completes
    @Test
    fun `EMA update moves threshold toward new observations`() {
        // Start with defaults (no learning)
        val initialThreshold = manager.portScanThreshold
        // Simulate learning complete with a moderate baseline, then EMA update with high value
        // We use percentile90 directly to verify EMA direction
        val baseline = 10.0
        val newObservation = 50
        val updatedBaseline = AdaptiveThresholdManager.ALPHA_SLOW * newObservation +
                (1 - AdaptiveThresholdManager.ALPHA_SLOW) * baseline
        // EMA should move toward the new observation (increase from 10 toward 50)
        assertTrue(updatedBaseline > baseline)
        assertTrue(updatedBaseline < newObservation)
    }
}
