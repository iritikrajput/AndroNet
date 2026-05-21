package com.example.packet_analyzer

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import kotlin.random.Random

class EntropyTest {

    // Track anomalies fired during each test
    private val firedAnomalies = mutableListOf<AnomalyDetector.Anomaly>()

    @Before
    fun setUp() {
        AnomalyDetector.reset()
        firedAnomalies.clear()
        AnomalyDetector.addAnomalyListener { firedAnomalies.add(it) }
    }

    // === Pre-existing calculateEntropy tests (unchanged) ===

    @Test
    fun `empty payload returns 0_0`() {
        val result = AnomalyDetector.calculateEntropy(ByteArray(0))
        assertEquals(0.0, result, 0.0001)
    }

    @Test
    fun `all identical bytes returns 0_0`() {
        val payload = ByteArray(100) { 0 }
        val result = AnomalyDetector.calculateEntropy(payload)
        assertEquals(0.0, result, 0.0001)
    }

    @Test
    fun `two alternating byte values returns 1_0`() {
        val payload = ByteArray(100) { i -> (i % 2).toByte() }
        val result = AnomalyDetector.calculateEntropy(payload)
        assertEquals(1.0, result, 0.0001)
    }

    @Test
    fun `256 uniformly distributed bytes returns 8_0`() {
        val payload = ByteArray(256) { i -> i.toByte() }
        val result = AnomalyDetector.calculateEntropy(payload)
        assertEquals(8.0, result, 0.0001)
    }

    @Test
    fun `ASCII string returns entropy between 2_0 and 4_0`() {
        val payload = "Hello World".toByteArray(Charsets.US_ASCII)
        val result = AnomalyDetector.calculateEntropy(payload)
        assertTrue("Expected entropy in [2.0, 4.0] but was $result", result >= 2.0 && result <= 4.0)
    }

    @Test
    fun `random ByteArray of 1000 bytes returns entropy above 7_5`() {
        val payload = Random(seed = 42).nextBytes(1000)
        val result = AnomalyDetector.calculateEntropy(payload)
        assertTrue("Expected entropy > 7.5 but was $result", result > 7.5)
    }

    // === New false-positive fix tests (COMMIT 15) ===

    // Helpers
    private fun highEntropyPayload(size: Int): ByteArray {
        val rng = java.util.Random(42)
        return ByteArray(size) { rng.nextInt(256).toByte() }
    }
    private fun lowEntropyPayload(size: Int): ByteArray = ByteArray(size) { 0x41.toByte() }

    // 1. isKnownCompressedFormat returns true for JPEG magic bytes [0xFF, 0xD8]
    @Test
    fun `isKnownCompressedFormat returns true for JPEG`() {
        val payload = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0x00, 0x00)
        assertTrue(AnomalyDetector.isKnownCompressedFormat(payload))
    }

    // 2. isKnownCompressedFormat returns true for PNG magic bytes [0x89, 0x50]
    @Test
    fun `isKnownCompressedFormat returns true for PNG`() {
        val payload = byteArrayOf(0x89.toByte(), 0x50.toByte(), 0x00, 0x00)
        assertTrue(AnomalyDetector.isKnownCompressedFormat(payload))
    }

    // 3. isKnownCompressedFormat returns true for GZIP magic bytes [0x1F, 0x8B]
    @Test
    fun `isKnownCompressedFormat returns true for GZIP`() {
        val payload = byteArrayOf(0x1F.toByte(), 0x8B.toByte(), 0x00, 0x00)
        assertTrue(AnomalyDetector.isKnownCompressedFormat(payload))
    }

    // 4. isKnownCompressedFormat returns false for plain text payload
    @Test
    fun `isKnownCompressedFormat returns false for plain text`() {
        val payload = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".toByteArray()
        assertFalse(AnomalyDetector.isKnownCompressedFormat(payload))
    }

    // 5. checkHighEntropyPayload does NOT fire for TLS protocol regardless of entropy
    @Test
    fun `no entropy alert for TLS protocol`() {
        val payload = highEntropyPayload(256)
        val packet = mapOf(
            "sourceIp" to "10.0.0.1",
            "destinationIp" to "10.0.0.2",
            "protocol" to "TLS",
            "destinationPort" to 443,
            "flags" to ""
        )
        repeat(10) { AnomalyDetector.analyzePacket(packet, payload) }
        val entropyAlerts = firedAnomalies.filter {
            it.type == AnomalyDetector.AnomalyType.HIGH_ENTROPY_PAYLOAD ||
            it.type == AnomalyDetector.AnomalyType.COVERT_CHANNEL
        }
        assertTrue("TLS should never trigger entropy alerts", entropyAlerts.isEmpty())
    }

    // 6. checkHighEntropyPayload does NOT fire for payload smaller than 64 bytes
    @Test
    fun `no entropy alert for payload under 64 bytes`() {
        val payload = highEntropyPayload(32)
        val packet = mapOf(
            "sourceIp" to "10.0.0.1",
            "destinationIp" to "10.0.0.2",
            "protocol" to "HTTP",
            "destinationPort" to 80,
            "flags" to ""
        )
        repeat(10) { AnomalyDetector.analyzePacket(packet, payload) }
        val entropyAlerts = firedAnomalies.filter {
            it.type == AnomalyDetector.AnomalyType.HIGH_ENTROPY_PAYLOAD
        }
        assertTrue("Payloads under 64 bytes should not trigger entropy alerts", entropyAlerts.isEmpty())
    }

    // 7. checkHighEntropyPayload does NOT fire on first 4 high-entropy packets;
    //    only fires on 5th consecutive
    @Test
    fun `entropy alert fires only after 5 consecutive high-entropy packets`() {
        val payload = highEntropyPayload(1000)
        val packet = mapOf(
            "sourceIp" to "10.0.0.3",
            "destinationIp" to "10.0.0.2",
            "protocol" to "HTTP",
            "destinationPort" to 80,
            "flags" to ""
        )
        repeat(4) { AnomalyDetector.analyzePacket(packet, payload) }
        val afterFour = firedAnomalies.filter {
            it.type == AnomalyDetector.AnomalyType.HIGH_ENTROPY_PAYLOAD
        }
        assertTrue("First 4 packets should not trigger alert", afterFour.isEmpty())

        AnomalyDetector.analyzePacket(packet, payload)
        val afterFive = firedAnomalies.filter {
            it.type == AnomalyDetector.AnomalyType.HIGH_ENTROPY_PAYLOAD
        }
        assertFalse("5th consecutive high-entropy packet should fire alert", afterFive.isEmpty())
    }

    // 8. checkHighEntropyPayload resets counter when normal-entropy packet arrives
    @Test
    fun `consecutive counter resets on normal entropy packet`() {
        val highPayload = highEntropyPayload(1000)
        val lowPayload = lowEntropyPayload(256)
        val packet = mapOf(
            "sourceIp" to "10.0.0.4",
            "destinationIp" to "10.0.0.2",
            "protocol" to "HTTP",
            "destinationPort" to 80,
            "flags" to ""
        )
        repeat(4) { AnomalyDetector.analyzePacket(packet, highPayload) }
        // Reset streak with one normal packet
        AnomalyDetector.analyzePacket(packet, lowPayload)
        // 4 more high-entropy — counter restarted from zero, still below threshold
        repeat(4) { AnomalyDetector.analyzePacket(packet, highPayload) }
        val alerts = firedAnomalies.filter {
            it.type == AnomalyDetector.AnomalyType.HIGH_ENTROPY_PAYLOAD
        }
        assertTrue("Streak reset should prevent alert after only 4 new packets", alerts.isEmpty())
    }

    // 9. Cooldown prevents second alert within 30 seconds from same source IP
    @Test
    fun `cooldown prevents second alert within 30 seconds`() {
        val payload = highEntropyPayload(1000)
        val packet = mapOf(
            "sourceIp" to "10.0.0.5",
            "destinationIp" to "10.0.0.2",
            "protocol" to "HTTP",
            "destinationPort" to 80,
            "flags" to ""
        )
        // Trigger the first alert (5 consecutive)
        repeat(5) { AnomalyDetector.analyzePacket(packet, payload) }
        val countAfterFirst = firedAnomalies.filter {
            it.type == AnomalyDetector.AnomalyType.HIGH_ENTROPY_PAYLOAD
        }.size

        // Send many more — all suppressed by cooldown
        repeat(20) { AnomalyDetector.analyzePacket(packet, payload) }
        val countAfterMore = firedAnomalies.filter {
            it.type == AnomalyDetector.AnomalyType.HIGH_ENTROPY_PAYLOAD
        }.size

        assertEquals(
            "Cooldown should suppress repeated alerts from same source IP",
            countAfterFirst,
            countAfterMore
        )
    }

    // 10. DNS tunneling check does not fire below entropy 6.2
    @Test
    fun `DNS tunneling check does not fire below threshold 6_2`() {
        val lowPayload = lowEntropyPayload(128)
        val entropy = AnomalyDetector.calculateEntropy(lowPayload)
        assertTrue("Low payload entropy should be well below 6.2, was $entropy", entropy < 6.2)

        val packet = mapOf(
            "sourceIp" to "10.0.0.6",
            "destinationIp" to "8.8.8.8",
            "protocol" to "DNS",
            "destinationPort" to 53,
            "flags" to ""
        )
        repeat(10) { AnomalyDetector.analyzePacket(packet, lowPayload) }
        val dnsTunnelAlerts = firedAnomalies.filter {
            it.type == AnomalyDetector.AnomalyType.DNS_TUNNELING &&
            it.description.contains("entropy")
        }
        assertTrue("Low-entropy DNS should not trigger tunneling alert", dnsTunnelAlerts.isEmpty())
    }
}
