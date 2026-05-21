package com.example.packet_analyzer

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.random.Random

class EntropyTest {

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
        // Payload with exactly two distinct values in equal proportion → entropy = 1.0
        val payload = ByteArray(100) { i -> (i % 2).toByte() }
        val result = AnomalyDetector.calculateEntropy(payload)
        assertEquals(1.0, result, 0.0001)
    }

    @Test
    fun `256 uniformly distributed bytes returns 8_0`() {
        // One of each byte value 0-255 → maximum entropy = log2(256) = 8.0
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
}
