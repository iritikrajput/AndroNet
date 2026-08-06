package com.example.packet_analyzer

import org.junit.Assert.*
import org.junit.Test

class PayloadAnalyzerTest {

    private fun packet(
        protocol: String = "TCP",
        destPort: Int = 9999,
        sourcePort: Int = 0
    ): Map<String, Any> = mapOf(
        "protocol" to protocol,
        "destinationPort" to destPort,
        "sourcePort" to sourcePort
    )

    @Suppress("UNCHECKED_CAST")
    private fun detectedMimeTypes(result: Map<String, Any>): List<String> {
        val files = result["detectedFiles"] as? List<Map<String, Any>> ?: return emptyList()
        return files.mapNotNull { it["mimeType"] as? String }
    }

    // ---- Magic-byte / file-signature detection ------------------------------

    @Test
    fun `detects JPEG by magic bytes`() {
        val payload = byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte(), 0, 0, 0)
        val result = PayloadAnalyzer.analyzePayload(payload, packet())
        assertTrue(detectedMimeTypes(result).contains("image/jpeg"))
    }

    @Test
    fun `detects PNG by magic bytes`() {
        val payload = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 0, 0, 0, 0)
        val result = PayloadAnalyzer.analyzePayload(payload, packet())
        assertTrue(detectedMimeTypes(result).contains("image/png"))
    }

    @Test
    fun `detects ZIP by magic bytes`() {
        val payload = byteArrayOf(0x50, 0x4B, 0x03, 0x04, 0, 0, 0, 0)
        val result = PayloadAnalyzer.analyzePayload(payload, packet())
        assertTrue(detectedMimeTypes(result).contains("application/zip"))
    }

    @Test
    fun `detects PDF by magic bytes`() {
        val payload = byteArrayOf(0x25, 0x50, 0x44, 0x46, '-'.code.toByte(), '1'.code.toByte())
        val result = PayloadAnalyzer.analyzePayload(payload, packet())
        assertTrue(detectedMimeTypes(result).contains("application/pdf"))
    }

    @Test
    fun `does not detect a file signature for plain benign text`() {
        val payload = "just a normal short benign text message, nothing special here".toByteArray()
        val result = PayloadAnalyzer.analyzePayload(payload, packet())
        assertTrue(
            "Expected no analysis keys for benign text, got: ${result.keys}",
            result.isEmpty()
        )
    }

    // ---- Embedded file scan (not just offset 0) ------------------------------

    @Test
    fun `finds an embedded ZIP signature in the middle of the payload`() {
        val prefix = "some random binary junk that is not a known file type-----".toByteArray()
        val zipSig = byteArrayOf(0x50, 0x4B, 0x03, 0x04)
        val suffix = "trailing data after the zip signature marker".toByteArray()
        val payload = prefix + zipSig + suffix

        val result = PayloadAnalyzer.analyzePayload(payload, packet())

        @Suppress("UNCHECKED_CAST")
        val files = result["detectedFiles"] as? List<Map<String, Any>>
        assertNotNull("Expected an embedded ZIP to be detected", files)
        val embedded = files!!.firstOrNull { it["type"] == "embedded_zip" }
        assertNotNull("Expected a detectedFiles entry of type embedded_zip", embedded)
        assertEquals(prefix.size, embedded!!["offset"])
    }

    // ---- Security risk flags --------------------------------------------------

    @Test
    fun `flags suspicious code execution keyword`() {
        val payload = "some code: eval(userInput); more text".toByteArray()
        val result = PayloadAnalyzer.analyzePayload(payload, packet())
        @Suppress("UNCHECKED_CAST")
        val flags = result["securityFlags"] as? List<String>
        assertNotNull(flags)
        assertTrue(flags!!.contains("SUSPICIOUS_CODE_EXECUTION"))
    }

    @Test
    fun `flags potential SQL injection when password and select co-occur`() {
        val payload = "SELECT password FROM users WHERE id=1".toByteArray()
        val result = PayloadAnalyzer.analyzePayload(payload, packet())
        @Suppress("UNCHECKED_CAST")
        val flags = result["securityFlags"] as? List<String>
        assertNotNull(flags)
        assertTrue(flags!!.contains("POTENTIAL_SQL_INJECTION"))
    }

    @Test
    fun `flags potential XSS when script and alert co-occur`() {
        val payload = "<script>alert('xss')</script>".toByteArray()
        val result = PayloadAnalyzer.analyzePayload(payload, packet())
        @Suppress("UNCHECKED_CAST")
        val flags = result["securityFlags"] as? List<String>
        assertNotNull(flags)
        assertTrue(flags!!.contains("POTENTIAL_XSS"))
    }

    @Test
    fun `flags executable content for Windows PE header`() {
        val payload = byteArrayOf(0x4D, 0x5A, 0, 0, 0, 0, 0, 0)
        val result = PayloadAnalyzer.analyzePayload(payload, packet())
        @Suppress("UNCHECKED_CAST")
        val flags = result["securityFlags"] as? List<String>
        assertNotNull(flags)
        assertTrue(flags!!.contains("EXECUTABLE_CONTENT_DETECTED"))
    }

    @Test
    fun `does not flag an innocuous conversational payload`() {
        val payload = "Hello, how are you today? The weather is nice.".toByteArray()
        val result = PayloadAnalyzer.analyzePayload(payload, packet())
        assertFalse(result.containsKey("securityFlags"))
    }
}
