package com.example.packet_analyzer

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

class RuleEngineTest {

    @Before
    fun setUp() {
        // Clears rate/window state (packetHistory, triggerCount, etc.) between tests.
        // Note: rules added via addRule() persist for the lifetime of the RuleEngine
        // singleton (there is no removeRule API), so custom rules below use unique,
        // narrowly-scoped conditions that cannot accidentally match other tests' packets.
        RuleEngine.clearState()
    }

    // ---- Helpers -------------------------------------------------------

    private fun packet(
        protocol: String = "TCP",
        destPort: Int = 0,
        sourcePort: Int = 0,
        destIp: String = "192.0.2.10",
        sourceIp: String = "192.0.2.20",
        flags: String = "",
        httpData: Map<String, Any>? = null,
        domain: String? = null,
        timestamp: Long = System.currentTimeMillis()
    ): Map<String, Any> {
        val map = mutableMapOf<String, Any>(
            "protocol" to protocol,
            "destinationPort" to destPort,
            "sourcePort" to sourcePort,
            "destinationIp" to destIp,
            "sourceIp" to sourceIp,
            "flags" to flags,
            "timestamp" to timestamp
        )
        if (httpData != null) map["httpData"] = httpData
        if (domain != null) map["domain"] = domain
        return map
    }

    private fun matches(packetInfo: Map<String, Any>, payload: ByteArray? = null) =
        RuleEngine.evaluateRules(packetInfo, payload)

    private fun List<RuleEngine.RuleMatch>.hasRule(id: String) = any { it.rule.id == id }

    // ---- Baseline --------------------------------------------------------

    @Test
    fun `benign packet with no payload triggers no default rules`() {
        val result = matches(packet(protocol = "TCP", destPort = 51000, sourcePort = 51001))
        assertTrue(
            "Expected no default rule to fire for a benign packet, got: ${result.map { it.rule.id }}",
            result.none { it.rule.id.startsWith("RULE-") }
        )
    }

    // ---- RULE-002 SQL Injection -------------------------------------------

    @Test
    fun `SQL injection rule fires for SQLi pattern in URL`() {
        val p = packet(
            protocol = "TCP",
            destPort = 80,
            httpData = mapOf("url" to "/login.php?id=1' OR '1'='1--")
        )
        assertTrue(matches(p).hasRule("RULE-002"))
    }

    @Test
    fun `SQL injection rule does not fire for benign URL`() {
        val p = packet(
            protocol = "TCP",
            destPort = 80,
            httpData = mapOf("url" to "/home/index.html")
        )
        assertFalse(matches(p).hasRule("RULE-002"))
    }

    // ---- RULE-003 Malicious File Download ----------------------------------

    @Test
    fun `malicious file download rule fires for exe download`() {
        val p = packet(httpData = mapOf("method" to "GET", "url" to "/downloads/setup.exe"))
        assertTrue(matches(p).hasRule("RULE-003"))
    }

    @Test
    fun `malicious file download rule does not fire for normal page GET`() {
        val p = packet(httpData = mapOf("method" to "GET", "url" to "/downloads/report.html"))
        assertFalse(matches(p).hasRule("RULE-003"))
    }

    // ---- RULE-001 Port Scan (UniqueDestinations + FlagsContain + Protocol) --

    @Test
    fun `port scan rule fires with many unique destinations and SYN flag`() {
        var result = emptyList<RuleEngine.RuleMatch>()
        for (i in 1..20) {
            result = matches(
                packet(protocol = "TCP", destPort = 443, destIp = "203.0.113.$i", flags = "SYN")
            )
        }
        assertTrue(result.hasRule("RULE-001"))
    }

    @Test
    fun `port scan rule does not fire with too few unique destinations`() {
        var result = emptyList<RuleEngine.RuleMatch>()
        for (i in 1..5) {
            result = matches(
                packet(protocol = "TCP", destPort = 443, destIp = "203.0.114.$i", flags = "SYN")
            )
        }
        assertFalse(result.hasRule("RULE-001"))
    }

    // ---- RULE-004 DNS Tunneling (PacketRate + PayloadSize / DomainMatches) --

    @Test
    fun `DNS tunneling rule fires via large payload at high query rate`() {
        val payload = ByteArray(200) { 0x41 }
        var result = emptyList<RuleEngine.RuleMatch>()
        repeat(11) {
            result = matches(packet(protocol = "UDP", destPort = 53), payload)
        }
        assertTrue(result.hasRule("RULE-004"))
    }

    @Test
    fun `DNS tunneling rule fires via long hex domain even with a small payload`() {
        // Exercises the Condition.DomainMatches branch (Or'd with PayloadSize).
        val longHexDomain = "0123456789abcdef0123456789abcdef.tunnel.example.com"
        val smallPayload = ByteArray(10) { 0x00 }
        var result = emptyList<RuleEngine.RuleMatch>()
        repeat(11) {
            result = matches(
                packet(protocol = "UDP", destPort = 53, domain = longHexDomain),
                smallPayload
            )
        }
        assertTrue(
            "Expected RULE-004 to fire via DomainMatches condition",
            result.hasRule("RULE-004")
        )
    }

    @Test
    fun `DNS tunneling rule does not fire for ordinary low-rate DNS queries`() {
        val payload = ByteArray(200) { 0x41 }
        val result = matches(packet(protocol = "UDP", destPort = 53, domain = "example.com"), payload)
        assertFalse(result.hasRule("RULE-004"))
    }

    // ---- RULE-005 Brute Force (Or ports + PacketRate) -----------------------

    @Test
    fun `brute force rule fires after 21 rapid SSH connection attempts`() {
        var result = emptyList<RuleEngine.RuleMatch>()
        repeat(21) {
            result = matches(packet(protocol = "TCP", destPort = 22))
        }
        assertTrue(result.hasRule("RULE-005"))
    }

    @Test
    fun `brute force rule does not fire for only a handful of attempts`() {
        var result = emptyList<RuleEngine.RuleMatch>()
        repeat(5) {
            result = matches(packet(protocol = "TCP", destPort = 22))
        }
        assertFalse(result.hasRule("RULE-005"))
    }

    // ---- RULE-006 Cryptomining (Protocol + Port + PayloadContains) ----------

    @Test
    fun `cryptomining rule fires for stratum payload on mining port`() {
        val payload = "stratum+tcp://pool.example.com:3333".toByteArray()
        val p = packet(protocol = "TCP", destPort = 3333)
        assertTrue(matches(p, payload).hasRule("RULE-006"))
    }

    @Test
    fun `cryptomining rule does not fire without stratum keyword`() {
        val payload = "just some ordinary tcp traffic".toByteArray()
        val p = packet(protocol = "TCP", destPort = 3333)
        assertFalse(matches(p, payload).hasRule("RULE-006"))
    }

    @Test
    fun `cryptomining rule does not fire on non-mining port even with stratum keyword`() {
        val payload = "stratum+tcp://pool.example.com".toByteArray()
        val p = packet(protocol = "TCP", destPort = 8080)
        assertFalse(matches(p, payload).hasRule("RULE-006"))
    }

    // ---- RULE-007 Suspicious Outbound Traffic (PacketRate + PayloadSize) ----

    @Test
    fun `outbound transfer rule fires for large payloads at high rate`() {
        val payload = ByteArray(2000) { 0x42 }
        var result = emptyList<RuleEngine.RuleMatch>()
        repeat(101) {
            result = matches(packet(protocol = "TCP", destPort = 54321, destIp = "198.51.100.5"), payload)
        }
        assertTrue(result.hasRule("RULE-007"))
    }

    @Test
    fun `outbound transfer rule does not fire for a single large payload`() {
        val payload = ByteArray(2000) { 0x42 }
        val result = matches(packet(protocol = "TCP", destPort = 54322, destIp = "198.51.100.6"), payload)
        assertFalse(result.hasRule("RULE-007"))
    }

    // ---- RULE-008 Shellcode Pattern (Or of PayloadMatches) -------------------

    @Test
    fun `shellcode rule fires for NOP sled pattern`() {
        val payload = ByteArray(15) { 0x90.toByte() }
        assertTrue(matches(packet(destPort = 44000), payload).hasRule("RULE-008"))
    }

    @Test
    fun `shellcode rule fires for JMP short pattern`() {
        val payload = byteArrayOf(0x01, 0x02, 0xEB.toByte(), 0x0E, 0x03, 0x04)
        assertTrue(matches(packet(destPort = 44001), payload).hasRule("RULE-008"))
    }

    @Test
    fun `shellcode rule does not fire for benign payload`() {
        val payload = "hello world, nothing suspicious here".toByteArray()
        assertFalse(matches(packet(destPort = 44002), payload).hasRule("RULE-008"))
    }

    // ---- RULE-009 Suspicious User-Agent (Or of HeaderMatches) ----------------

    @Test
    fun `suspicious user agent rule fires for python user agent`() {
        val p = packet(httpData = mapOf("User-Agent" to "python-requests/2.25.1"))
        assertTrue(matches(p).hasRule("RULE-009"))
    }

    @Test
    fun `suspicious user agent rule fires for curl user agent`() {
        val p = packet(httpData = mapOf("User-Agent" to "curl/7.68.0"))
        assertTrue(matches(p).hasRule("RULE-009"))
    }

    @Test
    fun `suspicious user agent rule does not fire for a normal browser`() {
        val p = packet(
            httpData = mapOf(
                "User-Agent" to "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/91.0.4472.124"
            )
        )
        assertFalse(matches(p).hasRule("RULE-009"))
    }

    // ---- RULE-010 ICMP Tunneling (Protocol + PayloadSize + PacketRate) ------

    @Test
    fun `ICMP tunneling rule fires for large payloads at high rate`() {
        val payload = ByteArray(100) { 0x7A }
        var result = emptyList<RuleEngine.RuleMatch>()
        repeat(11) {
            result = matches(packet(protocol = "ICMP", destIp = "198.51.100.9"), payload)
        }
        assertTrue(result.hasRule("RULE-010"))
    }

    @Test
    fun `ICMP tunneling rule does not fire for small payloads even at high rate`() {
        val payload = ByteArray(10) { 0x7A }
        var result = emptyList<RuleEngine.RuleMatch>()
        repeat(11) {
            result = matches(packet(protocol = "ICMP", destIp = "198.51.100.10"), payload)
        }
        assertFalse(result.hasRule("RULE-010"))
    }

    // ---- addRule -------------------------------------------------------------

    @Test
    fun `addRule adds a custom rule that gets evaluated`() {
        val custom = RuleEngine.Rule(
            id = "TEST-CUSTOM-PORT-59999",
            name = "Custom Test Rule",
            description = "test rule added at runtime",
            severity = AnomalyDetector.Severity.LOW,
            category = "TEST",
            conditions = listOf(RuleEngine.Condition.PortEquals(59999, RuleEngine.Direction.DESTINATION)),
            action = RuleEngine.Action.Alert
        )
        RuleEngine.addRule(custom)

        assertTrue(matches(packet(destPort = 59999)).hasRule("TEST-CUSTOM-PORT-59999"))
        assertFalse(matches(packet(destPort = 12345)).hasRule("TEST-CUSTOM-PORT-59999"))
    }

    @Test
    fun `custom rule with Not condition inverts the inner condition`() {
        val custom = RuleEngine.Rule(
            id = "TEST-CUSTOM-NOT-UDP",
            name = "Not UDP Rule",
            description = "fires for any non-UDP protocol",
            severity = AnomalyDetector.Severity.LOW,
            category = "TEST",
            conditions = listOf(RuleEngine.Condition.Not(RuleEngine.Condition.ProtocolEquals("UDP"))),
            action = RuleEngine.Action.Alert
        )
        RuleEngine.addRule(custom)

        assertTrue(matches(packet(protocol = "TCP", destPort = 22222)).hasRule("TEST-CUSTOM-NOT-UDP"))
        assertFalse(matches(packet(protocol = "UDP", destPort = 22222)).hasRule("TEST-CUSTOM-NOT-UDP"))
    }

    @Test
    fun `custom rule combining IpEquals and PortInRange matches correctly`() {
        val custom = RuleEngine.Rule(
            id = "TEST-CUSTOM-IP-RANGE",
            name = "IP + Port Range Rule",
            description = "test",
            severity = AnomalyDetector.Severity.LOW,
            category = "TEST",
            conditions = listOf(
                RuleEngine.Condition.And(
                    listOf(
                        RuleEngine.Condition.IpEquals("203.0.113.99", RuleEngine.Direction.DESTINATION),
                        RuleEngine.Condition.PortInRange(6000, 7000, RuleEngine.Direction.DESTINATION)
                    )
                )
            ),
            action = RuleEngine.Action.Alert
        )
        RuleEngine.addRule(custom)

        assertTrue(
            matches(packet(destIp = "203.0.113.99", destPort = 6500)).hasRule("TEST-CUSTOM-IP-RANGE")
        )
        assertFalse(
            "Wrong port should not match",
            matches(packet(destIp = "203.0.113.99", destPort = 8000)).hasRule("TEST-CUSTOM-IP-RANGE")
        )
        assertFalse(
            "Wrong IP should not match",
            matches(packet(destIp = "203.0.113.100", destPort = 6500)).hasRule("TEST-CUSTOM-IP-RANGE")
        )
    }

    // ---- getStatistics ---------------------------------------------------

    @Test
    fun `getStatistics reports rule counts by category and severity`() {
        val stats = RuleEngine.getStatistics()
        val total = stats["totalRules"] as Int
        assertTrue("Expected at least the 10 default rules, got $total", total >= 10)

        val enabled = stats["enabledRules"] as Int
        assertTrue(enabled in 1..total)

        @Suppress("UNCHECKED_CAST")
        val byCategory = stats["byCategory"] as Map<String, Int>
        assertTrue(byCategory.containsKey("WEB_ATTACK"))
        assertTrue(byCategory.containsKey("RECONNAISSANCE"))

        @Suppress("UNCHECKED_CAST")
        val bySeverity = stats["bySeverity"] as Map<AnomalyDetector.Severity, Int>
        assertTrue(bySeverity.containsKey(AnomalyDetector.Severity.CRITICAL))
    }

    // ---- clearState --------------------------------------------------------

    @Test
    fun `clearState resets rate-based rule history`() {
        var triggered = false
        repeat(25) {
            if (matches(packet(protocol = "TCP", destPort = 3389)).hasRule("RULE-005")) triggered = true
        }
        assertTrue("Expected brute force rule to fire before reset", triggered)

        RuleEngine.clearState()

        var triggeredAfterReset = false
        repeat(3) {
            if (matches(packet(protocol = "TCP", destPort = 3389)).hasRule("RULE-005")) {
                triggeredAfterReset = true
            }
        }
        assertFalse("Rule state should be reset after clearState()", triggeredAfterReset)
    }
}
