package com.example.packet_analyzer

import android.util.Log
import java.util.concurrent.ConcurrentHashMap

/**
 * Rule-Based Detection Engine
 * Evaluates complex rules combining multiple conditions and temporal logic
 */
object RuleEngine {
    private const val TAG = "RuleEngine"

    // Rule data structures
    data class Rule(
        val id: String,
        val name: String,
        val description: String,
        val severity: AnomalyDetector.Severity,
        val category: String,
        val conditions: List<Condition>,
        val action: Action,
        val enabled: Boolean = true
    )

    sealed class Condition {
        // Basic conditions
        data class ProtocolEquals(val protocol: String) : Condition()
        data class PortEquals(val port: Int, val direction: Direction = Direction.DESTINATION) : Condition()
        data class PortInRange(val start: Int, val end: Int, val direction: Direction = Direction.DESTINATION) : Condition()
        data class IpEquals(val ip: String, val direction: Direction = Direction.DESTINATION) : Condition()
        data class IpInCidr(val cidr: String, val direction: Direction = Direction.DESTINATION) : Condition()
        data class FlagsContain(val flags: List<String>) : Condition()

        // Payload conditions
        data class PayloadSize(val operator: Operator, val size: Int) : Condition()
        data class PayloadContains(val pattern: String) : Condition()
        data class PayloadMatches(val regex: Regex) : Condition()

        // Header conditions
        data class HeaderExists(val header: String) : Condition()
        data class HeaderEquals(val header: String, val value: String) : Condition()
        data class HeaderMatches(val header: String, val regex: Regex) : Condition()

        // Rate/Temporal conditions
        data class PacketRate(val operator: Operator, val count: Int, val windowMs: Long) : Condition()
        data class UniqueDestinations(val operator: Operator, val count: Int, val windowMs: Long) : Condition()
        data class TimeSince(val event: String, val operator: Operator, val durationMs: Long) : Condition()

        // Logical combinations
        data class And(val conditions: List<Condition>) : Condition()
        data class Or(val conditions: List<Condition>) : Condition()
        data class Not(val condition: Condition) : Condition()

        // Domain conditions
        data class DomainEquals(val domain: String) : Condition()
        data class DomainContains(val substring: String) : Condition()
        data class DomainMatches(val regex: Regex) : Condition()

        // DNS conditions
        data class DnsQueryType(val type: String) : Condition()
        data class DnsResponseCount(val operator: Operator, val count: Int) : Condition()

        // HTTP conditions
        data class HttpMethod(val method: String) : Condition()
        data class HttpStatus(val operator: Operator, val status: Int) : Condition()
        data class UrlContains(val substring: String) : Condition()
        data class UrlMatches(val regex: Regex) : Condition()
    }

    enum class Direction { SOURCE, DESTINATION, BOTH }
    enum class Operator { EQUALS, NOT_EQUALS, GREATER_THAN, LESS_THAN, GREATER_EQUAL, LESS_EQUAL }

    sealed class Action {
        object Alert : Action()
        data class AlertWithDetails(val message: String) : Action()
        object Block : Action()  // For future implementation
        object Log : Action()
        data class Custom(val handler: (Map<String, Any>) -> Unit) : Action()
    }

    // Rule state tracking
    private val rules = mutableListOf<Rule>()
    private val ruleState = ConcurrentHashMap<String, RuleState>()

    data class RuleState(
        var lastTriggered: Long = 0,
        var triggerCount: Int = 0,
        val eventHistory: MutableList<Long> = mutableListOf(),
        val packetHistory: MutableList<Map<String, Any>> = mutableListOf()
    )

    init {
        loadDefaultRules()
    }

    private fun loadDefaultRules() {
        // Rule 1: Port Scan Detection (Advanced)
        rules.add(
            Rule(
                id = "RULE-001",
                name = "Advanced Port Scan",
                description = "Detects port scanning with multiple unique destinations",
                severity = AnomalyDetector.Severity.HIGH,
                category = "RECONNAISSANCE",
                conditions = listOf(
                    Condition.And(
                        listOf(
                            Condition.ProtocolEquals("TCP"),
                            Condition.UniqueDestinations(Operator.GREATER_THAN, 15, 10000),
                            Condition.Or(
                                listOf(
                                    Condition.FlagsContain(listOf("SYN")),
                                    Condition.FlagsContain(listOf("NULL"))
                                )
                            )
                        )
                    )
                ),
                action = Action.AlertWithDetails("Port scan detected with advanced patterns")
            )
        )

        // Rule 2: SQL Injection Attack
        rules.add(
            Rule(
                id = "RULE-002",
                name = "SQL Injection Attack",
                description = "Detects SQL injection attempts in HTTP traffic",
                severity = AnomalyDetector.Severity.CRITICAL,
                category = "WEB_ATTACK",
                conditions = listOf(
                    Condition.And(
                        listOf(
                            Condition.ProtocolEquals("TCP"),
                            Condition.PortEquals(80, Direction.DESTINATION),
                            Condition.Or(
                                listOf(
                                    Condition.UrlMatches(Regex(".*('|--|;|/\\*|\\*/|xp_|sp_|UNION|SELECT).*", RegexOption.IGNORE_CASE)),
                                    Condition.PayloadMatches(Regex(".*(UNION.*SELECT|INSERT.*INTO|DELETE.*FROM|DROP.*TABLE).*", RegexOption.IGNORE_CASE))
                                )
                            )
                        )
                    )
                ),
                action = Action.AlertWithDetails("SQL injection attack detected")
            )
        )

        // Rule 3: Suspicious File Download
        rules.add(
            Rule(
                id = "RULE-003",
                name = "Malicious File Download",
                description = "Detects download of potentially malicious file types",
                severity = AnomalyDetector.Severity.HIGH,
                category = "MALWARE",
                conditions = listOf(
                    Condition.And(
                        listOf(
                            Condition.HttpMethod("GET"),
                            Condition.UrlMatches(Regex(".*\\.(exe|scr|bat|cmd|vbs|ps1|dll|jar)$", RegexOption.IGNORE_CASE))
                        )
                    )
                ),
                action = Action.AlertWithDetails("Suspicious file download attempt")
            )
        )

        // Rule 4: DNS Tunneling
        rules.add(
            Rule(
                id = "RULE-004",
                name = "DNS Tunneling",
                description = "Detects data exfiltration via DNS queries",
                severity = AnomalyDetector.Severity.HIGH,
                category = "EXFILTRATION",
                conditions = listOf(
                    Condition.And(
                        listOf(
                            Condition.ProtocolEquals("UDP"),
                            Condition.PortEquals(53, Direction.DESTINATION),
                            Condition.Or(
                                listOf(
                                    Condition.PayloadSize(Operator.GREATER_THAN, 128),
                                    Condition.DomainMatches(Regex(".*[0-9a-f]{32,}.*")) // Long hex strings
                                )
                            ),
                            Condition.PacketRate(Operator.GREATER_THAN, 10, 1000)
                        )
                    )
                ),
                action = Action.AlertWithDetails("Possible DNS tunneling detected")
            )
        )

        // Rule 5: Brute Force Attack
        rules.add(
            Rule(
                id = "RULE-005",
                name = "Brute Force Attack",
                description = "Detects brute force authentication attempts",
                severity = AnomalyDetector.Severity.HIGH,
                category = "BRUTE_FORCE",
                conditions = listOf(
                    Condition.And(
                        listOf(
                            Condition.Or(
                                listOf(
                                    Condition.PortEquals(22),  // SSH
                                    Condition.PortEquals(3389), // RDP
                                    Condition.PortEquals(21),  // FTP
                                    Condition.PortEquals(23)   // Telnet
                                )
                            ),
                            Condition.PacketRate(Operator.GREATER_THAN, 20, 60000)
                        )
                    )
                ),
                action = Action.AlertWithDetails("Brute force attack detected")
            )
        )

        // Rule 6: Cryptomining Activity
        rules.add(
            Rule(
                id = "RULE-006",
                name = "Cryptomining Detection",
                description = "Detects cryptocurrency mining pool connections",
                severity = AnomalyDetector.Severity.MEDIUM,
                category = "MALWARE",
                conditions = listOf(
                    Condition.And(
                        listOf(
                            Condition.ProtocolEquals("TCP"),
                            Condition.Or(
                                listOf(
                                    Condition.PortEquals(3333),
                                    Condition.PortEquals(4444),
                                    Condition.PortEquals(5555),
                                    Condition.PortEquals(7777),
                                    Condition.PortEquals(8888)
                                )
                            ),
                            Condition.PayloadContains("stratum")
                        )
                    )
                ),
                action = Action.AlertWithDetails("Cryptomining pool connection detected")
            )
        )

        // Rule 7: Suspicious Outbound Traffic
        rules.add(
            Rule(
                id = "RULE-007",
                name = "Suspicious Outbound Traffic",
                description = "Large amount of outbound data to single destination",
                severity = AnomalyDetector.Severity.MEDIUM,
                category = "EXFILTRATION",
                conditions = listOf(
                    Condition.And(
                        listOf(
                            Condition.PacketRate(Operator.GREATER_THAN, 100, 10000),
                            Condition.PayloadSize(Operator.GREATER_THAN, 1024)
                        )
                    )
                ),
                action = Action.AlertWithDetails("Unusual outbound traffic volume")
            )
        )

        // Rule 8: Shellcode Execution
        rules.add(
            Rule(
                id = "RULE-008",
                name = "Shellcode Pattern",
                description = "Detects common shellcode patterns",
                severity = AnomalyDetector.Severity.CRITICAL,
                category = "EXPLOIT",
                conditions = listOf(
                    Condition.Or(
                        listOf(
                            Condition.PayloadMatches(Regex(".*\\x90{10,}.*")), // NOP sled
                            Condition.PayloadMatches(Regex(".*\\xeb\\x0e.*")),  // JMP short
                            Condition.PayloadContains("\\x31\\xc0\\x50\\x68") // Common shellcode
                        )
                    )
                ),
                action = Action.AlertWithDetails("Shellcode pattern detected")
            )
        )

        // Rule 9: Suspicious User-Agent
        rules.add(
            Rule(
                id = "RULE-009",
                name = "Suspicious User-Agent",
                description = "Detects suspicious or automated user agents",
                severity = AnomalyDetector.Severity.MEDIUM,
                category = "RECONNAISSANCE",
                conditions = listOf(
                    Condition.Or(
                        listOf(
                            Condition.HeaderMatches("User-Agent", Regex(".*[Bb]ot.*")),
                            Condition.HeaderMatches("User-Agent", Regex(".*[Ss]canner.*")),
                            Condition.HeaderMatches("User-Agent", Regex(".*[Cc]rawler.*")),
                            Condition.HeaderMatches("User-Agent", Regex(".*python.*", RegexOption.IGNORE_CASE)),
                            Condition.HeaderMatches("User-Agent", Regex(".*curl.*", RegexOption.IGNORE_CASE))
                        )
                    )
                ),
                action = Action.AlertWithDetails("Suspicious User-Agent detected")
            )
        )

        // Rule 10: ICMP Tunnel
        rules.add(
            Rule(
                id = "RULE-010",
                name = "ICMP Tunneling",
                description = "Detects data tunneling via ICMP",
                severity = AnomalyDetector.Severity.HIGH,
                category = "EXFILTRATION",
                conditions = listOf(
                    Condition.And(
                        listOf(
                            Condition.ProtocolEquals("ICMP"),
                            Condition.PayloadSize(Operator.GREATER_THAN, 64),
                            Condition.PacketRate(Operator.GREATER_THAN, 10, 1000)
                        )
                    )
                ),
                action = Action.AlertWithDetails("ICMP tunneling detected")
            )
        )

        Log.i(TAG, "Loaded ${rules.size} detection rules")
    }

    /**
     * Evaluate all rules against a packet
     */
    fun evaluateRules(packetInfo: Map<String, Any>, payload: ByteArray?): List<RuleMatch> {
        val matches = mutableListOf<RuleMatch>()

        for (rule in rules) {
            if (!rule.enabled) continue

            try {
                val state = ruleState.getOrPut(rule.id) { RuleState() }

                // Add packet to history
                state.packetHistory.add(packetInfo)
                if (state.packetHistory.size > 1000) {
                    state.packetHistory.removeAt(0)
                }

                // Evaluate conditions
                if (evaluateConditions(rule.conditions, packetInfo, payload, state)) {
                    state.lastTriggered = System.currentTimeMillis()
                    state.triggerCount++
                    state.eventHistory.add(System.currentTimeMillis())

                    matches.add(
                        RuleMatch(
                            rule = rule,
                            timestamp = System.currentTimeMillis(),
                            details = buildMatchDetails(rule, packetInfo)
                        )
                    )

                    // Execute action
                    executeAction(rule.action, packetInfo)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error evaluating rule ${rule.id}: ${e.message}")
            }
        }

        return matches
    }

    private fun evaluateConditions(
        conditions: List<Condition>,
        packetInfo: Map<String, Any>,
        payload: ByteArray?,
        state: RuleState
    ): Boolean {
        // AND logic for top-level conditions
        return conditions.all { condition ->
            evaluateCondition(condition, packetInfo, payload, state)
        }
    }

    private fun evaluateCondition(
        condition: Condition,
        packetInfo: Map<String, Any>,
        payload: ByteArray?,
        state: RuleState
    ): Boolean {
        return when (condition) {
            is Condition.ProtocolEquals -> evaluateProtocolEquals(condition, packetInfo)
            is Condition.PortEquals -> evaluatePortEquals(condition, packetInfo)
            is Condition.PortInRange -> evaluatePortInRange(condition, packetInfo)
            is Condition.IpEquals -> evaluateIpEquals(condition, packetInfo)
            is Condition.FlagsContain -> evaluateFlagsContain(condition, packetInfo)
            is Condition.PayloadSize -> evaluatePayloadSize(condition, payload)
            is Condition.PayloadContains -> evaluatePayloadContains(condition, payload)
            is Condition.PayloadMatches -> evaluatePayloadMatches(condition, payload)
            is Condition.HeaderExists -> evaluateHeaderExists(condition, packetInfo)
            is Condition.HeaderEquals -> evaluateHeaderEquals(condition, packetInfo)
            is Condition.HeaderMatches -> evaluateHeaderMatches(condition, packetInfo)
            is Condition.PacketRate -> evaluatePacketRate(condition, state)
            is Condition.UniqueDestinations -> evaluateUniqueDestinations(condition, state)
            is Condition.And -> condition.conditions.all { evaluateCondition(it, packetInfo, payload, state) }
            is Condition.Or -> condition.conditions.any { evaluateCondition(it, packetInfo, payload, state) }
            is Condition.Not -> !evaluateCondition(condition.condition, packetInfo, payload, state)
            is Condition.DomainEquals -> evaluateDomainEquals(condition, packetInfo)
            is Condition.DomainContains -> evaluateDomainContains(condition, packetInfo)
            is Condition.HttpMethod -> evaluateHttpMethod(condition, packetInfo)
            is Condition.UrlContains -> evaluateUrlContains(condition, packetInfo)
            is Condition.UrlMatches -> evaluateUrlMatches(condition, packetInfo)
            else -> false
        }
    }

    // Evaluation helper functions
    private fun evaluateProtocolEquals(condition: Condition.ProtocolEquals, packetInfo: Map<String, Any>): Boolean {
        val protocol = packetInfo["protocol"]?.toString() ?: ""
        return protocol.equals(condition.protocol, ignoreCase = true)
    }

    private fun evaluatePortEquals(condition: Condition.PortEquals, packetInfo: Map<String, Any>): Boolean {
        val destPort = (packetInfo["destinationPort"] as? Int) ?: 0
        val sourcePort = (packetInfo["sourcePort"] as? Int) ?: 0
        return when (condition.direction) {
            Direction.DESTINATION -> destPort == condition.port
            Direction.SOURCE -> sourcePort == condition.port
            Direction.BOTH -> destPort == condition.port || sourcePort == condition.port
        }
    }

    private fun evaluatePortInRange(condition: Condition.PortInRange, packetInfo: Map<String, Any>): Boolean {
        val destPort = (packetInfo["destinationPort"] as? Int) ?: 0
        val sourcePort = (packetInfo["sourcePort"] as? Int) ?: 0
        val inRange = { port: Int -> port in condition.start..condition.end }
        return when (condition.direction) {
            Direction.DESTINATION -> inRange(destPort)
            Direction.SOURCE -> inRange(sourcePort)
            Direction.BOTH -> inRange(destPort) || inRange(sourcePort)
        }
    }

    private fun evaluateIpEquals(condition: Condition.IpEquals, packetInfo: Map<String, Any>): Boolean {
        val destIp = packetInfo["destinationIp"]?.toString() ?: ""
        val sourceIp = packetInfo["sourceIp"]?.toString() ?: ""
        return when (condition.direction) {
            Direction.DESTINATION -> destIp == condition.ip
            Direction.SOURCE -> sourceIp == condition.ip
            Direction.BOTH -> destIp == condition.ip || sourceIp == condition.ip
        }
    }

    private fun evaluateFlagsContain(condition: Condition.FlagsContain, packetInfo: Map<String, Any>): Boolean {
        val flags = packetInfo["flags"]?.toString() ?: ""
        return condition.flags.any { flags.contains(it, ignoreCase = true) }
    }

    private fun evaluatePayloadSize(condition: Condition.PayloadSize, payload: ByteArray?): Boolean {
        val size = payload?.size ?: 0
        return compareWithOperator(size, condition.size, condition.operator)
    }

    private fun evaluatePayloadContains(condition: Condition.PayloadContains, payload: ByteArray?): Boolean {
        if (payload == null) return false
        val payloadStr = String(payload, Charsets.ISO_8859_1).lowercase()
        return payloadStr.contains(condition.pattern.lowercase())
    }

    private fun evaluatePayloadMatches(condition: Condition.PayloadMatches, payload: ByteArray?): Boolean {
        if (payload == null) return false
        val payloadStr = String(payload, Charsets.ISO_8859_1)
        return condition.regex.containsMatchIn(payloadStr)
    }

    private fun evaluateHeaderExists(condition: Condition.HeaderExists, packetInfo: Map<String, Any>): Boolean {
        val httpData = packetInfo["httpData"] as? Map<String, Any> ?: return false
        return httpData.containsKey(condition.header)
    }

    private fun evaluateHeaderEquals(condition: Condition.HeaderEquals, packetInfo: Map<String, Any>): Boolean {
        val httpData = packetInfo["httpData"] as? Map<String, Any> ?: return false
        val headerValue = httpData[condition.header]?.toString() ?: return false
        return headerValue.equals(condition.value, ignoreCase = true)
    }

    private fun evaluateHeaderMatches(condition: Condition.HeaderMatches, packetInfo: Map<String, Any>): Boolean {
        val httpData = packetInfo["httpData"] as? Map<String, Any> ?: return false
        val headerValue = httpData[condition.header]?.toString() ?: return false
        return condition.regex.containsMatchIn(headerValue)
    }

    private fun evaluatePacketRate(condition: Condition.PacketRate, state: RuleState): Boolean {
        val now = System.currentTimeMillis()
        val windowStart = now - condition.windowMs
        val recentPackets = state.packetHistory.count { packet ->
            val timestamp = (packet["timestamp"] as? Long) ?: 0
            timestamp >= windowStart
        }
        return compareWithOperator(recentPackets, condition.count, condition.operator)
    }

    private fun evaluateUniqueDestinations(condition: Condition.UniqueDestinations, state: RuleState): Boolean {
        val now = System.currentTimeMillis()
        val windowStart = now - condition.windowMs
        val uniqueDests = state.packetHistory
            .filter { packet ->
                val timestamp = (packet["timestamp"] as? Long) ?: 0
                timestamp >= windowStart
            }
            .mapNotNull { it["destinationIp"]?.toString() }
            .toSet()
            .size
        return compareWithOperator(uniqueDests, condition.count, condition.operator)
    }

    private fun evaluateDomainEquals(condition: Condition.DomainEquals, packetInfo: Map<String, Any>): Boolean {
        val domain = packetInfo["domain"]?.toString() ?: ""
        return domain.equals(condition.domain, ignoreCase = true)
    }

    private fun evaluateDomainContains(condition: Condition.DomainContains, packetInfo: Map<String, Any>): Boolean {
        val domain = packetInfo["domain"]?.toString() ?: ""
        return domain.contains(condition.substring, ignoreCase = true)
    }

    private fun evaluateHttpMethod(condition: Condition.HttpMethod, packetInfo: Map<String, Any>): Boolean {
        val httpData = packetInfo["httpData"] as? Map<String, Any> ?: return false
        val method = httpData["method"]?.toString() ?: ""
        return method.equals(condition.method, ignoreCase = true)
    }

    private fun evaluateUrlContains(condition: Condition.UrlContains, packetInfo: Map<String, Any>): Boolean {
        val httpData = packetInfo["httpData"] as? Map<String, Any> ?: return false
        val url = httpData["url"]?.toString() ?: ""
        return url.contains(condition.substring, ignoreCase = true)
    }

    private fun evaluateUrlMatches(condition: Condition.UrlMatches, packetInfo: Map<String, Any>): Boolean {
        val httpData = packetInfo["httpData"] as? Map<String, Any> ?: return false
        val url = httpData["url"]?.toString() ?: ""
        return condition.regex.containsMatchIn(url)
    }

    private fun compareWithOperator(actual: Int, expected: Int, operator: Operator): Boolean {
        return when (operator) {
            Operator.EQUALS -> actual == expected
            Operator.NOT_EQUALS -> actual != expected
            Operator.GREATER_THAN -> actual > expected
            Operator.LESS_THAN -> actual < expected
            Operator.GREATER_EQUAL -> actual >= expected
            Operator.LESS_EQUAL -> actual <= expected
        }
    }

    private fun buildMatchDetails(rule: Rule, packetInfo: Map<String, Any>): Map<String, Any> {
        return mapOf(
            "ruleId" to rule.id,
            "ruleName" to rule.name,
            "category" to rule.category,
            "sourceIp" to (packetInfo["sourceIp"] ?: ""),
            "destinationIp" to (packetInfo["destinationIp"] ?: ""),
            "protocol" to (packetInfo["protocol"] ?: "")
        )
    }

    private fun executeAction(action: Action, packetInfo: Map<String, Any>) {
        when (action) {
            is Action.Alert -> Log.w(TAG, "Rule triggered")
            is Action.AlertWithDetails -> Log.w(TAG, "Rule triggered: ${action.message}")
            is Action.Block -> Log.w(TAG, "Blocking action not implemented")
            is Action.Log -> Log.i(TAG, "Rule matched: $packetInfo")
            is Action.Custom -> action.handler(packetInfo)
        }
    }

    data class RuleMatch(
        val rule: Rule,
        val timestamp: Long,
        val details: Map<String, Any>
    )

    /**
     * Add custom rule
     */
    fun addRule(rule: Rule) {
        rules.add(rule)
        Log.i(TAG, "Added rule: ${rule.id} - ${rule.name}")
    }

    /**
     * Get statistics
     */
    fun getStatistics(): Map<String, Any> = mapOf(
        "totalRules" to rules.size,
        "enabledRules" to rules.count { it.enabled },
        "byCategory" to rules.groupBy { it.category }.mapValues { it.value.size },
        "bySeverity" to rules.groupBy { it.severity }.mapValues { it.value.size }
    )

    /**
     * Clear rule state
     */
    fun clearState() {
        ruleState.clear()
        Log.i(TAG, "Rule state cleared")
    }
}
