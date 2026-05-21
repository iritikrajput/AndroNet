package com.example.packet_analyzer

import android.util.Log

/**
 * Signature-Based Detection Database
 * Contains known attack patterns, malware signatures, and threat indicators
 */
object SignatureDatabase {
    private const val TAG = "SignatureDatabase"

    // Signature categories
    data class Signature(
        val id: String,
        val name: String,
        val category: Category,
        val severity: AnomalyDetector.Severity,
        val pattern: Pattern,
        val description: String
    )

    enum class Category {
        MALWARE,           // Malware communication
        EXPLOIT,           // Exploit attempts
        RECONNAISSANCE,    // Scanning/probing
        COMMAND_CONTROL,   // C&C communication
        DATA_EXFILTRATION, // Data theft
        BRUTE_FORCE,       // Password attacks
        WEB_ATTACK,        // Web application attacks
        NETWORK_ATTACK     // Network layer attacks
    }

    sealed class Pattern {
        data class PayloadContains(val bytes: List<ByteArray>) : Pattern()
        data class HeaderPattern(val field: String, val regex: Regex) : Pattern()
        data class PortPattern(val ports: Set<Int>) : Pattern()
        data class IpPattern(val ips: Set<String>) : Pattern()
        data class DnsPattern(val domains: Set<String>) : Pattern()
        data class UrlPattern(val paths: Set<String>) : Pattern()
        data class CompositePattern(val patterns: List<Pattern>, val matchAll: Boolean = false) : Pattern()
    }

    // Known malicious IPs (sample - should be updated regularly)
    private val knownMaliciousIps = setOf(
        // Tor exit nodes (sample)
        "185.220.101.0",
        "185.220.102.0",
        // Known C&C servers (sample)
        "198.51.100.1",
        "203.0.113.1"
    )

    // Known malicious domains
    private val knownMaliciousDomains = setOf(
        "malware-test.com",
        "evil-command-control.net",
        "phishing-site.org",
        "ransomware-c2.com"
    )

    // Common exploit ports
    private val exploitPorts = setOf(
        1337,  // Common backdoor
        4444,  // Metasploit default
        5555,  // Android debug bridge (suspicious if external)
        6666,  // IRC bot
        6667,  // IRC bot
        31337  // Elite/Leet backdoor
    )

    // Signature database
    private val signatures = mutableListOf<Signature>()

    init {
        loadSignatures()
    }

    private fun loadSignatures() {
        // ==================== MALWARE SIGNATURES ====================

        // 1. Metasploit Meterpreter
        signatures.add(
            Signature(
                id = "MAL-001",
                name = "Metasploit Meterpreter",
                category = Category.MALWARE,
                severity = AnomalyDetector.Severity.CRITICAL,
                pattern = Pattern.PayloadContains(
                    listOf(
                        "meterpreter".toByteArray(),
                        "stdapi_".toByteArray(),
                        "core_loadlib".toByteArray()
                    )
                ),
                description = "Metasploit Meterpreter payload detected"
            )
        )

        // 2. WannaCry Ransomware
        signatures.add(
            Signature(
                id = "MAL-002",
                name = "WannaCry Ransomware",
                category = Category.MALWARE,
                severity = AnomalyDetector.Severity.CRITICAL,
                pattern = Pattern.CompositePattern(
                    listOf(
                        Pattern.PortPattern(setOf(445)), // SMB port
                        Pattern.PayloadContains(listOf("tasksche.exe".toByteArray()))
                    ),
                    matchAll = true
                ),
                description = "WannaCry ransomware network activity"
            )
        )

        // 3. Cobalt Strike Beacon
        signatures.add(
            Signature(
                id = "MAL-003",
                name = "Cobalt Strike Beacon",
                category = Category.COMMAND_CONTROL,
                severity = AnomalyDetector.Severity.CRITICAL,
                pattern = Pattern.HeaderPattern(
                    "User-Agent",
                    Regex("Mozilla/5\\.0 \\(compatible; MSIE [0-9]+\\.[0-9]+; Windows NT [0-9]+\\.[0-9]+; Trident/[0-9]+\\.[0-9]+\\)")
                ),
                description = "Cobalt Strike C2 beacon communication"
            )
        )

        // ==================== EXPLOIT SIGNATURES ====================

        // 4. SQL Injection Attempt
        signatures.add(
            Signature(
                id = "EXP-001",
                name = "SQL Injection",
                category = Category.WEB_ATTACK,
                severity = AnomalyDetector.Severity.HIGH,
                pattern = Pattern.UrlPattern(
                    setOf(
                        "' OR '1'='1",
                        "UNION SELECT",
                        "; DROP TABLE",
                        "' OR 1=1--",
                        "admin'--",
                        "' AND 1=0 UNION"
                    )
                ),
                description = "SQL injection attempt detected"
            )
        )

        // 5. Directory Traversal
        signatures.add(
            Signature(
                id = "EXP-002",
                name = "Directory Traversal",
                category = Category.WEB_ATTACK,
                severity = AnomalyDetector.Severity.HIGH,
                pattern = Pattern.UrlPattern(
                    setOf(
                        "../",
                        "..\\",
                        "....//",
                        "..%2F",
                        "%2e%2e%2f",
                        "/etc/passwd",
                        "C:\\Windows\\System32"
                    )
                ),
                description = "Directory traversal attack attempt"
            )
        )

        // 6. Remote Code Execution
        signatures.add(
            Signature(
                id = "EXP-003",
                name = "RCE Attempt",
                category = Category.EXPLOIT,
                severity = AnomalyDetector.Severity.CRITICAL,
                pattern = Pattern.PayloadContains(
                    listOf(
                        "; wget ".toByteArray(),
                        "| curl ".toByteArray(),
                        "/bin/sh".toByteArray(),
                        "/bin/bash".toByteArray(),
                        "eval(".toByteArray(),
                        "exec(".toByteArray(),
                        "system(".toByteArray()
                    )
                ),
                description = "Remote code execution attempt"
            )
        )

        // 7. XXE (XML External Entity)
        signatures.add(
            Signature(
                id = "EXP-004",
                name = "XXE Attack",
                category = Category.WEB_ATTACK,
                severity = AnomalyDetector.Severity.HIGH,
                pattern = Pattern.PayloadContains(
                    listOf(
                        "<!ENTITY".toByteArray(),
                        "<!DOCTYPE".toByteArray(),
                        "SYSTEM \"file://".toByteArray()
                    )
                ),
                description = "XML External Entity attack"
            )
        )

        // ==================== RECONNAISSANCE SIGNATURES ====================

        // 8. Nmap Scan
        signatures.add(
            Signature(
                id = "RECON-001",
                name = "Nmap Scan",
                category = Category.RECONNAISSANCE,
                severity = AnomalyDetector.Severity.MEDIUM,
                pattern = Pattern.HeaderPattern(
                    "User-Agent",
                    Regex("Nmap.*")
                ),
                description = "Nmap network scanner detected"
            )
        )

        // 9. Nikto Web Scanner
        signatures.add(
            Signature(
                id = "RECON-002",
                name = "Nikto Scanner",
                category = Category.RECONNAISSANCE,
                severity = AnomalyDetector.Severity.MEDIUM,
                pattern = Pattern.HeaderPattern(
                    "User-Agent",
                    Regex(".*Nikto.*")
                ),
                description = "Nikto web vulnerability scanner"
            )
        )

        // 10. SQL Injection Scanner
        signatures.add(
            Signature(
                id = "RECON-003",
                name = "SQLMap Scanner",
                category = Category.RECONNAISSANCE,
                severity = AnomalyDetector.Severity.MEDIUM,
                pattern = Pattern.HeaderPattern(
                    "User-Agent",
                    Regex(".*sqlmap.*")
                ),
                description = "SQLMap SQL injection scanner"
            )
        )

        // ==================== COMMAND & CONTROL ====================

        // 11. TOR Network
        signatures.add(
            Signature(
                id = "C2-001",
                name = "TOR Network",
                category = Category.COMMAND_CONTROL,
                severity = AnomalyDetector.Severity.MEDIUM,
                pattern = Pattern.IpPattern(knownMaliciousIps),
                description = "TOR exit node connection"
            )
        )

        // 12. Known C&C Domain
        signatures.add(
            Signature(
                id = "C2-002",
                name = "Known C&C Domain",
                category = Category.COMMAND_CONTROL,
                severity = AnomalyDetector.Severity.CRITICAL,
                pattern = Pattern.DnsPattern(knownMaliciousDomains),
                description = "Connection to known command and control server"
            )
        )

        // 13. IRC Bot
        signatures.add(
            Signature(
                id = "C2-003",
                name = "IRC Bot",
                category = Category.COMMAND_CONTROL,
                severity = AnomalyDetector.Severity.HIGH,
                pattern = Pattern.CompositePattern(
                    listOf(
                        Pattern.PortPattern(setOf(6667, 6666)),
                        Pattern.PayloadContains(
                            listOf(
                                "PRIVMSG".toByteArray(),
                                "JOIN #".toByteArray()
                            )
                        )
                    )
                ),
                description = "IRC-based botnet communication"
            )
        )

        // ==================== DATA EXFILTRATION ====================

        // 14. Base64 Encoded Data Transfer
        signatures.add(
            Signature(
                id = "EXFIL-001",
                name = "Base64 Exfiltration",
                category = Category.DATA_EXFILTRATION,
                severity = AnomalyDetector.Severity.HIGH,
                pattern = Pattern.CompositePattern(
                    listOf(
                        Pattern.UrlPattern(setOf("?data=")),
                        Pattern.PayloadContains(
                            listOf(
                                Regex("[A-Za-z0-9+/]{100,}=*").pattern.toByteArray()
                            )
                        )
                    )
                ),
                description = "Possible data exfiltration via base64 encoding"
            )
        )

        // ==================== BRUTE FORCE ====================

        // 15. SSH Brute Force
        signatures.add(
            Signature(
                id = "BRUTE-001",
                name = "SSH Brute Force",
                category = Category.BRUTE_FORCE,
                severity = AnomalyDetector.Severity.HIGH,
                pattern = Pattern.PortPattern(setOf(22)),
                description = "Possible SSH brute force attack (requires rate analysis)"
            )
        )

        // 16. RDP Brute Force
        signatures.add(
            Signature(
                id = "BRUTE-002",
                name = "RDP Brute Force",
                category = Category.BRUTE_FORCE,
                severity = AnomalyDetector.Severity.HIGH,
                pattern = Pattern.PortPattern(setOf(3389)),
                description = "Possible RDP brute force attack"
            )
        )

        // ==================== NETWORK ATTACKS ====================

        // 17. SMB Exploit (EternalBlue)
        signatures.add(
            Signature(
                id = "NET-001",
                name = "EternalBlue Exploit",
                category = Category.NETWORK_ATTACK,
                severity = AnomalyDetector.Severity.CRITICAL,
                pattern = Pattern.CompositePattern(
                    listOf(
                        Pattern.PortPattern(setOf(445)),
                        Pattern.PayloadContains(
                            listOf(
                                "\\PIPE\\".toByteArray()
                            )
                        )
                    )
                ),
                description = "EternalBlue SMB exploit attempt"
            )
        )

        // 18. Shellshock
        signatures.add(
            Signature(
                id = "NET-002",
                name = "Shellshock",
                category = Category.NETWORK_ATTACK,
                severity = AnomalyDetector.Severity.CRITICAL,
                pattern = Pattern.HeaderPattern(
                    "User-Agent",
                    Regex(".*\\(\\)\\s*\\{.*\\}.*")
                ),
                description = "Shellshock bash vulnerability exploit"
            )
        )

    }

    /**
     * Match packet against all signatures
     */
    fun matchSignatures(packetInfo: Map<String, Any>, payload: ByteArray?): List<SignatureMatch> {
        val matches = mutableListOf<SignatureMatch>()

        for (signature in signatures) {
            if (matchPattern(signature.pattern, packetInfo, payload)) {
                matches.add(
                    SignatureMatch(
                        signature = signature,
                        timestamp = System.currentTimeMillis()
                    )
                )
            }
        }

        return matches
    }

    private fun matchPattern(pattern: Pattern, packetInfo: Map<String, Any>, payload: ByteArray?): Boolean {
        return when (pattern) {
            is Pattern.PayloadContains -> matchPayloadContains(pattern, payload)
            is Pattern.HeaderPattern -> matchHeaderPattern(pattern, packetInfo)
            is Pattern.PortPattern -> matchPortPattern(pattern, packetInfo)
            is Pattern.IpPattern -> matchIpPattern(pattern, packetInfo)
            is Pattern.DnsPattern -> matchDnsPattern(pattern, packetInfo)
            is Pattern.UrlPattern -> matchUrlPattern(pattern, packetInfo)
            is Pattern.CompositePattern -> matchCompositePattern(pattern, packetInfo, payload)
        }
    }

    private fun matchPayloadContains(pattern: Pattern.PayloadContains, payload: ByteArray?): Boolean {
        if (payload == null || payload.isEmpty()) return false

        val payloadStr = String(payload, Charsets.ISO_8859_1).lowercase()

        return pattern.bytes.any { searchBytes ->
            val searchStr = String(searchBytes, Charsets.ISO_8859_1).lowercase()
            payloadStr.contains(searchStr)
        }
    }

    private fun matchHeaderPattern(pattern: Pattern.HeaderPattern, packetInfo: Map<String, Any>): Boolean {
        val httpData = packetInfo["httpData"] as? Map<String, Any> ?: return false
        val headerValue = httpData[pattern.field]?.toString() ?: return false
        return pattern.regex.containsMatchIn(headerValue)
    }

    private fun matchPortPattern(pattern: Pattern.PortPattern, packetInfo: Map<String, Any>): Boolean {
        val destPort = (packetInfo["destinationPort"] as? Int) ?: 0
        val sourcePort = (packetInfo["sourcePort"] as? Int) ?: 0
        return pattern.ports.contains(destPort) || pattern.ports.contains(sourcePort)
    }

    private fun matchIpPattern(pattern: Pattern.IpPattern, packetInfo: Map<String, Any>): Boolean {
        val destIp = packetInfo["destinationIp"]?.toString() ?: ""
        val sourceIp = packetInfo["sourceIp"]?.toString() ?: ""
        return pattern.ips.contains(destIp) || pattern.ips.contains(sourceIp)
    }

    private fun matchDnsPattern(pattern: Pattern.DnsPattern, packetInfo: Map<String, Any>): Boolean {
        val domain = packetInfo["domain"]?.toString()?.lowercase() ?: return false
        return pattern.domains.any { maliciousDomain ->
            domain.contains(maliciousDomain.lowercase())
        }
    }

    private fun matchUrlPattern(pattern: Pattern.UrlPattern, packetInfo: Map<String, Any>): Boolean {
        val httpData = packetInfo["httpData"] as? Map<String, Any> ?: return false
        val url = httpData["url"]?.toString()?.lowercase() ?: return false
        return pattern.paths.any { suspiciousPath ->
            url.contains(suspiciousPath.lowercase())
        }
    }

    private fun matchCompositePattern(
        pattern: Pattern.CompositePattern,
        packetInfo: Map<String, Any>,
        payload: ByteArray?
    ): Boolean {
        val results = pattern.patterns.map { subPattern ->
            matchPattern(subPattern, packetInfo, payload)
        }

        return if (pattern.matchAll) {
            results.all { it }  // AND logic
        } else {
            results.any { it }  // OR logic
        }
    }

    data class SignatureMatch(
        val signature: Signature,
        val timestamp: Long
    )

    /**
     * Add custom signature
     */
    fun addSignature(signature: Signature) {
        signatures.add(signature)
        Log.i(TAG, "Added signature: ${signature.id} - ${signature.name}")
    }

    /**
     * Get statistics
     */
    fun getStatistics(): Map<String, Any> = mapOf(
        "totalSignatures" to signatures.size,
        "byCategory" to signatures.groupBy { it.category }.mapValues { it.value.size },
        "bySeverity" to signatures.groupBy { it.severity }.mapValues { it.value.size }
    )
}
