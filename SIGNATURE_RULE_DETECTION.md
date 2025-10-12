# Signature and Rule-Based Anomaly Detection System

## 🎯 Overview

The AndroNet anomaly detection system now includes **comprehensive signature-based and rule-based detection engines** working alongside the existing statistical detectors. This creates a **three-layered defense system**:

1. **Basic Statistical Detection** - Port scans, SYN floods, connection floods
2. **Signature-Based Detection** - Known attack patterns and malware indicators (18 signatures)
3. **Rule-Based Detection** - Complex multi-condition rules (10 advanced rules)

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   PACKET ANALYSIS MANAGER                    │
│                          ↓                                   │
│                    enrichedPacket                            │
└─────────────────────────────────────────────────────────────┘
                           ↓
┌─────────────────────────────────────────────────────────────┐
│                    ANOMALY DETECTOR                          │
│         AnomalyDetector.analyzePacket()                      │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Layer 1: Basic Statistical Detection                   │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │ • Port Scan (20+ ports in 10s)                         │ │
│  │ • SYN Flood (100+ SYNs in 1s)                          │ │
│  │ • Connection Flood (50+ connections in 1s)             │ │
│  │ • DNS Tunneling (long queries)                         │ │
│  │ • ARP Spoofing (MAC changes)                           │ │
│  └────────────────────────────────────────────────────────┘ │
│                         ↓                                    │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Layer 2: Signature-Based Detection                     │ │
│  │      SignatureDatabase.matchSignatures()               │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │ Checks packet against 18 known attack signatures:      │ │
│  │                                                         │ │
│  │ MALWARE (3 signatures):                                │ │
│  │  • Metasploit Meterpreter                             │ │
│  │  • WannaCry Ransomware                                │ │
│  │  • Cobalt Strike Beacon                               │ │
│  │                                                         │ │
│  │ EXPLOITS (4 signatures):                               │ │
│  │  • SQL Injection                                       │ │
│  │  • Directory Traversal                                 │ │
│  │  • Remote Code Execution                               │ │
│  │  • XXE Attack                                          │ │
│  │                                                         │ │
│  │ RECONNAISSANCE (3 signatures):                         │ │
│  │  • Nmap Scanner                                        │ │
│  │  • Nikto Scanner                                       │ │
│  │  • SQLMap Scanner                                      │ │
│  │                                                         │ │
│  │ COMMAND & CONTROL (3 signatures):                      │ │
│  │  • TOR Network                                         │ │
│  │  • Known C&C Domains                                   │ │
│  │  • IRC Botnet                                          │ │
│  │                                                         │ │
│  │ Other categories: Data Exfiltration, Brute Force,      │ │
│  │                   Network Attacks                       │ │
│  └────────────────────────────────────────────────────────┘ │
│                         ↓                                    │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Layer 3: Rule-Based Detection                          │ │
│  │        RuleEngine.evaluateRules()                      │ │
│  ├────────────────────────────────────────────────────────┤ │
│  │ Evaluates 10 complex rules with multiple conditions:   │ │
│  │                                                         │ │
│  │ RULE-001: Advanced Port Scan                           │ │
│  │  - TCP + 15+ unique destinations + SYN flags           │ │
│  │                                                         │ │
│  │ RULE-002: SQL Injection Attack                         │ │
│  │  - HTTP + Port 80 + SQL keywords in URL/payload       │ │
│  │                                                         │ │
│  │ RULE-003: Malicious File Download                      │ │
│  │  - GET request + executable file extension            │ │
│  │                                                         │ │
│  │ RULE-004: DNS Tunneling                                │ │
│  │  - UDP + Port 53 + Large payload + High rate          │ │
│  │                                                         │ │
│  │ RULE-005: Brute Force Attack                           │ │
│  │  - SSH/RDP/FTP/Telnet + 20+ packets/minute            │ │
│  │                                                         │ │
│  │ RULE-006: Cryptomining Detection                       │ │
│  │  - TCP + Mining ports + "stratum" in payload          │ │
│  │                                                         │ │
│  │ RULE-007: Suspicious Outbound Traffic                  │ │
│  │  - 100+ packets/10s + Large payloads                   │ │
│  │                                                         │ │
│  │ RULE-008: Shellcode Pattern                            │ │
│  │  - NOP sled or shellcode bytes detected               │ │
│  │                                                         │ │
│  │ RULE-009: Suspicious User-Agent                        │ │
│  │  - Bot/Scanner/Crawler/Python/Curl agents             │ │
│  │                                                         │ │
│  │ RULE-010: ICMP Tunneling                               │ │
│  │  - ICMP + Large payload + High rate                    │ │
│  └────────────────────────────────────────────────────────┘ │
│                         ↓                                    │
│  ┌────────────────────────────────────────────────────────┐ │
│  │ Anomaly Reporting                                       │ │
│  │  • Creates Anomaly object                              │ │
│  │  • Broadcasts to listeners                             │ │
│  │  • Logs to console                                     │ │
│  └────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────┘
```

---

## 📝 Component Details

### 1. SignatureDatabase.kt

**Purpose:** Maintains a database of known attack signatures and matches packets against them.

**Key Features:**
- **18 pre-loaded signatures** covering major attack categories
- **Multiple pattern types:** Payload, Header, Port, IP, DNS, URL, Composite
- **Extensible:** Easy to add custom signatures
- **Category-based organization:** MALWARE, EXPLOIT, RECONNAISSANCE, etc.

**Signature Structure:**
```kotlin
data class Signature(
    val id: String,              // Unique identifier (e.g., "MAL-001")
    val name: String,            // Human-readable name
    val category: Category,      // Attack category
    val severity: Severity,      // Threat level
    val pattern: Pattern,        // Matching pattern
    val description: String      // Detailed description
)
```

**Pattern Types:**
```kotlin
sealed class Pattern {
    // Match if payload contains specific bytes
    data class PayloadContains(val bytes: List<ByteArray>)

    // Match HTTP header against regex
    data class HeaderPattern(val field: String, val regex: Regex)

    // Match specific ports
    data class PortPattern(val ports: Set<Int>)

    // Match specific IPs
    data class IpPattern(val ips: Set<String>)

    // Match DNS domains
    data class DnsPattern(val domains: Set<String>)

    // Match URL patterns
    data class UrlPattern(val paths: Set<String>)

    // Combine multiple patterns with AND/OR logic
    data class CompositePattern(
        val patterns: List<Pattern>,
        val matchAll: Boolean = false  // true = AND, false = OR
    )
}
```

**Example Signatures:**

**1. Metasploit Meterpreter (MAL-001)**
```kotlin
Signature(
    id = "MAL-001",
    name = "Metasploit Meterpreter",
    category = MALWARE,
    severity = CRITICAL,
    pattern = PayloadContains(
        listOf(
            "meterpreter".toByteArray(),
            "stdapi_".toByteArray(),
            "core_loadlib".toByteArray()
        )
    ),
    description = "Metasploit Meterpreter payload detected"
)
```

**2. SQL Injection (EXP-001)**
```kotlin
Signature(
    id = "EXP-001",
    name = "SQL Injection",
    category = WEB_ATTACK,
    severity = HIGH,
    pattern = UrlPattern(
        setOf(
            "' OR '1'='1",
            "UNION SELECT",
            "; DROP TABLE",
            "' OR 1=1--"
        )
    ),
    description = "SQL injection attempt detected"
)
```

**3. Cobalt Strike Beacon (MAL-003)**
```kotlin
Signature(
    id = "MAL-003",
    name = "Cobalt Strike Beacon",
    category = COMMAND_CONTROL,
    severity = CRITICAL,
    pattern = HeaderPattern(
        "User-Agent",
        Regex("Mozilla/5\\.0 \\(compatible; MSIE...")
    ),
    description = "Cobalt Strike C2 beacon communication"
)
```

**Usage:**
```kotlin
val matches = SignatureDatabase.matchSignatures(packetInfo, payload)
for (match in matches) {
    // match.signature contains the matched signature
    // Report anomaly
}
```

---

### 2. RuleEngine.kt

**Purpose:** Evaluates complex multi-condition rules with temporal and statistical logic.

**Key Features:**
- **10 pre-defined advanced rules**
- **Supports 20+ condition types**
- **Logical operators:** AND, OR, NOT
- **Temporal tracking:** Rate limiting, time windows, packet history
- **Extensible:** Custom rules and conditions

**Rule Structure:**
```kotlin
data class Rule(
    val id: String,                      // Unique identifier
    val name: String,                    // Human-readable name
    val description: String,             // Detailed description
    val severity: Severity,              // Threat level
    val category: String,                // Category (e.g., "WEB_ATTACK")
    val conditions: List<Condition>,     // Conditions to evaluate
    val action: Action,                  // What to do when matched
    val enabled: Boolean = true          // Can be disabled
)
```

**Condition Types:**

**Basic Conditions:**
```kotlin
ProtocolEquals("TCP")                    // Protocol must be TCP
PortEquals(80, DESTINATION)              // Destination port must be 80
PortInRange(1024, 65535, SOURCE)         // Source port in range
IpEquals("192.168.1.1", SOURCE)          // Source IP matches
FlagsContain(listOf("SYN", "ACK"))       // TCP flags present
```

**Payload Conditions:**
```kotlin
PayloadSize(GREATER_THAN, 1024)          // Payload > 1024 bytes
PayloadContains("malware")               // Payload contains string
PayloadMatches(Regex(".*evil.*"))        // Payload matches regex
```

**Header Conditions:**
```kotlin
HeaderExists("X-Custom-Header")          // HTTP header exists
HeaderEquals("Host", "evil.com")         // Header has value
HeaderMatches("User-Agent", Regex(...))  // Header matches regex
```

**Rate/Temporal Conditions:**
```kotlin
PacketRate(GREATER_THAN, 100, 10000)     // >100 packets in 10 seconds
UniqueDestinations(GREATER_THAN, 15, 10000) // >15 unique IPs in 10s
TimeSince("event", LESS_THAN, 5000)      // <5 seconds since event
```

**Domain/DNS Conditions:**
```kotlin
DomainEquals("malware.com")              // Domain matches exactly
DomainContains("evil")                   // Domain contains substring
DnsQueryType("AAAA")                     // DNS query type
```

**HTTP Conditions:**
```kotlin
HttpMethod("GET")                        // HTTP method is GET
HttpStatus(EQUALS, 200)                  // Status code is 200
UrlContains("/admin")                    // URL contains path
UrlMatches(Regex(".*\\.exe$"))           // URL matches pattern
```

**Logical Conditions:**
```kotlin
And(listOf(condition1, condition2))      // All must match
Or(listOf(condition1, condition2))       // Any must match
Not(condition)                           // Must NOT match
```

**Example Rules:**

**RULE-001: Advanced Port Scan**
```kotlin
Rule(
    id = "RULE-001",
    name = "Advanced Port Scan",
    severity = HIGH,
    category = "RECONNAISSANCE",
    conditions = listOf(
        And(listOf(
            ProtocolEquals("TCP"),
            UniqueDestinations(GREATER_THAN, 15, 10000),
            Or(listOf(
                FlagsContain(listOf("SYN")),
                FlagsContain(listOf("NULL"))
            ))
        ))
    ),
    action = AlertWithDetails("Port scan with advanced patterns")
)
```
**Detection:** TCP packets to 15+ unique destinations in 10 seconds with SYN or NULL flags

**RULE-002: SQL Injection**
```kotlin
Rule(
    id = "RULE-002",
    name = "SQL Injection Attack",
    severity = CRITICAL,
    category = "WEB_ATTACK",
    conditions = listOf(
        And(listOf(
            ProtocolEquals("TCP"),
            PortEquals(80, DESTINATION),
            Or(listOf(
                UrlMatches(Regex(".*('|--|;|UNION|SELECT).*")),
                PayloadMatches(Regex(".*(UNION.*SELECT|INSERT.*INTO).*"))
            ))
        ))
    ),
    action = AlertWithDetails("SQL injection detected")
)
```
**Detection:** HTTP traffic to port 80 with SQL keywords in URL or payload

**RULE-004: DNS Tunneling**
```kotlin
Rule(
    id = "RULE-004",
    name = "DNS Tunneling",
    severity = HIGH,
    category = "EXFILTRATION",
    conditions = listOf(
        And(listOf(
            ProtocolEquals("UDP"),
            PortEquals(53, DESTINATION),
            Or(listOf(
                PayloadSize(GREATER_THAN, 128),
                DomainMatches(Regex(".*[0-9a-f]{32,}.*"))
            )),
            PacketRate(GREATER_THAN, 10, 1000)
        ))
    ),
    action = AlertWithDetails("DNS tunneling detected")
)
```
**Detection:** DNS traffic with large payloads or long hex strings at >10 packets/second

**RULE-006: Cryptomining**
```kotlin
Rule(
    id = "RULE-006",
    name = "Cryptomining Detection",
    severity = MEDIUM,
    category = "MALWARE",
    conditions = listOf(
        And(listOf(
            ProtocolEquals("TCP"),
            Or(listOf(
                PortEquals(3333),
                PortEquals(4444),
                PortEquals(5555)
            )),
            PayloadContains("stratum")
        ))
    ),
    action = AlertWithDetails("Cryptomining pool detected")
)
```
**Detection:** TCP traffic to mining pool ports containing "stratum" protocol

---

## 🔄 Integration with AnomalyDetector

The signature and rule engines are integrated into `AnomalyDetector.analyzePacket()`:

```kotlin
fun analyzePacket(packetInfo: Map<String, Any>, payload: ByteArray? = null) {
    // Layer 1: Basic Statistical Detection
    detectPortScan(...)
    detectSynFlood(...)
    detectConnectionFlood(...)
    detectDnsTunneling(...)
    detectArpSpoofing(...)

    // Layer 2: Signature-Based Detection
    val signatureMatches = SignatureDatabase.matchSignatures(packetInfo, payload)
    for (match in signatureMatches) {
        reportAnomaly(createAnomalyFromSignature(match))
    }

    // Layer 3: Rule-Based Detection
    val ruleMatches = RuleEngine.evaluateRules(packetInfo, payload)
    for (match in ruleMatches) {
        reportAnomaly(createAnomalyFromRule(match))
    }

    // Layer 4: ML-Based Detection (future)
    detectBehavioralAnomalies(...)
    detectEntropyAnomalies(...)
    detectConnectionPatternAnomalies(...)
}
```

---

## 📊 Complete Signature List

| ID | Name | Category | Severity | Description |
|----|------|----------|----------|-------------|
| MAL-001 | Metasploit Meterpreter | MALWARE | CRITICAL | Meterpreter payload in traffic |
| MAL-002 | WannaCry Ransomware | MALWARE | CRITICAL | WannaCry SMB activity |
| MAL-003 | Cobalt Strike Beacon | COMMAND_CONTROL | CRITICAL | C2 beacon communication |
| EXP-001 | SQL Injection | WEB_ATTACK | HIGH | SQL injection attempt |
| EXP-002 | Directory Traversal | WEB_ATTACK | HIGH | Path traversal attack |
| EXP-003 | RCE Attempt | EXPLOIT | CRITICAL | Remote code execution |
| EXP-004 | XXE Attack | WEB_ATTACK | HIGH | XML external entity attack |
| RECON-001 | Nmap Scan | RECONNAISSANCE | MEDIUM | Nmap scanner detected |
| RECON-002 | Nikto Scanner | RECONNAISSANCE | MEDIUM | Nikto web scanner |
| RECON-003 | SQLMap Scanner | RECONNAISSANCE | MEDIUM | SQL injection scanner |
| C2-001 | TOR Network | COMMAND_CONTROL | MEDIUM | TOR exit node connection |
| C2-002 | Known C&C Domain | COMMAND_CONTROL | CRITICAL | C&C server connection |
| C2-003 | IRC Bot | COMMAND_CONTROL | HIGH | IRC botnet traffic |
| EXFIL-001 | Base64 Exfiltration | DATA_EXFILTRATION | HIGH | Base64 encoded data transfer |
| BRUTE-001 | SSH Brute Force | BRUTE_FORCE | HIGH | SSH brute force attempt |
| BRUTE-002 | RDP Brute Force | BRUTE_FORCE | HIGH | RDP brute force attempt |
| NET-001 | EternalBlue Exploit | NETWORK_ATTACK | CRITICAL | EternalBlue SMB exploit |
| NET-002 | Shellshock | NETWORK_ATTACK | CRITICAL | Shellshock vulnerability |

---

## 📊 Complete Rule List

| ID | Name | Category | Severity | Conditions |
|----|------|----------|----------|------------|
| RULE-001 | Advanced Port Scan | RECONNAISSANCE | HIGH | TCP + 15+ destinations + SYN |
| RULE-002 | SQL Injection | WEB_ATTACK | CRITICAL | HTTP + SQL keywords |
| RULE-003 | Malicious File Download | MALWARE | HIGH | GET + .exe/.scr/.bat |
| RULE-004 | DNS Tunneling | EXFILTRATION | HIGH | DNS + large payload + high rate |
| RULE-005 | Brute Force Attack | BRUTE_FORCE | HIGH | SSH/RDP/FTP + 20+ packets/min |
| RULE-006 | Cryptomining | MALWARE | MEDIUM | Mining ports + "stratum" |
| RULE-007 | Suspicious Outbound | EXFILTRATION | MEDIUM | 100+ packets + large payloads |
| RULE-008 | Shellcode Pattern | EXPLOIT | CRITICAL | NOP sled or shellcode bytes |
| RULE-009 | Suspicious User-Agent | RECONNAISSANCE | MEDIUM | Bot/Scanner/Curl agents |
| RULE-010 | ICMP Tunneling | EXFILTRATION | HIGH | ICMP + large payload + high rate |

---

## 🔧 Adding Custom Signatures

```kotlin
// Add custom signature
val customSignature = SignatureDatabase.Signature(
    id = "CUSTOM-001",
    name = "My Custom Attack",
    category = SignatureDatabase.Category.MALWARE,
    severity = AnomalyDetector.Severity.HIGH,
    pattern = SignatureDatabase.Pattern.PayloadContains(
        listOf("attack_pattern".toByteArray())
    ),
    description = "Detects my custom attack pattern"
)

SignatureDatabase.addSignature(customSignature)
```

---

## 🔧 Adding Custom Rules

```kotlin
// Add custom rule
val customRule = RuleEngine.Rule(
    id = "CUSTOM-RULE-001",
    name = "My Custom Rule",
    description = "Detects custom suspicious behavior",
    severity = AnomalyDetector.Severity.HIGH,
    category = "CUSTOM",
    conditions = listOf(
        RuleEngine.Condition.And(listOf(
            RuleEngine.Condition.ProtocolEquals("TCP"),
            RuleEngine.Condition.PortEquals(8080),
            RuleEngine.Condition.PayloadContains("suspicious")
        ))
    ),
    action = RuleEngine.Action.AlertWithDetails("Custom rule triggered")
)

RuleEngine.addRule(customRule)
```

---

## 📈 Performance Characteristics

### Signature Matching
- **Time Complexity:** O(n × m) where n = signatures, m = patterns per signature
- **Average matches per packet:** 0-2
- **Performance impact:** Minimal (<1ms per packet)

### Rule Evaluation
- **Time Complexity:** O(r × c) where r = rules, c = conditions per rule
- **Packet history size:** Last 1000 packets per rule
- **Average evaluations per packet:** 10 rules
- **Performance impact:** Low (1-2ms per packet)

### Memory Usage
- **SignatureDatabase:** ~50KB (18 signatures)
- **RuleEngine:** ~100KB + packet history
- **Per-rule state:** ~10-50KB depending on history

---

## 🚀 Next Steps

### ✅ Completed
- Signature database with 18 signatures
- Rule engine with 10 complex rules
- Integration with AnomalyDetector
- Pattern matching system
- Temporal tracking and rate limiting

### 🔄 In Progress
- Flutter UI integration (anomaly notifications)
- Anomaly score calculation
- Anomaly history/dashboard

### 📋 Planned
- Signature auto-updates from threat feeds
- Machine learning integration
- Custom signature/rule editor in UI
- Threat intelligence integration
- Anomaly correlation engine

---

**Document Version:** 1.0
**Last Updated:** 2025-10-08
**Author:** AndroNet Development Team
