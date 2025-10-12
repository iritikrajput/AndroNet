# AndroNet Anomaly Detection System - Complete Architecture

## 📋 Table of Contents
1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Component Breakdown](#component-breakdown)
4. [Data Flow](#data-flow)
5. [Detection Algorithms](#detection-algorithms)
6. [Integration Points](#integration-points)
7. [Current Implementation Status](#current-implementation-status)
8. [Planned Enhancements](#planned-enhancements)

---

## 🎯 Overview

The AndroNet Anomaly Detection System is a **multi-layered, real-time network security monitoring engine** integrated into the packet analysis pipeline. It detects suspicious network activities using both **rule-based** and **behavioral** analysis techniques.

### Key Capabilities
- ✅ **Port Scan Detection** - Identifies reconnaissance activities
- ✅ **SYN Flood Detection** - Detects DoS/DDoS attacks
- ✅ **Connection Flood Detection** - Monitors excessive connection attempts
- ✅ **DNS Tunneling Detection** - Identifies data exfiltration via DNS
- ✅ **ARP Spoofing Detection** - Detects MITM attacks
- ⚠️ **Behavioral Anomalies** - ML-based traffic pattern analysis (partial)
- ⚠️ **Entropy Analysis** - Payload randomness detection (partial)
- ⚠️ **Connection Patterns** - Temporal pattern analysis (partial)

---

## 🏗️ System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PACKET CAPTURE LAYER                          │
│              (ZdtunVpnService - Native packet capture)               │
└─────────────────────┬───────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   PACKET ANALYSIS MANAGER                            │
│         (PacketAnalysisManager.kt - Central orchestrator)            │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Phase 1: Basic Parsing (IP, Ports, Protocol)                 │  │
│  └──────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Phase 2: Deep Packet Inspection (DPI)                        │  │
│  │   - HTTP/HTTPS parsing                                        │  │
│  │   - DNS query/response analysis                               │  │
│  │   - TLS handshake inspection                                  │  │
│  │   - Payload extraction                                        │  │
│  └──────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Phase 2.5: Domain Name Enrichment                            │  │
│  │   - SNI extraction from TLS                                   │  │
│  │   - DNS resolution mapping                                    │  │
│  │   - Friendly name assignment                                  │  │
│  └──────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Phase 3: ANOMALY DETECTION ← YOU ARE HERE                    │  │
│  │   → AnomalyDetector.analyzePacket(enrichedPacket)            │  │
│  └──────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Phase 4: PCAP Export (if enabled)                            │  │
│  └──────────────────────────────────────────────────────────────┘  │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │ Phase 5: Bandwidth Tracking                                  │  │
│  └──────────────────────────────────────────────────────────────┘  │
└─────────────────────┬───────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      ANOMALY DETECTOR                                │
│                  (AnomalyDetector.kt - Singleton)                    │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    DETECTION ENGINES                            │ │
│  │                                                                 │ │
│  │  ┌──────────────────┐  ┌──────────────────┐                   │ │
│  │  │ Rule-Based       │  │ ML/Statistical   │                   │ │
│  │  │ Detection        │  │ Detection        │                   │ │
│  │  ├──────────────────┤  ├──────────────────┤                   │ │
│  │  │• Port Scan       │  │• Behavioral      │                   │ │
│  │  │• SYN Flood       │  │• Entropy         │                   │ │
│  │  │• Connection Flood│  │• Pattern         │                   │ │
│  │  │• DNS Tunneling   │  │• Adaptive        │                   │ │
│  │  │• ARP Spoofing    │  │  Thresholds      │                   │ │
│  │  └──────────────────┘  └──────────────────┘                   │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    DATA STRUCTURES                              │ │
│  │                                                                 │ │
│  │  • portScans: Map<SourceIP, PortScanTracker>                   │ │
│  │  • synFloodTracker: Map<TargetIP, SynFloodTracker>             │ │
│  │  • connectionTracker: Map<SourceIP, ConnectionRateTracker>     │ │
│  │  • arpCache: Map<IP, MAC>                                      │ │
│  │  • dnsQueryTracker: DnsQueryTracker                            │ │
│  │  • trafficStats: TrafficStatistics (ML models)                 │ │
│  │  • behavioralAnalyzer: BehavioralAnalyzer (activity maps)      │ │
│  │  • entropyAnalyzer: EntropyAnalyzer (payload patterns)         │ │
│  │  • connectionPatternAnalyzer: ConnectionPatternAnalyzer        │ │
│  └────────────────────────────────────────────────────────────────┘ │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────────┐ │
│  │                    OUTPUT LAYER                                 │ │
│  │                                                                 │ │
│  │  • anomalyListeners: List<(Anomaly) -> Unit>                   │ │
│  │  • reportAnomaly() → Broadcasts to all listeners               │ │
│  └────────────────────────────────────────────────────────────────┘ │
└─────────────────────┬───────────────────────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        FLUTTER UI LAYER                              │
│                      (main.dart, models.dart)                        │
│                                                                       │
│  • Receives anomaly notifications (NOT CURRENTLY CONNECTED)          │
│  • Displays anomaly alerts in UI                                     │
│  • Shows anomaly score in packet details (field exists but unused)   │
└─────────────────────────────────────────────────────────────────────┘
```

---

## 🧩 Component Breakdown

### 1. **AnomalyDetector.kt** (Core Engine)
**Location:** `android/app/src/main/kotlin/com/example/packet_analyzer/AnomalyDetector.kt`

**Type:** Kotlin Singleton Object

**Responsibilities:**
- Receives enriched packet data from PacketAnalysisManager
- Runs all detection algorithms
- Maintains tracking state for ongoing threats
- Reports anomalies to registered listeners

**Key Classes & Data Structures:**

```kotlin
// Main Anomaly Model
data class Anomaly(
    val type: AnomalyType,           // Type of threat detected
    val severity: Severity,           // LOW, MEDIUM, HIGH, CRITICAL
    val description: String,          // Human-readable description
    val sourceIp: String?,           // Attacker IP (if applicable)
    val destinationIp: String?,      // Target IP (if applicable)
    val details: Map<String, Any>,   // Additional context
    val timestamp: Long              // When detected
)

enum class AnomalyType {
    PORT_SCAN,           // Reconnaissance activity
    SYN_FLOOD,          // TCP SYN flood attack
    ARP_SPOOFING,       // MITM attack attempt
    DNS_TUNNELING,      // Data exfiltration
    CONNECTION_FLOOD,   // Connection exhaustion
    UNUSUAL_TRAFFIC,    // ML-detected anomaly
    MALFORMED_PACKET    // Protocol violations
}

enum class Severity {
    LOW,      // Informational, no immediate action needed
    MEDIUM,   // Suspicious, requires monitoring
    HIGH,     // Likely threat, action recommended
    CRITICAL  // Active attack, immediate action required
}
```

**Tracking Data Structures:**

```kotlin
// Port Scan Tracking
private data class PortScanTracker(
    var ports: MutableSet<Int>,      // Unique ports accessed
    var firstSeen: Long,             // Start of scan window
    var lastSeen: Long               // Last port access
)
private val portScans: Map<SourceIP, PortScanTracker>

// SYN Flood Tracking
private data class SynFloodTracker(
    var synCount: Int,               // SYN packets received
    var windowStart: Long            // Start of detection window
)
private val synFloodTracker: Map<TargetIP, SynFloodTracker>

// Connection Rate Tracking
private data class ConnectionRateTracker(
    var connections: Int,            // Connection attempts
    var windowStart: Long            // Start of detection window
)
private val connectionTracker: Map<SourceIP, ConnectionRateTracker>

// DNS Query Tracking
private data class DnsQueryTracker(
    var queries: Int,                // Query count
    var windowStart: Long,           // Detection window
    var domains: MutableSet<String>  // Queried domains
)

// ARP Cache (for spoofing detection)
private val arpCache: Map<IP, MAC>
```

**ML/Statistical Models (Partially Implemented):**

```kotlin
// Traffic Statistics
private data class TrafficStatistics(
    val packetSizeStats: StatisticalModel  // Packet size distribution
)

private data class StatisticalModel(
    var mean: Double,           // Mean packet size
    var variance: Double,       // Variance
    var count: Int,            // Sample count
    var lastUpdate: Long       // Last update timestamp
)

// Behavioral Analysis
private data class BehavioralAnalyzer(
    val ipActivityMap: Map<IP, List<Timestamp>>,        // IP access patterns
    val protocolUsageMap: Map<Protocol, List<Timestamp>>, // Protocol usage
    val portActivityMap: Map<Port, List<Timestamp>>      // Port access patterns
)

// Entropy Analysis
private data class EntropyAnalyzer(
    val payloadEntropyMap: Map<String, List<Double>>,   // Payload entropy
    val averageEntropy: Double                           // Baseline entropy
)

// Connection Pattern Analysis
private data class ConnectionPatternAnalyzer(
    val connectionSequences: Map<String, List<String>>,  // Connection order
    val timingPatterns: Map<String, List<Long>>          // Timing analysis
)
```

### 2. **PacketAnalysisManager.kt** (Integration Point)
**Location:** `android/app/src/main/kotlin/com/example/packet_analyzer/PacketAnalysisManager.kt`

**Integration Code:**
```kotlin
// Line 159: Anomaly detection is called after DPI and domain enrichment
AnomalyDetector.analyzePacket(finalPacket)
```

**Packet Data Passed to Anomaly Detector:**
```kotlin
Map<String, Any> containing:
├── sourceIp: String
├── destinationIp: String
├── sourcePort: Int
├── destinationPort: Int
├── protocol: String (TCP, UDP, ICMP, etc.)
├── size: Int
├── timestamp: Long
├── payload: String (ASCII representation)
├── direction: String (incoming/outgoing)
├── flags: String (TCP flags like SYN, ACK, FIN)
├── appName: String (HTTP, HTTPS, DNS, etc.)
├── domain: String? (if available)
├── domainFriendly: String? (e.g., "Google")
├── dpiData: Map<String, Any>? (protocol-specific data)
│   ├── httpData: Map (HTTP headers, method, etc.)
│   ├── dnsData: Map (query name, type, response)
│   ├── tlsData: Map (TLS version, handshake type, SNI)
│   └── quicData: Map (QUIC header info)
├── payloadHex: String (hex representation)
└── payloadSize: Int
```

### 3. **Flutter Data Models** (UI Layer)
**Location:** `lib/models.dart`

```dart
class PacketInfo {
  // ... other fields ...
  final double? anomalyScore;  // ← Field exists but NOT populated!

  // Constructor
  PacketInfo({
    // ...
    this.anomalyScore,  // Currently always null
    // ...
  });

  // Factory from Kotlin map
  factory PacketInfo.fromMap(Map<String, dynamic> map) {
    return PacketInfo(
      // ...
      anomalyScore: map['anomalyScore'] != null
          ? (map['anomalyScore'] as num).toDouble()
          : null,  // ← Kotlin never sends this field
      // ...
    );
  }
}
```

**⚠️ CURRENT ISSUE:** The `anomalyScore` field exists in the Flutter model but is **never populated** because:
1. AnomalyDetector doesn't calculate a score
2. PacketAnalysisManager doesn't add anomalyScore to packet map
3. Flutter always receives `null`

---

## 🔄 Data Flow

### Complete Packet Journey

```
1. PACKET CAPTURE
   ZdtunVpnService captures raw packet bytes
   ↓

2. BASIC PARSING
   PacketAnalysisManager extracts:
   - IP addresses
   - Ports
   - Protocol
   - Flags
   ↓

3. DEEP PACKET INSPECTION
   PacketDissector analyzes:
   - HTTP headers/body
   - DNS queries/responses
   - TLS handshakes (SNI extraction)
   - Payload extraction
   ↓

4. DOMAIN ENRICHMENT
   DomainTracker adds:
   - Domain name (from SNI or DNS)
   - Friendly name (e.g., "Google", "Facebook")
   ↓

5. ANOMALY DETECTION ← CURRENT FOCUS
   AnomalyDetector analyzes packet for:

   ┌─────────────────────────────────────┐
   │ Rule-Based Detections               │
   ├─────────────────────────────────────┤
   │ ✓ Port Scan Detection               │
   │   - Tracks unique ports per IP      │
   │   - 20+ ports in 10 seconds = alert │
   │                                     │
   │ ✓ SYN Flood Detection               │
   │   - Counts SYN packets per target   │
   │   - 100+ SYNs in 1 second = alert   │
   │                                     │
   │ ✓ Connection Flood Detection        │
   │   - Tracks connection attempts      │
   │   - 50+ connections/sec = alert     │
   │                                     │
   │ ✓ DNS Tunneling Detection           │
   │   - Checks query name length        │
   │   - 50+ chars = suspicious          │
   │                                     │
   │ ✓ ARP Spoofing Detection            │
   │   - Maintains IP→MAC mapping        │
   │   - MAC change = alert              │
   └─────────────────────────────────────┘

   ┌─────────────────────────────────────┐
   │ ML-Based Detections (STUB)          │
   ├─────────────────────────────────────┤
   │ ⚠ Behavioral Anomalies              │
   │   - Empty stub function             │
   │   - Data structures exist           │
   │                                     │
   │ ⚠ Entropy Analysis                  │
   │   - Empty stub function             │
   │   - Data structures exist           │
   │                                     │
   │ ⚠ Connection Patterns               │
   │   - Empty stub function             │
   │   - Data structures exist           │
   │                                     │
   │ ⚠ Adaptive Thresholds               │
   │   - Empty stub function             │
   │   - Variables exist but not used    │
   └─────────────────────────────────────┘
   ↓

6. ANOMALY REPORTING
   If anomaly detected:
   - Creates Anomaly object
   - Calls reportAnomaly()
   - Broadcasts to listeners
   ↓

7. LISTENER HANDLING
   ⚠️ PROBLEM: No listeners registered!
   - anomalyListeners list exists
   - addAnomalyListener() method exists
   - BUT: Nobody calls it!
   - Flutter never receives anomaly notifications
   ↓

8. PACKET SENT TO FLUTTER
   EventSink sends packet to Flutter
   - Contains all enriched data
   - Contains domain info
   - Does NOT contain anomaly info
   ↓

9. UI DISPLAY
   Flutter displays packet in list
   - Shows domain names ✓
   - Shows protocol info ✓
   - Does NOT show anomaly warnings ✗
```

---

## 🔍 Detection Algorithms (Detailed)

### 1. Port Scan Detection

**Algorithm:**
```
Input: sourceIp, port, destIp

1. Get or create PortScanTracker for sourceIp
2. Check if window expired (> 10 seconds):
   - If yes: Reset ports set and window
3. Add port to tracked ports set
4. If ports.size >= 20:
   - Create HIGH severity PORT_SCAN anomaly
   - Reset tracker
```

**Thresholds:**
- Window: 10,000ms (10 seconds)
- Port threshold: 20 unique ports

**Example Detection:**
```
Time    Source IP      Dest IP      Port    Unique Ports
-----   -----------    ----------   ----    ------------
00:00   192.168.1.5    10.0.0.10    80      1
00:01   192.168.1.5    10.0.0.10    443     2
00:02   192.168.1.5    10.0.0.10    22      3
...     ...            ...          ...     ...
00:08   192.168.1.5    10.0.0.10    8080    20  ← ALERT!

Anomaly: PORT_SCAN detected from 192.168.1.5
```

### 2. SYN Flood Detection

**Algorithm:**
```
Input: targetIp (from TCP packet with SYN flag)

1. Get or create SynFloodTracker for targetIp
2. Check if window expired (> 1 second):
   - If yes: Reset counter and window
3. Increment synCount
4. If synCount >= 100:
   - Create CRITICAL severity SYN_FLOOD anomaly
   - Reset counter
```

**Thresholds:**
- Window: 1,000ms (1 second)
- SYN threshold: 100 packets

**Attack Pattern:**
```
Attacker sends rapid SYN packets:
SYN → Target:80
SYN → Target:80
SYN → Target:80
... (100 times in 1 second) → ALERT!

Anomaly: SYN_FLOOD targeting 10.0.0.10
```

### 3. Connection Flood Detection

**Algorithm:**
```
Input: sourceIp (from TCP SYN packet)

1. Get or create ConnectionRateTracker for sourceIp
2. Check if window expired (> 1 second):
   - If yes: Reset counter and window
3. Increment connections
4. If connections >= 50:
   - Create HIGH severity CONNECTION_FLOOD anomaly
   - Reset counter
```

**Thresholds:**
- Window: 1,000ms (1 second)
- Connection threshold: 50 connections

### 4. DNS Tunneling Detection

**Algorithm:**
```
Input: queryName (from DNS packet)

1. Check if queryName is empty: return
2. If queryName.length > 50:
   - Create MEDIUM severity DNS_TUNNELING anomaly
```

**Detection Pattern:**
```
Normal DNS:
- google.com (10 chars) ✓
- facebook.com (12 chars) ✓

Suspicious DNS (data exfiltration):
- ABC123DEF456GHI789JKL012MNO345PQR678STU901VWX234YZ.evil.com (60+ chars) ✗

Anomaly: DNS_TUNNELING with suspicious query
```

### 5. ARP Spoofing Detection

**Algorithm:**
```
Input: senderIp, senderMac (from ARP packet)

1. Lookup senderIp in arpCache
2. If cached MAC exists AND cached != senderMac:
   - Create CRITICAL severity ARP_SPOOFING anomaly
3. Update arpCache[senderIp] = senderMac
```

**Attack Pattern:**
```
Normal:
192.168.1.1 → AA:BB:CC:DD:EE:01 (cached)

Attack (MAC changed):
192.168.1.1 → FF:FF:FF:FF:FF:FF (different!) ← ALERT!

Anomaly: ARP_SPOOFING from 192.168.1.1
```

### 6. Behavioral Anomalies (STUB)

**Current Implementation:**
```kotlin
private fun detectBehavioralAnomalies(packetInfo: Map<String, Any>) {
    // TODO: Empty stub - needs implementation
}
```

**Planned Algorithm:**
```
1. Track IP activity patterns over time
2. Build baseline behavior profile
3. Detect deviations from normal:
   - Unusual access times
   - Abnormal protocol usage
   - Unexpected destination IPs
4. Use statistical analysis (z-score)
5. Report UNUSUAL_TRAFFIC anomaly if deviation > threshold
```

**Data Structures Available:**
```kotlin
BehavioralAnalyzer(
    ipActivityMap: Map<IP, List<Timestamp>>,        // When each IP is accessed
    protocolUsageMap: Map<Protocol, List<Timestamp>>, // Protocol usage times
    portActivityMap: Map<Port, List<Timestamp>>      // Port access times
)
```

### 7. Entropy Analysis (STUB)

**Current Implementation:**
```kotlin
private fun detectEntropyAnomalies(packetInfo: Map<String, Any>, payload: ByteArray?) {
    // TODO: Empty stub - needs implementation
}
```

**Planned Algorithm:**
```
1. Calculate Shannon entropy of packet payload:
   Entropy = -Σ(p(i) * log2(p(i)))
   where p(i) = probability of byte i

2. Compare to baseline entropy (4.5 bits/byte for normal data)

3. High entropy (> 7.5) = encrypted/compressed data
   - Normal for HTTPS
   - Suspicious for HTTP, DNS

4. Very high entropy = possible data exfiltration

5. Report anomaly if entropy abnormal for protocol
```

**Data Structures Available:**
```kotlin
EntropyAnalyzer(
    payloadEntropyMap: Map<String, List<Double>>,  // Historical entropy values
    averageEntropy: Double = 4.5                    // Baseline
)
```

### 8. Connection Pattern Analysis (STUB)

**Current Implementation:**
```kotlin
private fun detectConnectionPatternAnomalies(packetInfo: Map<String, Any>) {
    // TODO: Empty stub - needs implementation
}
```

**Planned Algorithm:**
```
1. Track connection sequences:
   - Order of connections (IP1 → IP2 → IP3)
   - Timing between connections

2. Build Markov chain of connection patterns

3. Detect anomalies:
   - Unusual connection sequences
   - Abnormal timing patterns
   - Bot-like regular intervals

4. Report anomaly if pattern probability < threshold
```

**Data Structures Available:**
```kotlin
ConnectionPatternAnalyzer(
    connectionSequences: Map<String, List<String>>,  // Connection order
    timingPatterns: Map<String, List<Long>>          // Inter-connection times
)
```

### 9. Adaptive Thresholds (STUB)

**Current Implementation:**
```kotlin
private fun updateAdaptiveThresholds() {
    // TODO: Empty stub - needs implementation
}
```

**Planned Algorithm:**
```
1. Monitor false positive rate for each detection type

2. Adjust thresholds dynamically:
   - If false positives high: Increase threshold
   - If attacks missed: Decrease threshold

3. Use exponential moving average:
   new_threshold = α * current_threshold + (1-α) * observed_value

4. Update variables:
   - adaptivePortScanThreshold
   - adaptiveSynFloodThreshold
   - adaptiveConnectionRateThreshold
```

---

## 🔗 Integration Points

### 1. **Kotlin → Kotlin Integration** ✅ WORKING

**File:** `PacketAnalysisManager.kt` (Line 159)
```kotlin
// Called for every packet after DPI and domain enrichment
AnomalyDetector.analyzePacket(finalPacket)
```

**Status:** ✅ Fully integrated, working

### 2. **Kotlin → Flutter Integration** ❌ NOT CONNECTED

**Problem:** Anomalies detected in Kotlin are **not sent to Flutter**

**What's Missing:**
```kotlin
// In MainActivity.kt or ZdtunVpnService.kt
// This code DOES NOT EXIST:

// Step 1: Register anomaly listener when VPN starts
AnomalyDetector.addAnomalyListener { anomaly ->
    // Step 2: Send anomaly to Flutter via MethodChannel
    mainHandler.post {
        methodChannel.invokeMethod("onAnomalyDetected", mapOf(
            "type" to anomaly.type.name,
            "severity" to anomaly.severity.name,
            "description" to anomaly.description,
            "sourceIp" to anomaly.sourceIp,
            "destinationIp" to anomaly.destinationIp,
            "timestamp" to anomaly.timestamp
        ))
    }
}

// Step 3: Remove listener when VPN stops
AnomalyDetector.removeAnomalyListener(listener)
```

**In Flutter (main.dart):**
```dart
// This code DOES NOT EXIST:

// Step 1: Listen for anomaly notifications
_channel.setMethodCallHandler((call) async {
    if (call.method == 'onAnomalyDetected') {
        final anomaly = call.arguments as Map;
        _handleAnomaly(anomaly);
    }
});

// Step 2: Handle anomaly
void _handleAnomaly(Map<String, dynamic> anomaly) {
    // Show notification
    // Add to anomaly list
    // Display alert in UI
}
```

### 3. **Anomaly Score Integration** ❌ NOT IMPLEMENTED

**Problem:** The `anomalyScore` field exists but is never calculated

**What's Missing in AnomalyDetector.kt:**
```kotlin
// This code DOES NOT EXIST:

fun calculateAnomalyScore(packetInfo: Map<String, Any>): Double {
    var score = 0.0

    // Check if packet matches any ongoing detection
    val sourceIp = packetInfo["sourceIp"] as? String
    val destIp = packetInfo["destinationIp"] as? String

    // Contribute scores from different detections
    if (portScans.containsKey(sourceIp)) {
        score += 0.3 * (portScans[sourceIp]!!.ports.size / PORT_SCAN_THRESHOLD.toDouble())
    }

    if (synFloodTracker.containsKey(destIp)) {
        score += 0.4 * (synFloodTracker[destIp]!!.synCount / SYN_FLOOD_THRESHOLD.toDouble())
    }

    if (connectionTracker.containsKey(sourceIp)) {
        score += 0.3 * (connectionTracker[sourceIp]!!.connections / CONNECTION_RATE_THRESHOLD.toDouble())
    }

    return score.coerceIn(0.0, 1.0)
}
```

**What's Missing in PacketAnalysisManager.kt:**
```kotlin
// After line 159, should add:
val anomalyScore = AnomalyDetector.calculateAnomalyScore(finalPacket)
finalPacket["anomalyScore"] = anomalyScore
```

---

## 📊 Current Implementation Status

### ✅ Fully Implemented (Working)

| Component | Status | Description |
|-----------|--------|-------------|
| Port Scan Detection | ✅ Working | Detects 20+ ports in 10 seconds |
| SYN Flood Detection | ✅ Working | Detects 100+ SYNs per second |
| Connection Flood Detection | ✅ Working | Detects 50+ connections per second |
| DNS Tunneling Detection | ✅ Working | Detects long DNS queries (>50 chars) |
| ARP Spoofing Detection | ✅ Working | Detects MAC address changes |
| Packet Analysis Integration | ✅ Working | Called for every packet |
| Anomaly Reporting | ✅ Working | reportAnomaly() broadcasts to listeners |
| Cleanup Mechanism | ✅ Working | Removes stale trackers every 10-20 seconds |

### ⚠️ Partially Implemented (Stub Functions)

| Component | Status | What Exists | What's Missing |
|-----------|--------|-------------|----------------|
| Behavioral Analysis | ⚠️ Stub | Data structures | Algorithm implementation |
| Entropy Analysis | ⚠️ Stub | Data structures | Entropy calculation |
| Connection Patterns | ⚠️ Stub | Data structures | Pattern matching |
| Adaptive Thresholds | ⚠️ Stub | Variables | Threshold adjustment logic |
| Traffic Statistics | ⚠️ Stub | StatisticalModel | Mean/variance updates |

### ❌ Not Implemented (Missing)

| Component | Status | Impact | Priority |
|-----------|--------|--------|----------|
| Flutter Integration | ❌ Missing | Anomalies not visible in UI | HIGH |
| Anomaly Score Calculation | ❌ Missing | No threat scoring | HIGH |
| MethodChannel Handler | ❌ Missing | No Kotlin→Flutter bridge | HIGH |
| Anomaly UI Display | ❌ Missing | No user alerts | MEDIUM |
| Anomaly History | ❌ Missing | Can't review past threats | MEDIUM |
| ML Model Training | ❌ Missing | No learning capability | LOW |

---

## 🚀 Planned Enhancements

### Phase 1: Connect to UI (HIGH PRIORITY)

**Goal:** Make detected anomalies visible to users

**Tasks:**
1. ✅ Add MethodChannel handler in MainActivity.kt
2. ✅ Register anomaly listener on VPN start
3. ✅ Implement onAnomalyDetected in Flutter
4. ✅ Create anomaly notification UI
5. ✅ Add anomaly list screen

**Estimated Effort:** 4-6 hours

### Phase 2: Implement Anomaly Scoring (HIGH PRIORITY)

**Goal:** Assign risk scores to packets

**Tasks:**
1. ✅ Implement calculateAnomalyScore()
2. ✅ Add score to packet map
3. ✅ Display score in packet details
4. ✅ Add color coding by score

**Estimated Effort:** 2-3 hours

### Phase 3: Complete ML Features (MEDIUM PRIORITY)

**Goal:** Implement stub functions

**Tasks:**
1. ⚠️ Behavioral anomaly detection
2. ⚠️ Entropy analysis
3. ⚠️ Connection pattern analysis
4. ⚠️ Adaptive thresholds

**Estimated Effort:** 8-12 hours

### Phase 4: Advanced Features (LOW PRIORITY)

**Goal:** Add sophisticated detection

**Tasks:**
1. ❌ Train ML models on user's traffic
2. ❌ Implement time-series analysis
3. ❌ Add geo-IP anomaly detection
4. ❌ Implement protocol anomaly detection

**Estimated Effort:** 20+ hours

---

## 📝 Summary for Claude Opus / ChatGPT

### Key Points to Understand:

1. **Architecture:** Multi-layered system integrated into packet analysis pipeline
2. **Current State:** Rule-based detection WORKS, ML features are STUBS
3. **Main Problem:** Anomalies detected but NOT sent to Flutter UI
4. **Data Flow:** Packet → Analysis → DPI → Domain → **Anomaly** → (broken) → Flutter
5. **Next Steps:** Connect Kotlin anomaly events to Flutter via MethodChannel

### Files to Focus On:

1. `AnomalyDetector.kt` - Core detection engine (COMPLETE but needs ML)
2. `PacketAnalysisManager.kt` - Integration point (WORKING)
3. `MainActivity.kt` - Need to add listener registration (MISSING)
4. `main.dart` - Need to add anomaly handler (MISSING)
5. `models.dart` - anomalyScore field exists (UNUSED)

### Quick Start for Implementation:

To connect anomalies to UI, you need to:
1. Register listener in Kotlin when VPN starts
2. Send anomaly via MethodChannel
3. Handle in Flutter and display

That's the critical path to make the system functional!

---

**Document Version:** 1.0
**Last Updated:** 2025-10-08
**Author:** AndroNet Development Team
**Status:** Current Implementation Analysis
