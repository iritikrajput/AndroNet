# AndroNet Kotlin Services API Documentation

## Overview

This document provides comprehensive API documentation for all Kotlin services in the AndroNet packet analyzer application. These services handle packet capture, analysis, export, and real-time statistics.

## Table of Contents

1. [PacketAnalysisManager](#packetanalysismanager)
2. [PcapWriter](#pcapwriter)
3. [TrafficStatistics](#trafficstatistics)
4. [AnomalyDetector](#anomalydetector)
5. [PacketDissector](#packetdissector)
6. [CompleteVpnService](#completevpnservice)
7. [PacketBuilder](#packetbuilder)

## PacketAnalysisManager

**Location**: `com.example.packet_analyzer.PacketAnalysisManager`

Central coordinator for all Phase 2 analysis features including PCAP export, DPI, anomaly detection, and statistics.

### Constructor

```kotlin
PacketAnalysisManager(context: Context)
```

### Public Methods

#### Lifecycle Management

```kotlin
fun startAnalysis(): Unit
```
Starts packet analysis when capture begins. Initializes statistics tracking and anomaly detection.

```kotlin
fun stopAnalysis(): Unit
```
Stops packet analysis when capture ends. Cleans up resources and stops PCAP export if active.

#### Packet Processing

```kotlin
fun processPacket(packetInfo: Map<String, Any>, rawPacket: ByteArray? = null): Unit
```
Processes a captured packet through all analysis systems:
- Updates traffic statistics
- Performs deep packet inspection (if raw packet provided)
- Checks for security anomalies
- Exports to PCAP if enabled

#### PCAP Export Management

```kotlin
fun startPcapExport(outputPath: String, linktype: Int = 101): Boolean
```
Starts exporting captured packets to a PCAP file.

**Parameters:**
- `outputPath`: Absolute path for the output PCAP file
- `linktype`: Link layer type (1=Ethernet, 101=Raw IP)

**Returns:** `true` if export started successfully

```kotlin
fun stopPcapExport(): Map<String, Any>
```
Stops PCAP export and returns statistics.

**Returns:** Map containing `packetCount`, `totalBytes`, and `filepath`

```kotlin
fun isPcapExporting(): Boolean
```
Checks if PCAP export is currently active.

#### Statistics Access

```kotlin
fun getCurrentStats(): Map<String, Any>
```
Gets current traffic statistics including packet counts, bandwidth, and protocol distribution.

```kotlin
fun getProtocolDistribution(): Map<String, Long>
```
Gets protocol distribution by packet count.

```kotlin
fun getTopTalkers(limit: Int = 10): List<Map<String, Any>>
```
Gets top talkers by traffic volume.

### Companion Object Methods

```kotlin
fun setMethodChannel(channel: MethodChannel): Unit
```
Sets the Flutter MethodChannel for communication with the UI layer.

---

## PcapWriter

**Location**: `com.example.packet_analyzer.PcapWriter`

Handles exporting captured packets to Wireshark-compatible PCAP format.

### Public Methods

#### Core Export Functions

```kotlin
fun startCapture(outputPath: String, linktype: Int = 101): Boolean
```
Initializes PCAP file for writing.

**Parameters:**
- `outputPath`: Absolute path to output PCAP file
- `linktype`: Link layer type (1=Ethernet, 101=Raw IP)

```kotlin
fun writePacket(packetData: ByteArray, timestampMs: Long = System.currentTimeMillis()): Boolean
```
Writes a packet to the active PCAP file.

```kotlin
fun stopCapture(): Map<String, Any>
```
Stops writing and closes the PCAP file.

**Returns:** Map with `packetCount`, `totalBytes`, and `filepath`

#### Utility Methods

```kotlin
fun getStats(): Map<String, Any>
```
Gets current capture statistics.

```kotlin
fun isActive(): Boolean
```
Checks if currently writing to PCAP.

```kotlin
fun generateFilename(prefix: String = "andronet"): String
```
Generates a timestamped filename for PCAP export.

**Example:** `"andronet_20231201_143022.pcap"`

### Native Methods (JNI)

```kotlin
external fun nativeInit(filepath: String, linktype: Int = 101): Boolean
external fun nativeWritePacket(packetData: ByteArray, timestampMs: Long): Boolean
external fun nativeGetStats(): Map<String, Any>
external fun nativeClose(): Unit
```

---

## TrafficStatistics

**Location**: `com.example.packet_analyzer.TrafficStatistics`

Real-time traffic statistics tracker for dashboard visualization.

### Public Methods

#### Statistics Updates

```kotlin
fun updateStats(packetInfo: Map<String, Any>): Unit
```
Updates statistics with a new packet.

**Expected packetInfo keys:**
- `protocol`: Protocol name
- `appName`: Application name (optional)
- `size`: Packet size in bytes
- `sourceIp`: Source IP address
- `destinationIp`: Destination IP address
- `sourcePort`: Source port
- `destinationPort`: Destination port
- `direction`: "outgoing" or "incoming"

#### Data Retrieval

```kotlin
fun getStats(): Map<String, Any>
```
Gets comprehensive statistics including totals, rates, and distributions.

**Returns:** Map with keys like `totalPackets`, `totalBytes`, `protocols`, `topTalkers`, etc.

```kotlin
fun getProtocolDistribution(): Map<String, Long>
```
Gets protocol distribution by packet count.

```kotlin
fun getTopTalkers(limit: Int = 10): List<Map<String, Any>>
```
Gets top talkers by traffic volume.

```kotlin
fun getBandwidthHistory(): List<BandwidthSample>
```
Gets bandwidth samples for graphing.

```kotlin
fun getPacketRateHistory(): List<RateSample>
```
Gets packet rate samples for graphing.

#### Utility Methods

```kotlin
fun reset(): Unit
```
Resets all statistics counters.

```kotlin
fun getActiveConnections(): List<ConnectionInfo>
```
Gets list of currently active connections.

---

## AnomalyDetector

**Location**: `com.example.packet_analyzer.AnomalyDetector`

Real-time security anomaly detection system.

### Public Methods

#### Detection Management

```kotlin
fun addAnomalyListener(listener: (AnomalyInfo) -> Unit): Unit
```
Adds a listener for anomaly detection events.

```kotlin
fun removeAnomalyListener(listener: (AnomalyInfo) -> Unit): Unit
```
Removes an anomaly detection listener.

#### Manual Detection

```kotlin
fun checkPacketAnomaly(packetInfo: Map<String, Any>): AnomalyInfo?
```
Checks a packet for security anomalies.

```kotlin
fun checkConnectionAnomaly(connectionInfo: ConnectionInfo): AnomalyInfo?
```
Checks a connection for anomalies.

#### Statistics

```kotlin
fun getAnomalyStats(): Map<String, Any>
```
Gets anomaly detection statistics.

```kotlin
fun reset(): Unit
```
Resets anomaly counters.

### Built-in Detection Algorithms

1. **Port Scan Detection** - 20+ ports in 10 seconds
2. **SYN Flood Detection** - 100+ SYN packets/second
3. **Connection Flooding** - 50+ connections/second
4. **DNS Tunneling** - Excessive queries and long domain names
5. **ARP Spoofing** - IP-to-MAC mapping changes

---

## PacketDissector

**Location**: `com.example.packet_analyzer.PacketDissector`

Deep packet inspection for application-layer protocol analysis.

### Public Methods

#### Protocol Detection

```kotlin
fun detectProtocol(payload: ByteArray, port: Int, isOutgoing: Boolean): String
```
Detects application protocol from packet payload.

```kotlin
fun analyzeHttp(payload: ByteArray, isRequest: Boolean): Map<String, Any>?
```
Analyzes HTTP request/response.

```kotlin
fun analyzeDns(payload: ByteArray): Map<String, Any>?
```
Analyzes DNS query/response.

```kotlin
fun analyzeTls(payload: ByteArray): Map<String, Any>?
```
Analyzes TLS handshake.

#### Payload Analysis

```kotlin
fun extractPayload(rawPacket: ByteArray, packetInfo: Map<String, Any>): ByteArray?
```
Extracts payload from raw packet data.

```kotlin
fun getPayloadHexDump(payload: ByteArray, maxLength: Int = 256): String
```
Gets hex dump of payload for debugging.

### Supported Protocols

**HTTP/HTTPS:**
- Request methods (GET, POST, PUT, DELETE)
- URI/path extraction
- Headers (Host, User-Agent, Content-Type)
- TLS version and handshake detection

**DNS:**
- Query/Response type detection
- Domain name extraction
- Record types (A, AAAA, CNAME, MX, TXT)
- Response codes (NXDOMAIN, Server Failure)

**TLS/SSL:**
- Protocol versions (SSL 3.0, TLS 1.0-1.3)
- Handshake types (ClientHello, ServerHello, Certificate)
- Content types (Alert, Handshake, Application)

**DHCP:**
- Message types (Request/Reply)
- IP assignments (Client IP, Server IP, Gateway IP)
- Transaction IDs

---

## CompleteVpnService

**Location**: `com.example.packet_analyzer.CompleteVpnService`

Main VPN service with bidirectional packet flow and proper internet connectivity.

### Public Methods

#### VPN Lifecycle

```kotlin
fun startVpn(): Boolean
```
Starts the VPN service and establishes TUN interface.

```kotlin
fun stopVpn(): Unit
```
Stops the VPN service and cleans up resources.

#### Packet Processing

```kotlin
fun processOutgoingPacket(packet: ByteArray): ByteArray?
```
Processes outgoing packets before forwarding to internet.

```kotlin
fun processIncomingPacket(packet: ByteArray): ByteArray?
```
Processes incoming packets before writing to TUN interface.

#### Socket Management

```kotlin
fun createProtectedSocket(destination: InetAddress, port: Int): Socket?
```
Creates a socket protected from VPN routing loops.

```kotlin
fun getActiveConnections(): Map<String, ConnectionState>
```
Gets currently active TCP/UDP connections.

---

## PacketBuilder

**Location**: `com.example.packet_analyzer.PacketBuilder`

Utilities for building IP/TCP/UDP packets with proper checksums.

### Public Methods

#### Packet Construction

```kotlin
fun buildTcpPacket(
    sourceIP: String,
    destIP: String,
    sourcePort: Int,
    destPort: Int,
    sequenceNumber: Long,
    acknowledgmentNumber: Long,
    flags: Int,
    payload: ByteArray? = null
): ByteArray
```
Builds a complete TCP packet with proper checksums.

```kotlin
fun buildUdpPacket(
    sourceIP: String,
    destIP: String,
    sourcePort: Int,
    destPort: Int,
    payload: ByteArray? = null
): ByteArray
```
Builds a complete UDP packet with proper checksums.

#### Header Construction

```kotlin
fun buildIPv4Header(
    sourceIP: String,
    destIP: String,
    protocol: Byte,
    payloadLength: Int
): ByteArray
```
Builds IPv4 header with correct checksum.

```kotlin
fun buildTcpHeader(
    sourcePort: Int,
    destPort: Int,
    sequenceNumber: Long,
    acknowledgmentNumber: Long,
    flags: Int,
    windowSize: Int,
    payloadLength: Int
): ByteArray
```
Builds TCP header with proper checksum calculation.

#### Checksum Calculation

```kotlin
fun calculateTcpChecksum(
    sourceIP: String,
    destIP: String,
    tcpHeader: ByteArray,
    payload: ByteArray?
): Short
```
Calculates TCP checksum according to RFC 793.

```kotlin
fun calculateIpChecksum(header: ByteArray): Short
```
Calculates IPv4 header checksum.

---

## Usage Examples

### Basic Packet Capture with Analysis

```kotlin
// Initialize manager
val manager = PacketAnalysisManager(context)

// Start analysis
manager.startAnalysis()

// Process packets
packetStream.forEach { packetInfo ->
    manager.processPacket(packetInfo, rawPacketData)
}

// Stop analysis
manager.stopAnalysis()
```

### PCAP Export

```kotlin
// Start export
val filepath = "/sdcard/Download/AndroNet/capture.pcap"
if (PcapWriter.startCapture(filepath)) {
    // Export packets
    packets.forEach { packet ->
        PcapWriter.writePacket(packet.data, packet.timestamp)
    }

    // Stop export
    val stats = PcapWriter.stopCapture()
    println("Exported ${stats["packetCount"]} packets")
}
```

### Real-time Statistics

```kotlin
// Get current stats
val stats = TrafficStatistics.getStats()
println("Total packets: ${stats["totalPackets"]}")
println("Total bytes: ${stats["totalBytes"]}")

// Get protocol distribution
val protocols = TrafficStatistics.getProtocolDistribution()
protocols.forEach { (protocol, count) ->
    println("$protocol: $count packets")
}
```

### Anomaly Detection

```kotlin
// Add listener for anomalies
AnomalyDetector.addAnomalyListener { anomaly ->
    println("🚨 ${anomaly.type}: ${anomaly.description}")
    println("Severity: ${anomaly.severity}")
    println("Source: ${anomaly.sourceIp}:${anomaly.sourcePort}")
}
```

This API documentation provides comprehensive coverage of all public interfaces in the AndroNet Kotlin services. For implementation details, refer to the individual source files.
