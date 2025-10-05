# Architecture Decision Records (ADRs)

## Overview

This document captures the key architectural decisions made during the development of AndroNet, following the ADR format to document the context, decision, and consequences of significant architectural choices.

## Table of Contents

1. [ADR 001: Flutter + Kotlin Architecture](#adr-001)
2. [ADR 002: Dual-Mode Packet Capture](#adr-002)
3. [ADR 003: VPN Service with Socket Protection](#adr-003)
4. [ADR 004: Deep Packet Inspection Implementation](#adr-004)
5. [ADR 005: Real-time Anomaly Detection](#adr-005)
6. [ADR 006: PCAP Export with Native Code](#adr-006)
7. [ADR 007: Traffic Statistics Architecture](#adr-007)

---

## ADR 001: Flutter + Kotlin Architecture

**Date**: 2023-12-01

**Status**: Accepted

### Context

AndroNet needs to run on Android devices and integrate with both Flutter for UI and native Android services for packet capture. The application requires:
- Rich, responsive user interface
- Low-level network packet capture
- Real-time packet processing
- Integration with Android VPN API
- Compatibility with Kali NetHunter

### Decision

We chose a hybrid architecture with Flutter for the UI layer and Kotlin for the native Android services layer, communicating via MethodChannels and EventChannels.

**Flutter Layer (Dart)**:
- UI components and screens
- State management (Provider pattern)
- Business logic for UI interactions
- MethodChannel communication with native layer

**Kotlin Layer**:
- VPN service implementation (`CompleteVpnService`)
- Packet capture and processing
- Deep packet inspection
- Anomaly detection
- PCAP file export

### Consequences

**Positive**:
- Rich, cross-platform UI with Flutter's widget system
- Native performance for packet processing
- Access to Android VPN API and system services
- Better memory management for large packet buffers
- Integration with Android NDK for native libraries

**Negative**:
- Increased complexity in build configuration
- Need for JNI bridges for native code
- Potential communication overhead between layers
- Debugging across Dart/Kotlin boundary

**Mitigation**:
- Comprehensive error handling across boundaries
- Efficient serialization for MethodChannel communication
- Shared data models where possible

---

## ADR 002: Dual-Mode Packet Capture

**Date**: 2023-12-01

**Status**: Accepted

### Context

Android devices vary in capabilities:
- Most devices: No root access, limited to VPN API
- Kali NetHunter devices: Root access, can use libpcap
- Need consistent API for both modes

### Decision

Implement dual-mode packet capture:
1. **VPN Mode** (Unrooted): Uses Android VpnService + zdtun library
2. **Libpcap Mode** (Rooted): Uses native libpcap for Wireshark-like capture

Both modes present the same API to the Flutter layer but use different underlying implementations.

### Architecture

```
Flutter UI
    ↓ MethodChannel
MainActivity.kt (Mode Detection & Selection)
    ↓
┌─────────────────────────────────────┐
│           Service Selection         │
│  ┌──────────────┐ ┌──────────────┐  │
│  │ VPN Mode     │ │ Libpcap Mode │  │
│  │ (ZdtunVpn)   │ │ (NetHunter)  │  │
│  └──────────────┘ └──────────────┘  │
└─────────────────────────────────────┘
```

### Consequences

**Positive**:
- Works on all Android devices
- Optimal performance based on device capabilities
- Familiar libpcap API for penetration testers
- Seamless fallback from libpcap to VPN mode

**Negative**:
- Code duplication between two implementations
- Different debugging approaches for each mode
- Testing complexity across two code paths

**Mitigation**:
- Shared interfaces and data models
- Comprehensive integration tests
- Feature parity where possible

---

## ADR 003: VPN Service with Socket Protection

**Date**: 2023-12-01

**Status**: Accepted

### Context

VPN services create routing loops where packets meant for the internet get captured by the VPN and forwarded back to the TUN interface, creating infinite loops.

### Decision

Implement proper socket protection using Android's `VpnService.protect(socket)` method to exclude application sockets from VPN routing while maintaining packet capture for other traffic.

### Implementation

```kotlin
// Create protected socket for internet communication
val socket = DatagramSocket()
if (protect(socket)) {
    // Socket is protected from VPN routing
    socket.connect(destination, port)
    // Forward packets normally
} else {
    // Handle protection failure
}
```

### Consequences

**Positive**:
- Maintains internet connectivity during capture
- No packet loss or application breakage
- Proper bidirectional packet flow
- Compatible with all Android applications

**Negative**:
- Complex socket lifecycle management
- Potential for socket leaks if not properly closed
- Requires careful connection state tracking

**Mitigation**:
- Comprehensive connection cleanup in service destruction
- Socket pool management with timeouts
- Extensive logging for debugging

---

## ADR 004: Deep Packet Inspection Implementation

**Date**: 2023-12-15

**Status**: Accepted

### Context

Need to analyze application-layer protocols beyond basic packet headers for comprehensive network analysis. Requirements:
- HTTP/HTTPS request/response analysis
- DNS query/response parsing
- TLS handshake inspection
- DHCP analysis
- Performance impact must be minimal

### Decision

Implement a modular deep packet inspection (DPI) system with:
1. Protocol-specific analyzers
2. Payload extraction from raw packets
3. Pattern matching for protocol detection
4. Configurable inspection depth

### Architecture

```
PacketDissector.kt
    ↓
┌─────────────────────────────────────┐
│         Protocol Analyzers          │
├─────────────────────────────────────┤
│ HTTP │ DNS │ TLS │ DHCP │ ...       │
└─────────────────────────────────────┘
    ↓
Application Layer Information
```

### Implementation Strategy

- **Modular Design**: Each protocol has dedicated analyzer
- **Pattern Matching**: Efficient protocol detection
- **Error Handling**: Graceful degradation on malformed packets
- **Performance**: Lazy analysis, caching where possible

### Consequences

**Positive**:
- Detailed application-layer visibility
- Support for 65+ protocols
- Wireshark-like analysis capabilities
- Enhanced security anomaly detection

**Negative**:
- Increased processing overhead per packet
- Memory usage for payload storage
- Complexity in protocol detection accuracy

**Mitigation**:
- Configurable inspection levels
- Payload size limits
- Efficient byte operations
- Background processing for heavy analysis

---

## ADR 005: Real-time Anomaly Detection

**Date**: 2023-12-15

**Status**: Accepted

### Context

Need real-time security monitoring for:
- Port scanning detection
- SYN flood attacks
- Connection flooding
- DNS tunneling
- ARP spoofing

### Decision

Implement a multi-algorithm anomaly detection system with:
1. Real-time packet analysis
2. Configurable thresholds
3. Multiple detection algorithms
4. Event-driven notification system

### Detection Algorithms

1. **Port Scan Detection**: 20+ ports in 10 seconds
2. **SYN Flood Detection**: 100+ SYN packets/second
3. **Connection Flooding**: 50+ connections/second
4. **DNS Tunneling**: Long domain names + high query frequency
5. **ARP Spoofing**: IP-to-MAC mapping changes

### Architecture

```
AnomalyDetector.kt
    ↓
┌─────────────────────────────────────┐
│       Detection Algorithms          │
├─────────────────────────────────────┤
│ Port │ SYN │ Conn │ DNS │ ARP      │
│ Scan │ Flood│Flood │Tunnel│Spoof   │
└─────────────────────────────────────┘
    ↓
EventChannel → Flutter UI (Alerts)
```

### Consequences

**Positive**:
- Real-time threat detection
- Proactive security monitoring
- Integration with Flutter notification system
- Configurable sensitivity levels

**Negative**:
- False positive potential
- Performance overhead for tracking
- Storage requirements for detection state

**Mitigation**:
- Machine learning for threshold optimization
- User-configurable sensitivity
- Efficient state management
- Comprehensive logging for tuning

---

## ADR 006: PCAP Export with Native Code

**Date**: 2023-12-15

**Status**: Accepted

### Context

Need Wireshark-compatible packet export for forensic analysis. Requirements:
- Standard libpcap format
- Microsecond timestamp precision
- High-performance writing
- Cross-platform compatibility

### Decision

Implement native C code for PCAP writing with JNI bridge to Kotlin:
1. Native PCAP file format handling
2. Efficient binary writing
3. Proper timestamp handling
4. JNI interface for Kotlin integration

### Architecture

```
Flutter UI → MethodChannel → PcapWriter.kt → JNI → pcap_writer.c
                                                          ↓
                                                   PCAP File
```

### Implementation

- **Native Layer**: `android/app/src/main/jni/pcap_writer.c`
- **JNI Bridge**: `PcapWriter.kt`
- **Flutter Interface**: MethodChannel integration
- **File Format**: Standard libpcap with nanosecond timestamps

### Consequences

**Positive**:
- High-performance packet writing
- Wireshark/tshark compatibility
- Proper timestamp precision
- Minimal memory footprint

**Negative**:
- JNI complexity and potential crashes
- Native code debugging challenges
- Platform-specific build requirements

**Mitigation**:
- Comprehensive error handling in JNI layer
- Extensive testing of native code
- Proper memory management
- CMake build system for reliability

---

## ADR 007: Traffic Statistics Architecture

**Date**: 2023-12-15

**Status**: Accepted

### Context

Need real-time traffic analytics for dashboard visualization:
- Protocol distribution
- Bandwidth monitoring
- Top talkers identification
- Connection tracking
- Historical data for trends

### Decision

Implement a multi-layered statistics system:
1. **Real-time Collection**: Per-packet statistics updates
2. **Aggregation**: Rolling window calculations
3. **Storage**: Efficient data structures for queries
4. **Visualization**: Flutter charts integration

### Data Structures

```kotlin
// Protocol tracking
ConcurrentHashMap<String, Long> protocolCounts
ConcurrentHashMap<String, Long> protocolBytes

// IP tracking
ConcurrentHashMap<String, IpStats> ipTraffic

// Time series
CopyOnWriteArrayList<BandwidthSample> bandwidthSamples
CopyOnWriteArrayList<RateSample> packetRateHistory
```

### Architecture

```
TrafficStatistics.kt
    ↓ Updates
Packet Processing → Statistics Collection → Aggregation → Flutter UI
```

### Consequences

**Positive**:
- Real-time dashboard updates
- Efficient data structures for performance
- Historical trend analysis
- Multiple visualization options

**Negative**:
- Memory usage for historical data
- CPU overhead for real-time calculations
- Synchronization complexity

**Mitigation**:
- Configurable retention periods
- Efficient data structures (CopyOnWriteArrayList)
- Background processing for heavy calculations
- Memory-aware cleanup policies

---

## Summary

These ADRs document the key architectural decisions that shaped AndroNet's design. They provide context for future development decisions and help maintain consistency across the codebase.

**Key Principles**:
- Hybrid Flutter + Kotlin architecture for optimal UX and performance
- Dual-mode operation for maximum device compatibility
- Real-time analysis with efficient resource usage
- Wireshark-like capabilities in a mobile form factor
- Production-ready error handling and logging
