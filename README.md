# AndroNet - Mobile Network Packet Analyzer for Kali NetHunter

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Android-green.svg" alt="Platform">
  <img src="https://img.shields.io/badge/Kali_NetHunter-Compatible-red.svg" alt="NetHunter">
  <img src="https://img.shields.io/badge/Language-Dart%2FKotlin%2FC-blue.svg" alt="Language">
  <img src="https://img.shields.io/badge/Framework-Flutter-02569B.svg" alt="Framework">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
</p>

<p align="center">
  <strong>A professional-grade mobile network security analysis platform for penetration testers, network administrators, and cybersecurity professionals</strong>
</p>
<p align="center">
 <div id="team-container">
  <pre align="center">
    Team CipherSec
    Members: Ritik, Syed Misbah Uddin, Kamal Akhter, Swastik
  </pre>
</div>

</p>

---

##  Problem Statement

This application addresses the need for a **Wireshark-like packet analysis tool** that runs natively on Android devices, specifically designed to integrate with **Kali NetHunter**. It enables real-time network monitoring, deep packet inspection (DPI), and anomaly detection while running efficiently on mobile hardware.

### Target Users
-  Penetration Testers using Kali NetHunter
-  Network Administrators monitoring mobile networks
-  Cybersecurity Researchers conducting traffic analysis
-  Students learning network security concepts
-  Security Operations Teams performing incident response

### Key Challenges Solved

- **Packet Capture on Mobile** – Full packet capture without breaking internet connectivity  
- **Deep Packet Inspection** – Application-layer protocol analysis (HTTP, DNS, TLS, etc.)  
- **Dual-Mode Operation** – Works on both rooted (libpcap) and unrooted (VPN) devices  
- **Real-Time Analysis** – Live traffic statistics and anomaly detection  
- **Forensic Compatibility** – PCAP file export for Wireshark analysis  

---

##  Features

###  **Complete Network Visibility**
- **Dual-Mode Packet Capture**:
  - **VPN Mode** (Unrooted devices): Zero-setup packet capture using Android VPN API + zdtun library
  - **Libpcap Mode** (Kali NetHunter): Native libpcap integration for Wireshark-like deep inspection
- **Bidirectional Traffic**: Monitors both outgoing and incoming packets
- **Zero Packet Loss**: Maintains full internet connectivity (0% packet drop)
- **All Protocols**: TCP, UDP, ICMP, ARP, and more

###  **Deep Packet Inspection (DPI)**
Advanced payload analysis for application-layer protocols:

**HTTP/HTTPS Analysis**
- Request methods (GET, POST, PUT, DELETE, etc.)
- URI/path extraction
- Response status codes (200, 404, 500, etc.)
- Headers (Host, User-Agent, Cookie, Content-Type)
- TLS version and handshake detection

**DNS Analysis**
- Query/Response type detection
- Domain name extraction
- Record types (A, AAAA, CNAME, MX, TXT, PTR, SRV)
- Response codes (NXDOMAIN, Server Failure, etc.)
- Transaction ID tracking

**TLS/SSL Inspection**
- Protocol versions (TLS 1.0-1.3, SSL 3.0)
- Handshake types (ClientHello, ServerHello, Certificate)
- Content types (Alert, Handshake, Application)

**DHCP Analysis**
- Message types (Request/Reply)
- IP assignments (Client IP, Server IP, Gateway IP)
- Transaction IDs

###  **Security Anomaly Detection**
Real-time threat detection with 5 built-in algorithms:

1. **Port Scan Detection** - Threshold: 20+ ports in 10 seconds (Severity: HIGH)
2. **SYN Flood Detection** - Threshold: 100+ SYN packets/second (Severity: CRITICAL)
3. **Connection Flooding** - Threshold: 50+ connections/second (Severity: HIGH)
4. **DNS Tunneling** - Detects excessive queries and long domain names (Severity: MEDIUM)
5. **ARP Spoofing** - Monitors IP-to-MAC mapping changes (Severity: CRITICAL)
- Real-time SnackBar alerts in the Flutter UI showing severity, type, source IP, and description

###  **Traffic Statistics & Analytics**
- Real-time metrics (packets/sec, bytes/sec, connections)
- Protocol distribution charts
- Top talkers by traffic volume
- Bandwidth graphs (60-second rolling window)
- Active connection monitoring

###  **PCAP File Export**
- Wireshark-compatible standard libpcap format
- Microsecond timestamp precision
- Files saved to `/sdcard/Download/AndroNet/`
- Compatible with Wireshark, tcpdump, tshark

###  **Intelligent Protocol Detection**
Recognizes **65+ application protocols** including HTTPS, DNS, SSH, FTP, SMTP, MySQL, PostgreSQL, MongoDB, Redis, SIP, RDP, VNC, and many more.


###  **Advanced UI Features**

**Protocol Filtering**
- **16 Predefined Filters**: ALL, HTTP, HTTPS, DNS, TCP, UDP, TLS, QUIC, ICMP, DHCP, ARP, SSH, FTP, SMTP, POP3, IMAP
- **Color-Coded Chips**: Each protocol has a unique color for easy identification
- **Packet Counts**: Real-time counts displayed for each filter (e.g., "HTTP (25)")
- **Smart Display**: Filters show/hide based on captured traffic
- **Dual Matching**: Filters work on both transport (TCP/UDP) and application (HTTP/HTTPS) layers

**Visual Protocol Identification**
- HTTP/HTTPS → Blue | DNS → Purple | TCP → Green | UDP → Orange
- ICMP → Red | TLS/SSL → Indigo | QUIC → Teal | DHCP → Pink | ARP → Brown

**Real-Time DPI Display**
- Enriched packet information with application-layer details
- HTTP URLs, methods, and status codes visible in logs
- DNS queries and responses tracked
- TLS server names (SNI) extracted
- DHCP message types identified
---

##  System Architecture

```
                                        ┌─────────────────────────────────────────────────────────────────────┐
                                        │                         Flutter UI Layer                            │
                                        │  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐     │
                                        │  │ Packet List  │  │  Statistics  │  │  Anomaly Alerts        │     │
                                        │  │  Display     │  │  Dashboard   │  │  Notifications         │     │
                                        │  └──────────────┘  └──────────────┘  └────────────────────────┘     │
                                        └────────────────────────────┬────────────────────────────────────────┘
                                                                     │ EventChannel / MethodChannel
                                                                     ▼
                                        ┌─────────────────────────────────────────────────────────────────────┐
                                        │                      MainActivity.kt                                │
                                        │    • Root detection & mode selection                                │
                                        │    • Method handlers (startVpn, startLibpcap, exportPcap)           │
                                        │    • EventChannel setup for packet streaming                        │
                                        └─────────────────────────────────┬───────────────────────────────────┘
                                                                          │                  
                                                            ┌─────────────▼────────────┐  
                                                            │                          │ 
                                                ┌───────────▼────────────┐ ┌───────────▼──────────────┐
                                                │  ZdtunVpnService.kt    │ │  NetHunterService.kt     │
                                                │  (VPN Mode)            │ │  (Libpcap Mode)          │
                                                │                        │ │                          │
                                                │  • TUN interface mgmt  │ │  • Libpcap integration   │
                                                │  • Packet parsing      │ │  • Raw packet capture    │
                                                │  • Protocol detection  │ │  • All interfaces        │
                                                │  • 65+ app protocols   │ │  • Wireshark-like        │
                                                └─────┬──────────────────┘ └──────────┬───────────────┘
                                                      │                               │
                                                      ▼                               ▼
                                                ┌─────────────────────────────────────────────────────────┐
                                                │         PacketAnalysisManager.kt (Orchestrator)         │
                                                │    • Coordinates all Phase 2 features                   │
                                                │    • Lifecycle management                               │
                                                │    • Periodic stats updates                             │
                                                └───┬────────────┬─────────────┬──────────┬───────────────┘
                                                    │            │             │          │
                                                ┌───▼──┐    ┌────▼────┐  ┌─────▼────┐ ┌───▼───────┐
                                                │ DPI  │    │ Anomaly │  │ Traffic  │ │   PCAP    │
                                                │      │    │ Detector│  │  Stats   │ │  Writer   │
                                                └───┬──┘    └────┬────┘  └─────┬────┘ └──┬────────┘
                                                    │            │             │          │
                                                    ▼            ▼             ▼          ▼
                                                ┌─────────────────────────────────────────────────────────┐
                                                │              Native Layer (C/JNI)                       │
                                                │  ┌────────────────┐  ┌────────────────┐  ┌──────────┐   │
                                                │  │ zdtun_vpn.c    │  │ libpcap_       │  │ pcap_    │   │
                                                │  │ (VPN Bridge)   │  │ capture.c      │  │ writer.c │   │
                                                │  └────┬───────────┘  └────┬───────────┘  └──────────┘   │
                                                └───────┼──────────────────┼──────────────────────────────┘
                                                        │                  │
                                                   ┌────▼─────┐     ┌──────▼───────┐
                                                   │  zdtun   │     │   libpcap    │
                                                   │ library  │     │   library    │
                                                   └────┬─────┘     └──────┬───────┘
                                                        │                  │
                                                        ▼                  ▼
                                                ┌──────────────────────────────────────┐
                                                │  TUN / Network Interfaces            │
                                                │  (wlan0, rmnet0, eth0, etc.)         │
                                                └──────────────┬───────────────────────┘
                                                               │
                                                               ▼
                                                         ┌─────────────┐
                                                         │  Internet   │
                                                         └─────────────┘
```

---

##  Getting Started

### Build Requirements

| Component | Version |
|-----------|---------|
| Flutter | 3.44.0 stable |
| Dart SDK | 3.8.1+ |
| AGP (Android Gradle Plugin) | 8.7.3 |
| Gradle Wrapper | 8.10.2 |
| Kotlin | 2.1.0 |
| NDK | 28.2.13433566 |
| compileSdk / targetSdk | 36 |
| minSdk | 24 (Android 7.0) |

> **16KB page alignment**: Android 15+ (API 35+) devices with 16KB memory pages require native libraries to be compiled with `-Wl,-z,max-page-size=16384` and packaged with `useLegacyPackaging = false`. This build already includes both flags for all `.so` targets (`zdtun_vpn`, `pcap_writer`, `pcap_capture`).

### Prerequisites
- Flutter SDK 3.44.0+
- Android Studio with NDK 28.2.13433566
- CMake 3.22.1+
- Kali NetHunter (optional, for libpcap mode)

### Installation

```bash
# Clone repository
git clone https://github.com/iritikrajput/AndroNet.git
cd AndroNet

# Initialize zdtun submodule
git submodule update --init --recursive

# Install dependencies
flutter pub get

# Build APK
flutter build apk --debug

# Install on device
flutter install
```

---

##  Usage

### VPN Mode (Unrooted)
1. Launch app → Grant VPN permission
2. Tap "Start Capture"
3. Internet works normally while capturing

### Libpcap Mode (Kali NetHunter)
1. App detects root access automatically
2. Select network interface
3. Tap "Start Capture" for full Wireshark-like mode

### Exporting PCAP
1. Tap "Export PCAP" during capture
2. Files saved to `/sdcard/Download/AndroNet/`
3. Open in Wireshark for analysis

---

##  Performance

| Metric | VPN Mode | Libpcap Mode |
|--------|----------|--------------|
| Packet Rate | 500-800 pps | 1000+ pps |
| CPU Usage | 10-15% | 8-12% |
| RAM Usage | 60-80MB | 50-70MB |
| Packet Loss | 0% | 0% |

---

##  Technical Stack

- **UI**: Flutter 3.32.8, Dart 3.8.1
- **Service**: Kotlin 1.8, Coroutines
- **Native**: C (JNI), CMake 3.22.1
- **VPN Engine**: zdtun library
- **Capture**: libpcap (Kali NetHunter)

---

##  Troubleshooting

**VPN mode not working**
- Check VPN permission granted
- Restart app
- Check logs: `adb logcat | grep ZdtunVpn`

**Libpcap mode issues**
- Install libpcap: `su -c "apt install libpcap-dev"`
- Verify root: `su -c 'id'`
- Rebuild app

---

##  Acknowledgments

- **PCAPdroid** - Inspiration for zdtun integration
- **zdtun** - Packet tunneling library by @emanuele-f
- **libpcap** - Packet capture standard
- **Wireshark** - Protocols reference
- **Kali NetHunter** - Target platform

---

## 📄 License

MIT License - see LICENSE file

---

<p align="center">
  <strong>Made By Team CipherSec for the Cyber Security Community</strong>
</p>
