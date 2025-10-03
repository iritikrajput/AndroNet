# Dual-Mode Packet Capture Implementation

## Overview

AndroNet now supports **two capture modes** to provide optimal packet analysis based on device capabilities:

### 1. **VPN Mode** (Unrooted Devices)
- Uses Android VPN API + zdtun library
- No root access required
- Internet connectivity maintained through proper packet forwarding
- Suitable for regular Android devices

### 2. **Libpcap Mode** (Rooted Devices - Kali NetHunter)
- Uses native libpcap library for deep packet inspection
- Requires root access
- Wireshark-like capabilities with full packet details
- Captures all network interfaces
- Suitable for Kali NetHunter and rooted security devices

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Flutter UI Layer                         │
│                   (lib/main.dart)                            │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ├─ EventChannel: "packet_stream"
                     ├─ MethodChannel: "packet_analyzer"
                     │
┌────────────────────┴────────────────────────────────────────┐
│                  MainActivity.kt                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  Root Detection: checkRootAccess()                   │   │
│  │  Mode Selection Logic                                │   │
│  └──────────────┬────────────────────┬──────────────────┘   │
└─────────────────┼────────────────────┼──────────────────────┘
                  │                    │
      ┌───────────┴────────┐  ┌────────┴───────────┐
      │                    │  │                     │
┌─────▼──────────────┐ ┌───▼──────────────────┐
│ ZdtunVpnService.kt │ │ NetHunterService.kt   │
│  (VPN Mode)        │ │ (Libpcap Mode)        │
└─────┬──────────────┘ └───┬──────────────────┘
      │                    │
┌─────▼──────────────┐ ┌───▼──────────────────┐
│  zdtun_vpn.c       │ │ libpcap_capture.c     │
│  (Native JNI)      │ │ (Native JNI)          │
└─────┬──────────────┘ └───┬──────────────────┘
      │                    │
┌─────▼──────────────┐ ┌───▼──────────────────┐
│  zdtun library     │ │ libpcap library       │
│  (Packet forward)  │ │ (Raw capture)         │
└─────┬──────────────┘ └───┬──────────────────┘
      │                    │
┌─────▼────────────────────▼──────────────────┐
│         TUN / Network Interfaces            │
│     (wlan0, rmnet0, eth0, any, etc.)        │
└─────────────────────────────────────────────┘
```

---

## Implementation Details

### Created Files

#### 1. **Native Layer (C/JNI)**

**android/app/src/main/jni/libpcap_capture.c** (400+ lines)
- Native libpcap packet capture implementation
- Full packet parsing (Ethernet, IP, TCP, UDP, ICMP)
- Protocol detection (65+ protocols)
- Payload extraction (hex format)
- Thread-safe JNI callbacks
- Network interface enumeration

Key Functions:
```c
JNIEXPORT jboolean JNICALL
Java_com_example_packet_1analyzer_LibpcapBridge_nativeInit(
    JNIEnv *env, jobject thiz, jobject service_obj, jstring interface_name
);

void packet_handler(
    u_char *user_data,
    const struct pcap_pkthdr *pkthdr,
    const u_char *packet
);
```

#### 2. **Kotlin JNI Bridge**

**android/app/src/main/kotlin/com/example/packet_analyzer/LibpcapBridge.kt**
```kotlin
object LibpcapBridge {
    external fun nativeInit(serviceObj: Any, interfaceName: String): Boolean
    external fun nativeStartCapture(): Boolean
    external fun nativeStopCapture()
    external fun nativeCleanup()
    external fun nativeGetInterfaces(): Array<String>?
}
```

#### 3. **NetHunter Service (Rooted Mode)**

**android/app/src/main/kotlin/com/example/packet_analyzer/NetHunterService.kt** (200+ lines)
- Foreground service for libpcap capture
- Packet stream management
- Network interface selection
- Thread-safe packet forwarding to Flutter

Callbacks from native code:
```kotlin
fun onPacketCaptured(packetInfo: Map<String, Any>) // Called per packet
fun onStatusUpdate(status: String)                 // Status notifications
```

#### 4. **Build Configuration**

**android/app/CMakeLists.txt**
```cmake
# VPN mode library
add_library(zdtun_vpn SHARED ${ZDTUN_SOURCES} ${JNI_SOURCES})
target_link_libraries(zdtun_vpn log)

# Libpcap mode library
add_library(pcap_capture SHARED ${LIBPCAP_JNI_SOURCES})
target_link_libraries(pcap_capture pcap log)
```

---

## MainActivity Integration

The MainActivity now handles both modes:

```kotlin
when (call.method) {
    "checkRootAccess" -> {
        result.success(checkRootAccess())
    }

    "startVpn" -> {
        // VPN mode for unrooted devices
        val intent = Intent(this, ZdtunVpnService::class.java)
        startService(intent)
    }

    "startLibpcapCapture" -> {
        if (checkRootAccess()) {
            // Libpcap mode for rooted devices
            val intent = Intent(this, NetHunterService::class.java)
            intent.action = "START_CAPTURE"
            startService(intent)
        } else {
            result.error("ROOT_REQUIRED", "Root access required", null)
        }
    }
}
```

**Packet Stream** (shared by both modes):
```kotlin
val packetEventChannel = EventChannel(flutterEngine.dartExecutor.binaryMessenger, "packet_stream")
packetEventChannel.setStreamHandler(object : EventChannel.StreamHandler {
    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        events?.let {
            ZdtunVpnService.setPacketSink(it)      // VPN mode
            NetHunterService.setPacketSink(it)     // Libpcap mode
        }
    }
})
```

---

## Packet Format

Both modes produce the same packet format for Flutter:

```kotlin
Map<String, Any> {
    "sourceIp" -> "192.168.1.100",
    "destinationIp" -> "142.250.185.46",
    "sourcePort" -> 54321,
    "destinationPort" -> 443,
    "protocol" -> "TCP",
    "appName" -> "HTTPS",
    "size" -> 1420,
    "timestamp" -> 1704067200000,
    "flags" -> "ACK PSH",
    "payload" -> "170301...",  // Hex format
    "captureMode" -> "libpcap" | "vpn",
    "direction" -> "outgoing" | "incoming" | "both"
}
```

---

## Mode Selection Logic

### Root Detection
```kotlin
private fun checkRootAccess(): Boolean {
    return try {
        val process = Runtime.getRuntime().exec("su -c 'id'")
        process.waitFor() == 0
    } catch (e: Exception) {
        false
    }
}
```

### Flutter Usage
```dart
// Check if device is rooted
final bool isRooted = await platform.invokeMethod('checkRootAccess');

if (isRooted) {
    // Use libpcap mode - Wireshark-like capture
    await platform.invokeMethod('startLibpcapCapture');
} else {
    // Use VPN mode - works on unrooted devices
    await platform.invokeMethod('prepareVpn');
    await platform.invokeMethod('startVpn');
}
```

---

## Libpcap Capabilities (Rooted Mode)

### Features
✅ **Full packet capture** - Raw packet data from network interface
✅ **All layers** - Ethernet, IP, TCP, UDP, ICMP headers
✅ **Payload extraction** - First 128 bytes in hex format
✅ **TCP flags** - SYN, ACK, FIN, RST, PSH, URG
✅ **Protocol detection** - 65+ application protocols
✅ **Interface selection** - wlan0, rmnet0, eth0, any
✅ **Zero packet loss** - Native performance
✅ **Thread-safe** - Proper JNI threading

### Supported Protocols
- HTTP, HTTPS, HTTP/3 (QUIC)
- DNS, DNS-over-TLS, mDNS
- SSH, Telnet, FTP
- SMTP, IMAP, POP3 (+ TLS variants)
- MySQL, PostgreSQL, Redis, MongoDB, MSSQL
- RDP, VNC
- DHCP, NTP, SNMP
- IPSec, SIP
- IRC, BitTorrent
- And 40+ more...

### Packet Details
```
Source IP: 192.168.1.100:54321
Dest IP:   142.250.185.46:443
Protocol:  TCP
App:       HTTPS
Flags:     SYN ACK PSH
Size:      1420 bytes
Payload:   1703010005f701000... (hex)
Mode:      libpcap
```

---

## Comparison: VPN vs Libpcap

| Feature | VPN Mode (Unrooted) | Libpcap Mode (Rooted) |
|---------|--------------------|-----------------------|
| Root Required | ❌ No | ✅ Yes |
| Internet Works | ✅ Yes (zdtun forwarding) | ⚠️ Depends on configuration |
| Packet Detail | Good (IP/TCP/UDP headers) | Excellent (Full packet + payload) |
| Performance | High | Very High (native) |
| Capture Scope | App traffic through VPN | All network interfaces |
| Use Case | Daily use, regular apps | Penetration testing, analysis |
| Overhead | Low | Minimal |
| Permissions | VPN permission only | Root + CAP_NET_RAW |

---

## Building the App

### Prerequisites
1. Android NDK installed
2. CMake 3.10+
3. For rooted mode: libpcap library (usually pre-installed on Kali NetHunter)

### Build Steps
```bash
cd andronet
flutter clean
flutter pub get
flutter build apk
```

The build system will compile both libraries:
- `libzdtun_vpn.so` - VPN mode
- `libpcap_capture.so` - Libpcap mode

---

## Testing

### On Unrooted Device
```bash
flutter run
# App automatically uses VPN mode
# Internet should work normally
# Packets captured through TUN interface
```

### On Kali NetHunter (Rooted)
```bash
# Ensure libpcap is installed
su -c "which tcpdump"  # Should show /system/bin/tcpdump or similar

flutter run
# App detects root and enables libpcap mode
# Full Wireshark-like packet capture available
```

### Verify Mode
Check logs:
```bash
adb logcat | grep -E "(ZdtunVpn|NetHunter|Libpcap)"
```

Expected output for libpcap mode:
```
I/NetHunterService: 🚀 NetHunter Service created (Libpcap mode)
I/NetHunterService: 🔍 Starting native libpcap capture on: wlan0
I/LibpcapCapture: Libpcap initialized successfully on wlan0
I/NetHunterService: ✅ Libpcap capture started successfully
```

---

## Troubleshooting

### Libpcap Mode Issues

**❌ Failed to initialize libpcap**
- Check root access: `su -c 'id'`
- Verify libpcap: `su -c 'which tcpdump'`
- Check SELinux: `getenforce` (should be Permissive on NetHunter)

**❌ No packets captured**
- Verify interface name: `su -c 'ifconfig'` or `ip link`
- Try "any" interface: captures from all interfaces
- Check permissions: `su -c 'ls -l /dev/net/tun'`

**❌ Library not found**
- Ensure libpcap is installed: `su -c 'find /system -name "*pcap*"'`
- On NetHunter, install: `apt install libpcap-dev`

### VPN Mode Issues
Refer to main README.md troubleshooting section

---

## Security Considerations

### VPN Mode
- Requires only VPN permission
- Sandboxed execution
- Safe for daily use

### Libpcap Mode
- Requires full root access
- Can capture sensitive data
- **Use only on authorized networks**
- **For security testing/research only**
- Ensure compliance with local laws

---

## Future Enhancements

- [ ] PCAP file export (Wireshark-compatible)
- [ ] Real-time filtering (BPF filters)
- [ ] SSL/TLS decryption (with root CA)
- [ ] Custom protocol dissectors
- [ ] Packet injection capabilities
- [ ] Advanced statistics and graphs
- [ ] Network mapping and topology
- [ ] Automatic mode switching based on root detection

---

## License

This dual-mode implementation follows the same license as the main project.

### Third-Party Libraries
- **zdtun**: GPL-3.0 (VPN mode)
- **libpcap**: BSD License (Libpcap mode)

---

## Credits

- **PCAPdroid** - Inspiration for zdtun integration
- **Wireshark** - Protocol detection reference
- **libpcap** - Packet capture library
- **Kali NetHunter** - Target platform for rooted mode

---

## Summary

AndroNet now provides the best of both worlds:

1. **Accessibility** - Works on any Android device via VPN mode
2. **Power** - Full Wireshark-like analysis on rooted devices
3. **Flexibility** - Automatic mode detection and selection
4. **Performance** - Native C implementation for both modes
5. **Compatibility** - Shared packet format across modes

This makes AndroNet suitable for:
- Regular users (unrooted devices)
- Security researchers (Kali NetHunter)
- Network administrators
- Penetration testers
- Educational purposes
