# Changelog

All notable changes to **AndroNet** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [1.2.0] - 2026-05-21

### 🔧 Build & Install Fixes
- **C1** `build.gradle`: `ndk { abiFilters "arm64-v8a", "armeabi-v7a" }` — prevents `INSTALL_FAILED_NO_MATCHING_ABIS`
- **C2** `build.gradle`: `minSdkVersion 23`, `multiDexEnabled true`, `multidex:2.0.1` dependency
- **C3** `AndroidManifest.xml`: Switched to `MultiDexApplication`, removed conflicting `extractNativeLibs`, added `FOREGROUND_SERVICE_DATA_SYNC` + `POST_NOTIFICATIONS` permissions, added missing `CaptureService` declaration, fixed `NetHunterService` (`enabled=true`)
- **C4** `build.gradle` + `CMakeLists.txt`: `useLegacyPackaging=false`, `-Wl,-z,max-page-size=16384` for Android 15 16 KB page alignment

### 🐛 UI Crash Fixes (icon tap)
- **C5** `main.dart`: `FlutterError.onError` + `PlatformDispatcher.instance.onError` global handlers
- **C6** `main.dart`: Null guard + `try/catch` in `ListView.builder`, safe `_getThresholdStatus()`
- **C7** `main.dart`: Wrapped entire `_onMethodCall` body in `try/catch`
- **C8** `models.dart`: `PacketInfo.empty()`, safe casts throughout, `safeMap()` helper, fixed `AnomalyInfo.fromMap`

### 🐛 Start Capture Crash Fixes
- **C9** `MainActivity.kt`: JNI call guards, `onNativeLibraryError` / `onCaptureError` Flutter notifications
- **C10** `MainActivity.kt`: `pendingVpnAction` pattern + `onActivityResult` override — VPN permission flow now completes
- **C11** `NetHunterService.kt`: Root check before attempting libpcap
- **C12** `ZdtunVpnService.kt`: `createNotificationChannel()`, `buildNotification()`, `startForeground()` before any blocking work, `UnsatisfiedLinkError` catch notifying Flutter, `onRevoke()` cleanup
- **C13** `CaptureService.kt`: `onCreate()` for channel setup, `onRevoke()` added, `stopForeground()` before orphaned `stopSelf()` calls
- **C14** `PacketAnalysisManager.kt` + `AnomalyDetector.kt`: `AtomicInteger`/`AtomicLong` for shared counters, `ConcurrentHashMap` for all four tracker maps
- **C15** `main.dart`: `onVpnPermissionGranted` handler syncs `_isCapturing` + `_vpnPermissionGranted` to true; `onCaptureError` now also resets `_isCapturing`
- **C16** `main.dart`: `_isCaptureStarting` bool guards all entry/exit points, FAB shows spinner and disables during transition

### ⚡ Performance & Release Polish
- **C17** `build.gradle` + new `proguard-rules.pro`: `minifyEnabled true`, `shrinkResources true`, JNI keep rules, service keep rules
- **C18** `CMakeLists.txt`: Release optimization flags `CMAKE_C_FLAGS_RELEASE "-O2 -DNDEBUG"`
- **C19** `scripts/install-debug.ps1` + `scripts/get-crash-log.ps1`: Build+install helper and filtered crash log collector
- **C20** `README.md`: Comprehensive Troubleshooting section covering all three crash categories

### Build
- Flutter 3.44.0 stable
- AGP 8.7.3, Kotlin 2.1.0, Gradle 8.10.2
- NDK 28.2.13676358
- compileSdk/targetSdk 36
- 16KB page alignment for Android 15+ compatibility

## [2.0.0] - 2025-01-04

### 🚀 **Major Release: Enhanced DPI & ML-based Anomaly Detection**

#### ✨ **Deep Packet Inspection (DPI) Enhancements**
- **Expanded Protocol Support**: Added 5 new protocols (QUIC, SIP, RTP, SMB, NTP)
- **Advanced Parsing**: Enhanced HTTP/HTTPS, DNS, TLS/SSL, and DHCP analysis
- **Protocol Detection**: Now supports 9 application-layer protocols
- **Error Handling**: Improved parsing accuracy with robust error handling

#### 🤖 **Machine Learning-based Anomaly Detection**
- **Statistical Analysis**: Z-score based anomaly detection for packet sizes
- **Behavioral Learning**: IP activity pattern analysis and burst detection
- **Entropy Analysis**: Shannon entropy calculation for payload anomaly detection
- **Connection Patterns**: Timing and sequential pattern analysis
- **Adaptive Thresholds**: Self-learning detection parameters

#### 🔍 **Advanced Payload Analysis & File Carving**
- **File Type Detection**: 15+ file format signatures (JPEG, PDF, ZIP, executables)
- **Content Extraction**: HTTP downloads, email attachments, DNS tunneling data
- **Security Scanning**: Executable detection and suspicious pattern analysis
- **Multi-protocol Support**: SMTP, POP3, HTTP multipart, MIME attachments

#### 🛠️ **Technical Improvements**
- **Java 21 Compatibility**: Updated Android Gradle configuration
- **Performance Optimization**: Efficient algorithms for real-time analysis
- **Memory Management**: Improved cleanup and resource handling
- **Code Organization**: Better modular architecture

#### 📚 **Documentation**
- **Comprehensive Guides**: Updated implementation documentation
- **API Documentation**: Enhanced code comments and examples
- **Setup Instructions**: Improved development environment setup

### 🔧 **Infrastructure**
- **Development Branch**: Created `development` branch for active development
- **Git Workflow**: Established proper branching strategy
- **Build System**: Updated Gradle configuration for Java 17+

---

## [1.0.0] - 2024-12-01

### 🚀 **Initial Release**

#### ✨ **Core Features**
- **Dual-Mode Operation**: VPN mode (unrooted) and libpcap mode (rooted)
- **Real-time Packet Capture**: Zero packet loss with full internet connectivity
- **Protocol Detection**: 65+ application protocols
- **Deep Packet Inspection**: HTTP/HTTPS, DNS, TLS/SSL, DHCP analysis
- **Anomaly Detection**: 5 built-in security detection algorithms
- **Traffic Statistics**: Real-time bandwidth and packet rate monitoring
- **PCAP Export**: Wireshark-compatible packet capture files

#### 📱 **Platform Support**
- **Android Compatibility**: Works with Kali NetHunter
- **Flutter Framework**: Cross-platform UI with native performance
- **Native Integration**: Kotlin/Java for Android-specific features

#### 🔧 **Technical Architecture**
- **Modular Design**: Separated concerns with clear interfaces
- **Event-driven**: Flutter platform channels for real-time communication
- **Performance Optimized**: Efficient packet processing and memory usage
- **Error Resilient**: Comprehensive error handling and recovery

---

## Version History Format

### Release Types

- **Major (X.y.z)**: Breaking changes, new major features, significant API changes
- **Minor (x.Y.z)**: New features, enhancements, backward-compatible changes
- **Patch (x.y.Z)**: Bug fixes, security patches, minor improvements

### Changelog Sections

-  Features: New functionality added
-  Bug Fixes: Issues resolved
-  Documentation: Documentation updates
-  Maintenance: Technical improvements, refactoring, dependency updates
-  Security: Security-related changes

### Contributing to Changelog

When making changes:

1. **Add entries** to the `[Unreleased]` section during development
2. **Move entries** to appropriate version section before release
3. **Follow format**: `Component: Brief description`
4. **Include links** to related issues/PRs when relevant
5. **Use emojis** consistently for visual organization

---

## [Pre-1.0.0] - Development Phase

The project was in active development before the official 1.0.0 release. Early versions included:

- **Initial Architecture**: Basic Flutter app structure
- **VPN Integration**: zdtun library integration for packet capture
- **Basic UI**: Initial user interface design
- **Core Functionality**: Fundamental packet capture capabilities
- **Platform Setup**: Android and iOS platform configuration

---

<p align="center">
  <strong>For older changes, see the Git commit history</strong>
</p>

## 📝 **Updating the Changelog**

### For Contributors

1. **Add changes** to `[Unreleased]` section during development
2. **Use appropriate category** (🚀 Features, 🐛 Bug Fixes, etc.)
3. **Be specific** but concise in descriptions
4. **Reference issues/PRs** when applicable

### For Maintainers

1. **Create version section** before release: `## [X.Y.Z] - YYYY-MM-DD`
2. **Move entries** from `[Unreleased]` to version section
3. **Update links** and cross-references
4. **Verify format** and consistency

---

*This changelog follows the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format and adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).*
