# Changelog

All notable changes to **AndroNet** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

---

## [1.3.0] - 2026-08-06

A full pass across the codebase: dead code removal, real bug fixes, dependency/toolchain
modernization, security hardening, hot-path performance work, and new features. Verified with
`flutter analyze` (0 issues), `flutter test` (25/25), `./gradlew :app:testDebugUnitTest` (106/106),
and live on-device testing (VPN capture, IPv6, per-app attribution, dark mode).

### ✨ Added
- **Per-app traffic attribution** — resolves the installed app owning each TCP/UDP flow via
  `ConnectivityManager.getConnectionOwnerUid` and shows it on every packet card. Something desktop
  Wireshark has no equivalent of, since it doesn't run on the device whose traffic it inspects.
- **Dark mode** — system/light/dark, persisted across launches (Settings → Theme).
- **IPv6 support in VPN-mode capture** — `ZdtunVpnService` previously returned `null` for any
  non-IPv4 packet, so IPv6 traffic was tunneled correctly but completely invisible to DPI, anomaly
  detection, and PCAP logging. Now fully parsed (address, ports, TCP flags) and analyzed.
  Confirmed live: IPv6 link-local multicast traffic now shows up correctly formatted
  (`fe80::...` zero-compressed notation) in the packet stream.
- **Malformed-TCP-packet detection** — flags illegal flag combinations (SYN+FIN, SYN+RST), a
  known firewall/IDS evasion and stack-fingerprinting technique. Fills in the one `AnomalyType`
  that previously existed in the model but was never actually produced.
- **DNS-over-HTTPS (DoH) detection** — TLS connections whose SNI matches a known public DoH
  resolver are now labeled `DoH` instead of generic `HTTPS`, surfacing a common technique for
  bypassing on-path DNS monitoring.
- **Change PIN/Password/Pattern** and **configurable auto-lock duration** (1/5/15/30/60 min),
  both previously backed by working service methods with no UI path to reach them.
- `.github/dependabot.yml` (pub, gradle, github-actions) and a CodeQL workflow for the
  Kotlin/Java surface.

### 🐛 Fixed
- **TCP flags were never populated on the VPN-mode (unrooted, default) capture path at all** —
  `ZdtunVpnService.parseIpv4Packet`/`parseIpv6Packet` never extracted them, meaning SYN-flood and
  connection-flood detection silently never fired for anyone using the app's zero-setup default
  mode, despite being fully implemented and README-advertised as working. Only rooted
  libpcap-mode users ever got real detection for these two. Now extracted on both paths.
- **PCAP annotated-packet timestamps were corrupted** — `PcapWriter.nativeWriteAnnotatedPacket`
  treated a millisecond value from Kotlin as if it were already nanoseconds with no conversion, so
  every anomaly-flagged packet (exactly the ones an analyst cares about) got written with a
  timestamp near the 1970 epoch. Fixed to mirror the working `nativeWritePacket` path.
- **A live, UI-reachable capture path silently dropped all packets** — "Enhanced" mode
  (`CaptureService`) never wrote packets back to the TUN device, blackholing the device's internet
  connection whenever selected, and never ran DPI/anomaly detection/PCAP logging at all. Retired;
  enhanced mode now shares the same proven `ZdtunVpnService` pipeline as VPN mode.
- **`test/widget_test.dart` was broken** — asserted stale UI text and pumped the app without its
  required `Provider` ancestor, so `flutter test` (and CI's Kotlin/Dart test steps) had been
  failing on every push/PR since at least May 2026. CI is green again; PR checks now fail on
  `flutter analyze` warnings, not just hard errors, so this can't silently regress.
- `PcapWriter.nativeWriteAnnotatedPacket`'s JNI signature mismatch (`Boolean` in Kotlin vs `void`
  in C) — the returned success/failure value was previously meaningless.
- PCAP file-count rotation (`max_files`) was a no-op that only logged; old rotated captures now
  actually get pruned.
- `PacketInfo.fromMap`'s numeric field parsing threw (rather than falling back) for non-null,
  non-numeric values (e.g. a stringified port) because `as num?` throws instead of returning null
  for a type mismatch — caught by a new unit test, fixed with a proper safe-coercion helper.
- `RuleEngine`'s DNS-tunneling rule's `DomainMatches` condition was defined and used by the
  default rule set but never handled by the evaluator, silently always `false` — caught by a new
  Kotlin unit test, fixed.
- Root detection was implemented three different, inconsistent ways across the codebase (including
  a fragile unquoted `su -c 'id'` shell string); consolidated into one `RootChecker`.
- Settings dialog: "Auto-scroll" no longer closes the whole dialog on every toggle; "Anomaly
  notifications" and "Max packets limit" are now real, working, persisted-for-the-session controls
  instead of a hardcoded switch and a display-only label.

### 🔒 Security
- **Release APKs are now properly signed** instead of using the public Android debug key —
  `android/key.properties` (gitignored) drives local/CI signing with a documented GitHub Actions
  secrets flow (`KEYSTORE_BASE64`, `KEYSTORE_PASSWORD`, `KEY_ALIAS`, `KEY_PASSWORD`); `release.yml`
  now cryptographically verifies the built APK's signing certificate before publishing.
- **PIN/password/pattern hashing switched from unsalted SHA-256 to salted PBKDF2-HMAC-SHA256**
  (120,000 iterations) — the old scheme meant all 10,000 possible 4-digit PIN hashes could be
  precomputed in microseconds, notable given the app explicitly targets rooted devices. Existing
  installs upgrade transparently on next successful login, no forced re-setup.
- `generateTestAnomaly` (injects a fake anomaly into the live detection stream) is now compiled
  out of release builds instead of always being a reachable MethodChannel endpoint.
- Removed sensitive per-packet debug logging (source/dest IPs, domains, full packet maps) that ran
  unconditionally on every packet, including in release builds, on a tool whose entire purpose is
  capturing potentially sensitive traffic metadata.

### ⚡ Performance
- `RuleEngine`'s per-rule packet history used `ArrayList.removeAt(0)` for eviction — an O(n) shift
  on every packet, across up to 10 rules simultaneously, once the 1000-entry cap filled. Switched
  to `ArrayDeque` for O(1) eviction.
- `SignatureDatabase` (18 signatures) and `RuleEngine` (10 rules) each independently re-decoded the
  same packet payload bytes to a string per check — now decoded once per packet and shared.
  `PayloadAnalyzer`'s file-carving/keyword scans are now skipped entirely for known-encrypted
  traffic (TLS/QUIC/HTTPS), where they could only ever produce noise, not signal.
- Packet hex-dump formatting used to format the *entire* payload (up to tens of KB) before
  truncating the display string — now sliced to the display bound first.
- `AnomalyDetector`'s entropy-consecutive-hit counters (`highEntropyPacketCount`,
  `dnsHighEntropyCount`) were the only trackers never included in the periodic cleanup sweep,
  growing by one entry per unique source IP for the life of a capture session — now bounded.

### 🧹 Removed
- ~5,700 lines of confirmed-dead Kotlin (12 files — six abandoned VPN-service implementations, plus
  their now-orphaned helpers) and an entire second, never-built native C++ capture tree
  (`android/app/src/main/cpp/`), verified dead by inspecting actual build output, not just
  cross-referencing symbols.
- Stray, misleading `build.gradle.kts`/`settings.gradle.kts` scaffolding (declared a different,
  wrong package name than the live Groovy build files).
- Duplicate `ProtocolStats`/`NetworkMetrics` class definitions in `main.dart` that silently shadowed
  the real ones in `models.dart`, plus a dead module-level `MethodChannel` handler
  (`initPacketListener`) that was unreachable the moment the main screen mounted, and several
  `NativeBridge` methods with no caller.

### 📦 Dependencies & Tooling
- Gradle 8.10.2 → 8.14.3, AGP 8.7.3 → 8.11.2, Kotlin 2.1.0 → 2.2.21, compileSdk 36 → 37,
  kotlinx-coroutines 1.7.3 → 1.11.0.
- `fl_chart` 0.70 → 1.2, `flutter_secure_storage` 9 → 11, `local_auth` 2 → 3,
  `permission_handler` 11 → 13, `share_plus` 10 → 13 (`Share.shareXFiles` →
  `SharePlus.instance.share`), `flutter_lints` 5 → 6 — all breaking API changes at each major
  fixed at the call site.

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
