# AndroNet Testing Guide

## 🧪 Comprehensive Testing Strategy for AndroNet

This document outlines the testing methodology, tools, and best practices for ensuring AndroNet's reliability, performance, and security.

---

## 📋 Testing Overview

### Testing Levels

```
┌─────────────────────────────────────────────────────────┐
│                    Testing Pyramid                      │
├─────────────────────────────────────────────────────────┤
│  Manual Testing              (Exploratory, Usability)   │
├─────────────────────────────────────────────────────────┤
│  Integration Tests           (Component Interaction)    │
├─────────────────────────────────────────────────────────┤
│  Unit Tests                  (Individual Functions)     │
├─────────────────────────────────────────────────────────┤
│  Static Analysis             (Code Quality, Security)   │
└─────────────────────────────────────────────────────────┘
```

### Test Categories

1. **Unit Tests** - Individual function/method testing
2. **Integration Tests** - Component interaction testing
3. **End-to-End Tests** - Complete user workflow testing
4. **Performance Tests** - Load and stress testing
5. **Security Tests** - Vulnerability and penetration testing
6. **Manual Tests** - Usability and exploratory testing

---

## 🛠️ Testing Tools & Setup

### Flutter/Dart Testing

#### Dependencies
```yaml
# pubspec.yaml
dev_dependencies:
  test: ^1.24.0
  mockito: ^5.4.0
  build_runner: ^2.4.0
  flutter_test:
    sdk: flutter
```

#### Running Tests
```bash
# Run all tests
flutter test

# Run specific test file
flutter test test/unit/packet_parser_test.dart

# Run with coverage
flutter test --coverage

# Run integration tests
flutter test integration_test/

# Watch mode for development
flutter test --watch
```

### Android/Kotlin Testing

#### Dependencies (build.gradle)
```kotlin
dependencies {
    // Unit testing
    testImplementation 'junit:junit:4.13.2'
    testImplementation 'org.mockito:mockito-core:5.1.1'
    testImplementation 'org.mockito.kotlin:mockito-kotlin:4.1.0'

    // Instrumented testing
    androidTestImplementation 'androidx.test.ext:junit:1.1.5'
    androidTestImplementation 'androidx.test.espresso:espresso-core:3.5.1'
    androidTestImplementation 'org.mockito:mockito-android:5.1.1'
}
```

#### Running Native Tests
```bash
# Unit tests
./gradlew testDebugUnitTest

# Instrumented tests
./gradlew connectedDebugAndroidTest

# With coverage
./gradlew testDebugUnitTest jacocoTestReport
```

### Performance Testing Tools

- **Flutter DevTools** - Performance profiling
- **Android Profiler** - Memory, CPU, network analysis
- **Systrace** - System-level performance analysis
- **LeakCanary** - Memory leak detection

---

## 🧪 Unit Testing

### Flutter/Dart Unit Tests

#### Test Structure
```
test/
├── unit/                    # Unit tests
│   ├── packet_parser_test.dart
│   ├── auth_service_test.dart
│   └── ui_components_test.dart
├── integration/             # Integration tests
│   ├── packet_capture_flow_test.dart
│   └── vpn_service_test.dart
└── test_utils.dart           # Shared test utilities
```

#### Writing Unit Tests

```dart
// test/unit/packet_parser_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:andronet/services/packet_parser.dart';

class MockPacketData extends Mock {
  Map<String, dynamic> get packetInfo => {
    'protocol': 'TCP',
    'sourceIp': '192.168.1.1',
    'destinationIp': '10.0.0.1',
    'sourcePort': 443,
    'destinationPort': 12345,
    'size': 1500,
    'direction': 'outgoing'
  };
}

void main() {
  group('PacketParser', () {
    late PacketParser parser;
    late MockPacketData mockData;

    setUp(() {
      parser = PacketParser();
      mockData = MockPacketData();
    });

    test('should parse TCP packet correctly', () {
      final packet = parser.parsePacket(mockData.packetInfo);

      expect(packet.protocol, equals('TCP'));
      expect(packet.sourceIp, equals('192.168.1.1'));
      expect(packet.size, equals(1500));
      expect(packet.isOutgoing, isTrue);
    });

    test('should handle malformed packet data', () {
      final malformedData = {'protocol': null};

      expect(() => parser.parsePacket(malformedData),
             throwsA(isA<FormatException>()));
    });

    test('should calculate packet rate correctly', () {
      final packets = List.generate(10, (i) =>
        PacketInfo(protocol: 'TCP', timestamp: DateTime.now().add(Duration(milliseconds: i * 100)))
      );

      final rate = parser.calculatePacketRate(packets);

      expect(rate, greaterThan(0));
      expect(rate, lessThanOrEqualTo(10)); // Max 10 packets per second
    });
  });
}
```

#### Mocking External Dependencies

```dart
// test/unit/vpn_service_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:mockito/mockito.dart';
import 'package:andronet/services/vpn_service.dart';

class MockMethodChannel extends Mock implements MethodChannel {}

void main() {
  group('VpnService', () {
    late VpnService vpnService;
    late MockMethodChannel mockChannel;

    setUp(() {
      mockChannel = MockMethodChannel();
      vpnService = VpnService(channel: mockChannel);
    });

    test('should start VPN successfully', () async {
      when(mockChannel.invokeMethod('startVpn'))
          .thenAnswer((_) async => true);

      final result = await vpnService.startVpn();

      expect(result, isTrue);
      verify(mockChannel.invokeMethod('startVpn')).called(1);
    });

    test('should handle VPN start failure', () async {
      when(mockChannel.invokeMethod('startVpn'))
          .thenThrow(PlatformException(code: 'VPN_ERROR'));

      expect(() => vpnService.startVpn(),
             throwsA(isA<PlatformException>()));
    });
  });
}
```

### Kotlin Unit Tests

#### Test Structure
```
android/app/src/test/java/com/example/packet_analyzer/
├── PacketParserTest.kt
├── AnomalyDetectorTest.kt
├── TrafficStatisticsTest.kt
└── PcapWriterTest.kt
```

#### Writing Kotlin Unit Tests

```kotlin
// android/app/src/test/java/com/example/packet_analyzer/PacketParserTest.kt
package com.example.packet_analyzer

import org.junit.Test
import org.junit.Assert.*
import org.junit.Before
import org.mockito.Mock
import org.mockito.MockitoAnnotations
import org.mockito.Mockito.`when`

class PacketParserTest {
    private lateinit var packetParser: PacketParser

    @Mock
    private lateinit var mockRawPacket: ByteArray

    @Before
    fun setUp() {
        MockitoAnnotations.openMocks(this)
        packetParser = PacketParser()
    }

    @Test
    fun `should parse TCP packet correctly`() {
        val packetInfo = mapOf(
            "protocol" to "TCP",
            "sourceIp" to "192.168.1.1",
            "destinationIp" to "10.0.0.1",
            "sourcePort" to 443,
            "destinationPort" to 12345,
            "size" to 1500,
            "direction" to "outgoing"
        )

        val packet = packetParser.parsePacket(packetInfo, mockRawPacket)

        assertEquals("TCP", packet.protocol)
        assertEquals("192.168.1.1", packet.sourceIp)
        assertEquals(1500, packet.size)
        assertTrue(packet.isOutgoing)
    }

    @Test
    fun `should handle null protocol gracefully`() {
        val invalidPacketInfo = mapOf<String, Any>(
            "protocol" to null,
            "sourceIp" to "192.168.1.1"
        )

        // Should not throw exception, return default values
        val packet = packetParser.parsePacket(invalidPacketInfo, mockRawPacket)

        assertNotNull(packet)
        assertEquals("Unknown", packet.protocol)
    }

    @Test
    fun `should extract payload from raw packet`() {
        val rawPacket = byteArrayOf(0x45, 0x00, 0x01, 0x00) // Sample IP packet
        `when`(mockRawPacket.size).thenReturn(4)

        val payload = packetParser.extractPayload(rawPacket)

        assertNotNull(payload)
        assertTrue(payload.isNotEmpty())
    }
}
```

---

## 🔗 Integration Testing

### Flutter Integration Tests

#### Test Structure
```
integration_test/
├── app_startup_test.dart
├── packet_capture_flow_test.dart
├── vpn_service_integration_test.dart
└── pcap_export_test.dart
```

#### Writing Integration Tests

```dart
// integration_test/packet_capture_flow_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:andronet/main.dart' as app;

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('Packet Capture Flow', () {
    testWidgets('should complete full capture workflow', (WidgetTester tester) async {
      // Start the app
      app.main();
      await tester.pumpAndSettle();

      // Navigate to capture screen
      await tester.tap(find.text('Start Capture'));
      await tester.pumpAndSettle();

      // Verify VPN permission dialog appears
      expect(find.text('VPN Connection'), findsOneWidget);

      // Grant permission (mock response)
      // Note: In real tests, you'd use patrol or similar for system interactions

      // Verify capture starts
      await tester.pump(Duration(seconds: 2));
      expect(find.text('Capturing...'), findsOneWidget);

      // Verify packets appear in list
      await tester.pump(Duration(seconds: 5));
      expect(find.byType(PacketCard), findsAtLeastNWidgets(1));

      // Stop capture
      await tester.tap(find.text('Stop Capture'));
      await tester.pumpAndSettle();

      // Verify capture stops
      expect(find.text('Start Capture'), findsOneWidget);
    });

    testWidgets('should handle capture errors gracefully', (WidgetTester tester) async {
      // Test error scenarios
      app.main();
      await tester.pumpAndSettle();

      // Simulate network error
      // Verify error message displays
      // Verify fallback behavior
    });
  });
}
```

### Android Integration Tests

#### Instrumented Tests
```kotlin
// android/app/src/androidTest/java/com/example/packet_analyzer/VpnServiceTest.kt
@RunWith(AndroidJUnit4::class)
class VpnServiceTest {
    @get:Rule
    val rule = ActivityScenarioRule(MainActivity::class.java)

    @Test
    fun testVpnServiceIntegration() {
        // Test VPN service establishment
        val scenario = rule.scenario

        scenario.onActivity { activity ->
            // Test VPN service binding
            val intent = Intent(activity, CompleteVpnService::class.java)
            activity.bindService(intent, object : ServiceConnection {
                override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
                    assertNotNull("VPN service should be bound", service)
                }

                override fun onServiceDisconnected(name: ComponentName?) {
                    // Handle disconnection
                }
            }, Context.BIND_AUTO_CREATE)
        }
    }
}
```

---

## ⚡ Performance Testing

### Flutter Performance Tests

#### Widget Performance
```dart
// test/performance/ui_performance_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'package:andronet/ui/packet_list.dart';

void main() {
  group('UI Performance Tests', () {
    testWidgets('packet list should handle 1000 packets smoothly',
        (WidgetTester tester) async {
      // Create 1000 mock packets
      final packets = List.generate(1000, (i) =>
        PacketInfo(
          protocol: 'TCP',
          sourceIp: '192.168.1.${i % 255}',
          destinationIp: '10.0.0.1',
          size: 1500,
          timestamp: DateTime.now(),
        )
      );

      final stopwatch = Stopwatch()..start();

      await tester.pumpWidget(
        MaterialApp(
          home: PacketList(packets: packets),
        ),
      );

      await tester.pumpAndSettle();

      stopwatch.stop();
      final renderTime = stopwatch.elapsedMilliseconds;

      // Should render within 100ms
      expect(renderTime, lessThan(100));
    });

    testWidgets('packet processing should not block UI thread',
        (WidgetTester tester) async {
      // Test that heavy packet processing doesn't freeze UI
      final completer = Completer<void>();

      // Simulate heavy processing
      Future.delayed(Duration(milliseconds: 500), () {
        completer.complete();
      });

      await tester.pumpWidget(
        MaterialApp(
          home: Scaffold(
            body: FutureBuilder(
              future: completer.future,
              builder: (context, snapshot) {
                if (snapshot.connectionState == ConnectionState.done) {
                  return Text('Processing Complete');
                }
                return CircularProgressIndicator();
              },
            ),
          ),
        ),
      );

      // UI should remain responsive during processing
      await tester.tap(find.byType(CircularProgressIndicator));
      await tester.pump();

      // Should be able to interact with UI
      expect(find.byType(CircularProgressIndicator), findsOneWidget);
    });
  });
}
```

### Android Performance Tests

#### Memory and CPU Testing
```kotlin
// android/app/src/androidTest/java/com/example/packet_analyzer/PerformanceTest.kt
class PerformanceTest {
    @Test
    fun testMemoryUsageDuringCapture() {
        val runtime = Runtime.getRuntime()

        // Record initial memory
        val initialMemory = runtime.totalMemory() - runtime.freeMemory()

        // Start packet capture
        val vpnService = CompleteVpnService()
        vpnService.startCapture()

        // Simulate packet processing
        repeat(10000) {
            val packetInfo = createMockPacketInfo()
            PacketAnalysisManager.processPacket(packetInfo)
        }

        // Record final memory
        val finalMemory = runtime.totalMemory() - runtime.freeMemory()
        val memoryIncrease = finalMemory - initialMemory

        // Memory increase should be reasonable (< 50MB for 10k packets)
        assertTrue("Memory usage too high: $memoryIncrease bytes",
                  memoryIncrease < 50 * 1024 * 1024)
    }

    @Test
    fun testPacketProcessingPerformance() {
        val packets = List(1000) { createMockPacketInfo() }
        val startTime = System.currentTimeMillis()

        packets.forEach { packetInfo ->
            PacketAnalysisManager.processPacket(packetInfo)
        }

        val endTime = System.currentTimeMillis()
        val processingTime = endTime - startTime

        // Should process 1000 packets in under 1 second
        assertTrue("Packet processing too slow: $processingTime ms",
                  processingTime < 1000)
    }
}
```

---

## 🔒 Security Testing

### Vulnerability Testing

#### Packet Injection Tests
```dart
// test/security/packet_injection_test.dart
void main() {
  group('Security Tests', () {
    test('should reject malformed packets', () {
      final malformedPackets = [
        {'protocol': null, 'data': 'malicious'},
        {'protocol': 'TCP', 'sourceIp': '999.999.999.999'}, // Invalid IP
        {'protocol': 'TCP', 'size': -1}, // Negative size
        {'protocol': '<script>alert("xss")</script>'}, // XSS attempt
      ];

      malformedPackets.forEach((packet) {
        expect(() => PacketParser.parsePacket(packet),
               throwsA(isA<SecurityException>()));
      });
    });

    test('should prevent buffer overflow attacks', () {
      // Test with oversized payloads
      final oversizedPayload = 'A' * 100000; // 100KB payload

      expect(() => PacketParser.parsePayload(oversizedPayload),
             throwsA(isA<SecurityException>()));
    });

    test('should validate IP addresses', () {
      final invalidIPs = [
        '256.1.1.1',
        '192.168.1.1.1',
        'not.an.ip.address',
        '192.168.1',
      ];

      invalidIPs.forEach((ip) {
        expect(() => IpValidator.validate(ip),
               throwsA(isA<FormatException>()));
      });
    });
  });
}
```

### Penetration Testing Checklist

- [ ] Test for SQL injection in search fields
- [ ] Test for XSS in packet data display
- [ ] Test for buffer overflow in native code
- [ ] Test for privilege escalation attempts
- [ ] Test for man-in-the-middle attack vectors
- [ ] Test for denial-of-service via packet flooding
- [ ] Test for unauthorized file access

---

## 📊 Test Coverage Requirements

### Minimum Coverage Targets

| Component | Minimum Coverage |
|-----------|------------------|
| Flutter Business Logic | 90% |
| Flutter UI Components | 80% |
| Kotlin Services | 85% |
| Native C/C++ Code | 75% |
| Integration Flows | 80% |

### Coverage Reporting

```bash
# Flutter coverage
flutter test --coverage
# Generates coverage/lcov.info

# Kotlin coverage
./gradlew testDebugUnitTest jacocoTestReport
# Generates build/reports/jacoco/test/html/index.html

# Combined coverage (if configured)
# Use tools like codecov or coveralls for reporting
```

---

## 🏃‍♂️ Automated Testing Pipeline

### CI/CD Integration

#### GitHub Actions Workflow
```yaml
# .github/workflows/test.yml
name: Tests
on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-java@v3
        with:
          java-version: '11'
      - uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.32.8'

      - name: Install dependencies
        run: flutter pub get

      - name: Run Flutter tests
        run: flutter test --coverage

      - name: Run Kotlin tests
        run: ./gradlew testDebugUnitTest

      - name: Upload coverage
        uses: codecov/codecov-action@v3
```

### Pre-commit Hooks

```bash
# Install pre-commit hooks
pre-commit install

# .pre-commit-config.yaml
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
      - id: trailing-whitespace
      - id: end-of-file-fixer
      - id: check-yaml
      - id: check-added-large-files

  - repo: local
    hooks:
      - id: flutter-test
        name: Flutter Tests
        entry: flutter test
        language: system
        pass_filenames: false

      - id: kotlin-test
        name: Kotlin Tests
        entry: ./gradlew testDebugUnitTest
        language: system
        pass_filenames: false
```

---

## 🐛 Manual Testing Guide

### Exploratory Testing Checklist

#### Installation & Setup
- [ ] App installs successfully on target devices
- [ ] VPN permission dialog appears and functions
- [ ] Initial setup wizard completes without errors
- [ ] Root detection works correctly for libpcap mode

#### Packet Capture (VPN Mode)
- [ ] Internet connectivity maintained during capture
- [ ] Packets appear in real-time in UI
- [ ] Both outgoing and incoming packets captured
- [ ] Protocol detection works for common protocols (HTTP, DNS, TCP)
- [ ] Packet details display correctly

#### Packet Capture (Libpcap Mode)
- [ ] Root access detected and mode selected automatically
- [ ] Network interface selection works
- [ ] Wireshark-like packet capture functions
- [ ] All protocols captured (including ICMP)

#### Deep Packet Inspection
- [ ] HTTP request/response analysis shows details
- [ ] DNS queries display domain information
- [ ] TLS handshake information extracted
- [ ] Application protocol detection works

#### Anomaly Detection
- [ ] Port scan detection triggers alerts
- [ ] SYN flood detection works
- [ ] DNS tunneling detection functions
- [ ] ARP spoofing detection alerts

#### PCAP Export
- [ ] Export dialog opens and functions
- [ ] PCAP files created in correct location
- [ ] Files open correctly in Wireshark
- [ ] Export statistics displayed

#### Performance
- [ ] App remains responsive with high packet rates
- [ ] Memory usage stays reasonable
- [ ] Battery impact is acceptable
- [ ] No crashes during extended capture sessions

#### UI/UX
- [ ] All screens render correctly
- [ ] Navigation works smoothly
- [ ] Dark/light theme switching functions
- [ ] Accessibility features work

### Bug Reporting Template

When reporting bugs, include:

```markdown
## Bug Report

**Description:**
[Clear description of the issue]

**Steps to Reproduce:**
1. [Step 1]
2. [Step 2]
3. [Step 3]

**Expected Behavior:**
[What should happen]

**Actual Behavior:**
[What actually happens]

**Environment:**
- Device: [Device model]
- Android Version: [Version]
- App Version: [Version]
- Capture Mode: [VPN/Libpcap]

**Logs:**
```
[Paste relevant logs here]
```

**Screenshots:**
[Attach screenshots if applicable]
```

---

## 📈 Performance Benchmarks

### Target Performance Metrics

| Metric | Target | Notes |
|--------|--------|-------|
| Packet Processing Rate | 1000+ pps | Packets per second |
| Memory Usage | < 100MB | During active capture |
| CPU Usage | < 15% | On modern devices |
| Battery Impact | < 10%/hour | During capture |
| UI Responsiveness | < 16ms/frame | Flutter performance |
| Startup Time | < 3 seconds | App launch to ready |

### Load Testing Scenarios

1. **High Packet Rate**: 2000 packets/second for 5 minutes
2. **Long Duration**: 24-hour continuous capture
3. **Large Payloads**: Packets with 64KB payloads
4. **Concurrent Connections**: 1000+ simultaneous connections
5. **Memory Pressure**: Capture with limited available memory

---

## 🎯 Best Practices

### Writing Good Tests

1. **Test One Thing**: Each test should verify one behavior
2. **Use Descriptive Names**: Test names should explain what's being tested
3. **Arrange-Act-Assert**: Follow the AAA pattern
4. **Mock External Dependencies**: Isolate units under test
5. **Test Edge Cases**: Null values, empty data, boundary conditions
6. **Performance Conscious**: Avoid slow tests in CI

### Test Data Management

1. **Realistic Test Data**: Use real packet captures when possible
2. **Data Factories**: Create reusable test data generators
3. **Anonymized Data**: Remove sensitive information from test data
4. **Version Control**: Keep test data under version control

### Continuous Testing

1. **Fast Feedback**: Run tests on every commit
2. **Parallel Execution**: Run tests in parallel where possible
3. **Flaky Test Detection**: Monitor and fix flaky tests
4. **Test Result Trending**: Track test success rates over time

---

## 📚 Resources

### Testing Documentation
- [Flutter Testing Guide](https://docs.flutter.dev/testing)
- [Android Testing Guide](https://developer.android.com/training/testing)
- [JUnit 5 Documentation](https://junit.org/junit5/docs/current/user-guide/)
- [Mockito Documentation](https://javadoc.io/doc/org.mockito/mockito-core/latest/org/mockito/Mockito.html)

### Tools
- [Flutter DevTools](https://docs.flutter.dev/development/tools/devtools)
- [Android Studio Profiler](https://developer.android.com/studio/profile)
- [Charles Proxy](https://www.charlesproxy.com/) - Network debugging
- [Wireshark](https://www.wireshark.org/) - Packet analysis

---

*Happy testing! 🧪*
