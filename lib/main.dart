import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'dart:async';
import 'dart:convert';
import 'package:fl_chart/fl_chart.dart';
import 'package:flutter/foundation.dart';
import 'auth/auth_service.dart';
import 'auth/auth_wrapper.dart';
import 'auth/login_screen.dart';
import 'auth/setup_auth_screen.dart';
import 'models.dart';
import 'enhanced_ui_components.dart';
import 'anomaly_dashboard.dart';

// ================= CAPTURE MODE ENUM =================
enum CaptureMode {
  vpn,
  libpcap,
  enhanced;

  String get displayName {
    switch (this) {
      case CaptureMode.vpn:
        return 'VPN Service (COMPREHENSIVE ALL TRAFFIC)';
      case CaptureMode.libpcap:
        return 'LibPCAP (Root)';
      case CaptureMode.enhanced:
        return 'Enhanced VPN';
    }
  }

  String get title {
    switch (this) {
      case CaptureMode.vpn:
        return 'VPN';
      case CaptureMode.libpcap:
        return 'LibPCAP';
      case CaptureMode.enhanced:
        return 'Enhanced';
    }
  }

  String get description {
    switch (this) {
      case CaptureMode.vpn:
        return 'Comprehensive packet capture of ALL internet traffic with bidirectional analysis and smart direction detection';
      case CaptureMode.libpcap:
        return 'Uses libpcap/tcpdump for direct packet capture (requires root)';
      case CaptureMode.enhanced:
        return 'PCAPdroid-inspired VPN capture with advanced features and statistics';
    }
  }

  Color get color {
    switch (this) {
      case CaptureMode.vpn:
        return Colors.blue;
      case CaptureMode.libpcap:
        return Colors.green;
      case CaptureMode.enhanced:
        return Colors.purple;
    }
  }

  IconData get icon {
    switch (this) {
      case CaptureMode.vpn:
        return Icons.vpn_lock;
      case CaptureMode.libpcap:
        return Icons.security;
      case CaptureMode.enhanced:
        return Icons.radar;
    }
  }
}

// ================= GLOBAL PACKET LISTENER =================
const _channel = MethodChannel("packet_analyzer");

void initPacketListener() {
  print("🔧 Setting up packet listener..."); // Debug log
  _channel.setMethodCallHandler((call) async {
    print("📞 Flutter received method call: ${call.method}"); // Debug log
    switch (call.method) {
      case "onPacketReceived":
        print("📥 onPacketReceived called"); // Debug log
        PacketService._handleNativePacket(
          Map<String, dynamic>.from(call.arguments),
        );
        break;
      case "onPacketEvent":
        print(
          "📥 onPacketEvent called with args: ${call.arguments}",
        ); // Debug log
        final eventData = Map<String, dynamic>.from(call.arguments);
        final event = eventData['event'] as String?;
        final data = eventData['data'];

        print("🎯 Processing event: $event"); // Debug log
        switch (event) {
          case "PACKET_CAPTURED":
            print("📦 PACKET_CAPTURED event received!"); // Debug log
            if (data is Map<String, dynamic>) {
              PacketService._handleNativePacket(data);
            }
            break;
          case "VPN_STARTED":
          case "VPN_STOPPED":
          case "LIBPCAP_STARTED":
          case "LIBPCAP_STOPPED":
          case "LIBPCAP_ERROR":
            PacketService._statusController.add(
              data?.toString() ?? event ?? "Unknown Event",
            );
            break;
        }
        break;
      case "onStatsUpdated":
        final stats = call.arguments;
        if (stats is String) {
          try {
            final parsed = jsonDecode(stats);
            PacketService._handleNativeStats(parsed);
          } catch (_) {}
        } else {
          PacketService._handleNativeStats(stats);
        }
        break;
      case "onStatusChanged":
        final status = call.arguments;
        if (status is Map<String, dynamic>) {
          PacketService._handleNativeStatus(status);
        } else if (status is String) {
          PacketService._handleNativeStatus({'status': status});
        }
        break;
      case "onSessionsUpdated":
        PacketService._handleNativeSessions(call.arguments);
        break;
      case "onMetricsUpdated":
        if (call.arguments is Map) {
          PacketService._handleNativeMetrics(
            Map<String, dynamic>.from(call.arguments),
          );
        }
        break;
      case "onDashboardUpdate":
        print("📊 Dashboard update received"); // Debug log
        if (call.arguments is Map) {
          PacketService._handleDashboardUpdate(
            Map<String, dynamic>.from(call.arguments),
          );
        }
        break;
      case "onAnomalyDetected":
        print("🚨 Anomaly detected"); // Debug log
        // Handle anomaly notifications
        break;
    }
  });
}

void main() {
  WidgetsFlutterBinding.ensureInitialized();
  initPacketListener();
  PacketService.initialize();
  runApp(
    ChangeNotifierProvider(
      create: (context) => AuthenticationService(),
      child: const PacketAnalyzerApp(),
    ),
  );
}

// ================= ENHANCED VPN CONTROLLER =================
class VpnController {
  static const _channel = MethodChannel("packet_analyzer");

  static Future<bool> prepareVpn() async {
    try {
      final prepared = await _channel.invokeMethod("prepareVpn");
      return prepared == true;
    } catch (e) {
      debugPrint("VPN prepare failed: $e");
      return false;
    }
  }

  static Future<void> startVpn() async {
    try {
      final prepared = await _channel.invokeMethod("prepareVpn");
      if (prepared == true) {
        try {
          await _channel.invokeMethod("startVpn");
          debugPrint("✅ VPN started successfully");
          PacketService._statusController.add("VPN Started");
        } catch (e) {
          debugPrint("VPN start failed: $e");
          PacketService._statusController.add("VPN Start Failed: $e");
          throw Exception("VPN start failed: $e");
        }
      } else {
        debugPrint("⚠️ VPN permission not granted yet");
        PacketService._statusController.add("VPN Permission Required");
        throw Exception("VPN permission not granted");
      }
    } catch (e) {
      debugPrint("VPN operation failed: $e");
      rethrow;
    }
  }

  static Future<void> stopVpn() async {
    try {
      await _channel.invokeMethod("stopVpn");
      debugPrint("🛑 VPN stopped");
      PacketService._statusController.add("VPN Stopped");
    } catch (e) {
      debugPrint("VPN stop failed: $e");
      PacketService._statusController.add("VPN Stop Failed: $e");
      throw Exception("VPN stop failed: $e");
    }
  }

  static Future<bool> isVpnRunning() async {
    try {
      final result = await _channel.invokeMethod("isVpnRunning");
      return result == true;
    } catch (e) {
      debugPrint("VPN status check failed: $e");
      return false;
    }
  }

  static Future<String> getVpnStatus() async {
    try {
      final result = await _channel.invokeMethod("getVpnStatus");
      return result?.toString() ?? "Unknown";
    } catch (e) {
      debugPrint("VPN status retrieval failed: $e");
      return "Error: $e";
    }
  }

  // NetHunter/Root-specific methods
  static Future<bool> checkRootAccess() async {
    try {
      final result = await _channel.invokeMethod("checkRootAccess");
      return result == true;
    } catch (e) {
      debugPrint("Root check failed: $e");
      return false;
    }
  }

  static Future<void> startLibpcapCapture() async {
    try {
      await _channel.invokeMethod("startLibpcapCapture");
      debugPrint("✅ Libpcap capture started");
      PacketService._statusController.add("Libpcap Started");
    } catch (e) {
      debugPrint("Libpcap start failed: $e");
      PacketService._statusController.add("Libpcap Start Failed: $e");
      throw Exception("Libpcap start failed: $e");
    }
  }

  static Future<void> stopLibpcapCapture() async {
    try {
      await _channel.invokeMethod("stopLibpcapCapture");
      debugPrint("🛑 Libpcap capture stopped");
      PacketService._statusController.add("Libpcap Stopped");
    } catch (e) {
      debugPrint("Libpcap stop failed: $e");
      PacketService._statusController.add("Libpcap Stop Failed: $e");
      throw Exception("Libpcap stop failed: $e");
    }
  }

  // ================= ENHANCED CAPTURE METHODS =================
  static Future<void> startEnhancedCapture() async {
    try {
      final prepared = await _channel.invokeMethod("prepareVpn");
      if (prepared == true) {
        try {
          await _channel.invokeMethod("startCapture");
          debugPrint("🚀 Enhanced capture started successfully");
          PacketService._statusController.add("Enhanced Capture Started");
        } catch (e) {
          debugPrint("Enhanced capture start failed: $e");
          PacketService._statusController.add(
            "Enhanced Capture Start Failed: $e",
          );
          throw Exception("Enhanced capture start failed: $e");
        }
      } else {
        debugPrint("⚠️ VPN permission not granted yet");
        PacketService._statusController.add("VPN Permission Required");
        throw Exception("VPN permission not granted");
      }
    } catch (e) {
      debugPrint("Enhanced capture operation failed: $e");
      rethrow;
    }
  }

  static Future<void> stopEnhancedCapture() async {
    try {
      await _channel.invokeMethod("stopCapture");
      debugPrint("🛑 Enhanced capture stopped");
      PacketService._statusController.add("Enhanced Capture Stopped");
    } catch (e) {
      debugPrint("Enhanced capture stop failed: $e");
      PacketService._statusController.add("Enhanced Capture Stop Failed: $e");
      throw Exception("Enhanced capture stop failed: $e");
    }
  }
}

// ================= NATIVE BRIDGE CLASS =================
class NativeBridge {
  static const platform = MethodChannel("packet_analyzer");

  // Root detection with enhanced error handling
  static Future<bool> isRooted() async {
    try {
      final result = await platform.invokeMethod("isDeviceRooted");
      return result == true;
    } catch (e) {
      debugPrint("Error checking root status: $e");
      return false;
    }
  }

  // Enhanced VPN control methods using VpnController
  static Future<String> startVpn() async {
    try {
      await VpnController.startVpn();
      return "VPN started successfully";
    } catch (e) {
      return "VPN start failed: $e";
    }
  }

  static Future<String> stopVpn() async {
    try {
      await VpnController.stopVpn();
      return "VPN stopped successfully";
    } catch (e) {
      return "VPN stop failed: $e";
    }
  }

  // Additional bridge methods for comprehensive functionality
  static Future<String> getDeviceInfo() async {
    try {
      final result = await platform.invokeMethod("getDeviceInfo");
      return result?.toString() ?? "Device info unavailable";
    } catch (e) {
      debugPrint("Error getting device info: $e");
      return "Error: ${e.toString()}";
    }
  }

  static Future<List<String>> getNetworkInterfaces() async {
    try {
      final result = await platform.invokeMethod("getNetworkInterfaces");
      return List<String>.from(result ?? []);
    } catch (e) {
      debugPrint("Error getting network interfaces: $e");
      return [];
    }
  }

  static Future<Map<String, dynamic>> getSystemStats() async {
    try {
      final result = await platform.invokeMethod("getSystemStats");
      return Map<String, dynamic>.from(result ?? {});
    } catch (e) {
      debugPrint("Error getting system stats: $e");
      return {};
    }
  }

  static Future<bool> requestPermissions() async {
    try {
      final result = await platform.invokeMethod("requestPermissions");
      return result == true;
    } catch (e) {
      debugPrint("Error requesting permissions: $e");
      return false;
    }
  }

  static Future<String> exportData(Map<String, dynamic> data) async {
    try {
      final result = await platform.invokeMethod("exportData", data);
      return result?.toString() ?? "Export failed";
    } catch (e) {
      debugPrint("Error exporting data: $e");
      return "Error: ${e.toString()}";
    }
  }

  static Future<bool> startRootCapture() async {
    try {
      final result = await platform.invokeMethod("startRootedCapture");
      return result == true;
    } catch (e) {
      debugPrint("Error starting root capture: $e");
      return false;
    }
  }

  static Future<bool> stopRootCapture() async {
    try {
      final result = await platform.invokeMethod("stopRootedCapture");
      return result == true;
    } catch (e) {
      debugPrint("Error stopping root capture: $e");
      return false;
    }
  }

  static Future<bool> startPcapCapture() async {
    try {
      final result = await platform.invokeMethod("startPcapCapture");
      return result == true;
    } catch (e) {
      debugPrint("Error starting PCAP capture: $e");
      return false;
    }
  }

  static Future<bool> stopPcapCapture() async {
    try {
      final result = await platform.invokeMethod("stopPcapCapture");
      return result == true;
    } catch (e) {
      debugPrint("Error stopping PCAP capture: $e");
      return false;
    }
  }
}

class ProtocolStats {
  final String protocol;
  final int packetCount;
  final double percentage;

  const ProtocolStats({
    required this.protocol,
    required this.packetCount,
    this.percentage = 0.0,
  });
}

class NetworkMetrics {
  final int totalPackets;
  final double packetsPerSecond;
  final int totalSessions;
  final double dataRate;

  const NetworkMetrics({
    required this.totalPackets,
    required this.packetsPerSecond,
    this.totalSessions = 0,
    this.dataRate = 0.0,
  });

  factory NetworkMetrics.fromMap(Map<String, dynamic> map) {
    int _toInt(dynamic v) =>
        (v is int) ? v : int.tryParse(v?.toString() ?? "0") ?? 0;
    double _toDouble(dynamic v) =>
        (v is double) ? v : double.tryParse(v?.toString() ?? "0") ?? 0;

    return NetworkMetrics(
      totalPackets: _toInt(map['totalPackets']),
      packetsPerSecond: _toDouble(map['packetsPerSecond']),
      totalSessions: _toInt(map['totalSessions']),
      dataRate: _toDouble(map['dataRate']),
    );
  }
}

// ================= ENHANCED PACKET SERVICE WITH VPN CONTROLLER =================
class PacketService {
  static const MethodChannel _channel = MethodChannel('packet_analyzer');
  static const EventChannel _packetEventChannel = EventChannel('packet_stream');
  static const EventChannel _anomalyEventChannel = EventChannel(
    'anomaly_stream',
  );

  static final _packetController = StreamController<PacketInfo>.broadcast();
  static final _statusController = StreamController<String>.broadcast();
  static final _metricsController =
      StreamController<NetworkMetrics>.broadcast();
  static final _statsController =
      StreamController<List<ProtocolStats>>.broadcast();
  static final _anomalyController = StreamController<AnomalyInfo>.broadcast();

  static Stream<PacketInfo> get packetStream => _packetController.stream;
  static Stream<String> get statusStream => _statusController.stream;
  static Stream<NetworkMetrics> get metricsStream => _metricsController.stream;
  static Stream<List<ProtocolStats>> get statsStream => _statsController.stream;
  static Stream<AnomalyInfo> get anomalyStream => _anomalyController.stream;

  static final _buffer = <Map<String, dynamic>>[];
  static Timer? _flushTimer;
  static StreamSubscription? _eventChannelSubscription;
  static StreamSubscription? _anomalySubscription;

  static Future<void> initialize() async {
    _flushTimer ??= Timer.periodic(
      const Duration(milliseconds: 150),
      (_) => _flush(),
    );

    // Listen to EventChannel for real-time packet streaming from Go layer
    _eventChannelSubscription ??= _packetEventChannel
        .receiveBroadcastStream()
        .listen(
          (dynamic event) {
            try {
              print("📡 Received packet from EventChannel: $event");

              Map<String, dynamic> packetData;

              // Handle different event types from native code
              if (event is String) {
                packetData = jsonDecode(event) as Map<String, dynamic>;
                print("📦 Parsed JSON packet: $packetData");
              } else if (event is Map<String, dynamic>) {
                packetData = event;
              } else if (event is Map) {
                // Handle Map<Object?, Object?> from native Android
                packetData = Map<String, dynamic>.from(event);
                print("📦 Converted native map packet: $packetData");
              } else {
                print("⚠️ Unknown event type: ${event.runtimeType}");
                print("⚠️ Raw event data: $event");
                return;
              }

              final packet = PacketInfo.fromMap(packetData);
              print(
                "✅ EventChannel PacketInfo: ${packet.protocol} ${packet.sourceIp}:${packet.sourcePort} → ${packet.destinationIp}:${packet.destinationPort}",
              );
              _packetController.add(packet);
            } catch (e) {
              print("❌ Error processing EventChannel packet: $e");
              print("❌ Raw event: $event");
            }
          },
          onError: (error) {
            print("❌ EventChannel error: $error");
          },
        );

    // Listen to EventChannel for anomaly alerts
    _anomalySubscription ??= _anomalyEventChannel
        .receiveBroadcastStream()
        .listen(
          (dynamic event) {
            try {
              print("🚨 Received anomaly from EventChannel: $event");

              Map<String, dynamic> anomalyData;

              // Handle different event types from native code
              if (event is String) {
                anomalyData = jsonDecode(event) as Map<String, dynamic>;
              } else if (event is Map<String, dynamic>) {
                anomalyData = event;
              } else if (event is Map) {
                anomalyData = Map<String, dynamic>.from(event);
              } else {
                print("⚠️ Unknown anomaly event type: ${event.runtimeType}");
                return;
              }

              final anomaly = AnomalyInfo.fromMap(anomalyData);
              print(
                "🚨 Anomaly detected: ${anomaly.title} - ${anomaly.severity}",
              );
              _anomalyController.add(anomaly);
            } catch (e) {
              print("❌ Error processing anomaly: $e");
              print("❌ Raw event: $event");
            }
          },
          onError: (error) {
            print("❌ Anomaly EventChannel error: $error");
          },
        );
  }

  static void disposeService() {
    _flushTimer?.cancel();
    _eventChannelSubscription?.cancel();
    _anomalySubscription?.cancel();
    _packetController.close();
    _statusController.close();
    _metricsController.close();
    _statsController.close();
    _anomalyController.close();
  }

  // Native handlers
  static void _handleNativePacket(Map<String, dynamic> map) {
    print("🔥 Flutter received packet: $map"); // Debug log
    _buffer.add(map);
  }

  static void _handleNativeStats(dynamic stats) {
    try {
      if (stats is List) {
        final protocolStats = stats
            .map(
              (e) => ProtocolStats(
                protocol: e['protocol']?.toString() ?? 'Unknown',
                packetCount:
                    int.tryParse(e['packetCount']?.toString() ?? '0') ?? 0,
                percentage:
                    double.tryParse(e['percentage']?.toString() ?? '0') ?? 0.0,
              ),
            )
            .toList();
        _statsController.add(protocolStats);
      }
    } catch (e) {
      debugPrint("Error processing stats: $e");
    }
  }

  static void _handleNativeStatus(Map<String, dynamic> status) {
    _statusController.add(status['status']?.toString() ?? "Unknown");
  }

  static void _handleNativeSessions(dynamic sessionsData) {
    debugPrint("Sessions update: $sessionsData");
  }

  static void _handleNativeMetrics(Map<String, dynamic> metricsData) {
    try {
      _metricsController.add(NetworkMetrics.fromMap(metricsData));
    } catch (e) {
      debugPrint("Error processing metrics: $e");
    }
  }

  static void _handleDashboardUpdate(Map<String, dynamic> dashboardData) {
    try {
      // Extract protocol distribution from dashboard data
      final protocolDistribution =
          dashboardData['protocolDistribution'] as Map<dynamic, dynamic>?;

      if (protocolDistribution != null && protocolDistribution.isNotEmpty) {
        // Calculate total packets for percentage
        final totalPackets = protocolDistribution.values.fold<int>(
          0,
          (sum, count) => sum + ((count as num).toInt()),
        );

        // Convert to ProtocolStats list
        final protocolStats = protocolDistribution.entries.map((entry) {
          final protocol = entry.key.toString();
          final count = (entry.value as num).toInt();
          final percentage = totalPackets > 0
              ? (count * 100.0 / totalPackets)
              : 0.0;

          return ProtocolStats(
            protocol: protocol,
            packetCount: count,
            percentage: percentage,
          );
        }).toList();

        // Sort by packet count descending
        protocolStats.sort((a, b) => b.packetCount.compareTo(a.packetCount));

        _statsController.add(protocolStats);
        debugPrint(
          "📊 Updated protocol stats: ${protocolStats.length} protocols",
        );
      }
    } catch (e) {
      debugPrint("Error processing dashboard update: $e");
    }
  }

  static void _flush() {
    if (_buffer.isEmpty) return;
    final batch = List<Map<String, dynamic>>.from(_buffer);
    print("🚀 Flutter flushing ${batch.length} packets to UI"); // Debug log
    _buffer.clear();
    for (final m in batch) {
      try {
        final packet = PacketInfo.fromMap(m);
        print(
          "✅ Created PacketInfo: ${packet.protocol} ${packet.sourceIp}:${packet.sourcePort} → ${packet.destinationIp}:${packet.destinationPort}",
        );

        _packetController.add(packet);
      } catch (e) {
        print("❌ Error creating PacketInfo from map: $e");
        print("❌ Problematic map: $m");
      }
    }
  }

  // ================= ENHANCED CONTROL METHODS WITH VPN CONTROLLER =================

  // VPN Service Control via VpnController
  static Future<bool> startVpnService() async {
    try {
      await VpnController.startVpn();
      return true;
    } catch (e) {
      _statusController.add("VPN Error: ${e.toString()}");
      return false;
    }
  }

  static Future<bool> stopVpnService() async {
    try {
      await VpnController.stopVpn();
      return true;
    } catch (e) {
      _statusController.add("VPN Stop Error: ${e.toString()}");
      return false;
    }
  }

  static Future<bool> checkVpnPermission() async {
    try {
      return await VpnController.prepareVpn();
    } catch (e) {
      debugPrint("Error checking VPN permission: $e");
      return false;
    }
  }

  static Future<bool> isVpnActive() async {
    try {
      return await VpnController.isVpnRunning();
    } catch (e) {
      debugPrint("Error checking VPN status: $e");
      return false;
    }
  }

  // Root Detection via NativeBridge
  static Future<bool> isDeviceRooted() async {
    try {
      return await NativeBridge.isRooted();
    } catch (e) {
      debugPrint("Error checking root: $e");
      return false;
    }
  }

  // System Information via NativeBridge
  static Future<String> getDeviceInfo() async {
    try {
      return await NativeBridge.getDeviceInfo();
    } catch (e) {
      return "Device info unavailable: ${e.toString()}";
    }
  }

  static Future<List<String>> getNetworkInterfaces() async {
    try {
      return await NativeBridge.getNetworkInterfaces();
    } catch (e) {
      debugPrint("Error getting network interfaces: $e");
      return [];
    }
  }

  static Future<Map<String, dynamic>> getSystemStats() async {
    try {
      return await NativeBridge.getSystemStats();
    } catch (e) {
      debugPrint("Error getting system stats: $e");
      return {};
    }
  }

  // Permission Management via NativeBridge
  static Future<bool> requestAllPermissions() async {
    try {
      return await NativeBridge.requestPermissions();
    } catch (e) {
      debugPrint("Error requesting permissions: $e");
      return false;
    }
  }

  static Future<void> clearPackets() async {
    try {
      await _channel.invokeMethod('clearPackets');
      _buffer.clear();
    } catch (_) {
      debugPrint("clearPackets not implemented natively");
    }
  }

  // Anomaly testing
  static Future<void> generateTestAnomaly() async {
    try {
      await _channel.invokeMethod('generateTestAnomaly');
    } catch (e) {
      debugPrint("Test anomaly generation failed: $e");
    }
  }
}

// ================= ENHANCED UI APP =================
class PacketAnalyzerApp extends StatelessWidget {
  const PacketAnalyzerApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Andronet by CipherSec',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        useMaterial3: true,
        colorScheme:
            ColorScheme.fromSeed(
              seedColor: const Color(0xFF1565C0),
              brightness: Brightness.light,
            ).copyWith(
              surface: const Color(0xFFFAFBFC),
              surfaceContainerHighest: const Color(0xFFF1F3F4),
            ),
        cardTheme: const CardThemeData(
          elevation: 2,
          margin: EdgeInsets.zero,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.all(Radius.circular(12)),
          ),
        ),
        appBarTheme: const AppBarTheme(
          centerTitle: false,
          elevation: 0,
          scrolledUnderElevation: 1,
        ),
        elevatedButtonTheme: ElevatedButtonThemeData(
          style: ElevatedButton.styleFrom(
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(8),
            ),
            padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
          ),
        ),
      ),
      home: const AuthWrapper(),
      routes: {
        '/setup-auth': (context) => const SetupAuthScreen(),
        '/login': (context) => const LoginScreen(),
        '/main': (context) => const PacketAnalyzerScreen(),
      },
    );
  }
}

class PacketAnalyzerScreen extends StatefulWidget {
  const PacketAnalyzerScreen({Key? key}) : super(key: key);

  @override
  State<PacketAnalyzerScreen> createState() => _PacketAnalyzerScreenState();
}

class _PacketAnalyzerScreenState extends State<PacketAnalyzerScreen>
    with TickerProviderStateMixin {
  // Core state
  bool _isCapturing = false;
  bool _isRooted = false;
  bool _vpnPermissionGranted = false;
  CaptureMode _selectedCaptureMode = CaptureMode.vpn;

  final List<PacketInfo> _packets = [];
  final List<AnomalyInfo> _anomalies = [];
  List<ProtocolStats> _protocolStats = [];
  String _currentStatus = 'Ready';
  NetworkMetrics? _metrics;
  String _selectedProtocolFilter = "ALL";
  bool _autoScroll = true;

  // Device and system information
  String _deviceInfo = 'Unknown';
  List<String> _networkInterfaces = [];
  Map<String, dynamic> _systemStats = {};

  // Subscriptions
  StreamSubscription<PacketInfo>? _packetSub;
  StreamSubscription<String>? _statusSub;
  StreamSubscription<NetworkMetrics>? _metricsSub;
  StreamSubscription<List<ProtocolStats>>? _statsSub;
  StreamSubscription<AnomalyInfo>? _anomalySub;

  // Controllers
  late TabController _tabController;
  late AnimationController _pulseController;
  late Animation<double> _pulseAnimation;

  // Performance optimization
  Timer? _debounceTimer;
  static const int _maxPackets = 1500;

  @override
  void initState() {
    super.initState();
    // Setup method call handler to receive events from native code (packets, anomalies, status)
    _channel.setMethodCallHandler(_onMethodCall);
    _initializeControllers();
    _setupStreamSubscriptions();
    _initializeNativeBridge();
  }

  Future<dynamic> _onMethodCall(MethodCall call) async {
    switch (call.method) {
      case 'onPacketReceived':
        PacketService._handleNativePacket(
          Map<String, dynamic>.from(call.arguments as Map),
        );
      case 'onPacketEvent':
        final eventData = Map<String, dynamic>.from(call.arguments as Map);
        final event = eventData['event'] as String?;
        final data = eventData['data'];
        switch (event) {
          case 'PACKET_CAPTURED':
            if (data is Map<String, dynamic>) {
              PacketService._handleNativePacket(data);
            }
          case 'VPN_STARTED' ||
                'VPN_STOPPED' ||
                'LIBPCAP_STARTED' ||
                'LIBPCAP_STOPPED' ||
                'LIBPCAP_ERROR':
            PacketService._statusController.add(
              data?.toString() ?? event ?? 'Unknown Event',
            );
        }
      case 'onStatsUpdated':
        final stats = call.arguments;
        if (stats is String) {
          try {
            PacketService._handleNativeStats(jsonDecode(stats));
          } catch (_) {}
        } else {
          PacketService._handleNativeStats(stats);
        }
      case 'onStatusChanged':
        final status = call.arguments;
        if (status is Map<String, dynamic>) {
          PacketService._handleNativeStatus(status);
        } else if (status is String) {
          PacketService._handleNativeStatus({'status': status});
        }
      case 'onSessionsUpdated':
        PacketService._handleNativeSessions(call.arguments);
      case 'onMetricsUpdated':
        if (call.arguments is Map) {
          PacketService._handleNativeMetrics(
            Map<String, dynamic>.from(call.arguments as Map),
          );
        }
      case 'onDashboardUpdate':
        if (call.arguments is Map) {
          PacketService._handleDashboardUpdate(
            Map<String, dynamic>.from(call.arguments as Map),
          );
        }
      case 'onAnomalyDetected':
        // Handle real-time anomaly alerts from native anomaly detector
        if (call.arguments is Map) {
          _handleAnomaly(Map<String, dynamic>.from(call.arguments as Map));
        }
    }
  }

  void _handleAnomaly(Map<String, dynamic> data) {
    if (!mounted) return;
    final severity = data['severity']?.toString().toUpperCase() ?? 'LOW';
    final type = data['type']?.toString() ?? 'UNKNOWN';
    final description = data['description']?.toString() ?? '';
    final sourceIp = data['sourceIp']?.toString() ?? '';

    // Determine color based on severity: CRITICAL (red) > HIGH (orange) > MEDIUM (amber) > LOW (blue)
    final color = switch (severity) {
      'CRITICAL' => Colors.red.shade700,
      'HIGH' => Colors.orange.shade700,
      'MEDIUM' => Colors.amber.shade700,
      _ => Colors.blue.shade700,
    };

    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              type.replaceAll('_', ' '),
              style: const TextStyle(
                fontWeight: FontWeight.bold,
                color: Colors.white,
              ),
            ),
            if (description.isNotEmpty)
              Text(
                description,
                style: const TextStyle(color: Colors.white70, fontSize: 12),
              ),
            if (sourceIp.isNotEmpty)
              Text(
                'Source: $sourceIp',
                style: const TextStyle(color: Colors.white70, fontSize: 11),
              ),
          ],
        ),
        backgroundColor: color,
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        duration: const Duration(seconds: 4),
        margin: const EdgeInsets.all(16),
      ),
    );
  }

  void _initializeControllers() {
    _tabController = TabController(length: 4, vsync: this);
    _pulseController = AnimationController(
      duration: const Duration(milliseconds: 1200),
      vsync: this,
    );

    _pulseAnimation = Tween<double>(begin: 0.9, end: 1.1).animate(
      CurvedAnimation(parent: _pulseController, curve: Curves.easeInOut),
    );
  }

  void _setupStreamSubscriptions() {
    _packetSub = PacketService.packetStream.listen((packet) {
      _debounceTimer?.cancel();
      _debounceTimer = Timer(const Duration(milliseconds: 50), () {
        if (mounted) {
          setState(() {
            _packets.insert(0, packet);
            if (_packets.length > _maxPackets) {
              _packets.removeRange(_maxPackets ~/ 2, _packets.length);
            }
            _updateProtocolStatsRealtime();
          });

          if (_isCapturing) {
            _pulseController.forward().then((_) => _pulseController.reverse());
          }
        }
      });
    });

    _statusSub = PacketService.statusStream.listen((status) {
      if (mounted) setState(() => _currentStatus = status);
    });

    _metricsSub = PacketService.metricsStream.listen((metrics) {
      if (mounted) setState(() => _metrics = metrics);
    });

    // Anomaly subscription
    _anomalySub = PacketService.anomalyStream.listen((anomaly) {
      if (mounted) {
        setState(() {
          _anomalies.insert(0, anomaly);
          if (_anomalies.length > 100) {
            _anomalies.removeRange(50, _anomalies.length);
          }
        });
      }
    });
  }

  void _updateProtocolStatsRealtime() {
    if (_packets.isEmpty) {
      _protocolStats = [];
      return;
    }

    final Map<String, int> protocolCounts = {};
    for (final packet in _packets) {
      final protocol = packet.appName ?? packet.protocol;
      protocolCounts[protocol] = (protocolCounts[protocol] ?? 0) + 1;
    }

    final totalPackets = _packets.length;

    _protocolStats = protocolCounts.entries.map((entry) {
      final count = entry.value;
      final percentage = (count * 100.0 / totalPackets);

      return ProtocolStats(
        protocol: entry.key,
        packetCount: count,
        percentage: percentage,
      );
    }).toList();

    _protocolStats.sort((a, b) => b.packetCount.compareTo(a.packetCount));
  }

  Future<void> _initializeNativeBridge() async {
    try {
      _isRooted = await VpnController.checkRootAccess();
      _vpnPermissionGranted = await VpnController.prepareVpn();

      if (_isRooted && !_vpnPermissionGranted) {
        _selectedCaptureMode = CaptureMode.libpcap;
      } else {
        _selectedCaptureMode = CaptureMode.vpn;
      }

      try {
        _deviceInfo = await PacketService.getDeviceInfo();
        _networkInterfaces = await PacketService.getNetworkInterfaces();
        _systemStats = await PacketService.getSystemStats();
      } catch (e) {
        debugPrint("Device info unavailable: $e");
        _deviceInfo = 'Device info unavailable';
      }

      if (mounted) {
        setState(() {});
        _showSnackBar(
          "✅ Andronet initialized - Root: ${_isRooted ? 'Available' : 'Not Available'}, VPN: ${_vpnPermissionGranted ? 'Ready' : 'Permission Required'}",
          Colors.green,
          Icons.check_circle,
        );
      }
    } catch (e) {
      _showSnackBar(
        "❌ Initialization failed: ${e.toString()}",
        Colors.red,
        Icons.error,
      );
    }
  }

  Future<void> _startCapture() async {
    try {
      setState(() => _isCapturing = true);

      switch (_selectedCaptureMode) {
        case CaptureMode.vpn:
          if (!_vpnPermissionGranted) {
            final permitted = await VpnController.prepareVpn();
            if (!permitted) {
              _showVpnPermissionDialog();
              setState(() => _isCapturing = false);
              return;
            }
            _vpnPermissionGranted = true;
          }
          await VpnController.startVpn();
          break;
        case CaptureMode.libpcap:
          if (!_isRooted) {
            _showSnackBar(
              "Root access required for LibPCAP mode",
              Colors.red,
              Icons.error_outline,
            );
            setState(() => _isCapturing = false);
            return;
          }
          await VpnController.startLibpcapCapture();
          break;
        case CaptureMode.enhanced:
          if (!_vpnPermissionGranted) {
            final permitted = await VpnController.prepareVpn();
            if (!permitted) {
              _showVpnPermissionDialog();
              setState(() => _isCapturing = false);
              return;
            }
            _vpnPermissionGranted = true;
          }
          await VpnController.startEnhancedCapture();
          break;
      }

      _showSnackBar(
        "✅ ${_selectedCaptureMode == CaptureMode.vpn ? 'VPN' : 'LibPCAP'} capture started",
        Colors.green,
        Icons.play_circle_filled,
      );
    } catch (e) {
      setState(() => _isCapturing = false);
      _showSnackBar(
        "Error starting capture: ${e.toString()}",
        Colors.red,
        Icons.error,
      );
    }
  }

  Future<void> _stopCapture() async {
    try {
      _showSnackBar(
        "⏹️ Stopping capture...",
        Colors.orange,
        Icons.hourglass_empty,
      );

      switch (_selectedCaptureMode) {
        case CaptureMode.vpn:
          await VpnController.stopVpn();
          break;
        case CaptureMode.libpcap:
          await VpnController.stopLibpcapCapture();
          break;
        case CaptureMode.enhanced:
          await VpnController.stopEnhancedCapture();
          break;
      }

      await Future.delayed(const Duration(milliseconds: 500));

      setState(() => _isCapturing = false);
      _showSnackBar(
        "✅ Capture stopped successfully",
        Colors.green,
        Icons.check_circle,
      );
    } catch (e) {
      setState(() => _isCapturing = false);
      _showSnackBar(
        "Error stopping capture: ${e.toString()}",
        Colors.red,
        Icons.error,
      );
    }
  }

  Future<void> _toggleCapture() async {
    if (_isCapturing) {
      await _stopCapture();
    } else {
      await _startCapture();
    }
  }

  void _showVpnPermissionDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Row(
          children: [
            Icon(Icons.vpn_lock, color: Colors.blue),
            SizedBox(width: 8),
            Text('VPN Permission Required'),
          ],
        ),
        content: const Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('This app needs VPN permission to capture network packets.'),
            SizedBox(height: 12),
            Text(
              'When you tap "Grant Permission", Android will show a VPN permission dialog.',
            ),
            SizedBox(height: 8),
            Text('Please tap "OK" to allow packet capture.'),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton.icon(
            onPressed: () async {
              Navigator.pop(context);
              await _requestVpnPermission();
            },
            icon: const Icon(Icons.security),
            label: const Text('Grant Permission'),
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.blue,
              foregroundColor: Colors.white,
            ),
          ),
        ],
      ),
    );
  }

  Future<void> _requestVpnPermission() async {
    try {
      final permitted = await PacketService.checkVpnPermission();
      setState(() => _vpnPermissionGranted = permitted);

      if (permitted) {
        _showSnackBar(
          "✅ VPN permission granted",
          Colors.green,
          Icons.check_circle,
        );
        _toggleCapture();
      } else {
        _showSnackBar("❌ VPN permission denied", Colors.red, Icons.error);
      }
    } catch (e) {
      _showSnackBar(
        "Permission request failed: ${e.toString()}",
        Colors.red,
        Icons.error,
      );
    }
  }

  void _clearAllData() {
    setState(() {
      _packets.clear();
      _anomalies.clear();
    });
    PacketService.clearPackets();
    _showSnackBar("🗑️ All data cleared", Colors.blue, Icons.clear_all);
  }

  void _showSnackBar(String message, Color color, IconData icon) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Row(
          children: [
            Icon(icon, color: Colors.white, size: 20),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                message,
                style: const TextStyle(fontWeight: FontWeight.w500),
              ),
            ),
          ],
        ),
        backgroundColor: color,
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        duration: const Duration(seconds: 3),
        margin: const EdgeInsets.all(16),
      ),
    );
  }

  Color _protocolColor(String proto) {
    switch (proto.toUpperCase()) {
      case "TCP":
        return const Color(0xFF2196F3);
      case "UDP":
        return const Color(0xFF4CAF50);
      case "HTTP":
        return const Color(0xFFFF9800);
      case "HTTPS":
        return const Color(0xFF9C27B0);
      case "DNS":
        return const Color(0xFF00BCD4);
      case "ICMP":
        return const Color(0xFFF44336);
      case "SSH":
        return const Color(0xFF3F51B5);
      default:
        return const Color(0xFF607D8B);
    }
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '${bytes}B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)}KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)}MB';
  }

  List<PacketInfo> get _filteredPackets {
    if (_selectedProtocolFilter == "ALL") return _packets;
    return _packets
        .where((pkt) => pkt.protocol.toUpperCase() == _selectedProtocolFilter)
        .toList();
  }

  bool get isCapturing => _isCapturing;
  List<PacketInfo> get packets => _packets;
  List<ProtocolStats> get protocolStats => _protocolStats;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Theme.of(context).colorScheme.surface,
      appBar: _buildEnhancedAppBar(),
      body: Column(
        children: [
          _buildEnhancedMetricsPanel(),
          _buildModernTabBar(),
          Expanded(child: _buildTabContent()),
        ],
      ),
      floatingActionButton: _buildEnhancedFAB(),
      floatingActionButtonLocation: FloatingActionButtonLocation.endFloat,
    );
  }

  PreferredSizeWidget _buildEnhancedAppBar() {
    return AppBar(
      title: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.primaryContainer,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Icon(
              Icons.network_check,
              color: Theme.of(context).colorScheme.primary,
              size: 20,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  'Andronet',
                  style: TextStyle(
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                    color: Theme.of(context).colorScheme.onSurface,
                  ),
                ),
                Text(
                  _currentStatus,
                  style: TextStyle(
                    fontSize: 12,
                    color: Theme.of(
                      context,
                    ).colorScheme.onSurface.withValues(alpha: 0.7),
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
        ],
      ),
      backgroundColor: Theme.of(context).colorScheme.surface,
      actions: [
        _buildLiveStatusIndicator(),

        // Anomaly indicator badge
        if (_anomalies.isNotEmpty)
          IconButton(
            icon: Stack(
              children: [
                const Icon(Icons.security, color: Colors.red),
                Positioned(
                  right: 0,
                  top: 0,
                  child: Container(
                    padding: const EdgeInsets.all(1),
                    decoration: BoxDecoration(
                      color: Colors.red,
                      borderRadius: BorderRadius.circular(6),
                    ),
                    constraints: const BoxConstraints(
                      minWidth: 12,
                      minHeight: 12,
                    ),
                    child: Text(
                      _anomalies.length.toString(),
                      style: const TextStyle(color: Colors.white, fontSize: 8),
                      textAlign: TextAlign.center,
                    ),
                  ),
                ),
              ],
            ),
            onPressed: () {
              Navigator.of(context).push(
                MaterialPageRoute(
                  builder: (context) => AnomalyDashboard(
                    anomalyStream: PacketService.anomalyStream,
                  ),
                ),
              );
            },
            tooltip: 'View Anomalies',
          ),

        // Debug test anomaly button
        if (kDebugMode)
          IconButton(
            icon: const Icon(Icons.bug_report, color: Colors.purple),
            onPressed: _generateTestAnomaly,
            tooltip: 'Generate Test Anomaly',
          ),

        Consumer<AuthenticationService>(
          builder: (context, auth, child) {
            if (auth.currentAuthMethod != AuthMethod.none) {
              return IconButton(
                icon: const Icon(Icons.logout),
                onPressed: () => auth.logout(),
                tooltip: 'Logout',
              );
            }
            return const SizedBox.shrink();
          },
        ),
        PopupMenuButton<String>(
          icon: const Icon(Icons.more_vert),
          onSelected: _handleMenuSelection,
          itemBuilder: (context) => [
            const PopupMenuItem(
              value: 'mode',
              child: Text('Change Capture Mode'),
            ),
            const PopupMenuItem(
              value: 'vpn_permission',
              child: Text('Check VPN Permission'),
            ),
            const PopupMenuItem(
              value: 'anomalies',
              child: Row(
                children: [
                  Icon(Icons.security, size: 16, color: Colors.red),
                  SizedBox(width: 8),
                  Text('Anomaly Dashboard'),
                ],
              ),
            ),
            const PopupMenuItem(value: 'clear', child: Text('Clear All Data')),
            const PopupMenuItem(
              value: 'refresh',
              child: Text('Refresh System Info'),
            ),
            const PopupMenuItem(
              value: 'permissions',
              child: Text('Request Permissions'),
            ),
            const PopupMenuItem(
              value: 'security',
              child: Text('Security Settings'),
            ),
            const PopupMenuItem(value: 'settings', child: Text('Settings')),
            const PopupMenuItem(value: 'about', child: Text('About')),
          ],
        ),
      ],
    );
  }

  Widget _buildLiveStatusIndicator() {
    return Container(
      margin: const EdgeInsets.only(right: 12),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: _isCapturing
            ? Colors.green.withValues(alpha: 0.1)
            : Colors.grey.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: _isCapturing ? Colors.green : Colors.grey,
          width: 1,
        ),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          AnimatedBuilder(
            animation: _pulseAnimation,
            builder: (context, child) {
              return Transform.scale(
                scale: _isCapturing ? _pulseAnimation.value : 1.0,
                child: Container(
                  width: 6,
                  height: 6,
                  decoration: BoxDecoration(
                    color: _isCapturing ? Colors.green : Colors.grey,
                    shape: BoxShape.circle,
                  ),
                ),
              );
            },
          ),
          const SizedBox(width: 6),
          Text(
            _isCapturing ? 'LIVE' : 'OFF',
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.bold,
              color: _isCapturing ? Colors.green : Colors.grey,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildEnhancedMetricsPanel() {
    return Container(
      margin: const EdgeInsets.fromLTRB(16, 12, 16, 16),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [
            Theme.of(
              context,
            ).colorScheme.primaryContainer.withValues(alpha: 0.3),
            Theme.of(
              context,
            ).colorScheme.surfaceContainerHighest.withValues(alpha: 0.5),
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: Theme.of(context).colorScheme.outline.withValues(alpha: 0.2),
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              decoration: BoxDecoration(
                color: _selectedCaptureMode.color.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(
                  color: _selectedCaptureMode.color.withValues(alpha: 0.3),
                ),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(
                    _selectedCaptureMode.icon,
                    size: 18,
                    color: _selectedCaptureMode.color,
                  ),
                  const SizedBox(width: 8),
                  Text(
                    _selectedCaptureMode.title,
                    style: TextStyle(
                      fontSize: 14,
                      fontWeight: FontWeight.w600,
                      color: _selectedCaptureMode.color,
                    ),
                  ),
                  const SizedBox(width: 4),
                  if (_selectedCaptureMode == CaptureMode.vpn)
                    Container(
                      width: 8,
                      height: 8,
                      decoration: BoxDecoration(
                        color: _vpnPermissionGranted
                            ? Colors.green
                            : Colors.orange,
                        shape: BoxShape.circle,
                      ),
                    ),
                  const SizedBox(width: 4),
                  Container(
                    width: 8,
                    height: 8,
                    decoration: const BoxDecoration(
                      color: Colors.green,
                      shape: BoxShape.circle,
                    ),
                  ),
                  const SizedBox(width: 4),
                  InkWell(
                    onTap: _showCaptureModeSelector,
                    borderRadius: BorderRadius.circular(12),
                    child: Padding(
                      padding: const EdgeInsets.all(4),
                      child: Icon(
                        Icons.tune,
                        size: 16,
                        color: _selectedCaptureMode.color,
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                _buildMetricCard(
                  'Packets',
                  (_metrics?.totalPackets ?? _packets.length).toString(),
                  Icons.stream,
                  Colors.blue,
                ),
                const SizedBox(width: 8),
                _buildMetricCard(
                  'Rate',
                  '${(_metrics?.packetsPerSecond ?? 0).toStringAsFixed(1)}/s',
                  Icons.speed,
                  Colors.green,
                ),
                const SizedBox(width: 8),
                _buildMetricCard(
                  'Protocols',
                  _protocolStats.length.toString(),
                  Icons.category,
                  Colors.purple,
                ),
                const SizedBox(width: 8),
                _buildMetricCard(
                  'Anomalies',
                  _anomalies.length.toString(),
                  Icons.security,
                  _anomalies.isNotEmpty ? Colors.red : Colors.green,
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildMetricCard(
    String label,
    String value,
    IconData icon,
    Color color,
  ) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.05),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: color.withValues(alpha: 0.2)),
        ),
        child: Column(
          children: [
            Icon(icon, color: color, size: 18),
            const SizedBox(height: 4),
            Text(
              value,
              style: const TextStyle(fontSize: 14, fontWeight: FontWeight.bold),
              overflow: TextOverflow.ellipsis,
            ),
            Text(
              label,
              style: TextStyle(
                fontSize: 10,
                color: Theme.of(
                  context,
                ).colorScheme.onSurface.withValues(alpha: 0.6),
              ),
              overflow: TextOverflow.ellipsis,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildModernTabBar() {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 16),
      decoration: BoxDecoration(
        color: Theme.of(
          context,
        ).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
        borderRadius: BorderRadius.circular(12),
      ),
      child: TabBar(
        controller: _tabController,
        indicator: BoxDecoration(
          color: Theme.of(context).colorScheme.primary,
          borderRadius: BorderRadius.circular(10),
        ),
        labelColor: Colors.white,
        unselectedLabelColor: Theme.of(
          context,
        ).colorScheme.onSurface.withValues(alpha: 0.6),
        dividerColor: Colors.transparent,
        labelStyle: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600),
        unselectedLabelStyle: const TextStyle(fontSize: 12),
        tabs: const [
          Tab(text: 'Stream', icon: Icon(Icons.stream, size: 14)),
          Tab(text: 'Analytics', icon: Icon(Icons.analytics, size: 14)),
          Tab(text: 'Statistics', icon: Icon(Icons.bar_chart, size: 14)),
          Tab(text: 'System', icon: Icon(Icons.settings, size: 14)),
        ],
      ),
    );
  }

  Widget _buildTabContent() {
    return TabBarView(
      controller: _tabController,
      children: [
        _buildLiveStreamTab(),
        _buildAnalyticsTab(),
        _buildStatisticsTab(),
        _buildEnhancedSystemInfoTab(),
      ],
    );
  }

  Widget _buildLiveStreamTab() {
    return Column(
      children: [
        if (_packets.isNotEmpty) _buildProtocolFilter(),
        Expanded(child: _buildEnhancedPacketList()),
      ],
    );
  }

  Widget _buildProtocolFilter() {
    final protocols = <String>{"ALL"};
    protocols.addAll(_packets.map((p) => p.protocol.toUpperCase()).toSet());

    return Container(
      height: 44,
      margin: const EdgeInsets.fromLTRB(16, 8, 16, 0),
      child: ListView.builder(
        scrollDirection: Axis.horizontal,
        itemCount: protocols.length,
        itemBuilder: (context, index) {
          final protocol = protocols.elementAt(index);
          final isSelected = _selectedProtocolFilter == protocol;

          return Container(
            margin: const EdgeInsets.only(right: 8),
            child: FilterChip(
              label: Text(
                protocol,
                style: TextStyle(
                  fontSize: 11,
                  fontWeight: isSelected ? FontWeight.w600 : FontWeight.normal,
                ),
              ),
              selected: isSelected,
              selectedColor: _protocolColor(protocol).withValues(alpha: 0.2),
              checkmarkColor: _protocolColor(protocol),
              onSelected: (_) =>
                  setState(() => _selectedProtocolFilter = protocol),
              materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
              visualDensity: VisualDensity.compact,
            ),
          );
        },
      ),
    );
  }

  Widget _buildEnhancedPacketList() {
    final packets = _filteredPackets;

    if (packets.isEmpty) {
      return _buildEmptyState();
    }

    return Column(
      children: [
        // Anomaly Detection Panel (if there are anomalies)
        if (_anomalies.isNotEmpty)
          Card(
            margin: const EdgeInsets.fromLTRB(16, 8, 16, 0),
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Row(
                    children: [
                      const Icon(Icons.warning, color: Colors.orange, size: 20),
                      const SizedBox(width: 8),
                      const Text(
                        'Recent Anomalies',
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                          color: Colors.orange,
                        ),
                      ),
                      const Spacer(),
                      TextButton(
                        onPressed: () {
                          Navigator.of(context).push(
                            MaterialPageRoute(
                              builder: (context) => AnomalyDashboard(
                                anomalyStream: PacketService.anomalyStream,
                              ),
                            ),
                          );
                        },
                        child: const Text('View All'),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  ..._anomalies
                      .take(2)
                      .map(
                        (anomaly) => Container(
                          margin: const EdgeInsets.only(bottom: 8),
                          padding: const EdgeInsets.all(8),
                          decoration: BoxDecoration(
                            color: anomaly.severityColor.withValues(alpha: 0.1),
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(
                              color: anomaly.severityColor.withValues(
                                alpha: 0.3,
                              ),
                            ),
                          ),
                          child: Row(
                            children: [
                              Icon(
                                anomaly.typeIcon,
                                color: anomaly.severityColor,
                                size: 16,
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  anomaly.title,
                                  style: const TextStyle(
                                    fontSize: 12,
                                    fontWeight: FontWeight.w600,
                                  ),
                                ),
                              ),
                              Container(
                                padding: const EdgeInsets.symmetric(
                                  horizontal: 6,
                                  vertical: 2,
                                ),
                                decoration: BoxDecoration(
                                  color: anomaly.severityColor,
                                  borderRadius: BorderRadius.circular(8),
                                ),
                                child: Text(
                                  anomaly.severity,
                                  style: const TextStyle(
                                    color: Colors.white,
                                    fontSize: 10,
                                    fontWeight: FontWeight.bold,
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                ],
              ),
            ),
          ),

        Expanded(
          child: ListView.builder(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
            reverse: _autoScroll,
            itemCount: packets.length,
            itemBuilder: (context, index) {
              final packet =
                  packets[_autoScroll ? (packets.length - 1 - index) : index];
              return EnhancedPacketCard(packet: packet);
            },
          ),
        ),
      ],
    );
  }

  Widget _buildAnalyticsTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          if (_packets.isNotEmpty) ...[
            Card(
              color: Theme.of(
                context,
              ).colorScheme.primaryContainer.withValues(alpha: 0.3),
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceAround,
                  children: [
                    _buildQuickStat(
                      'Total',
                      _packets.length.toString(),
                      Icons.filter_list,
                    ),
                    _buildQuickStat(
                      'Protocols',
                      _protocolStats.length.toString(),
                      Icons.category,
                    ),
                    _buildQuickStat(
                      'Incoming',
                      _packets.where((p) => !p.isOutgoing).length.toString(),
                      Icons.arrow_downward,
                    ),
                    _buildQuickStat(
                      'Outgoing',
                      _packets.where((p) => p.isOutgoing).length.toString(),
                      Icons.arrow_upward,
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),
          ],

          _buildProtocolDistributionCard(),
          const SizedBox(height: 16),

          // ========== ANOMALY DETECTION SECTION ==========
          buildAnomalyDetectionCard(),
          const SizedBox(height: 16),

          _buildTrafficAnalyticsCard(),
        ],
      ),
    );
  }

  Widget _buildQuickStat(String label, String value, IconData icon) {
    return Column(
      children: [
        Icon(icon, size: 20, color: Theme.of(context).colorScheme.primary),
        const SizedBox(height: 4),
        Text(
          value,
          style: TextStyle(
            fontSize: 18,
            fontWeight: FontWeight.bold,
            color: Theme.of(context).colorScheme.primary,
          ),
        ),
        Text(
          label,
          style: TextStyle(
            fontSize: 11,
            color: Theme.of(
              context,
            ).colorScheme.onSurface.withValues(alpha: 0.6),
          ),
        ),
      ],
    );
  }

  Widget _buildProtocolDistributionCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.pie_chart,
                  color: Theme.of(context).colorScheme.primary,
                  size: 20,
                ),
                const SizedBox(width: 8),
                Text(
                  'Protocol Distribution',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                ),
                const Spacer(),
                if (_isCapturing && _packets.isNotEmpty) ...[
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: Colors.green.withValues(alpha: 0.1),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(
                        color: Colors.green.withValues(alpha: 0.3),
                      ),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Container(
                          width: 6,
                          height: 6,
                          decoration: const BoxDecoration(
                            color: Colors.green,
                            shape: BoxShape.circle,
                          ),
                        ),
                        const SizedBox(width: 6),
                        Text(
                          'LIVE',
                          style: TextStyle(
                            fontSize: 10,
                            fontWeight: FontWeight.bold,
                            color: Colors.green.shade700,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ],
            ),
            const SizedBox(height: 16),
            if (_protocolStats.isEmpty)
              const Center(
                child: Padding(
                  padding: EdgeInsets.all(32),
                  child: Text('No protocol data available'),
                ),
              )
            else ...[
              SizedBox(
                height: 200,
                child: AnimatedSwitcher(
                  duration: const Duration(milliseconds: 300),
                  child: PieChart(
                    key: ValueKey(_protocolStats.length),
                    PieChartData(
                      sections: _protocolStats.take(5).map((stat) {
                        final color = _protocolColor(stat.protocol);

                        return PieChartSectionData(
                          color: color,
                          value: stat.percentage,
                          title: '${stat.percentage.toStringAsFixed(1)}%',
                          radius: 50,
                          titleStyle: const TextStyle(
                            fontSize: 12,
                            fontWeight: FontWeight.bold,
                            color: Colors.white,
                          ),
                          titlePositionPercentageOffset: 0.6,
                        );
                      }).toList(),
                      sectionsSpace: 2,
                      centerSpaceRadius: 40,
                      pieTouchData: PieTouchData(
                        touchCallback: (FlTouchEvent event, pieTouchResponse) {
                          // Add touch feedback if desired
                        },
                      ),
                    ),
                  ),
                ),
              ),
              const SizedBox(height: 16),
              ..._protocolStats
                  .take(5)
                  .map((stat) => _buildProtocolStatRow(stat)),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildProtocolStatRow(ProtocolStats stat) {
    final protocolColor = _protocolColor(stat.protocol);

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      child: Row(
        children: [
          Container(
            width: 32,
            height: 32,
            decoration: BoxDecoration(
              color: protocolColor.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Center(
              child: Text(
                stat.protocol.isNotEmpty ? stat.protocol.substring(0, 1) : '?',
                style: TextStyle(
                  fontSize: 14,
                  color: protocolColor,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      stat.protocol,
                      style: const TextStyle(fontWeight: FontWeight.w600),
                    ),
                    Text(
                      '${stat.percentage.toStringAsFixed(1)}%',
                      style: const TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                ClipRRect(
                  borderRadius: BorderRadius.circular(2),
                  child: LinearProgressIndicator(
                    value: (stat.percentage / 100).clamp(0.0, 1.0),
                    backgroundColor: Colors.grey.shade200,
                    valueColor: AlwaysStoppedAnimation(protocolColor),
                    minHeight: 4,
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  '${stat.packetCount} packets',
                  style: TextStyle(
                    fontSize: 10,
                    color: Theme.of(
                      context,
                    ).colorScheme.onSurface.withValues(alpha: 0.6),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget buildAnomalyDetectionCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.security,
                  color: Theme.of(context).colorScheme.primary,
                  size: 20,
                ),
                const SizedBox(width: 8),
                Text(
                  'Security Anomalies',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                ),
                const Spacer(),
                if (isCapturing) ...[
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: Colors.green.withValues(alpha: 0.1),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(
                        color: Colors.green.withValues(alpha: 0.3),
                      ),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Container(
                          width: 6,
                          height: 6,
                          decoration: const BoxDecoration(
                            color: Colors.green,
                            shape: BoxShape.circle,
                          ),
                        ),
                        const SizedBox(width: 6),
                        Text(
                          'MONITORING',
                          style: TextStyle(
                            fontSize: 10,
                            fontWeight: FontWeight.bold,
                            color: Colors.green.shade700,
                          ),
                        ),
                      ],
                    ),
                  ),
                ] else ...[
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: Colors.grey.withValues(alpha: 0.1),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(
                        color: Colors.grey.withValues(alpha: 0.3),
                      ),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Container(
                          width: 6,
                          height: 6,
                          decoration: const BoxDecoration(
                            color: Colors.grey,
                            shape: BoxShape.circle,
                          ),
                        ),
                        const SizedBox(width: 6),
                        Text(
                          'IDLE',
                          style: TextStyle(
                            fontSize: 10,
                            fontWeight: FontWeight.bold,
                            color: Colors.grey.shade600,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ],
            ),
            const SizedBox(height: 16),

            if (_anomalies.isNotEmpty) ...[
              Row(
                children: [
                  buildSeverityChip(
                    'CRITICAL',
                    _anomalies
                        .where((a) => a.severity.toUpperCase() == 'CRITICAL')
                        .length,
                    const Color(0xFFD32F2F),
                  ),
                  const SizedBox(width: 8),
                  buildSeverityChip(
                    'HIGH',
                    _anomalies
                        .where((a) => a.severity.toUpperCase() == 'HIGH')
                        .length,
                    const Color(0xFFFF5722),
                  ),
                  const SizedBox(width: 8),
                  buildSeverityChip(
                    'MEDIUM',
                    _anomalies
                        .where((a) => a.severity.toUpperCase() == 'MEDIUM')
                        .length,
                    const Color(0xFFFF9800),
                  ),
                  const SizedBox(width: 8),
                  buildSeverityChip(
                    'LOW',
                    _anomalies
                        .where((a) => a.severity.toUpperCase() == 'LOW')
                        .length,
                    const Color(0xFFFFC107),
                  ),
                ],
              ),
              const SizedBox(height: 16),
            ],

            if (_anomalies.isEmpty) ...[
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(24),
                decoration: BoxDecoration(
                  color: Theme.of(
                    context,
                  ).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Column(
                  children: [
                    Icon(
                      Icons.shield_outlined,
                      size: 48,
                      color: Colors.green.shade300.withValues(alpha: 0.7),
                    ),
                    const SizedBox(height: 12),
                    Text(
                      'No Anomalies Detected',
                      style: TextStyle(
                        fontSize: 16,
                        fontWeight: FontWeight.bold,
                        color: Theme.of(context).colorScheme.onSurface,
                      ),
                    ),
                    const SizedBox(height: 4),
                    Text(
                      isCapturing
                          ? 'Network monitoring active'
                          : 'Start capture to monitor threats',
                      style: TextStyle(
                        fontSize: 12,
                        color: Colors.green.shade600,
                      ),
                    ),
                  ],
                ),
              ),
            ] else ...[
              ..._anomalies
                  .take(3)
                  .map((anomaly) => buildInlineAnomalyCard(anomaly)),

              if (_anomalies.length > 3) ...[
                const SizedBox(height: 12),
                SizedBox(
                  width: double.infinity,
                  child: OutlinedButton.icon(
                    onPressed: () {
                      Navigator.of(context).push(
                        MaterialPageRoute(
                          builder: (context) => AnomalyDashboard(
                            anomalyStream: PacketService.anomalyStream,
                          ),
                        ),
                      );
                    },
                    icon: const Icon(Icons.visibility),
                    label: Text('View All ${_anomalies.length} Anomalies'),
                    style: OutlinedButton.styleFrom(
                      foregroundColor: Theme.of(context).colorScheme.primary,
                      side: BorderSide(
                        color: Theme.of(
                          context,
                        ).colorScheme.primary.withValues(alpha: 0.5),
                      ),
                    ),
                  ),
                ),
              ],
            ],
          ],
        ),
      ),
    );
  }

  Widget buildSeverityChip(String severity, int count, Color color) {
    if (count == 0) return const SizedBox.shrink();

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withValues(alpha: 0.3)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            severity,
            style: TextStyle(
              fontSize: 11,
              fontWeight: FontWeight.bold,
              color: color,
            ),
          ),
          const SizedBox(width: 6),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 4, vertical: 1),
            decoration: BoxDecoration(
              color: color,
              borderRadius: BorderRadius.circular(8),
            ),
            child: Text(
              count.toString(),
              style: const TextStyle(
                fontSize: 10,
                fontWeight: FontWeight.bold,
                color: Colors.white,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget buildInlineAnomalyCard(AnomalyInfo anomaly) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Theme.of(
          context,
        ).colorScheme.surfaceContainerHighest.withValues(alpha: 0.3),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: anomaly.severityColor.withValues(alpha: 0.3),
          width: 1,
        ),
      ),
      child: InkWell(
        onTap: () => _showAnomalyDetails(anomaly),
        borderRadius: BorderRadius.circular(8),
        child: Row(
          children: [
            Container(
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: anomaly.severityColor.withValues(alpha: 0.1),
                borderRadius: BorderRadius.circular(6),
              ),
              child: Icon(
                anomaly.typeIcon,
                color: anomaly.severityColor,
                size: 16,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    anomaly.title,
                    style: TextStyle(
                      fontSize: 13,
                      fontWeight: FontWeight.w600,
                      color: Theme.of(context).colorScheme.onSurface,
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                  const SizedBox(height: 2),
                  Text(
                    anomaly.description,
                    style: TextStyle(
                      fontSize: 11,
                      color: Theme.of(
                        context,
                      ).colorScheme.onSurface.withValues(alpha: 0.7),
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ],
              ),
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
              decoration: BoxDecoration(
                color: anomaly.severityColor,
                borderRadius: BorderRadius.circular(10),
              ),
              child: Text(
                anomaly.severity.toUpperCase(),
                style: const TextStyle(
                  fontSize: 9,
                  fontWeight: FontWeight.bold,
                  color: Colors.white,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  void _showAnomalyDetails(AnomalyInfo anomaly) {
    showDialog(
      context: context,
      builder: (context) => Dialog(
        backgroundColor: Theme.of(context).colorScheme.surface,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        child: SingleChildScrollView(
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: anomaly.severityColor.withValues(alpha: 0.1),
                        borderRadius: BorderRadius.circular(12),
                      ),
                      child: Icon(
                        anomaly.typeIcon,
                        color: anomaly.severityColor,
                        size: 32,
                      ),
                    ),
                    const SizedBox(width: 16),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            anomaly.title,
                            style: TextStyle(
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                              color: Theme.of(context).colorScheme.onSurface,
                            ),
                          ),
                          const SizedBox(height: 4),
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 10,
                              vertical: 4,
                            ),
                            decoration: BoxDecoration(
                              color: anomaly.severityColor,
                              borderRadius: BorderRadius.circular(12),
                            ),
                            child: Text(
                              anomaly.severity.toUpperCase(),
                              style: const TextStyle(
                                color: Colors.white,
                                fontSize: 12,
                                fontWeight: FontWeight.bold,
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                    IconButton(
                      icon: Icon(
                        Icons.close,
                        color: Theme.of(
                          context,
                        ).colorScheme.onSurface.withValues(alpha: 0.7),
                      ),
                      onPressed: () => Navigator.pop(context),
                    ),
                  ],
                ),
                Divider(
                  height: 32,
                  color: Theme.of(
                    context,
                  ).colorScheme.outline.withValues(alpha: 0.2),
                ),
                buildDetailRow('Description', anomaly.description),
                const SizedBox(height: 12),
                buildDetailRow(
                  'Time',
                  '${anomaly.formattedDate} ${anomaly.formattedTime}',
                ),
                if (anomaly.sourceIp.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  buildDetailRow('Source IP', anomaly.sourceIp),
                ],
                if (anomaly.destinationIp.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  buildDetailRow('Destination IP', anomaly.destinationIp),
                ],
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget buildDetailRow(String label, String value) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 100,
          child: Text(
            label,
            style: TextStyle(
              fontSize: 13,
              fontWeight: FontWeight.w600,
              color: Theme.of(
                context,
              ).colorScheme.onSurface.withValues(alpha: 0.7),
            ),
          ),
        ),
        Expanded(
          child: SelectableText(
            value,
            style: TextStyle(
              fontSize: 13,
              color: Theme.of(context).colorScheme.onSurface,
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildTrafficAnalyticsCard() {
    final incomingPackets = _packets.where((p) => !p.isOutgoing).length;
    final outgoingPackets = _packets.where((p) => p.isOutgoing).length;

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.trending_up,
                  color: Theme.of(context).colorScheme.primary,
                  size: 20,
                ),
                const SizedBox(width: 8),
                Text(
                  'Traffic Analytics',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                _buildTrafficCard(
                  'Incoming',
                  incomingPackets.toString(),
                  Icons.arrow_downward,
                  Colors.green,
                ),
                const SizedBox(width: 12),
                _buildTrafficCard(
                  'Outgoing',
                  outgoingPackets.toString(),
                  Icons.arrow_upward,
                  Colors.blue,
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildTrafficCard(
    String title,
    String value,
    IconData icon,
    Color color,
  ) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.05),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: color.withValues(alpha: 0.2)),
        ),
        child: Column(
          children: [
            Icon(icon, color: color, size: 20),
            const SizedBox(height: 6),
            Text(
              value,
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.bold,
                color: color,
              ),
            ),
            Text(
              title,
              style: TextStyle(
                fontSize: 12,
                color: Theme.of(
                  context,
                ).colorScheme.onSurface.withValues(alpha: 0.6),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStatisticsTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          _buildNetworkSummaryCard(),
          const SizedBox(height: 16),
          _buildPerformanceMetricsCard(),
        ],
      ),
    );
  }

  Widget _buildNetworkSummaryCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.network_check,
                  color: Theme.of(context).colorScheme.primary,
                  size: 20,
                ),
                const SizedBox(width: 8),
                Text(
                  'Network Summary',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                _buildStatCard(
                  'Total Packets',
                  _packets.length.toString(),
                  Colors.blue,
                ),
                const SizedBox(width: 12),
                _buildStatCard(
                  'Data Volume',
                  _formatBytes(_packets.fold(0, (sum, p) => sum + p.size)),
                  Colors.green,
                ),
              ],
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                _buildStatCard(
                  'Unique IPs',
                  _getUniqueIPs().length.toString(),
                  Colors.orange,
                ),
                const SizedBox(width: 12),
                _buildStatCard(
                  'Avg Size',
                  _packets.isEmpty
                      ? '0B'
                      : _formatBytes(
                          _packets.fold(0, (sum, p) => sum + p.size) ~/
                              _packets.length,
                        ),
                  Colors.purple,
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildPerformanceMetricsCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.speed,
                  color: Theme.of(context).colorScheme.primary,
                  size: 20,
                ),
                const SizedBox(width: 8),
                Text(
                  'Performance Metrics',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                _buildStatCard(
                  'Packets/sec',
                  '${(_metrics?.packetsPerSecond ?? 0).toStringAsFixed(1)}',
                  Colors.cyan,
                ),
                const SizedBox(width: 12),
                _buildStatCard(
                  'Sessions',
                  (_metrics?.totalSessions ?? 0).toString(),
                  Colors.indigo,
                ),
              ],
            ),
            const SizedBox(height: 12),
            Row(
              children: [
                _buildStatCard(
                  'Protocols',
                  _protocolStats.length.toString(),
                  Colors.teal,
                ),
                const SizedBox(width: 12),
                _buildStatCard(
                  'Capture Time',
                  _getCaptureDuration(),
                  Colors.amber,
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildStatCard(String title, String value, Color color) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.05),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: color.withValues(alpha: 0.2)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              value,
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: color,
              ),
              overflow: TextOverflow.ellipsis,
            ),
            const SizedBox(height: 4),
            Text(
              title,
              style: TextStyle(
                fontSize: 12,
                color: Theme.of(
                  context,
                ).colorScheme.onSurface.withValues(alpha: 0.6),
              ),
              overflow: TextOverflow.ellipsis,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildEnhancedSystemInfoTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          _buildVpnControllerCard(),
          const SizedBox(height: 16),
          _buildDeviceInfoCard(),
          const SizedBox(height: 16),
          _buildNetworkInterfacesCard(),
          const SizedBox(height: 16),
          _buildSystemStatsCard(),
          const SizedBox(height: 16),
          _buildNativeBridgeStatusCard(),
        ],
      ),
    );
  }

  Widget _buildVpnControllerCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.vpn_lock,
                  color: Theme.of(context).colorScheme.primary,
                  size: 20,
                ),
                const SizedBox(width: 8),
                Text(
                  'VPN Controller',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            _buildInfoRow(
              'Permission Status',
              _vpnPermissionGranted ? 'Granted' : 'Required',
              _vpnPermissionGranted ? Colors.green : Colors.orange,
            ),
            _buildInfoRow(
              'VPN Status',
              _isCapturing && _selectedCaptureMode == CaptureMode.vpn
                  ? 'Active'
                  : 'Inactive',
              null,
            ),
            _buildInfoRow(
              'Root Status',
              _isRooted ? 'Available' : 'Not Available',
              _isRooted ? Colors.green : Colors.grey,
            ),
            _buildInfoRow(
              'Controller Type',
              'Enhanced VpnController + NetHunter',
              Colors.blue,
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: SegmentedButton<CaptureMode>(
                    segments: [
                      const ButtonSegment(
                        value: CaptureMode.vpn,
                        label: Text('VPN'),
                        icon: Icon(Icons.vpn_lock),
                      ),
                      if (_isRooted)
                        const ButtonSegment(
                          value: CaptureMode.libpcap,
                          label: Text('LibPCAP'),
                          icon: Icon(Icons.security),
                        ),
                    ],
                    selected: {_selectedCaptureMode},
                    onSelectionChanged: (Set<CaptureMode> newSelection) {
                      setState(() {
                        _selectedCaptureMode = newSelection.first;
                      });
                    },
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: _isCapturing ? null : _startCapture,
                    icon: const Icon(Icons.play_arrow),
                    label: Text(
                      _selectedCaptureMode == CaptureMode.vpn
                          ? "Start VPN"
                          : "Start LibPCAP",
                    ),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: _isCapturing
                          ? Colors.grey
                          : Colors.green,
                      foregroundColor: Colors.white,
                      disabledBackgroundColor: Colors.grey.shade300,
                      disabledForegroundColor: Colors.grey.shade600,
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: !_isCapturing ? null : _stopCapture,
                    icon: const Icon(Icons.stop),
                    label: Text(
                      _selectedCaptureMode == CaptureMode.vpn
                          ? "Stop VPN"
                          : "Stop LibPCAP",
                    ),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: !_isCapturing ? Colors.grey : Colors.red,
                      foregroundColor: Colors.white,
                      disabledBackgroundColor: Colors.grey.shade300,
                      disabledForegroundColor: Colors.grey.shade600,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            if (!_vpnPermissionGranted)
              SizedBox(
                width: double.infinity,
                child: ElevatedButton.icon(
                  onPressed: _requestVpnPermission,
                  icon: const Icon(Icons.security),
                  label: const Text("Request VPN Permission"),
                  style: ElevatedButton.styleFrom(
                    backgroundColor: Colors.orange,
                    foregroundColor: Colors.white,
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildDeviceInfoCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.phone_android,
                  color: Theme.of(context).colorScheme.primary,
                  size: 20,
                ),
                const SizedBox(width: 8),
                Text(
                  'Device Information',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            _buildInfoRow(
              'Root Status',
              _isRooted ? 'Available' : 'Not Available',
              _isRooted ? Colors.green : Colors.red,
            ),
            _buildInfoRow('Device Info', _deviceInfo, null),
            _buildInfoRow(
              'Selected Mode',
              _selectedCaptureMode.title,
              _selectedCaptureMode.color,
            ),
            _buildInfoRow('Native Bridge', 'Connected', Colors.green),
            _buildInfoRow(
              'VPN Permission',
              _vpnPermissionGranted ? 'Granted' : 'Required',
              _vpnPermissionGranted ? Colors.green : Colors.orange,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildNetworkInterfacesCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.network_wifi,
                  color: Theme.of(context).colorScheme.primary,
                  size: 20,
                ),
                const SizedBox(width: 8),
                Text(
                  'Network Interfaces',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            if (_networkInterfaces.isEmpty)
              const Text('No network interfaces detected')
            else
              ..._networkInterfaces.map(
                (interface) => Padding(
                  padding: const EdgeInsets.symmetric(vertical: 4),
                  child: Row(
                    children: [
                      const Icon(
                        Icons.network_cell,
                        size: 16,
                        color: Colors.blue,
                      ),
                      const SizedBox(width: 8),
                      Text(interface),
                    ],
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildSystemStatsCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.memory,
                  color: Theme.of(context).colorScheme.primary,
                  size: 20,
                ),
                const SizedBox(width: 8),
                Text(
                  'System Statistics',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            if (_systemStats.isEmpty)
              const Text('System stats unavailable')
            else
              ..._systemStats.entries.map(
                (entry) =>
                    _buildInfoRow(entry.key, entry.value.toString(), null),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildNativeBridgeStatusCard() {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  Icons.link,
                  color: Theme.of(context).colorScheme.primary,
                  size: 20,
                ),
                const SizedBox(width: 8),
                Text(
                  'Native Bridge Status',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 16),
            _buildInfoRow('Connection', 'Active', Colors.green),
            _buildInfoRow('VPN Controller', 'Integrated', Colors.blue),
            _buildInfoRow('Root Detection', 'Available', Colors.orange),
            _buildInfoRow('Anomaly Detection', 'Active', Colors.red),
            _buildInfoRow('Permission Handling', 'Enhanced', Colors.teal),
            const SizedBox(height: 16),
            Row(
              children: [
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: () => _initializeNativeBridge(),
                    icon: const Icon(Icons.refresh),
                    label: const Text('Refresh'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.blue,
                      foregroundColor: Colors.white,
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: () => PacketService.requestAllPermissions(),
                    icon: const Icon(Icons.security),
                    label: const Text('Permissions'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.green,
                      foregroundColor: Colors.white,
                    ),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildInfoRow(String label, String value, Color? valueColor) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Expanded(
            flex: 2,
            child: Text(
              label,
              style: const TextStyle(fontWeight: FontWeight.w500),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            flex: 3,
            child: Text(
              value,
              style: TextStyle(
                fontWeight: FontWeight.bold,
                color: valueColor ?? Theme.of(context).colorScheme.primary,
              ),
              textAlign: TextAlign.end,
              overflow: TextOverflow.ellipsis,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(
            Icons.network_check,
            size: 80,
            color: Theme.of(context).colorScheme.outline,
          ),
          const SizedBox(height: 16),
          Text(
            'No packets captured yet',
            style: Theme.of(context).textTheme.headlineSmall?.copyWith(
              color: Theme.of(context).colorScheme.onSurface,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            _isCapturing
                ? 'Waiting for network traffic...'
                : 'Start packet capture to see network activity',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
              color: Theme.of(
                context,
              ).colorScheme.onSurface.withValues(alpha: 0.7),
            ),
            textAlign: TextAlign.center,
          ),
          if (!_isCapturing) ...[
            const SizedBox(height: 24),
            ElevatedButton.icon(
              onPressed: _toggleCapture,
              icon: const Icon(Icons.play_arrow),
              label: const Text('Start Capture'),
              style: ElevatedButton.styleFrom(
                backgroundColor: Theme.of(context).colorScheme.primary,
                foregroundColor: Colors.white,
                padding: const EdgeInsets.symmetric(
                  horizontal: 24,
                  vertical: 12,
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildEnhancedFAB() {
    return FloatingActionButton.extended(
      onPressed: _toggleCapture,
      icon: AnimatedBuilder(
        animation: _pulseAnimation,
        builder: (context, child) {
          return Transform.scale(
            scale: _isCapturing ? _pulseAnimation.value : 1.0,
            child: Icon(_isCapturing ? Icons.stop : Icons.play_arrow),
          );
        },
      ),
      label: Text(_isCapturing ? 'Stop' : 'Start'),
      backgroundColor: _isCapturing ? Colors.red : Colors.green,
      foregroundColor: Colors.white,
    );
  }

  void _showCaptureModeSelector() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Select Capture Mode'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: CaptureMode.values.map((mode) {
            final isSelected = _selectedCaptureMode == mode;
            final isDisabled =
                (mode == CaptureMode.libpcap && !_isRooted) ||
                (mode == CaptureMode.vpn && !_vpnPermissionGranted);

            return Container(
              margin: const EdgeInsets.only(bottom: 8),
              child: Material(
                color: isSelected
                    ? mode.color.withValues(alpha: 0.1)
                    : Colors.transparent,
                borderRadius: BorderRadius.circular(8),
                child: InkWell(
                  onTap: isDisabled
                      ? null
                      : () {
                          setState(() => _selectedCaptureMode = mode);
                          Navigator.pop(context);
                        },
                  borderRadius: BorderRadius.circular(8),
                  child: Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      border: Border.all(
                        color: isSelected
                            ? mode.color
                            : Colors.grey.withValues(alpha: 0.3),
                      ),
                      borderRadius: BorderRadius.circular(8),
                    ),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Icon(
                              mode.icon,
                              color: isDisabled ? Colors.grey : mode.color,
                              size: 20,
                            ),
                            const SizedBox(width: 8),
                            Text(
                              mode.displayName,
                              style: TextStyle(
                                fontWeight: FontWeight.bold,
                                color: isDisabled
                                    ? Colors.grey
                                    : (isSelected ? mode.color : null),
                              ),
                            ),
                            if (isSelected)
                              const Spacer()
                            else
                              const SizedBox.shrink(),
                            if (isSelected)
                              Icon(Icons.check, color: mode.color, size: 16),
                            if (isDisabled)
                              const Icon(
                                Icons.lock,
                                color: Colors.grey,
                                size: 16,
                              ),
                          ],
                        ),
                        const SizedBox(height: 4),
                        Text(
                          mode.description,
                          style: TextStyle(
                            fontSize: 12,
                            color: isDisabled
                                ? Colors.grey
                                : Theme.of(context).colorScheme.onSurface
                                      .withValues(alpha: 0.7),
                          ),
                        ),
                        if (isDisabled) ...[
                          const SizedBox(height: 4),
                          Text(
                            mode == CaptureMode.libpcap
                                ? 'Requires root access'
                                : 'VPN permission required',
                            style: const TextStyle(
                              fontSize: 10,
                              color: Colors.red,
                              fontStyle: FontStyle.italic,
                            ),
                          ),
                        ],
                      ],
                    ),
                  ),
                ),
              ),
            );
          }).toList(),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
        ],
      ),
    );
  }

  void _handleMenuSelection(String value) {
    switch (value) {
      case 'mode':
        _showCaptureModeSelector();
        break;
      case 'vpn_permission':
        _requestVpnPermission();
        break;
      case 'anomalies':
        Navigator.of(context).push(
          MaterialPageRoute(
            builder: (context) =>
                AnomalyDashboard(anomalyStream: PacketService.anomalyStream),
          ),
        );
        break;
      case 'clear':
        _clearAllData();
        break;
      case 'refresh':
        _initializeNativeBridge();
        break;
      case 'permissions':
        PacketService.requestAllPermissions().then((success) {
          _showSnackBar(
            success ? 'Permissions granted' : 'Permission request failed',
            success ? Colors.green : Colors.red,
            success ? Icons.check_circle : Icons.error,
          );
        });
        break;
      case 'security':
        _showSecuritySettingsDialog();
        break;
      case 'settings':
        _showSettingsDialog();
        break;
      case 'about':
        _showAboutDialog();
        break;
    }
  }

  void _showSecuritySettingsDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Row(
          children: [
            Icon(Icons.security, color: Colors.red),
            SizedBox(width: 8),
            Text('Security Settings'),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Security Features:'),
            const SizedBox(height: 12),
            _buildSecurityOption('Anomaly Detection', _anomalies.isNotEmpty),
            _buildSecurityOption('Signature Database', true),
            _buildSecurityOption('Rule Engine', true),
            _buildSecurityOption('Traffic Analysis', true),
            _buildSecurityOption('Protocol Inspection', true),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  Widget _buildSecurityOption(String title, bool enabled) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Icon(
            enabled ? Icons.check_circle : Icons.cancel,
            color: enabled ? Colors.green : Colors.grey,
            size: 16,
          ),
          const SizedBox(width: 8),
          Text(title),
        ],
      ),
    );
  }

  void _showSettingsDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Row(
          children: [
            Icon(Icons.settings, color: Colors.blue),
            SizedBox(width: 8),
            Text('Settings'),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            ListTile(
              title: const Text('Auto-scroll packets'),
              trailing: Switch(
                value: _autoScroll,
                onChanged: (value) {
                  setState(() => _autoScroll = value);
                  Navigator.pop(context);
                },
              ),
              contentPadding: EdgeInsets.zero,
            ),
            ListTile(
              title: const Text('Max packets limit'),
              subtitle: Text('$_maxPackets packets'),
              trailing: const Icon(Icons.info_outline),
              contentPadding: EdgeInsets.zero,
            ),
            ListTile(
              title: const Text('Anomaly notifications'),
              trailing: Switch(
                value: true,
                onChanged: (value) {
                  Navigator.pop(context);
                },
              ),
              contentPadding: EdgeInsets.zero,
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  void _showAboutDialog() {
    showDialog(
      context: context,
      builder: (context) => AboutDialog(
        applicationName: 'Andronet',
        applicationVersion: '2.0.0',
        applicationIcon: Container(
          padding: const EdgeInsets.all(8),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.primaryContainer,
            borderRadius: BorderRadius.circular(8),
          ),
          child: Icon(
            Icons.network_check,
            color: Theme.of(context).colorScheme.primary,
            size: 32,
          ),
        ),
        children: [
          const Text(
            'Advanced Network Packet Analyzer with AI-powered Anomaly Detection',
          ),
          const SizedBox(height: 16),
          const Text('Features:'),
          const SizedBox(height: 8),
          const Text('• VPN & Root packet capture'),
          const Text('• Real-time protocol analysis'),
          const Text('• AI-powered security anomaly detection'),
          const Text('• 18+ threat signatures'),
          const Text('• 10+ behavioral rules'),
          const Text('• Enhanced UI with Material 3'),
          const Text('• Native bridge integration'),
          const SizedBox(height: 16),
          Text(
            'Developed by CipherSec',
            style: TextStyle(
              fontWeight: FontWeight.bold,
              color: Theme.of(context).colorScheme.primary,
            ),
          ),
        ],
      ),
    );
  }

  void _generateTestAnomaly() {
    final testAnomaly = AnomalyInfo(
      type: 'UNUSUAL_TRAFFIC',
      severity: 'HIGH',
      title: 'Test Security Alert',
      description: 'This is a test anomaly for UI verification',
      sourceIp: '192.168.1.100',
      destinationIp: '8.8.8.8',
      timestamp: DateTime.now().millisecondsSinceEpoch.toString(),
      details: {
        'testMode': true,
        'generatedBy': 'Flutter UI',
        'purpose': 'Testing anomaly display',
      },
    );

    PacketService._anomalyController.add(testAnomaly);
    _showSnackBar('Test anomaly generated!', Colors.purple, Icons.bug_report);
  }

  // Helper methods for statistics
  Set<String> _getUniqueIPs() {
    final ips = <String>{};
    for (final packet in _packets) {
      ips.add(packet.sourceIp);
      ips.add(packet.destinationIp);
    }
    return ips;
  }

  String _getCaptureDuration() {
    if (_packets.isEmpty) return '0s';

    try {
      final timestamps = _packets
          .map((p) => int.tryParse(p.timestamp) ?? 0)
          .where((t) => t > 0)
          .toList();

      if (timestamps.isEmpty) return '0s';

      timestamps.sort();
      final duration = timestamps.last - timestamps.first;

      if (duration < 1000) return '${duration}ms';
      if (duration < 60000) return '${(duration / 1000).toStringAsFixed(1)}s';
      return '${(duration / 60000).toStringAsFixed(1)}m';
    } catch (e) {
      return '0s';
    }
  }

  @override
  void dispose() {
    _packetSub?.cancel();
    _statusSub?.cancel();
    _metricsSub?.cancel();
    _statsSub?.cancel();
    _anomalySub?.cancel();
    _debounceTimer?.cancel();
    _tabController.dispose();
    _pulseController.dispose();
    super.dispose();
  }
}
