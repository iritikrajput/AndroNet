import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:provider/provider.dart';
import 'dart:async';
import 'dart:convert';
import 'dart:math' as math;
import 'auth/auth_service.dart';
import 'auth/auth_wrapper.dart';
import 'auth/login_screen.dart';
import 'auth/setup_auth_screen.dart';
import 'enhanced_ui_components.dart';

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
        print("📥 onPacketEvent called with args: ${call.arguments}"); // Debug log
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
            PacketService._statusController.add(data?.toString() ?? event ?? "Unknown Event");
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

  // ================= ENHANCED CAPTURE METHODS (PCAPdroid-inspired) =================

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
          PacketService._statusController.add("Enhanced Capture Start Failed: $e");
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

  // Enhanced packet capture controls
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


// ================= ENHANCED MODELS =================
class PacketInfo {
  final String sourceIp, destinationIp, protocol, timestamp, payload;
  final int sourcePort, destinationPort, size;
  final String? direction, flags, appName;
  final double? anomalyScore;
  final Map<String, dynamic>? payloadAnalysis;
  final Map<String, dynamic>? httpData;
  final Map<String, dynamic>? dnsData;
  final Map<String, dynamic>? tlsData;
  final Map<String, dynamic>? quicData;

  const PacketInfo({
    required this.sourceIp,
    required this.destinationIp,
    required this.sourcePort,
    required this.destinationPort,
    required this.protocol,
    required this.size,
    required this.timestamp,
    required this.payload,
    this.direction,
    this.flags,
    this.appName,
    this.anomalyScore,
    this.payloadAnalysis,
    this.httpData,
    this.dnsData,
    this.tlsData,
    this.quicData,
  });

  factory PacketInfo.fromMap(Map<String, dynamic> map) => PacketInfo(
    sourceIp: map['sourceIp']?.toString() ?? '',
    destinationIp: map['destinationIp']?.toString() ?? '',
    sourcePort: int.tryParse(map['sourcePort'].toString()) ?? 0,
    destinationPort: int.tryParse(map['destinationPort'].toString()) ?? 0,
    protocol: map['protocol']?.toString() ?? 'UNK',
    size: int.tryParse(map['size'].toString()) ?? 0,
    timestamp:
        map['timestamp']?.toString() ??
        DateTime.now().millisecondsSinceEpoch.toString(),
    payload: map['payload']?.toString() ?? '',
    direction: map['direction']?.toString(),
    flags: map['flags']?.toString(),
    appName: map['appName']?.toString(),
    anomalyScore: map['anomalyScore'] != null ? double.tryParse(map['anomalyScore'].toString()) : null,
    payloadAnalysis: map['payloadAnalysis'] as Map<String, dynamic>?,
    httpData: map['httpData'] as Map<String, dynamic>?,
    dnsData: map['dnsData'] as Map<String, dynamic>?,
    tlsData: map['tlsData'] as Map<String, dynamic>?,
    quicData: map['quicData'] as Map<String, dynamic>?,
  );

  String get formattedTime {
    try {
      final time = DateTime.fromMillisecondsSinceEpoch(int.parse(timestamp));
      return '${time.hour.toString().padLeft(2, '0')}:${time.minute.toString().padLeft(2, '0')}:${time.second.toString().padLeft(2, '0')}';
    } catch (e) {
      return timestamp.substring(0, math.min(8, timestamp.length));
    }
  }

  bool get isOutgoing =>
      direction?.toUpperCase() == 'OUT' ||
      direction?.toUpperCase() == 'OUTGOING';
  String get displayDirection => isOutgoing ? 'OUT' : 'IN';
  Color get directionColor =>
      isOutgoing ? const Color(0xFF2196F3) : const Color(0xFF4CAF50);
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

// Anomaly Information Model
class AnomalyInfo {
  final String id;
  final String type;
  final String severity;
  final String title;
  final String description;
  final String timestamp;

  const AnomalyInfo({
    required this.id,
    required this.type,
    required this.severity,
    required this.title,
    required this.description,
    required this.timestamp,
  });
}

// ================= ENHANCED PACKET SERVICE WITH VPN CONTROLLER =================
class PacketService {
  static const MethodChannel _channel = MethodChannel('packet_analyzer');
  static const EventChannel _packetEventChannel = EventChannel('packet_stream');

  static final _packetController = StreamController<PacketInfo>.broadcast();
  static final _statusController = StreamController<String>.broadcast();
  static final _metricsController =
      StreamController<NetworkMetrics>.broadcast();
  static final _statsController =
      StreamController<List<ProtocolStats>>.broadcast();

  static Stream<PacketInfo> get packetStream => _packetController.stream;
  static Stream<String> get statusStream => _statusController.stream;
  static Stream<NetworkMetrics> get metricsStream => _metricsController.stream;
  static Stream<List<ProtocolStats>> get statsStream => _statsController.stream;

  static final _buffer = <Map<String, dynamic>>[];
  static Timer? _flushTimer;
  static Timer? _statsTimer;
  static StreamSubscription? _eventChannelSubscription;

  static Future<void> initialize() async {
    _flushTimer ??= Timer.periodic(
      const Duration(milliseconds: 150),
      (_) => _flush(),
    );

    // Mock stats disabled - using only real packet statistics
    // _statsTimer ??= Timer.periodic(
    //   const Duration(seconds: 3),
    //   (_) => _generateMockStats(),
    // );

    // Listen to EventChannel for real-time packet streaming from Go layer
    _eventChannelSubscription ??= _packetEventChannel
        .receiveBroadcastStream()
        .listen((dynamic event) {
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
        print("✅ EventChannel PacketInfo: ${packet.protocol} ${packet.sourceIp}:${packet.sourcePort} → ${packet.destinationIp}:${packet.destinationPort}");
        _packetController.add(packet);

      } catch (e) {
        print("❌ Error processing EventChannel packet: $e");
        print("❌ Raw event: $event");
      }
    }, onError: (error) {
      print("❌ EventChannel error: $error");
    });
  }

  static void disposeService() {
    _flushTimer?.cancel();
    // _statsTimer?.cancel(); // No longer needed - mock stats disabled
    _eventChannelSubscription?.cancel();
    _packetController.close();
    _statusController.close();
    _metricsController.close();
    _statsController.close();
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

  static void _flush() {
    if (_buffer.isEmpty) return;
    final batch = List<Map<String, dynamic>>.from(_buffer);
    print("🚀 Flutter flushing ${batch.length} packets to UI"); // Debug log
    _buffer.clear();
    for (final m in batch) {
      try {
        final packet = PacketInfo.fromMap(m);
        print("✅ Created PacketInfo: ${packet.protocol} ${packet.sourceIp}:${packet.sourcePort} → ${packet.destinationIp}:${packet.destinationPort}"); // Debug log
        _packetController.add(packet);
      } catch (e) {
        print("❌ Error creating PacketInfo from map: $e"); // Debug log
        print("❌ Problematic map: $m"); // Debug log
      }
    }
  }

  // Mock stats function removed - using only real packet statistics

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

  // Enhanced Capture Methods via NativeBridge
  static Future<bool> startRootCapture() async {
    try {
      final success = await NativeBridge.startRootCapture();
      if (success) {
        _statusController.add("Root Capture Started");
      } else {
        _statusController.add("Root Capture Failed");
      }
      return success;
    } catch (e) {
      _statusController.add("Root Capture Error: ${e.toString()}");
      return false;
    }
  }

  static Future<bool> stopRootCapture() async {
    try {
      final success = await NativeBridge.stopRootCapture();
      if (success) {
        _statusController.add("Root Capture Stopped");
      } else {
        _statusController.add("Root Capture Stop Failed");
      }
      return success;
    } catch (e) {
      _statusController.add("Root Capture Stop Error: ${e.toString()}");
      return false;
    }
  }

  static Future<bool> startPcapCapture() async {
    try {
      final success = await NativeBridge.startPcapCapture();
      if (success) {
        _statusController.add("PCAP Capture Started");
      } else {
        _statusController.add("PCAP Capture Failed");
      }
      return success;
    } catch (e) {
      _statusController.add("PCAP Capture Error: ${e.toString()}");
      return false;
    }
  }

  static Future<bool> stopPcapCapture() async {
    try {
      final success = await NativeBridge.stopPcapCapture();
      if (success) {
        _statusController.add("PCAP Capture Stopped");
      } else {
        _statusController.add("PCAP Capture Stop Failed");
      }
      return success;
    } catch (e) {
      _statusController.add("PCAP Capture Stop Error: ${e.toString()}");
      return false;
    }
  }

  // Enhanced Export via NativeBridge
  static Future<String?> exportPackets() async {
    try {
      final packetData = {
        'packets': _buffer,
        'count': _buffer.length,
        'timestamp': DateTime.now().millisecondsSinceEpoch,
      };
      final result = await NativeBridge.exportData(packetData);
      return result.contains("Error") ? null : result;
    } catch (e) {
      debugPrint("Error exporting packets: $e");
      return null;
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
              surfaceVariant: const Color(0xFFF1F3F4),
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
  List<ProtocolStats> _protocolStats = [];
  String _currentStatus = 'Ready';
  NetworkMetrics? _metrics;
  String _selectedProtocolFilter = "ALL";
  bool _autoScroll = true;
  int _selectedTabIndex = 0;

  // Device and system information
  String _deviceInfo = 'Unknown';
  List<String> _networkInterfaces = [];
  Map<String, dynamic> _systemStats = {};

  // Subscriptions
  StreamSubscription<PacketInfo>? _packetSub;
  StreamSubscription<String>? _statusSub;
  StreamSubscription<NetworkMetrics>? _metricsSub;
  StreamSubscription<List<ProtocolStats>>? _statsSub;

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
    _initializeControllers();
    _setupStreamSubscriptions();
    _initializeNativeBridge();
  }

  void _initializeControllers() {
    _tabController = TabController(length: 4, vsync: this);
    _tabController.addListener(() {
      if (mounted) setState(() => _selectedTabIndex = _tabController.index);
    });

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
      _debounceTimer = Timer(const Duration(milliseconds: 100), () {
        if (mounted) {
          setState(() {
            _packets.insert(0, packet);
            if (_packets.length > _maxPackets) {
              _packets.removeRange(_maxPackets ~/ 2, _packets.length);
            }
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

    _statsSub = PacketService.statsStream.listen((stats) {
      if (mounted) setState(() => _protocolStats = stats);
    });
  }

  // ================= ENHANCED NATIVE BRIDGE INITIALIZATION =================
  Future<void> _initializeNativeBridge() async {
    try {
      // Check root status for NetHunter functionality
      _isRooted = await VpnController.checkRootAccess();

      // Check VPN permission status
      _vpnPermissionGranted = await VpnController.prepareVpn();

      // Set default capture mode based on capabilities
      if (_isRooted && !_vpnPermissionGranted) {
        _selectedCaptureMode = CaptureMode.libpcap;
      } else {
        _selectedCaptureMode = CaptureMode.vpn;
      }

      // Get device information (if available)
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

  // ================= ENHANCED CAPTURE CONTROL WITH VPN + LIBPCAP =================
  Future<void> _startCapture() async {
    try {
      setState(() => _isCapturing = true);

      switch (_selectedCaptureMode) {
        case CaptureMode.vpn:
          // Check VPN permission first
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
          // Check VPN permission first
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
      _showSnackBar("Error starting capture: ${e.toString()}", Colors.red, Icons.error);
    }
  }

  Future<void> _stopCapture() async {
    try {
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

      setState(() => _isCapturing = false);
      _showSnackBar(
        "⏹️ Capture stopped",
        Colors.orange,
        Icons.stop_circle,
      );
    } catch (e) {
      _showSnackBar("Error stopping capture: ${e.toString()}", Colors.red, Icons.error);
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
        // Automatically start VPN after permission is granted
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

  Future<void> _exportPackets() async {
    try {
      final path = await PacketService.exportPackets();
      if (path != null && mounted) {
        _showSnackBar(
          "✅ Exported to: $path",
          Colors.green,
          Icons.file_download,
        );
      } else {
        _showSnackBar("❌ Export failed", Colors.red, Icons.error);
      }
    } catch (e) {
      _showSnackBar("Export error: ${e.toString()}", Colors.red, Icons.error);
    }
  }

  void _clearAllData() {
    setState(() => _packets.clear());
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

  // UI Helper Methods
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

  // ================= ENHANCED UI COMPONENTS =================

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
                    ).colorScheme.onSurface.withOpacity(0.7),
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
        IconButton(
          icon: const Icon(Icons.file_download),
          onPressed: _exportPackets,
          tooltip: 'Export Packets',
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
            ? Colors.green.withOpacity(0.1)
            : Colors.grey.withOpacity(0.1),
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
            Theme.of(context).colorScheme.primaryContainer.withOpacity(0.3),
            Theme.of(context).colorScheme.surfaceVariant.withOpacity(0.5),
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: Theme.of(context).colorScheme.outline.withOpacity(0.2),
        ),
      ),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          children: [
            // Enhanced Capture Mode Indicator with VPN Permission Status
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
              decoration: BoxDecoration(
                color: _selectedCaptureMode.color.withOpacity(0.1),
                borderRadius: BorderRadius.circular(20),
                border: Border.all(
                  color: _selectedCaptureMode.color.withOpacity(0.3),
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
                  // VPN Permission indicator
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
                  // Native Bridge indicator
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
            // Enhanced Metrics Grid
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
                  'Size',
                  _formatBytes(_packets.fold(0, (sum, p) => sum + p.size)),
                  Icons.data_usage,
                  Colors.orange,
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
          color: color.withOpacity(0.05),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: color.withOpacity(0.2)),
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
                color: Theme.of(context).colorScheme.onSurface.withOpacity(0.6),
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
        color: Theme.of(context).colorScheme.surfaceVariant.withOpacity(0.3),
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
        ).colorScheme.onSurface.withOpacity(0.6),
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
        _buildEnhancedSystemInfoTab(), // Enhanced with VPN permission info
      ],
    );
  }

  // ================= ENHANCED SYSTEM INFO TAB WITH VPN CONTROLLER =================
  Widget _buildEnhancedSystemInfoTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          _buildVpnControllerCard(), // New VPN Controller card
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
            // Capture Mode Selection
            Row(
              children: [
                Expanded(
                  child: SegmentedButton<CaptureMode>(
                    segments: [
                      ButtonSegment(
                        value: CaptureMode.vpn,
                        label: Text('VPN'),
                        icon: Icon(Icons.vpn_lock),
                      ),
                      if (_isRooted)
                        ButtonSegment(
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
            // Capture Control Buttons
            Row(
              children: [
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: _startCapture,
                    icon: const Icon(Icons.play_arrow),
                    label: Text(_selectedCaptureMode == CaptureMode.vpn ? "Start VPN" : "Start LibPCAP"),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.green,
                      foregroundColor: Colors.white,
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: ElevatedButton.icon(
                    onPressed: _stopCapture,
                    icon: const Icon(Icons.stop),
                    label: Text(_selectedCaptureMode == CaptureMode.vpn ? "Stop VPN" : "Stop LibPCAP"),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Colors.red,
                      foregroundColor: Colors.white,
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
                      Icon(Icons.network_cell, size: 16, color: Colors.blue),
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
            _buildInfoRow('Data Export', 'Available', Colors.purple),
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
            child: Text(label, style: const TextStyle(fontWeight: FontWeight.w500)),
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

  // [REST OF THE UI METHODS - Include all from previous version with minor modifications]

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
              selectedColor: _protocolColor(protocol).withOpacity(0.2),
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
        if (_shouldShowAnomalyPanel())
          AnomalyDetectionPanel(
            anomalies: _getActiveAnomalies(),
            onClearAnomalies: _clearAnomalies,
          ),

        // File Carving Panel (if files detected)
        if (_shouldShowFileCarvingPanel())
          FileCarvingPanel(
            payloadAnalysis: _getLatestFileAnalysis(),
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

  // ================= DIALOG & UTILITY METHODS =================

  void _showPacketDetails(PacketInfo packet) {
    showDialog(
      context: context,
      builder: (context) => EnhancedPacketDetailsDialog(packet: packet),
    );
  }

  Widget _buildAnalyticsTab() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          _buildProtocolDistributionCard(),
          const SizedBox(height: 16),
          _buildTrafficAnalyticsCard(),
        ],
      ),
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
            else
              ..._protocolStats
                  .take(5)
                  .map((stat) => _buildProtocolStatRow(stat)),
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
              color: protocolColor.withOpacity(0.1),
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
                    ).colorScheme.onSurface.withOpacity(0.6),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
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
          color: color.withOpacity(0.05),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: color.withOpacity(0.2)),
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
                color: Theme.of(context).colorScheme.onSurface.withOpacity(0.6),
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
            _buildSummaryRow('Total Packets', _packets.length.toString()),
            _buildSummaryRow(
              'Unique Protocols',
              _protocolStats.length.toString(),
            ),
            _buildSummaryRow('Capture Mode', _selectedCaptureMode.title),
            _buildSummaryRow(
              'Device Status',
              _isRooted ? 'Rooted' : 'Standard',
            ),
            _buildSummaryRow(
              'VPN Permission',
              _vpnPermissionGranted ? 'Granted' : 'Required',
            ),
            if (_metrics != null) ...[
              _buildSummaryRow(
                'Packet Rate',
                '${_metrics!.packetsPerSecond.toStringAsFixed(1)}/s',
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildPerformanceMetricsCard() {
    final avgPacketSize = _packets.isNotEmpty
        ? _packets.map((p) => p.size).reduce((a, b) => a + b) / _packets.length
        : 0.0;

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
            _buildSummaryRow(
              'Average Packet Size',
              '${avgPacketSize.toStringAsFixed(1)} bytes',
            ),
            _buildSummaryRow(
              'Buffer Utilization',
              '${(_packets.length / _maxPackets * 100).toStringAsFixed(1)}%',
            ),
            _buildSummaryRow(
              'Capture Status',
              _isCapturing ? 'Active' : 'Stopped',
            ),
            _buildSummaryRow('Performance Mode', 'VpnController Enhanced'),
          ],
        ),
      ),
    );
  }

  Widget _buildSummaryRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: const TextStyle(fontWeight: FontWeight.w500)),
          Text(
            value,
            style: TextStyle(
              fontWeight: FontWeight.bold,
              color: Theme.of(context).colorScheme.primary,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.stream, size: 64, color: Colors.grey.shade400),
            const SizedBox(height: 16),
            Text(
              'No packets captured yet',
              style: TextStyle(
                fontSize: 18,
                color: Colors.grey.shade600,
                fontWeight: FontWeight.w500,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Start capturing to monitor network traffic',
              style: TextStyle(fontSize: 14, color: Colors.grey.shade500),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),
            FilledButton.icon(
              onPressed: _toggleCapture,
              icon: const Icon(Icons.play_arrow),
              label: const Text('Start Capture'),
              style: FilledButton.styleFrom(
                backgroundColor: _selectedCaptureMode.color,
                foregroundColor: Colors.white,
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ================= ENHANCED UI HELPERS =================

  bool _shouldShowAnomalyPanel() {
    // Show if there are packets with high anomaly scores or security flags
    return _packets.any((packet) =>
      (packet.anomalyScore != null && packet.anomalyScore! > 0.7) ||
      (packet.payloadAnalysis?['securityFlags'] != null &&
       (packet.payloadAnalysis!['securityFlags'] as List).isNotEmpty)
    );
  }

  List<AnomalyInfo> _getActiveAnomalies() {
    return _packets
        .where((packet) =>
            (packet.anomalyScore != null && packet.anomalyScore! > 0.7) ||
            (packet.payloadAnalysis?['securityFlags'] != null &&
             (packet.payloadAnalysis!['securityFlags'] as List).isNotEmpty))
        .take(5)
        .map((packet) => AnomalyInfo(
          id: '${packet.sourceIp}_${packet.timestamp}',
          type: _getAnomalyType(packet),
          severity: _getAnomalySeverity(packet),
          title: _getAnomalyTitle(packet),
          description: _getAnomalyDescription(packet),
          timestamp: packet.formattedTime,
        ))
        .toList();
  }

  void _clearAnomalies() {
    setState(() {
      // Remove packets with anomalies or mark them as reviewed
      _packets.removeWhere((packet) =>
        (packet.anomalyScore != null && packet.anomalyScore! > 0.7) ||
        (packet.payloadAnalysis?['securityFlags'] != null &&
         (packet.payloadAnalysis!['securityFlags'] as List).isNotEmpty)
      );
    });
  }

  bool _shouldShowFileCarvingPanel() {
    // Show if there are packets with file detection or extraction
    return _packets.any((packet) =>
      (packet.payloadAnalysis?['detectedFiles'] != null &&
       (packet.payloadAnalysis!['detectedFiles'] as List).isNotEmpty) ||
      (packet.payloadAnalysis?['extractedFiles'] != null &&
       (packet.payloadAnalysis!['extractedFiles'] as List).isNotEmpty)
    );
  }

  Map<String, dynamic> _getLatestFileAnalysis() {
    // Get the most recent packet with file analysis
    for (var packet in _packets.reversed) {
      if (packet.payloadAnalysis != null) {
        return packet.payloadAnalysis!;
      }
    }
    return {};
  }

  String _getAnomalyType(PacketInfo packet) {
    if (packet.anomalyScore != null && packet.anomalyScore! > 0.8) {
      return 'unusual_traffic';
    }
    if (packet.payloadAnalysis?['securityFlags'] != null) {
      final flags = packet.payloadAnalysis!['securityFlags'] as List;
      if (flags.contains('EXECUTABLE_CONTENT_DETECTED')) return 'malicious_content';
      if (flags.contains('SUSPICIOUS_CODE_EXECUTION')) return 'suspicious_activity';
    }
    return 'unusual_traffic';
  }

  String _getAnomalySeverity(PacketInfo packet) {
    if (packet.anomalyScore != null && packet.anomalyScore! > 0.9) return 'critical';
    if (packet.anomalyScore != null && packet.anomalyScore! > 0.8) return 'high';
    if (packet.payloadAnalysis?['securityFlags'] != null) return 'medium';
    return 'low';
  }

  String _getAnomalyTitle(PacketInfo packet) {
    if (packet.anomalyScore != null && packet.anomalyScore! > 0.8) {
      return 'Unusual Traffic Pattern';
    }
    if (packet.payloadAnalysis?['securityFlags'] != null) {
      final flags = packet.payloadAnalysis!['securityFlags'] as List;
      if (flags.contains('EXECUTABLE_CONTENT_DETECTED')) return 'Malicious Content';
      if (flags.contains('SUSPICIOUS_CODE_EXECUTION')) return 'Suspicious Activity';
    }
    return 'Anomaly Detected';
  }

  List<PacketInfo> get _filteredPackets {
    if (_selectedProtocolFilter == "ALL") {
      return _packets;
    }
    return _packets
        .where((packet) => packet.protocol.toUpperCase() == _selectedProtocolFilter)
        .toList();
  }

  Color _protocolColor(String protocol) {
    switch (protocol.toUpperCase()) {
      case 'HTTP':
        return Colors.blue;
      case 'HTTPS':
        return Colors.green;
      case 'DNS':
        return Colors.orange;
      case 'TLS':
      case 'SSL':
        return Colors.teal;
      case 'QUIC':
        return Colors.purple;
      case 'SIP':
        return Colors.cyan;
      case 'RTP':
        return Colors.indigo;
      case 'SMB':
        return Colors.brown;
      case 'NTP':
        return Colors.lime;
      case 'TCP':
        return Colors.blueGrey;
      case 'UDP':
        return Colors.deepOrange;
      default:
        return Colors.grey;
    }
  }

  void _showVpnPermissionDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('VPN Permission Required'),
        content: const Text(
          'AndroNet needs VPN permission to capture and analyze network packets. '
          'Please grant VPN permission in the next dialog.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () {
              Navigator.pop(context);
              // VPN permission request is handled by VpnController.prepareVpn()
            },
            child: const Text('Grant Permission'),
          ),
        ],
      ),
    );
  }

  void _showSnackBar(String message, Color backgroundColor, IconData icon) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Row(
          children: [
            Icon(icon, color: Colors.white),
            const SizedBox(width: 8),
            Expanded(child: Text(message)),
          ],
        ),
        backgroundColor: backgroundColor,
        duration: const Duration(seconds: 3),
      ),
    );
  }

  Future<void> _toggleCapture() async {
    if (_isCapturing) {
      await _stopCapture();
    } else {
      await _startCapture();
    }
  }

  // ================= DIALOG & UTILITY METHODS =================

  void _showPacketDetails(PacketInfo packet) {
    showDialog(
      context: context,
      builder: (context) => EnhancedPacketDetailsDialog(packet: packet),
    );
  }

  void _showCaptureModeSelector() {
    showModalBottomSheet(
      context: context,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (context) => Container(
        padding: const EdgeInsets.all(20),
        constraints: BoxConstraints(
          maxHeight: MediaQuery.of(context).size.height * 0.8,
        ),
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
            Row(
              children: [
                Icon(Icons.tune, color: Theme.of(context).colorScheme.primary),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    'Select Capture Mode',
                    style: TextStyle(
                      fontSize: 20,
                      fontWeight: FontWeight.bold,
                      color: Theme.of(context).colorScheme.primary,
                    ),
                  ),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 8,
                    vertical: 4,
                  ),
                  decoration: BoxDecoration(
                    color: Colors.green.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: const Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(Icons.check_circle, color: Colors.green, size: 12),
                      SizedBox(width: 4),
                      Text(
                        'VpnController',
                        style: TextStyle(
                          fontSize: 10,
                          color: Colors.green,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 20),
            ...CaptureMode.values.map((mode) => _buildModeOption(mode)),
            const SizedBox(width: 8),
            if (!_isRooted)
              Container(
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.orange.shade50,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: Colors.orange.shade200),
                ),
                child: const Row(
                  children: [
                    Icon(Icons.info_outline, color: Colors.orange, size: 16),
                    SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'Root access required for enhanced capture modes',
                        style: TextStyle(fontSize: 12, color: Colors.orange),
                      ),
                    ),
                  ],
                ),
              ),
            if (!_vpnPermissionGranted &&
                _selectedCaptureMode == CaptureMode.vpn)
              Container(
                margin: const EdgeInsets.only(top: 8),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Colors.blue.shade50,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: Colors.blue.shade200),
                ),
                child: const Row(
                  children: [
                    Icon(Icons.vpn_lock, color: Colors.blue, size: 16),
                    SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        'VPN permission required for packet capture',
                        style: TextStyle(fontSize: 12, color: Colors.blue),
                      ),
                    ),
                  ],
                ),
              ),
          ],
        ),
      ),
    ),
    );
  }

  Widget _buildModeOption(CaptureMode mode) {
    final isSelected = _selectedCaptureMode == mode;
    final isEnabled = mode == CaptureMode.vpn || _isRooted;
    final needsPermission = mode == CaptureMode.vpn && !_vpnPermissionGranted;

    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: isEnabled
              ? () {
                  setState(() => _selectedCaptureMode = mode);
                  Navigator.pop(context);
                  _showSnackBar(
                    "${mode.title} selected${needsPermission ? ' (Permission Required)' : ''}",
                    mode.color,
                    mode.icon,
                  );
                }
              : null,
          borderRadius: BorderRadius.circular(12),
          child: Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: isSelected
                  ? mode.color.withOpacity(0.1)
                  : Colors.transparent,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(
                color: isSelected ? mode.color : Colors.grey.shade300,
                width: isSelected ? 2 : 1,
              ),
            ),
            child: Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: isEnabled
                        ? mode.color.withOpacity(0.1)
                        : Colors.grey.shade100,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Icon(
                    mode.icon,
                    color: isEnabled ? mode.color : Colors.grey,
                    size: 24,
                  ),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Text(
                            mode.title,
                            style: TextStyle(
                              fontWeight: FontWeight.w600,
                              fontSize: 16,
                              color: isEnabled ? null : Colors.grey,
                            ),
                          ),
                          if (needsPermission) ...[
                            const SizedBox(width: 8),
                            Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 6,
                                vertical: 2,
                              ),
                              decoration: BoxDecoration(
                                color: Colors.orange.withOpacity(0.1),
                                borderRadius: BorderRadius.circular(10),
                              ),
                              child: const Text(
                                'PERM',
                                style: TextStyle(
                                  fontSize: 8,
                                  color: Colors.orange,
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ),
                          ],
                        ],
                      ),
                      const SizedBox(height: 4),
                      Text(
                        mode.description,
                        style: TextStyle(
                          fontSize: 13,
                          color: isEnabled
                              ? Theme.of(
                                  context,
                                ).colorScheme.onSurface.withOpacity(0.6)
                              : Colors.grey,
                        ),
                      ),
                    ],
                  ),
                ),
                if (isSelected)
                  Icon(Icons.check_circle, color: mode.color, size: 24),
                if (!isEnabled)
                  Icon(Icons.lock, color: Colors.grey.shade400, size: 20),
              ],
            ),
          ),
        ),
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
      case 'clear':
        _clearAllData();
        break;
      case 'refresh':
        _initializeNativeBridge();
        break;
      case 'permissions':
        PacketService.requestAllPermissions().then((success) {
          _showSnackBar(
            success ? '✅ Permissions granted' : '❌ Permission request failed',
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
    final authService = Provider.of<AuthenticationService>(context, listen: false);

    showDialog(
      context: context,
      builder: (context) => Consumer<AuthenticationService>(
        builder: (context, auth, child) => AlertDialog(
          title: const Row(
            children: [
              Icon(Icons.security, color: Colors.blue),
              SizedBox(width: 8),
              Text('Security Settings'),
            ],
          ),
          content: SizedBox(
            width: double.maxFinite,
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                // Current Authentication Status
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surfaceVariant.withOpacity(0.3),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Current Security',
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                          color: Theme.of(context).colorScheme.primary,
                        ),
                      ),
                      const SizedBox(height: 8),
                      _buildSecurityInfoRow('Method', auth.currentAuthMethod.name.toUpperCase()),
                      _buildSecurityInfoRow('Biometric', auth.biometricEnabled ? 'Enabled' : 'Disabled'),
                      _buildSecurityInfoRow('Auto-lock', '${auth.autoLockTime} minutes'),
                    ],
                  ),
                ),
                const SizedBox(height: 16),

                // Security Actions
                if (auth.currentAuthMethod != AuthMethod.none) ...[
                  _buildSecurityActionTile(
                    'Change Security Method',
                    'Modify PIN, password, or pattern',
                    Icons.edit_outlined,
                    () => Navigator.of(context).pushNamed('/setup-auth'),
                  ),
                  _buildSecurityActionTile(
                    'Auto-lock Settings',
                    'Configure automatic lock time',
                    Icons.timer_outlined,
                    () => _showAutoLockDialog(auth),
                  ),
                  if (auth.biometricEnabled)
                    _buildSecurityActionTile(
                      'Disable Biometric',
                      'Turn off fingerprint/face unlock',
                      Icons.fingerprint_outlined,
                      () async {
                        auth.disableAuthentication();
                        Navigator.of(context).pop();
                        _showSnackBar('Biometric authentication disabled', Colors.orange, Icons.info);
                      },
                    )
                  else
                    FutureBuilder<bool>(
                      future: auth.isBiometricAvailable(),
                      builder: (context, snapshot) {
                        if (snapshot.data == true) {
                          return _buildSecurityActionTile(
                            'Enable Biometric',
                            'Use fingerprint or face unlock',
                            Icons.fingerprint,
                            () async {
                              final success = await auth.enableBiometric();
                              if (success) {
                                _showSnackBar('Biometric authentication enabled', Colors.green, Icons.check_circle);
                              } else {
                                _showSnackBar('Failed to enable biometric', Colors.red, Icons.error);
                              }
                            },
                          );
                        }
                        return const SizedBox.shrink();
                      },
                    ),
                  _buildSecurityActionTile(
                    'Remove Security',
                    'Disable all security features',
                    Icons.no_encryption_outlined,
                    () => _showRemoveSecurityDialog(auth),
                  ),
                ] else ...[
                  _buildSecurityActionTile(
                    'Setup Security',
                    'Add PIN, password, or pattern',
                    Icons.add_moderator_outlined,
                    () => Navigator.of(context).pushNamed('/setup-auth'),
                  ),
                ],
              ],
            ),
          ),
          actions: [
            TextButton(
              onPressed: () => Navigator.pop(context),
              child: const Text('Close'),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSecurityInfoRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(label, style: const TextStyle(fontSize: 14)),
          Text(
            value,
            style: TextStyle(
              fontSize: 14,
              fontWeight: FontWeight.w600,
              color: Theme.of(context).colorScheme.primary,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSecurityActionTile(String title, String subtitle, IconData icon, VoidCallback onTap) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(8),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        child: Row(
          children: [
            Icon(icon, size: 24, color: Theme.of(context).colorScheme.primary),
            const SizedBox(width: 16),
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    title,
                    style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w500),
                  ),
                  Text(
                    subtitle,
                    style: TextStyle(
                      fontSize: 14,
                      color: Theme.of(context).colorScheme.onSurface.withOpacity(0.7),
                    ),
                  ),
                ],
              ),
            ),
            Icon(Icons.chevron_right, color: Colors.grey.shade400),
          ],
        ),
      ),
    );
  }

  void _showAutoLockDialog(AuthenticationService auth) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Auto-lock Time'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text('Choose how long the app stays unlocked when in background:'),
            const SizedBox(height: 16),
            ...([1, 2, 5, 10, 15, 30].map((minutes) => RadioListTile<int>(
              title: Text('$minutes ${minutes == 1 ? 'minute' : 'minutes'}'),
              value: minutes,
              groupValue: auth.autoLockTime,
              onChanged: (value) {
                if (value != null) {
                  auth.setAutoLockTime(value);
                  Navigator.pop(context);
                  _showSnackBar('Auto-lock time updated', Colors.green, Icons.check_circle);
                }
              },
            ))),
          ],
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

  void _showRemoveSecurityDialog(AuthenticationService auth) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Row(
          children: [
            Icon(Icons.warning, color: Colors.orange),
            SizedBox(width: 8),
            Text('Remove Security?'),
          ],
        ),
        content: const Text(
          'This will remove all security features including PIN, password, pattern, and biometric authentication. Your packet analyzer will be accessible without any protection.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () async {
              await auth.disableAuthentication();
              Navigator.pop(context);
              Navigator.pop(context);
              _showSnackBar('Security disabled', Colors.orange, Icons.info);
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.red,
              foregroundColor: Colors.white,
            ),
            child: const Text('Remove'),
          ),
        ],
      ),
    );
  }

  void _showSettingsDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Settings'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            SwitchListTile(
              title: const Text('Auto-scroll packets'),
              subtitle: const Text('Automatically scroll to newest packets'),
              value: _autoScroll,
              onChanged: (value) {
                setState(() => _autoScroll = value);
                Navigator.pop(context);
              },
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
      builder: (context) => AlertDialog(
        title: const Text('About Andronet'),
        content: const Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Professional Network Security Analysis Tool'),
            SizedBox(height: 8),
            Text('Version 6.1.0 • Secure Edition by CipherSec'),
            SizedBox(height: 16),
            Text('Features:', style: TextStyle(fontWeight: FontWeight.bold)),
            Text('• Real-time packet capture & analysis'),
            Text('• Multiple capture modes (VPN, Root, PCAP)'),
            Text('• Enhanced VpnController integration'),
            Text('• Advanced authentication & security'),
            Text('• Professional UI with Material 3 design'),
            Text('• Native Bridge integration'),
            Text('• Export functionality for captured packets'),
            Text('• Comprehensive system information'),
            Text('• Performance optimized with buffering'),
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

  @override
  void dispose() {
    _debounceTimer?.cancel();
    _packetSub?.cancel();
    _statusSub?.cancel();
    _metricsSub?.cancel();
    _statsSub?.cancel();
    _tabController.dispose();
    _pulseController.dispose();
    PacketService.disposeService();
    super.dispose();
  }
}
