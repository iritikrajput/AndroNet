import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:async';
import 'dart:convert';
import 'dart:math' as math;

// NOTE: We intentionally keep MethodChannel & EventChannel inside PacketService
// to centralize native integration.

// ============= MAIN =============
Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Initialize PacketService early so native calls can be handled before UI mount
  await PacketService.initialize();
  print("🚀 NetFlow Pro - PacketService Initialized");

  runApp(const PacketAnalyzerApp());
}

// ============= APP =============
class PacketAnalyzerApp extends StatelessWidget {
  const PacketAnalyzerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'NetFlow Pro',
      debugShowCheckedModeBanner: false,
      theme: _buildOptimizedTheme(),
      home: const PacketAnalyzerScreen(),
    );
  }

  ThemeData _buildOptimizedTheme() {
    return ThemeData(
      useMaterial3: true,
      colorScheme:
          ColorScheme.fromSeed(
            seedColor: const Color(0xFF2563EB),
            brightness: Brightness.light,
          ).copyWith(
            surface: const Color(0xFFFAFAFA),
            surfaceVariant: const Color(0xFFF1F5F9),
          ),
      cardTheme: const CardThemeData(
        elevation: 1,
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
      dividerTheme: const DividerThemeData(thickness: 0.5, space: 1),
    );
  }
}

// ============= CAPTURE MODE ENUM =============
enum CaptureMode {
  vpn(
    'VPN Mode',
    'Standard packet capture using VPN service',
    Icons.vpn_lock,
    Colors.blue,
  ),
  root(
    'Root Mode',
    'Enhanced capture with root privileges',
    Icons.security,
    Colors.orange,
  ),
  pcap(
    'PCAP Mode',
    'Native packet capture (requires root)',
    Icons.network_check,
    Colors.green,
  );

  const CaptureMode(this.title, this.description, this.icon, this.color);

  final String title;
  final String description;
  final IconData icon;
  final Color color;
}

// ============= MODELS =============
class PacketInfo {
  final String sourceIp;
  final String destinationIp;
  final int sourcePort;
  final int destinationPort;
  final String protocol;
  final int size;
  final String timestamp;
  final String payload;
  final String? direction;
  final String? networkType;
  final bool? isVpnTraffic;
  final int? ttl;
  final String? flags;

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
    this.networkType,
    this.isVpnTraffic,
    this.ttl,
    this.flags,
  });

  factory PacketInfo.fromMap(Map<String, dynamic> map) {
    return PacketInfo(
      sourceIp: map['sourceIp']?.toString() ?? '',
      destinationIp: map['destinationIp']?.toString() ?? '',
      sourcePort: map['sourcePort'] is int
          ? map['sourcePort']
          : int.tryParse(map['sourcePort']?.toString() ?? '0') ?? 0,
      destinationPort: map['destinationPort'] is int
          ? map['destinationPort']
          : int.tryParse(map['destinationPort']?.toString() ?? '0') ?? 0,
      protocol: map['protocol']?.toString() ?? '',
      size: map['size'] is int
          ? map['size']
          : int.tryParse(map['size']?.toString() ?? '0') ?? 0,
      timestamp:
          map['timestamp']?.toString() ??
          DateTime.now().millisecondsSinceEpoch.toString(),
      payload: map['payload']?.toString() ?? '',
      direction: map['direction']?.toString(),
      networkType: map['networkType']?.toString(),
      isVpnTraffic: map['isVpnTraffic'] is bool
          ? map['isVpnTraffic'] as bool
          : null,
      ttl: map['ttl'] is int
          ? map['ttl'] as int
          : int.tryParse(map['ttl']?.toString() ?? '') ?? null,
      flags: map['flags']?.toString(),
    );
  }

  String get formattedTime {
    try {
      final time = DateTime.fromMillisecondsSinceEpoch(int.parse(timestamp));
      return '${time.hour.toString().padLeft(2, '0')}:${time.minute.toString().padLeft(2, '0')}:${time.second.toString().padLeft(2, '0')}.${(time.millisecond ~/ 100).toString()}';
    } catch (e) {
      return timestamp;
    }
  }

  bool get isOutgoing =>
      direction?.toUpperCase() == 'OUTGOING' ||
      direction?.toUpperCase() == 'OUT';

  String get displayDirection => isOutgoing ? 'OUT' : 'IN';

  Color get directionColor =>
      isOutgoing ? const Color(0xFF3B82F6) : const Color(0xFF10B981);
}

class SessionInfo {
  final String sessionId;
  final String type;
  final String sourceIp;
  final int sourcePort;
  final String destIp;
  final int destPort;
  final int packetCount;
  final int totalBytes;
  final String lastActivity;
  final String status;
  final Duration? duration;

  const SessionInfo({
    required this.sessionId,
    required this.type,
    required this.sourceIp,
    required this.sourcePort,
    required this.destIp,
    required this.destPort,
    required this.packetCount,
    required this.totalBytes,
    required this.lastActivity,
    required this.status,
    this.duration,
  });

  factory SessionInfo.fromMap(Map<String, dynamic> map) {
    return SessionInfo(
      sessionId: map['sessionId']?.toString() ?? '',
      type: map['type']?.toString() ?? '',
      sourceIp: map['sourceIp']?.toString() ?? '',
      sourcePort: map['sourcePort'] is int
          ? map['sourcePort']
          : int.tryParse(map['sourcePort']?.toString() ?? '0') ?? 0,
      destIp:
          map['destIp']?.toString() ?? map['destinationIp']?.toString() ?? '',
      destPort: map['destPort'] is int
          ? map['destPort']
          : int.tryParse(map['destPort']?.toString() ?? '0') ?? 0,
      packetCount: map['packetCount'] is int
          ? map['packetCount']
          : int.tryParse(map['packetCount']?.toString() ?? '0') ?? 0,
      totalBytes: map['totalBytes'] is int
          ? map['totalBytes']
          : int.tryParse(map['totalBytes']?.toString() ?? '0') ?? 0,
      lastActivity: map['lastActivity']?.toString() ?? '',
      status: map['status']?.toString() ?? 'UNKNOWN',
      duration: map['duration'] != null
          ? Duration(
              seconds: map['duration'] is int
                  ? map['duration']
                  : int.tryParse(map['duration']?.toString() ?? '0') ?? 0,
            )
          : null,
    );
  }

  bool get isActive => status.toUpperCase() == 'ACTIVE';
  String get sessionKey => '$sourceIp:$sourcePort→$destIp:$destPort';
}

class ProtocolStats {
  final String protocol;
  final int packetCount;
  final int totalBytes;
  final double percentage;

  const ProtocolStats({
    required this.protocol,
    required this.packetCount,
    required this.totalBytes,
    this.percentage = 0.0,
  });

  factory ProtocolStats.fromMap(Map<String, dynamic> map) {
    return ProtocolStats(
      protocol: map['protocol']?.toString() ?? '',
      packetCount: map['packetCount'] is int
          ? map['packetCount']
          : int.tryParse(map['packetCount']?.toString() ?? '0') ?? 0,
      totalBytes: map['totalBytes'] is int
          ? map['totalBytes']
          : int.tryParse(map['totalBytes']?.toString() ?? '0') ?? 0,
      percentage: map['percentage'] is double
          ? map['percentage']
          : double.tryParse(map['percentage']?.toString() ?? '0') ?? 0.0,
    );
  }
}

class NetworkMetrics {
  final int totalPackets;
  final int totalBytes;
  final double packetsPerSecond;
  final double bytesPerSecond;
  final int activeSessions;
  final Duration uptime;

  const NetworkMetrics({
    required this.totalPackets,
    required this.totalBytes,
    required this.packetsPerSecond,
    required this.bytesPerSecond,
    required this.activeSessions,
    required this.uptime,
  });

  factory NetworkMetrics.fromMap(Map<String, dynamic> map) {
    return NetworkMetrics(
      totalPackets: map['totalPackets'] is int
          ? map['totalPackets']
          : int.tryParse(map['totalPackets']?.toString() ?? '0') ?? 0,
      totalBytes: map['totalBytes'] is int
          ? map['totalBytes']
          : int.tryParse(map['totalBytes']?.toString() ?? '0') ?? 0,
      packetsPerSecond: map['packetsPerSecond'] is double
          ? map['packetsPerSecond']
          : double.tryParse(map['packetsPerSecond']?.toString() ?? '0') ?? 0.0,
      bytesPerSecond: map['bytesPerSecond'] is double
          ? map['bytesPerSecond']
          : double.tryParse(map['bytesPerSecond']?.toString() ?? '0') ?? 0.0,
      activeSessions: map['activeSessions'] is int
          ? map['activeSessions']
          : int.tryParse(map['activeSessions']?.toString() ?? '0') ?? 0,
      uptime: Duration(
        seconds: map['uptime'] is int
            ? map['uptime']
            : int.tryParse(map['uptime']?.toString() ?? '0') ?? 0,
      ),
    );
  }
}

// ============= PACKET SERVICE (native integration) =============
class PacketService {
  static const MethodChannel _channel = MethodChannel('packet_analyzer');
  static const EventChannel _eventChannel = EventChannel(
    'packet_analyzer/events',
  );

  static final StreamController<PacketInfo> _packetController =
      StreamController<PacketInfo>.broadcast();
  static final StreamController<List<ProtocolStats>> _statsController =
      StreamController<List<ProtocolStats>>.broadcast();
  static final StreamController<List<SessionInfo>> _sessionsController =
      StreamController<List<SessionInfo>>.broadcast();
  static final StreamController<NetworkMetrics> _metricsController =
      StreamController<NetworkMetrics>.broadcast();
  static final StreamController<String> _statusController =
      StreamController<String>.broadcast();

  static Stream<PacketInfo> get packetStream => _packetController.stream;
  static Stream<List<ProtocolStats>> get statsStream => _statsController.stream;
  static Stream<List<SessionInfo>> get sessionsStream =>
      _sessionsController.stream;
  static Stream<NetworkMetrics> get metricsStream => _metricsController.stream;
  static Stream<String> get statusStream => _statusController.stream;

  // Initialize: set method handler and event channel listener
  static Future<void> initialize() async {
    print("🔧 Initializing PacketService...");

    _channel.setMethodCallHandler(_handleMethodCall);

    // Event channel might stream packet maps at high frequency
    try {
      _eventChannel.receiveBroadcastStream().listen(
        (dynamic event) {
          try {
            if (event is Map) {
              final map = Map<String, dynamic>.from(event);
              _handleNativePacket(map);
            }
          } catch (e) {
            debugPrint("EventChannel error processing: $e");
          }
        },
        onError: (error) {
          debugPrint("EventChannel error: $error");
        },
      );
    } catch (e) {
      debugPrint("EventChannel setup failed: $e");
    }

    print("✅ PacketService initialized successfully");
  }

  // Method handler (legacy single calls)
  static Future<dynamic> _handleMethodCall(MethodCall call) async {
    try {
      switch (call.method) {
        case 'onPacketReceived':
          if (call.arguments is Map) {
            _handleNativePacket(
              Map<String, dynamic>.from(call.arguments as Map),
            );
          }
          break;
        case 'onStatsUpdated':
          _handleNativeStats(call.arguments);
          break;
        case 'onSessionsUpdated':
          _handleNativeSessions(call.arguments);
          break;
        case 'onMetricsUpdated':
          if (call.arguments is Map) {
            _handleNativeMetrics(
              Map<String, dynamic>.from(call.arguments as Map),
            );
          }
          break;
        case 'onStatusChanged':
          if (call.arguments is Map) {
            _handleNativeStatus(
              Map<String, dynamic>.from(call.arguments as Map),
            );
          } else if (call.arguments is String) {
            _handleNativeStatus({'status': call.arguments});
          }
          break;
        default:
          debugPrint("Unknown native method: ${call.method}");
      }
    } catch (e) {
      debugPrint("Error handling native method ${call.method}: $e");
    }
    return null;
  }

  // Native handlers (consolidated)
  static void _handleNativePacket(Map<String, dynamic> packetData) {
    try {
      final packet = PacketInfo.fromMap(packetData);
      _packetController.add(packet);
      debugPrint(
        "✅ Packet processed: ${packet.protocol} ${packet.sourceIp}→${packet.destinationIp}",
      );
    } catch (e) {
      debugPrint("❌ Error processing packet: $e");
    }
  }

  static void _handleNativeStats(dynamic statsData) {
    try {
      List<ProtocolStats> stats = [];

      if (statsData is List) {
        stats = statsData
            .where((item) => item is Map)
            .map(
              (item) =>
                  ProtocolStats.fromMap(Map<String, dynamic>.from(item as Map)),
            )
            .toList();
      } else if (statsData is Map) {
        final m = Map<String, dynamic>.from(statsData);
        if (m.containsKey('protocols') && m['protocols'] is List) {
          stats = (m['protocols'] as List)
              .where((item) => item is Map)
              .map(
                (item) => ProtocolStats.fromMap(
                  Map<String, dynamic>.from(item as Map),
                ),
              )
              .toList();
        } else {
          stats = [ProtocolStats.fromMap(m)];
        }
      } else if (statsData is String) {
        final parsed = jsonDecode(statsData);
        _handleNativeStats(parsed);
        return;
      }

      _statsController.add(stats);
      debugPrint("✅ Stats processed: ${stats.length} protocols");
    } catch (e) {
      debugPrint("❌ Error processing stats: $e");
    }
  }

  static void _handleNativeSessions(dynamic sessionsData) {
    try {
      List<SessionInfo> sessions = [];

      if (sessionsData is List) {
        sessions = sessionsData
            .where((item) => item is Map)
            .map(
              (item) =>
                  SessionInfo.fromMap(Map<String, dynamic>.from(item as Map)),
            )
            .toList();
      } else if (sessionsData is Map) {
        sessions = [
          SessionInfo.fromMap(Map<String, dynamic>.from(sessionsData as Map)),
        ];
      }

      _sessionsController.add(sessions);
      debugPrint("✅ Sessions processed: ${sessions.length} sessions");
    } catch (e) {
      debugPrint("❌ Error processing sessions: $e");
    }
  }

  static void _handleNativeMetrics(Map<String, dynamic> metricsData) {
    try {
      final metrics = NetworkMetrics.fromMap(metricsData);
      _metricsController.add(metrics);
      debugPrint(
        "✅ Metrics processed: ${metrics.packetsPerSecond.toStringAsFixed(1)} pps",
      );
    } catch (e) {
      debugPrint("❌ Error processing metrics: $e");
    }
  }

  static void _handleNativeStatus(Map<String, dynamic> statusData) {
    try {
      final status =
          statusData['status']?.toString() ??
          statusData['message']?.toString() ??
          'Unknown';
      _statusController.add(status);
      debugPrint("✅ Status processed: $status");
    } catch (e) {
      debugPrint("❌ Error processing status: $e");
    }
  }

  // ============= COMMANDS =============
  static Future<bool> startVpnService() async {
    try {
      final result = await _channel.invokeMethod('startVpnService');
      return result == true;
    } catch (e) {
      debugPrint('Error starting VPN service: $e');
      return false;
    }
  }

  static Future<bool> stopVpnService() async {
    try {
      final result = await _channel.invokeMethod('stopVpnService');
      return result == true;
    } catch (e) {
      debugPrint('Error stopping VPN service: $e');
      return false;
    }
  }

  static Future<bool> startRootCapture() async {
    try {
      final result = await _channel.invokeMethod('startRootedCapture');
      return result == true;
    } catch (e) {
      debugPrint('Error starting root capture: $e');
      return false;
    }
  }

  static Future<bool> stopRootCapture() async {
    try {
      final result = await _channel.invokeMethod('stopRootedCapture');
      return result == true;
    } catch (e) {
      debugPrint('Error stopping root capture: $e');
      return false;
    }
  }

  static Future<bool> startPcapCapture() async {
    try {
      final result = await _channel.invokeMethod('startPcapCapture');
      return result == true;
    } catch (e) {
      debugPrint('Error starting pcap capture: $e');
      return false;
    }
  }

  static Future<bool> stopPcapCapture() async {
    try {
      final result = await _channel.invokeMethod('stopPcapCapture');
      return result == true;
    } catch (e) {
      debugPrint('Error stopping pcap capture: $e');
      return false;
    }
  }

  static Future<bool> closeSession(String sessionId) async {
    try {
      final result = await _channel.invokeMethod('closeSession', {
        'sessionId': sessionId,
      });
      return result == true;
    } catch (e) {
      debugPrint('Error closing session: $e');
      return false;
    }
  }

  static Future<bool> isDeviceRooted() async {
    try {
      final result = await _channel.invokeMethod('isDeviceRooted');
      return result == true;
    } catch (e) {
      debugPrint('Error checking root status: $e');
      return false;
    }
  }

  static Future<List<String>> getAvailableInterfaces() async {
    try {
      final result = await _channel.invokeMethod('getAvailableInterfaces');
      return List<String>.from(result ?? []);
    } catch (e) {
      debugPrint('Error getting network interfaces: $e');
      return [];
    }
  }

  static Future<void> clearPackets() async {
    try {
      await _channel.invokeMethod('clearPackets');
      debugPrint("Packets cleared");
    } catch (e) {
      debugPrint('Error clearing packets: $e');
    }
  }

  static Future<Map<String, dynamic>?> getNetworkInfo() async {
    try {
      final result = await _channel.invokeMethod('getNetworkInfo');
      return result != null ? Map<String, dynamic>.from(result) : null;
    } catch (e) {
      debugPrint('Error getting network info: $e');
      return null;
    }
  }

  static void dispose() {
    _packetController.close();
    _statsController.close();
    _sessionsController.close();
    _metricsController.close();
    _statusController.close();
  }
}

// ============= UI: PacketAnalyzerScreen =============
class PacketAnalyzerScreen extends StatefulWidget {
  const PacketAnalyzerScreen({super.key});

  @override
  State<PacketAnalyzerScreen> createState() => _PacketAnalyzerScreenState();
}

class _PacketAnalyzerScreenState extends State<PacketAnalyzerScreen>
    with TickerProviderStateMixin {
  // Core state
  bool _isCapturing = false;
  bool _isRooted = false;
  CaptureMode _selectedCaptureMode = CaptureMode.vpn;
  final List<PacketInfo> _packets = [];
  List<ProtocolStats> _stats = [];
  List<SessionInfo> _sessions = [];
  List<String> _availableInterfaces = [];
  NetworkMetrics? _metrics;
  String _currentStatus = 'Ready';

  // UI state
  String _selectedProtocolFilter = 'ALL';
  bool _autoScroll = true;
  int _currentTab = 0;

  // Subscriptions
  StreamSubscription<PacketInfo>? _packetSubscription;
  StreamSubscription<List<ProtocolStats>>? _statsSubscription;
  StreamSubscription<List<SessionInfo>>? _sessionsSubscription;
  StreamSubscription<NetworkMetrics>? _metricsSubscription;
  StreamSubscription<String>? _statusSubscription;

  // Controllers
  late TabController _tabController;
  late AnimationController _pulseController;
  late Animation<double> _pulseAnimation;

  // Performance optimizations
  Timer? _debounceTimer;
  static const int _maxPackets = 2000;
  static const Duration _debounceDelay = Duration(milliseconds: 100);

  @override
  void initState() {
    super.initState();
    print("🎯 PacketAnalyzerScreen initializing...");
    _initializeControllers();
    _initializeService();
  }

  void _initializeControllers() {
    _tabController = TabController(length: 3, vsync: this);
    _tabController.addListener(() {
      if (mounted) {
        setState(() => _currentTab = _tabController.index);
      }
    });

    _pulseController = AnimationController(
      duration: const Duration(milliseconds: 1200),
      vsync: this,
    );

    _pulseAnimation = Tween<double>(begin: 1.0, end: 1.3).animate(
      CurvedAnimation(parent: _pulseController, curve: Curves.easeInOut),
    );
  }

  Future<void> _initializeService() async {
    print("🔧 Checking device capabilities...");
    _isRooted = await PacketService.isDeviceRooted();
    _availableInterfaces = await PacketService.getAvailableInterfaces();

    if (_isRooted) {
      _selectedCaptureMode = CaptureMode.root;
      print("📱 Device is rooted - auto-selected root mode");
    } else {
      _selectedCaptureMode = CaptureMode.vpn;
      print("📱 Device is not rooted - using VPN mode");
    }

    _setupStreamSubscriptions();
    setState(() {});
  }

  void _setupStreamSubscriptions() {
    _packetSubscription = PacketService.packetStream.listen((packet) {
      _debounceTimer?.cancel();
      _debounceTimer = Timer(_debounceDelay, () {
        if (!mounted) return;
        setState(() {
          _packets.insert(0, packet);
          if (_packets.length > _maxPackets) {
            _packets.removeRange(_maxPackets ~/ 2, _packets.length);
          }
        });
        if (_isCapturing) {
          _pulseController.forward().then((_) => _pulseController.reverse());
        }
      });
    });

    _statsSubscription = PacketService.statsStream.listen((stats) {
      if (!mounted) return;
      setState(() => _stats = stats);
    });

    _sessionsSubscription = PacketService.sessionsStream.listen((sessions) {
      if (!mounted) return;
      setState(() => _sessions = sessions);
    });

    _metricsSubscription = PacketService.metricsStream.listen((metrics) {
      if (!mounted) return;
      setState(() => _metrics = metrics);
    });

    _statusSubscription = PacketService.statusStream.listen((status) {
      if (!mounted) return;
      setState(() => _currentStatus = status);
    });
  }

  // Toggle capture based on selected mode
  Future<void> _toggleCapture() async {
    bool success = false;

    if (_isCapturing) {
      switch (_selectedCaptureMode) {
        case CaptureMode.vpn:
          success = await PacketService.stopVpnService();
          break;
        case CaptureMode.root:
          success = await PacketService.stopRootCapture();
          break;
        case CaptureMode.pcap:
          success = await PacketService.stopPcapCapture();
          break;
      }
    } else {
      switch (_selectedCaptureMode) {
        case CaptureMode.vpn:
          success = await PacketService.startVpnService();
          break;
        case CaptureMode.root:
          if (!_isRooted) {
            _showOptimizedSnackBar(
              'Root access required for this mode',
              Colors.red,
              Icons.error_outline,
            );
            return;
          }
          success = await PacketService.startRootCapture();
          break;
        case CaptureMode.pcap:
          if (!_isRooted) {
            _showOptimizedSnackBar(
              'Root access required for PCAP mode',
              Colors.red,
              Icons.error_outline,
            );
            return;
          }
          success = await PacketService.startPcapCapture();
          break;
      }
    }

    if (success && mounted) {
      setState(() => _isCapturing = !_isCapturing);
      _showOptimizedSnackBar(
        _isCapturing
            ? '✅ ${_selectedCaptureMode.title} started'
            : '⏹️ Capture stopped',
        _isCapturing ? Colors.green : Colors.orange,
        _isCapturing ? Icons.play_circle : Icons.stop_circle,
      );
    } else {
      _showOptimizedSnackBar(
        '❌ Operation failed',
        Colors.red,
        Icons.error_outline,
      );
    }
  }

  void _showCaptureModeSelector() {
    showModalBottomSheet(
      context: context,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(16)),
      ),
      builder: (context) => Container(
        padding: const EdgeInsets.all(16),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(Icons.tune, color: Theme.of(context).colorScheme.primary),
                const SizedBox(width: 8),
                Text(
                  'Select Capture Mode',
                  style: TextStyle(
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),
            ...CaptureMode.values.map((mode) => _buildCaptureModeOption(mode)),
            const SizedBox(height: 8),
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
          ],
        ),
      ),
    );
  }

  Widget _buildCaptureModeOption(CaptureMode mode) {
    final isSelected = _selectedCaptureMode == mode;
    final isEnabled = mode == CaptureMode.vpn || _isRooted;

    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          onTap: isEnabled
              ? () {
                  setState(() => _selectedCaptureMode = mode);
                  Navigator.pop(context);
                  _showOptimizedSnackBar(
                    '${mode.title} selected',
                    mode.color,
                    mode.icon,
                  );
                }
              : null,
          borderRadius: BorderRadius.circular(8),
          child: Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: isSelected
                  ? mode.color.withOpacity(0.08)
                  : Colors.transparent,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(
                color: isSelected ? mode.color : Colors.grey.shade300,
                width: isSelected ? 2 : 1,
              ),
            ),
            child: Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: isEnabled
                        ? mode.color.withOpacity(0.08)
                        : Colors.grey.shade100,
                    borderRadius: BorderRadius.circular(6),
                  ),
                  child: Icon(
                    mode.icon,
                    color: isEnabled ? mode.color : Colors.grey,
                    size: 20,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        mode.title,
                        style: TextStyle(
                          fontWeight: FontWeight.w600,
                          color: isEnabled ? null : Colors.grey,
                        ),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        mode.description,
                        style: TextStyle(
                          fontSize: 12,
                          color: isEnabled
                              ? Theme.of(
                                  context,
                                ).colorScheme.onSurface.withOpacity(0.7)
                              : Colors.grey,
                        ),
                      ),
                    ],
                  ),
                ),
                if (isSelected)
                  Icon(Icons.check_circle, color: mode.color, size: 20),
                if (!isEnabled)
                  Icon(Icons.lock, color: Colors.grey.shade400, size: 16),
              ],
            ),
          ),
        ),
      ),
    );
  }

  void _clearAllData() {
    setState(() {
      _packets.clear();
      _stats.clear();
      _sessions.clear();
      _metrics = null;
    });
    PacketService.clearPackets();
    _showOptimizedSnackBar(
      '🗑️ All data cleared',
      Colors.blue,
      Icons.clear_all,
    );
  }

  void _showOptimizedSnackBar(String message, Color color, IconData icon) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, color: Colors.white, size: 18),
            const SizedBox(width: 8),
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

  List<PacketInfo> get _filteredPackets {
    if (_selectedProtocolFilter == 'ALL') return _packets;
    return _packets
        .where((p) => p.protocol.toUpperCase() == _selectedProtocolFilter)
        .toList();
  }

  // ============= BUILD (Scaffold) ============
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Theme.of(context).colorScheme.surface,
      appBar: _buildOptimizedAppBar(),
      body: Column(
        children: [
          _buildEnhancedMetricsPanel(),
          _buildOptimizedTabBar(),
          Expanded(child: _buildTabContent()),
        ],
      ),
      floatingActionButton: _buildEnhancedFAB(),
      floatingActionButtonLocation: FloatingActionButtonLocation.endFloat,
    );
  }

  PreferredSizeWidget _buildOptimizedAppBar() {
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
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'NetFlow Pro',
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
              ),
            ],
          ),
        ],
      ),
      backgroundColor: Theme.of(context).colorScheme.surface,
      elevation: 0,
      actions: [
        _buildOptimizedStatusIndicator(),
        IconButton(
          icon: const Icon(Icons.more_vert),
          onPressed: () => _showOptionsMenu(context),
        ),
      ],
    );
  }

  Widget _buildOptimizedStatusIndicator() {
    return Container(
      margin: const EdgeInsets.only(right: 8),
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
      margin: const EdgeInsets.fromLTRB(16, 8, 16, 16),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceVariant.withOpacity(0.5),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: Theme.of(context).colorScheme.outline.withOpacity(0.2),
        ),
      ),
      child: Column(
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
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
                  size: 16,
                  color: _selectedCaptureMode.color,
                ),
                const SizedBox(width: 6),
                Text(
                  _selectedCaptureMode.title,
                  style: TextStyle(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: _selectedCaptureMode.color,
                  ),
                ),
                const SizedBox(width: 8),
                Container(
                  width: 6,
                  height: 6,
                  decoration: const BoxDecoration(
                    color: Colors.green,
                    shape: BoxShape.circle,
                  ),
                ),
                const SizedBox(width: 6),
                InkWell(
                  onTap: _showCaptureModeSelector,
                  borderRadius: BorderRadius.circular(12),
                  child: Padding(
                    padding: const EdgeInsets.all(2),
                    child: Icon(
                      Icons.tune,
                      size: 14,
                      color: _selectedCaptureMode.color,
                    ),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              _buildCompactMetric(
                'Packets',
                _packets.length.toString(),
                Icons.stream,
                Colors.blue,
              ),
              const SizedBox(width: 1, child: VerticalDivider()),
              _buildCompactMetric(
                'Sessions',
                _sessions.length.toString(),
                Icons.lan,
                Colors.green,
              ),
              const SizedBox(width: 1, child: VerticalDivider()),
              _buildCompactMetric(
                'Protocols',
                _stats.length.toString(),
                Icons.category,
                Colors.orange,
              ),
              const SizedBox(width: 1, child: VerticalDivider()),
              _buildCompactMetric(
                'Rate',
                _metrics != null
                    ? '${_metrics!.packetsPerSecond.toStringAsFixed(0)}/s'
                    : '0/s',
                Icons.speed,
                Colors.purple,
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildCompactMetric(
    String label,
    String value,
    IconData icon,
    Color color,
  ) {
    return Expanded(
      child: Column(
        children: [
          Icon(icon, color: color, size: 18),
          const SizedBox(height: 4),
          Text(
            value,
            style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
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
    );
  }

  Widget _buildOptimizedTabBar() {
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
        labelStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
        unselectedLabelStyle: const TextStyle(fontSize: 13),
        tabs: const [
          Tab(text: 'Stream', icon: Icon(Icons.stream, size: 16)),
          Tab(text: 'Analytics', icon: Icon(Icons.analytics, size: 16)),
          Tab(text: 'Sessions', icon: Icon(Icons.lan, size: 16)),
        ],
      ),
    );
  }

  Widget _buildTabContent() {
    return TabBarView(
      controller: _tabController,
      children: [
        _buildOptimizedPacketsTab(),
        _buildOptimizedAnalyticsTab(),
        _buildOptimizedSessionsTab(),
      ],
    );
  }

  Widget _buildEnhancedFAB() {
    return FloatingActionButton.extended(
      onPressed: _toggleCapture,
      icon: AnimatedSwitcher(
        duration: const Duration(milliseconds: 200),
        child: Icon(
          _isCapturing ? Icons.stop : Icons.play_arrow,
          key: ValueKey(_isCapturing),
        ),
      ),
      label: Text(_isCapturing ? 'Stop' : 'Start'),
      backgroundColor: _isCapturing ? Colors.red : _selectedCaptureMode.color,
      elevation: 2,
    );
  }

  Widget _buildOptimizedPacketsTab() {
    return Column(
      children: [
        if (_packets.isNotEmpty) _buildOptimizedProtocolFilter(),
        Expanded(child: _buildOptimizedPacketList()),
      ],
    );
  }

  Widget _buildOptimizedProtocolFilter() {
    Set<String> protocols = {'ALL'};
    protocols.addAll(_packets.map((p) => p.protocol.toUpperCase()).toSet());

    return Container(
      height: 40,
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
              onSelected: (selected) =>
                  setState(() => _selectedProtocolFilter = protocol),
              selectedColor: Theme.of(context).colorScheme.primaryContainer,
              checkmarkColor: Theme.of(context).colorScheme.primary,
              materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
              visualDensity: VisualDensity.compact,
            ),
          );
        },
      ),
    );
  }

  Widget _buildOptimizedPacketList() {
    final filteredPackets = _filteredPackets;

    if (filteredPackets.isEmpty) {
      return _buildEmptyState();
    }

    return ListView.builder(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
      reverse: _autoScroll,
      itemCount: filteredPackets.length,
      itemBuilder: (context, index) {
        final packet =
            filteredPackets[_autoScroll
                ? (filteredPackets.length - 1 - index)
                : index];
        return _buildOptimizedPacketItem(packet, index);
      },
    );
  }

  Widget _buildOptimizedPacketItem(PacketInfo packet, int index) {
    final protocolColor = _getProtocolColor(packet.protocol);

    return Container(
      margin: const EdgeInsets.only(bottom: 6),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surface,
        borderRadius: BorderRadius.circular(8),
        border: Border.all(
          color: packet.directionColor.withOpacity(0.2),
          width: 1,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.03),
            blurRadius: 2,
            offset: const Offset(0, 1),
          ),
        ],
      ),
      child: InkWell(
        onTap: () => _showOptimizedPacketDetails(packet),
        borderRadius: BorderRadius.circular(8),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 6,
                    vertical: 2,
                  ),
                  decoration: BoxDecoration(
                    color: protocolColor.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Text(
                    packet.protocol,
                    style: TextStyle(
                      fontSize: 10,
                      fontWeight: FontWeight.bold,
                      color: protocolColor,
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                Container(
                  padding: const EdgeInsets.symmetric(
                    horizontal: 4,
                    vertical: 1,
                  ),
                  decoration: BoxDecoration(
                    color: packet.directionColor.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(3),
                  ),
                  child: Text(
                    packet.displayDirection,
                    style: TextStyle(
                      fontSize: 9,
                      fontWeight: FontWeight.bold,
                      color: packet.directionColor,
                    ),
                  ),
                ),
                const Spacer(),
                Text(
                  packet.formattedTime,
                  style: TextStyle(
                    fontSize: 10,
                    color: Theme.of(
                      context,
                    ).colorScheme.onSurface.withOpacity(0.6),
                    fontFamily: 'monospace',
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(
              '${packet.sourceIp}:${packet.sourcePort} → ${packet.destinationIp}:${packet.destinationPort}',
              style: const TextStyle(
                fontSize: 12,
                fontFamily: 'monospace',
                fontWeight: FontWeight.w500,
              ),
            ),
            const SizedBox(height: 4),
            Row(
              children: [
                Icon(Icons.data_usage, size: 12, color: Colors.grey.shade600),
                const SizedBox(width: 4),
                Text(
                  '${packet.size}B',
                  style: TextStyle(fontSize: 10, color: Colors.grey.shade600),
                ),
                if (packet.networkType != null) ...[
                  const SizedBox(width: 12),
                  Icon(
                    Icons.network_cell,
                    size: 12,
                    color: Colors.grey.shade600,
                  ),
                  const SizedBox(width: 4),
                  Text(
                    packet.networkType!,
                    style: TextStyle(fontSize: 10, color: Colors.grey.shade600),
                  ),
                ],
                const Spacer(),
                Icon(
                  Icons.chevron_right,
                  size: 16,
                  color: Colors.grey.shade400,
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildOptimizedAnalyticsTab() {
    // Placeholder: you can plug charts here later (e.g., using fl_chart)
    final totalBytes = _stats.fold<int>(0, (s, e) => s + e.totalBytes);
    return SingleChildScrollView(
      padding: const EdgeInsets.all(16),
      child: Column(
        children: [
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                children: [
                  Row(
                    children: [
                      Icon(
                        Icons.pie_chart,
                        color: Theme.of(context).colorScheme.primary,
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
                  const SizedBox(height: 12),
                  if (_stats.isEmpty)
                    const Padding(
                      padding: EdgeInsets.all(16),
                      child: Text('No protocol stats available'),
                    )
                  else
                    ..._stats.map((stat) {
                      return Padding(
                        padding: const EdgeInsets.symmetric(vertical: 8),
                        child: Row(
                          children: [
                            CircleAvatar(
                              radius: 14,
                              backgroundColor: _getProtocolColor(stat.protocol),
                              child: Text(
                                stat.protocol.isNotEmpty
                                    ? stat.protocol[0]
                                    : '?',
                                style: const TextStyle(
                                  color: Colors.white,
                                  fontSize: 12,
                                ),
                              ),
                            ),
                            const SizedBox(width: 12),
                            Expanded(
                              child: Text(
                                stat.protocol,
                                style: const TextStyle(
                                  fontWeight: FontWeight.bold,
                                ),
                              ),
                            ),
                            Text('${stat.percentage.toStringAsFixed(1)}%'),
                          ],
                        ),
                      );
                    }).toList(),
                ],
              ),
            ),
          ),
          const SizedBox(height: 12),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                children: [
                  Row(
                    children: [
                      Icon(
                        Icons.speed,
                        color: Theme.of(context).colorScheme.primary,
                      ),
                      const SizedBox(width: 8),
                      Text(
                        'Traffic Summary',
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                          color: Theme.of(context).colorScheme.primary,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      Expanded(
                        child: _smallStat(
                          'Total Packets',
                          _packets.length.toString(),
                        ),
                      ),
                      Expanded(
                        child: _smallStat(
                          'Total Bytes',
                          _formatBytes(totalBytes),
                        ),
                      ),
                      Expanded(
                        child: _smallStat(
                          'Active Sessions',
                          _sessions.length.toString(),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _smallStat(String label, String value) {
    return Column(
      children: [
        Text(
          value,
          style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold),
        ),
        const SizedBox(height: 4),
        Text(
          label,
          style: TextStyle(
            fontSize: 12,
            color: Theme.of(context).colorScheme.onSurface.withOpacity(0.6),
          ),
        ),
      ],
    );
  }

  Widget _buildOptimizedSessionsTab() {
    if (_sessions.isEmpty)
      return _buildEmptyState(message: 'No active sessions');
    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: _sessions.length,
      itemBuilder: (context, index) {
        final s = _sessions[index];
        return Card(
          margin: const EdgeInsets.only(bottom: 8),
          child: ListTile(
            leading: CircleAvatar(
              backgroundColor: s.isActive ? Colors.green : Colors.grey,
              child: Text(s.type, style: const TextStyle(fontSize: 10)),
            ),
            title: Text(
              s.sessionKey,
              style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            ),
            subtitle: Text(
              '${s.packetCount} packets • ${_formatBytes(s.totalBytes)}',
            ),
            trailing: Chip(
              label: Text(s.status),
              backgroundColor: s.isActive
                  ? Colors.green.shade100
                  : Colors.grey.shade200,
              labelStyle: TextStyle(
                color: s.isActive ? Colors.green : Colors.grey,
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildEmptyState({String message = 'No data available'}) {
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(
              _currentTab == 0
                  ? Icons.stream
                  : _currentTab == 1
                  ? Icons.analytics
                  : Icons.lan,
              size: 48,
              color: Colors.grey.shade400,
            ),
            const SizedBox(height: 16),
            Text(
              message,
              style: TextStyle(
                fontSize: 16,
                color: Colors.grey.shade600,
                fontWeight: FontWeight.w500,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Start capturing to monitor traffic',
              style: TextStyle(fontSize: 12, color: Colors.grey.shade500),
            ),
            if (!_isCapturing) ...[
              const SizedBox(height: 16),
              ElevatedButton.icon(
                onPressed: _toggleCapture,
                icon: const Icon(Icons.play_arrow),
                label: const Text('Start Capture'),
                style: ElevatedButton.styleFrom(
                  backgroundColor: _selectedCaptureMode.color,
                  foregroundColor: Colors.white,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  // ============= Dialogs & Menus (implemented) =============
  void _showOptimizedPacketDetails(PacketInfo packet) {
    showDialog(
      context: context,
      builder: (context) => Dialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        child: ConstrainedBox(
          constraints: BoxConstraints(
            maxHeight: MediaQuery.of(context).size.height * 0.8,
            maxWidth: MediaQuery.of(context).size.width * 0.9,
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: _getProtocolColor(packet.protocol),
                  borderRadius: const BorderRadius.only(
                    topLeft: Radius.circular(12),
                    topRight: Radius.circular(12),
                  ),
                ),
                child: Row(
                  children: [
                    CircleAvatar(
                      radius: 22,
                      backgroundColor: Colors.white.withOpacity(0.2),
                      child: Text(
                        packet.protocol.isNotEmpty
                            ? packet.protocol.substring(0, 1)
                            : '?',
                        style: const TextStyle(
                          fontSize: 18,
                          color: Colors.white,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text(
                            'Packet Details',
                            style: TextStyle(
                              color: Colors.white,
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          Text(
                            '${packet.protocol.toUpperCase()} • ${packet.displayDirection} • ${packet.formattedTime}',
                            style: TextStyle(
                              color: Colors.white.withOpacity(0.9),
                              fontSize: 12,
                            ),
                          ),
                        ],
                      ),
                    ),
                    IconButton(
                      icon: const Icon(Icons.close, color: Colors.white),
                      onPressed: () => Navigator.pop(context),
                    ),
                  ],
                ),
              ),
              Expanded(
                child: SingleChildScrollView(
                  padding: const EdgeInsets.all(16),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _buildDetailSection('Network Information', [
                        _buildDetailItem(
                          'Source',
                          '${packet.sourceIp}:${packet.sourcePort}',
                          Icons.arrow_upward,
                        ),
                        _buildDetailItem(
                          'Destination',
                          '${packet.destinationIp}:${packet.destinationPort}',
                          Icons.arrow_downward,
                        ),
                        _buildDetailItem(
                          'Protocol',
                          packet.protocol,
                          Icons.language,
                        ),
                      ]),
                      const SizedBox(height: 12),
                      _buildDetailSection('Packet Information', [
                        _buildDetailItem(
                          'Size',
                          '${packet.size} bytes',
                          Icons.data_usage,
                        ),
                        _buildDetailItem(
                          'Timestamp',
                          packet.formattedTime,
                          Icons.access_time,
                        ),
                        if (packet.direction != null)
                          _buildDetailItem(
                            'Direction',
                            packet.direction!,
                            Icons.swap_horiz,
                          ),
                        if (packet.ttl != null)
                          _buildDetailItem(
                            'TTL',
                            packet.ttl.toString(),
                            Icons.timer,
                          ),
                        if (packet.flags != null)
                          _buildDetailItem('Flags', packet.flags!, Icons.flag),
                      ]),
                      if (packet.networkType != null ||
                          packet.isVpnTraffic != null)
                        const SizedBox(height: 12),
                      if (packet.networkType != null ||
                          packet.isVpnTraffic != null)
                        _buildDetailSection('Additional', [
                          if (packet.networkType != null)
                            _buildDetailItem(
                              'Network',
                              packet.networkType!,
                              Icons.wifi,
                            ),
                          if (packet.isVpnTraffic != null)
                            _buildDetailItem(
                              'VPN Traffic',
                              packet.isVpnTraffic! ? 'Yes' : 'No',
                              Icons.vpn_key,
                            ),
                        ]),
                      if (packet.payload.isNotEmpty) ...[
                        const SizedBox(height: 16),
                        const Text(
                          'Payload',
                          style: TextStyle(
                            fontSize: 14,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        const SizedBox(height: 8),
                        Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: Colors.grey.shade100,
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(color: Colors.grey.shade300),
                          ),
                          child: SelectableText(
                            packet.payload,
                            style: const TextStyle(
                              fontFamily: 'monospace',
                              fontSize: 12,
                            ),
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildDetailSection(String title, List<Widget> children) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          title,
          style: TextStyle(
            fontSize: 14,
            fontWeight: FontWeight.bold,
            color: Theme.of(context).colorScheme.primary,
          ),
        ),
        const SizedBox(height: 8),
        ...children,
      ],
    );
  }

  Widget _buildDetailItem(String label, String value, IconData icon) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceVariant.withOpacity(0.3),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(6),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.primary.withOpacity(0.1),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Icon(
              icon,
              size: 16,
              color: Theme.of(context).colorScheme.primary,
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  label,
                  style: TextStyle(
                    fontSize: 12,
                    color: Colors.grey.shade600,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                const SizedBox(height: 2),
                SelectableText(
                  value,
                  style: const TextStyle(
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  void _showOptionsMenu(BuildContext context) {
    showModalBottomSheet(
      context: context,
      shape: const RoundedRectangleBorder(
        borderRadius: BorderRadius.vertical(top: Radius.circular(12)),
      ),
      builder: (c) => SafeArea(
        child: Wrap(
          children: [
            ListTile(
              leading: const Icon(Icons.tune),
              title: const Text('Change Capture Mode'),
              onTap: () {
                Navigator.pop(c);
                _showCaptureModeSelector();
              },
            ),
            ListTile(
              leading: const Icon(Icons.clear_all),
              title: const Text('Clear Data'),
              onTap: () {
                Navigator.pop(c);
                _clearAllData();
              },
            ),
            ListTile(
              leading: const Icon(Icons.save_alt),
              title: const Text('Export PCAP (coming soon)'),
              onTap: () {
                Navigator.pop(c);
                _showOptimizedSnackBar(
                  'Export coming soon',
                  Colors.orange,
                  Icons.file_download,
                );
              },
            ),
            ListTile(
              leading: const Icon(Icons.info_outline),
              title: const Text('About'),
              onTap: () {
                Navigator.pop(c);
                showAboutDialog(
                  context: context,
                  applicationName: 'NetFlow Pro',
                  applicationVersion: '3.0.0',
                  children: [const Text('Professional-grade packet analyzer')],
                );
              },
            ),
          ],
        ),
      ),
    );
  }

  // ============= Utilities ============
  Color _getProtocolColor(String protocol) {
    switch (protocol.toUpperCase()) {
      case 'TCP':
        return const Color(0xFF3B82F6);
      case 'UDP':
        return const Color(0xFF10B981);
      case 'HTTP':
        return const Color(0xFFF59E0B);
      case 'HTTPS':
        return const Color(0xFF8B5CF6);
      case 'DNS':
        return const Color(0xFF14B8A6);
      case 'ICMP':
        return const Color(0xFFEF4444);
      case 'SSH':
        return const Color(0xFF6366F1);
      default:
        return const Color(0xFF6B7280);
    }
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '${bytes}B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)}KB';
    if (bytes < 1024 * 1024 * 1024)
      return '${(bytes / (1024 * 1024)).toStringAsFixed(1)}MB';
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)}GB';
  }

  String _formatDuration(Duration duration) {
    final minutes = duration.inMinutes;
    final seconds = duration.inSeconds % 60;
    if (minutes > 0) return '${minutes}m ${seconds}s';
    return '${seconds}s';
  }

  @override
  void dispose() {
    print("🔄 PacketAnalyzerScreen disposing...");
    _debounceTimer?.cancel();
    _packetSubscription?.cancel();
    _statsSubscription?.cancel();
    _sessionsSubscription?.cancel();
    _metricsSubscription?.cancel();
    _statusSubscription?.cancel();
    _tabController.dispose();
    _pulseController.dispose();
    super.dispose();
  }
}
