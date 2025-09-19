import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:async';
import 'dart:convert';
import 'dart:math' as math;

// ================= GLOBAL PACKET LISTENER =================
const _channel = MethodChannel("packet_analyzer");

void initPacketListener() {
  _channel.setMethodCallHandler((call) async {
    switch (call.method) {
      case "onPacketReceived":
        PacketService._handleNativePacket(
          Map<String, dynamic>.from(call.arguments),
        );
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
  runApp(const PacketAnalyzerApp());
}

// ================= CAPTURE MODE ENUM =================
enum CaptureMode {
  vpn(
    "VPN Mode",
    "Capture via Android VPNService",
    Icons.vpn_lock,
    Colors.blue,
  ),
  root(
    "Root Mode",
    "Raw sockets with root access",
    Icons.security,
    Colors.orange,
  ),
  pcap(
    "PCAP Mode",
    "Native libpcap capture (root required)",
    Icons.network_check,
    Colors.green,
  );

  const CaptureMode(this.title, this.description, this.icon, this.color);

  final String title;
  final String description;
  final IconData icon;
  final Color color;
}

// ================= ENHANCED MODELS =================
class PacketInfo {
  final String sourceIp, destinationIp, protocol, timestamp, payload;
  final int sourcePort, destinationPort, size;
  final String? direction, flags;

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

// ================= ENHANCED PACKET SERVICE =================
class PacketService {
  static const MethodChannel _channel = MethodChannel('packet_analyzer');

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

  static Future<void> initialize() async {
    _flushTimer ??= Timer.periodic(
      const Duration(milliseconds: 150),
      (_) => _flush(),
    );

    _statsTimer ??= Timer.periodic(
      const Duration(seconds: 3),
      (_) => _generateMockStats(),
    );
  }

  static void disposeService() {
    _flushTimer?.cancel();
    _statsTimer?.cancel();
    _packetController.close();
    _statusController.close();
    _metricsController.close();
    _statsController.close();
  }

  // Native handlers
  static void _handleNativePacket(Map<String, dynamic> map) {
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
    _buffer.clear();
    for (final m in batch) {
      _packetController.add(PacketInfo.fromMap(m));
    }
  }

  // Mock stats for demo purposes
  static void _generateMockStats() {
    final protocols = ['TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS', 'ICMP'];
    final stats = protocols
        .map(
          (p) => ProtocolStats(
            protocol: p,
            packetCount: math.Random().nextInt(150) + 10,
            percentage: math.Random().nextDouble() * 25 + 5,
          ),
        )
        .toList();
    _statsController.add(stats);
  }

  // Control methods (merged from both sources)
  static Future<bool> startVpnService() async =>
      (await _channel.invokeMethod('startVpnService')) == true;

  static Future<bool> stopVpnService() async =>
      (await _channel.invokeMethod('stopVpnService')) == true;

  static Future<bool> startRootCapture() async =>
      (await _channel.invokeMethod('startRootedCapture')) == true;

  static Future<bool> stopRootCapture() async =>
      (await _channel.invokeMethod('stopRootedCapture')) == true;

  static Future<bool> startPcapCapture() async =>
      (await _channel.invokeMethod('startPcapCapture')) == true;

  static Future<bool> stopPcapCapture() async =>
      (await _channel.invokeMethod('stopPcapCapture')) == true;

  static Future<bool> isDeviceRooted() async =>
      (await _channel.invokeMethod('isDeviceRooted')) == true;

  static Future<String?> exportPackets() async =>
      await _channel.invokeMethod('exportPackets');

  static Future<void> clearPackets() async {
    try {
      await _channel.invokeMethod('clearPackets');
    } catch (_) {
      debugPrint("clearPackets not implemented natively");
    }
  }
}

// ================= OPTIMIZED UI APP =================
class PacketAnalyzerApp extends StatelessWidget {
  const PacketAnalyzerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Andronet',
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
      ),
      home: const PacketAnalyzerScreen(),
    );
  }
}

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
  List<ProtocolStats> _protocolStats = [];
  String _currentStatus = 'Ready';
  NetworkMetrics? _metrics;
  String _selectedProtocolFilter = "ALL";
  bool _autoScroll = true;
  int _selectedTabIndex = 0;

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
  static const int _maxPackets = 1500; // Optimized buffer size

  @override
  void initState() {
    super.initState();
    _initializeControllers();
    _setupStreamSubscriptions();
    _checkRoot();
  }

  void _initializeControllers() {
    _tabController = TabController(length: 3, vsync: this);
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

  Future<void> _checkRoot() async {
    try {
      _isRooted = await PacketService.isDeviceRooted();
      if (mounted) {
        setState(() {
          if (_isRooted) _selectedCaptureMode = CaptureMode.root;
        });
      }
    } catch (e) {
      debugPrint('Error checking root: $e');
    }
  }

  Future<void> _toggleCapture() async {
    bool success = false;

    try {
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
              _showSnackBar(
                "Root access required for this mode",
                Colors.red,
                Icons.error_outline,
              );
              return;
            }
            success = await PacketService.startRootCapture();
            break;
          case CaptureMode.pcap:
            if (!_isRooted) {
              _showSnackBar(
                "Root access required for PCAP mode",
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
        _showSnackBar(
          _isCapturing
              ? "✅ ${_selectedCaptureMode.title} started successfully"
              : "⏹️ Capture stopped",
          _isCapturing ? Colors.green : Colors.orange,
          _isCapturing ? Icons.play_circle_filled : Icons.stop_circle,
        );
      } else {
        _showSnackBar(
          "❌ Failed to ${_isCapturing ? 'stop' : 'start'} capture",
          Colors.red,
          Icons.error,
        );
      }
    } catch (e) {
      _showSnackBar("Error: ${e.toString()}", Colors.red, Icons.error);
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
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              Text(
                'Andronet\n   by CipherSec',
                style: TextStyle(
                  fontSize: 12,
                  fontWeight: FontWeight.bold,
                  color: Theme.of(context).colorScheme.onSurface,
                ),
              ),
              Text(
                _currentStatus,
                style: TextStyle(
                  fontSize: 6,
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
      actions: [
        _buildLiveStatusIndicator(),
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
            const PopupMenuItem(value: 'clear', child: Text('Clear All Data')),
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
            // Capture Mode Indicator
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
        labelStyle: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
        unselectedLabelStyle: const TextStyle(fontSize: 13),
        tabs: const [
          Tab(text: 'Live Stream', icon: Icon(Icons.stream, size: 16)),
          Tab(text: 'Analytics', icon: Icon(Icons.analytics, size: 16)),
          Tab(text: 'Statistics', icon: Icon(Icons.bar_chart, size: 16)),
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

    return ListView.builder(
      padding: const EdgeInsets.fromLTRB(16, 8, 16, 16),
      reverse: _autoScroll,
      itemCount: packets.length,
      itemBuilder: (context, index) {
        final packet =
            packets[_autoScroll ? (packets.length - 1 - index) : index];
        return _buildOptimizedPacketCard(packet);
      },
    );
  }

  Widget _buildOptimizedPacketCard(PacketInfo packet) {
    final protocolColor = _protocolColor(packet.protocol);

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      elevation: 1,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(
          color: packet.directionColor.withOpacity(0.3),
          width: 1,
        ),
      ),
      child: InkWell(
        onTap: () => _showPacketDetails(packet),
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: protocolColor.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(6),
                    ),
                    child: Text(
                      packet.protocol,
                      style: TextStyle(
                        fontSize: 11,
                        fontWeight: FontWeight.bold,
                        color: protocolColor,
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 6,
                      vertical: 2,
                    ),
                    decoration: BoxDecoration(
                      color: packet.directionColor.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(
                          packet.isOutgoing
                              ? Icons.arrow_upward
                              : Icons.arrow_downward,
                          size: 12,
                          color: packet.directionColor,
                        ),
                        const SizedBox(width: 2),
                        Text(
                          packet.displayDirection,
                          style: TextStyle(
                            fontSize: 9,
                            fontWeight: FontWeight.bold,
                            color: packet.directionColor,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const Spacer(),
                  Text(
                    packet.formattedTime,
                    style: TextStyle(
                      fontSize: 11,
                      color: Theme.of(
                        context,
                      ).colorScheme.onSurface.withOpacity(0.6),
                      fontFamily: 'monospace',
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              Text(
                '${packet.sourceIp}:${packet.sourcePort} → ${packet.destinationIp}:${packet.destinationPort}',
                style: const TextStyle(
                  fontSize: 13,
                  fontFamily: 'monospace',
                  fontWeight: FontWeight.w500,
                ),
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Icon(Icons.data_usage, size: 14, color: Colors.grey.shade600),
                  const SizedBox(width: 4),
                  Text(
                    '${packet.size} bytes',
                    style: const TextStyle(
                      fontSize: 11,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                  if (packet.flags != null) ...[
                    const SizedBox(width: 16),
                    Icon(Icons.flag, size: 14, color: Colors.grey.shade600),
                    const SizedBox(width: 4),
                    Text(packet.flags!, style: const TextStyle(fontSize: 11)),
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
      ),
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
            _buildSummaryRow('Performance Mode', 'Optimized'),
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
      elevation: 3,
    );
  }

  // ================= DIALOG & UTILITY METHODS =================

  void _showPacketDetails(PacketInfo packet) {
    showDialog(
      context: context,
      builder: (context) => Dialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        child: Container(
          constraints: BoxConstraints(
            maxHeight: MediaQuery.of(context).size.height * 0.7,
            maxWidth: MediaQuery.of(context).size.width * 0.9,
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              Container(
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: _protocolColor(packet.protocol),
                  borderRadius: const BorderRadius.only(
                    topLeft: Radius.circular(16),
                    topRight: Radius.circular(16),
                  ),
                ),
                child: Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: Colors.white.withOpacity(0.2),
                        borderRadius: BorderRadius.circular(8),
                      ),
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
                    const SizedBox(width: 16),
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
                            '${packet.protocol} • ${packet.displayDirection} • ${packet.formattedTime}',
                            style: TextStyle(
                              color: Colors.white.withOpacity(0.8),
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
              Flexible(
                child: SingleChildScrollView(
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _buildDetailSection('Network Information', [
                        _buildDetailRow(
                          'Source',
                          '${packet.sourceIp}:${packet.sourcePort}',
                        ),
                        _buildDetailRow(
                          'Destination',
                          '${packet.destinationIp}:${packet.destinationPort}',
                        ),
                        _buildDetailRow('Protocol', packet.protocol),
                        _buildDetailRow('Direction', packet.displayDirection),
                      ]),
                      const SizedBox(height: 16),
                      _buildDetailSection('Packet Information', [
                        _buildDetailRow('Size', '${packet.size} bytes'),
                        _buildDetailRow('Timestamp', packet.formattedTime),
                        if (packet.flags != null)
                          _buildDetailRow('Flags', packet.flags!),
                      ]),
                      if (packet.payload.isNotEmpty) ...[
                        const SizedBox(height: 16),
                        Text(
                          'Payload Data',
                          style: TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                            color: Theme.of(context).colorScheme.primary,
                          ),
                        ),
                        const SizedBox(height: 8),
                        Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(16),
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
            fontSize: 16,
            fontWeight: FontWeight.bold,
            color: Theme.of(context).colorScheme.primary,
          ),
        ),
        const SizedBox(height: 8),
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: Theme.of(
              context,
            ).colorScheme.surfaceVariant.withOpacity(0.3),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: children,
          ),
        ),
      ],
    );
  }

  Widget _buildDetailRow(String label, String value) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 80,
            child: Text(
              '$label:',
              style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
            ),
          ),
          Expanded(
            child: SelectableText(value, style: const TextStyle(fontSize: 12)),
          ),
        ],
      ),
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
                    fontSize: 20,
                    fontWeight: FontWeight.bold,
                    color: Theme.of(context).colorScheme.primary,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 20),
            ...CaptureMode.values.map((mode) => _buildModeOption(mode)),
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

  Widget _buildModeOption(CaptureMode mode) {
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
                  _showSnackBar(
                    "${mode.title} selected",
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
                      Text(
                        mode.title,
                        style: TextStyle(
                          fontWeight: FontWeight.w600,
                          fontSize: 16,
                          color: isEnabled ? null : Colors.grey,
                        ),
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
      case 'clear':
        _clearAllData();
        break;
      case 'settings':
        _showSettingsDialog();
        break;
      case 'about':
        _showAboutDialog();
        break;
    }
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
        title: const Text('About NetFlow Pro'),
        content: const Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('Professional Network Packet Analyzer'),
            SizedBox(height: 8),
            Text('Version 5.1.0 • Merged Edition'),
            SizedBox(height: 16),
            Text('Features:', style: TextStyle(fontWeight: FontWeight.bold)),
            Text('• Real-time packet capture & analysis'),
            Text('• Multiple capture modes (VPN, Root, PCAP)'),
            Text('• Advanced protocol analytics & statistics'),
            Text('• Professional UI with Material 3 design'),
            Text('• Export functionality for captured packets'),
            Text('• Comprehensive packet inspection'),
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
