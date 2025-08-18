import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:async';

void main() {
  runApp(PacketAnalyzerApp());
}

class PacketAnalyzerApp extends StatelessWidget {
  const PacketAnalyzerApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Packet Analyzer',
      theme: ThemeData(
        primarySwatch: Colors.indigo,
        visualDensity: VisualDensity.adaptivePlatformDensity,
      ),
      home: PacketAnalyzerScreen(),
    );
  }
}

// Models
class PacketInfo {
  final String sourceIp;
  final String destinationIp;
  final int sourcePort;
  final int destinationPort;
  final String protocol;
  final int size;
  final String timestamp;
  final String payload;

  PacketInfo({
    required this.sourceIp,
    required this.destinationIp,
    required this.sourcePort,
    required this.destinationPort,
    required this.protocol,
    required this.size,
    required this.timestamp,
    required this.payload,
  });

  factory PacketInfo.fromMap(Map<String, dynamic> map) {
    return PacketInfo(
      sourceIp: map['sourceIp'] ?? '',
      destinationIp: map['destinationIp'] ?? '',
      sourcePort: map['sourcePort'] ?? 0,
      destinationPort: map['destinationPort'] ?? 0,
      protocol: map['protocol'] ?? '',
      size: map['size'] ?? 0,
      timestamp: map['timestamp'] ?? '',
      payload: map['payload'] ?? '',
    );
  }
}

class ProtocolStats {
  final String protocol;
  final int packetCount;
  final int totalBytes;

  ProtocolStats({
    required this.protocol,
    required this.packetCount,
    required this.totalBytes,
  });

  factory ProtocolStats.fromMap(Map<String, dynamic> map) {
    return ProtocolStats(
      protocol: map['protocol'] ?? '',
      packetCount: map['packetCount'] ?? 0,
      totalBytes: map['totalBytes'] ?? 0,
    );
  }
}

// Service
class PacketService {
  static const MethodChannel _channel = MethodChannel('packet_analyzer');

  static final StreamController<PacketInfo> _packetController =
      StreamController<PacketInfo>.broadcast();

  static final StreamController<List<ProtocolStats>> _statsController =
      StreamController<List<ProtocolStats>>.broadcast();

  static Stream<PacketInfo> get packetStream => _packetController.stream;
  static Stream<List<ProtocolStats>> get statsStream => _statsController.stream;

  static Future<void> initialize() async {
    _channel.setMethodCallHandler(_handleMethodCall);
  }

  static Future<dynamic> _handleMethodCall(MethodCall call) async {
    switch (call.method) {
      case 'onPacketReceived':
        final packetData = Map<String, dynamic>.from(call.arguments);
        final packet = PacketInfo.fromMap(packetData);
        _packetController.add(packet);
        break;
      case 'onStatsUpdated':
        final statsData = List<Map<String, dynamic>>.from(call.arguments);
        final stats = statsData.map((e) => ProtocolStats.fromMap(e)).toList();
        _statsController.add(stats);
        break;
    }
  }

  static Future<bool> startVpnService() async {
    try {
      final result = await _channel.invokeMethod('startVpnService');
      return result ?? false;
    } catch (e) {
      print('Error starting VPN service: $e');
      return false;
    }
  }

  static Future<bool> stopVpnService() async {
    try {
      final result = await _channel.invokeMethod('stopVpnService');
      return result ?? false;
    } catch (e) {
      print('Error stopping VPN service: $e');
      return false;
    }
  }

  static Future<bool> startRootedCapture() async {
    try {
      final result = await _channel.invokeMethod('startRootedCapture');
      return result ?? false;
    } catch (e) {
      print('Error starting rooted capture: $e');
      return false;
    }
  }

  static Future<bool> stopRootedCapture() async {
    try {
      final result = await _channel.invokeMethod('stopRootedCapture');
      return result ?? false;
    } catch (e) {
      print('Error stopping rooted capture: $e');
      return false;
    }
  }

  static Future<bool> isDeviceRooted() async {
    try {
      final result = await _channel.invokeMethod('isDeviceRooted');
      return result ?? false;
    } catch (e) {
      print('Error checking root status: $e');
      return false;
    }
  }

  static Future<void> clearPackets() async {
    try {
      await _channel.invokeMethod('clearPackets');
    } catch (e) {
      print('Error clearing packets: $e');
    }
  }

  static void dispose() {
    _packetController.close();
    _statsController.close();
  }
}

// Main Screen
class PacketAnalyzerScreen extends StatefulWidget {
  const PacketAnalyzerScreen({super.key});

  @override
  _PacketAnalyzerScreenState createState() => _PacketAnalyzerScreenState();
}

class _PacketAnalyzerScreenState extends State<PacketAnalyzerScreen>
    with TickerProviderStateMixin {
  bool _isCapturing = false;
  bool _isRooted = false;
  bool _useRootedMode = false;
  final List<PacketInfo> _packets = [];
  List<ProtocolStats> _stats = [];
  String _selectedProtocolFilter = 'ALL';

  StreamSubscription<PacketInfo>? _packetSubscription;
  StreamSubscription<List<ProtocolStats>>? _statsSubscription;

  late AnimationController _statusAnimationController;
  late AnimationController _statsAnimationController;
  late Animation<double> _statusAnimation;
  late Animation<double> _statsAnimation;

  @override
  void initState() {
    super.initState();
    _initializeAnimations();
    _initializeService();
  }

  void _initializeAnimations() {
    _statusAnimationController = AnimationController(
      duration: Duration(milliseconds: 800),
      vsync: this,
    );

    _statsAnimationController = AnimationController(
      duration: Duration(milliseconds: 1000),
      vsync: this,
    );

    _statusAnimation = Tween<double>(begin: 0.0, end: 1.0).animate(
      CurvedAnimation(
        parent: _statusAnimationController,
        curve: Curves.elasticOut,
      ),
    );

    _statsAnimation = Tween<double>(begin: 0.0, end: 1.0).animate(
      CurvedAnimation(
        parent: _statsAnimationController,
        curve: Curves.easeInOut,
      ),
    );

    _statusAnimationController.forward();
  }

  Future<void> _initializeService() async {
    await PacketService.initialize();
    _isRooted = await PacketService.isDeviceRooted();
    setState(() {});

    _packetSubscription = PacketService.packetStream.listen((packet) {
      setState(() {
        _packets.insert(0, packet);
        if (_packets.length > 1000) {
          _packets.removeLast();
        }
      });
    });

    _statsSubscription = PacketService.statsStream.listen((stats) {
      setState(() {
        _stats = stats;
      });
      if (!_statsAnimationController.isAnimating) {
        _statsAnimationController.forward();
      }
    });
  }

  Future<void> _toggleCapture() async {
    if (_isCapturing) {
      bool success;
      if (_useRootedMode) {
        success = await PacketService.stopRootedCapture();
      } else {
        success = await PacketService.stopVpnService();
      }
      if (success) {
        setState(() {
          _isCapturing = false;
        });
        _showSnackBar('Packet capture stopped', Colors.orange);
      }
    } else {
      bool success;
      if (_useRootedMode) {
        success = await PacketService.startRootedCapture();
      } else {
        success = await PacketService.startVpnService();
      }
      if (success) {
        setState(() {
          _isCapturing = true;
        });
        _showSnackBar('Packet capture started', Colors.green);
      } else {
        _showSnackBar('Failed to start packet capture', Colors.red);
      }
    }
  }

  void _clearPackets() {
    setState(() {
      _packets.clear();
      _stats.clear();
    });
    PacketService.clearPackets();
    _showSnackBar('Packets cleared', Colors.blue);
  }

  void _showSnackBar(String message, Color color) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Text(message),
        backgroundColor: color,
        duration: Duration(seconds: 2),
      ),
    );
  }

  List<PacketInfo> get _filteredPackets {
    if (_selectedProtocolFilter == 'ALL') {
      return _packets;
    }
    return _packets
        .where(
          (packet) => packet.protocol.toUpperCase() == _selectedProtocolFilter,
        )
        .toList();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            Icon(Icons.network_check, color: Colors.white),
            SizedBox(width: 8),
            Text(
              'Packet Analyzer',
              style: TextStyle(fontWeight: FontWeight.bold),
            ),
          ],
        ),
        backgroundColor: Colors.indigo,
        foregroundColor: Colors.white,
        elevation: 4,
        actions: [
          IconButton(
            icon: Icon(Icons.clear),
            onPressed: _clearPackets,
            tooltip: 'Clear Packets',
          ),
          IconButton(
            icon: Icon(Icons.info_outline),
            onPressed: _showAboutDialog,
            tooltip: 'About',
          ),
        ],
      ),
      body: Column(
        children: [
          _buildControlPanel(),
          _buildStatsPanel(),
          _buildProtocolFilter(),
          Expanded(child: _buildPacketList()),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _toggleCapture,
        icon: Icon(_isCapturing ? Icons.stop : Icons.play_arrow),
        label: Text(_isCapturing ? 'Stop' : 'Start'),
        backgroundColor: _isCapturing ? Colors.red : Colors.green,
      ),
    );
  }

  Widget _buildControlPanel() {
    return AnimatedBuilder(
      animation: _statusAnimation,
      builder: (context, child) {
        return Transform.scale(
          scale: _statusAnimation.value,
          child: Card(
            margin: EdgeInsets.all(12),
            elevation: 6,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(12),
            ),
            child: Container(
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(12),
                gradient: LinearGradient(
                  colors: [Colors.indigo.shade50, Colors.white],
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                ),
              ),
              child: Padding(
                padding: EdgeInsets.all(16),
                child: Column(
                  children: [
                    // Device Status Row
                    Row(
                      children: [
                        Icon(
                          _isRooted ? Icons.security : Icons.smartphone,
                          color: _isRooted ? Colors.green : Colors.orange,
                        ),
                        SizedBox(width: 8),
                        Text(
                          'Device Status: ',
                          style: TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                        Container(
                          padding: EdgeInsets.symmetric(
                            horizontal: 8,
                            vertical: 4,
                          ),
                          decoration: BoxDecoration(
                            color: _isRooted
                                ? Colors.green.shade100
                                : Colors.orange.shade100,
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: Text(
                            _isRooted ? 'Rooted' : 'Unrooted',
                            style: TextStyle(
                              fontWeight: FontWeight.bold,
                              color: _isRooted
                                  ? Colors.green.shade700
                                  : Colors.orange.shade700,
                            ),
                          ),
                        ),
                      ],
                    ),

                    SizedBox(height: 12),

                    // Capture Mode Switch (only for rooted devices)
                    if (_isRooted) ...[
                      Container(
                        padding: EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: Colors.grey.shade100,
                          borderRadius: BorderRadius.circular(8),
                        ),
                        child: Row(
                          children: [
                            Icon(Icons.swap_horiz, color: Colors.indigo),
                            SizedBox(width: 8),
                            Text(
                              'Capture Mode: ',
                              style: TextStyle(
                                fontSize: 16,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                            Expanded(
                              child: Row(
                                mainAxisAlignment: MainAxisAlignment.end,
                                children: [
                                  Text(
                                    _useRootedMode
                                        ? 'Rooted (libpcap)'
                                        : 'VPN Proxy',
                                    style: TextStyle(
                                      fontWeight: FontWeight.bold,
                                      color: _useRootedMode
                                          ? Colors.green
                                          : Colors.blue,
                                    ),
                                  ),
                                  Switch(
                                    value: _useRootedMode,
                                    onChanged: _isCapturing
                                        ? null
                                        : (value) {
                                            setState(() {
                                              _useRootedMode = value;
                                            });
                                          },
                                    activeColor: Colors.green,
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ),
                      ),
                      SizedBox(height: 12),
                    ],

                    // Capture Status
                    Container(
                      padding: EdgeInsets.all(12),
                      decoration: BoxDecoration(
                        color: _isCapturing
                            ? Colors.green.shade100
                            : Colors.grey.shade100,
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Row(
                        children: [
                          AnimatedContainer(
                            duration: Duration(milliseconds: 300),
                            width: 12,
                            height: 12,
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              color: _isCapturing ? Colors.green : Colors.grey,
                            ),
                            child: _isCapturing
                                ? Container(
                                    width: 8,
                                    height: 8,
                                    margin: EdgeInsets.all(2),
                                    decoration: BoxDecoration(
                                      shape: BoxShape.circle,
                                      color: Colors.white,
                                    ),
                                  )
                                : null,
                          ),
                          SizedBox(width: 8),
                          Text(
                            'Status: ${_isCapturing ? "Capturing" : "Stopped"}',
                            style: TextStyle(
                              fontSize: 16,
                              fontWeight: FontWeight.w500,
                              color: _isCapturing
                                  ? Colors.green.shade700
                                  : Colors.grey.shade600,
                            ),
                          ),
                          Spacer(),
                          if (_isCapturing)
                            SizedBox(
                              width: 20,
                              height: 20,
                              child: CircularProgressIndicator(
                                strokeWidth: 2,
                                valueColor: AlwaysStoppedAnimation<Color>(
                                  Colors.green,
                                ),
                              ),
                            ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildStatsPanel() {
    return AnimatedBuilder(
      animation: _statsAnimation,
      builder: (context, child) {
        return Transform.scale(
          scale: 0.8 + (_statsAnimation.value * 0.2),
          child: Opacity(
            opacity: _statsAnimation.value,
            child: Card(
              margin: EdgeInsets.symmetric(horizontal: 12),
              elevation: 4,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
              child: Padding(
                padding: EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.analytics, color: Colors.indigo),
                        SizedBox(width: 8),
                        Text(
                          'Protocol Statistics',
                          style: TextStyle(
                            fontSize: 18,
                            fontWeight: FontWeight.bold,
                            color: Colors.indigo,
                          ),
                        ),
                        Spacer(),
                        Container(
                          padding: EdgeInsets.symmetric(
                            horizontal: 8,
                            vertical: 4,
                          ),
                          decoration: BoxDecoration(
                            color: Colors.indigo.shade100,
                            borderRadius: BorderRadius.circular(12),
                          ),
                          child: Text(
                            'Total: ${_packets.length}',
                            style: TextStyle(
                              fontWeight: FontWeight.bold,
                              color: Colors.indigo.shade700,
                            ),
                          ),
                        ),
                      ],
                    ),
                    SizedBox(height: 12),
                    if (_stats.isEmpty)
                      Container(
                        padding: EdgeInsets.all(20),
                        child: Center(
                          child: Column(
                            children: [
                              Icon(
                                Icons.inbox,
                                size: 48,
                                color: Colors.grey.shade400,
                              ),
                              SizedBox(height: 8),
                              Text(
                                'No data captured yet',
                                style: TextStyle(
                                  color: Colors.grey.shade600,
                                  fontSize: 16,
                                ),
                              ),
                            ],
                          ),
                        ),
                      )
                    else
                      Column(
                        children: _stats
                            .take(5)
                            .map(
                              (stat) => Padding(
                                padding: EdgeInsets.symmetric(vertical: 4),
                                child: Container(
                                  padding: EdgeInsets.all(12),
                                  decoration: BoxDecoration(
                                    color: _getProtocolColor(
                                      stat.protocol,
                                    ).withOpacity(0.1),
                                    borderRadius: BorderRadius.circular(8),
                                  ),
                                  child: Row(
                                    children: [
                                      CircleAvatar(
                                        radius: 12,
                                        backgroundColor: _getProtocolColor(
                                          stat.protocol,
                                        ),
                                        child: Text(
                                          stat.protocol.substring(0, 1),
                                          style: TextStyle(
                                            fontSize: 10,
                                            color: Colors.white,
                                            fontWeight: FontWeight.bold,
                                          ),
                                        ),
                                      ),
                                      SizedBox(width: 12),
                                      Text(
                                        stat.protocol,
                                        style: TextStyle(
                                          fontWeight: FontWeight.bold,
                                          fontSize: 14,
                                        ),
                                      ),
                                      Spacer(),
                                      Text(
                                        '${stat.packetCount} packets',
                                        style: TextStyle(
                                          fontSize: 12,
                                          color: Colors.grey.shade600,
                                        ),
                                      ),
                                      SizedBox(width: 8),
                                      Text(
                                        _formatBytes(stat.totalBytes),
                                        style: TextStyle(
                                          fontSize: 12,
                                          fontWeight: FontWeight.bold,
                                          color: Colors.grey.shade700,
                                        ),
                                      ),
                                    ],
                                  ),
                                ),
                              ),
                            )
                            .toList(),
                      ),
                  ],
                ),
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildProtocolFilter() {
    Set<String> protocols = {'ALL'};
    protocols.addAll(_packets.map((p) => p.protocol.toUpperCase()).toSet());

    return Container(
      height: 50,
      margin: EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      child: ListView(
        scrollDirection: Axis.horizontal,
        children: protocols
            .map(
              (protocol) => Padding(
                padding: EdgeInsets.only(right: 8),
                child: FilterChip(
                  label: Text(protocol),
                  selected: _selectedProtocolFilter == protocol,
                  onSelected: (selected) {
                    setState(() {
                      _selectedProtocolFilter = protocol;
                    });
                  },
                  selectedColor: Colors.indigo.shade100,
                  checkmarkColor: Colors.indigo,
                  labelStyle: TextStyle(
                    color: _selectedProtocolFilter == protocol
                        ? Colors.indigo.shade700
                        : Colors.grey.shade600,
                    fontWeight: _selectedProtocolFilter == protocol
                        ? FontWeight.bold
                        : FontWeight.normal,
                  ),
                ),
              ),
            )
            .toList(),
      ),
    );
  }

  // ----- KEY FIX -----
  Widget _buildPacketList() {
    final filteredPackets = _filteredPackets;
    return Card(
      margin: EdgeInsets.all(12),
      elevation: 4,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: Colors.indigo.shade50,
              borderRadius: BorderRadius.only(
                topLeft: Radius.circular(12),
                topRight: Radius.circular(12),
              ),
            ),
            child: Row(
              children: [
                Icon(Icons.list, color: Colors.indigo),
                SizedBox(width: 8),
                Text(
                  'Live Packets',
                  style: TextStyle(
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                    color: Colors.indigo,
                  ),
                ),
                Spacer(),
                Container(
                  padding: EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: Colors.indigo,
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: Text(
                    '${filteredPackets.length}',
                    style: TextStyle(
                      color: Colors.white,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ],
            ),
          ),
          Flexible(
            child: filteredPackets.isEmpty
                ? Container(
                    padding: EdgeInsets.all(40),
                    child: Center(
                      child: SingleChildScrollView(
                        // <-- Fix overflow
                        child: Column(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Icon(
                              Icons.network_check,
                              size: 64,
                              color: Colors.grey.shade400,
                            ),
                            SizedBox(height: 16),
                            Text(
                              'No packets captured',
                              style: TextStyle(
                                fontSize: 18,
                                color: Colors.grey.shade600,
                                fontWeight: FontWeight.w500,
                              ),
                            ),
                            SizedBox(height: 8),
                            Text(
                              'Start capturing to see network traffic',
                              style: TextStyle(
                                fontSize: 14,
                                color: Colors.grey.shade500,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  )
                : ListView.builder(
                    itemCount: filteredPackets.length,
                    itemBuilder: (context, index) {
                      final packet = filteredPackets[index];
                      return _buildPacketItem(packet, index);
                    },
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildPacketItem(PacketInfo packet, int index) {
    return Container(
      margin: EdgeInsets.symmetric(horizontal: 8, vertical: 2),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(8),
        color: index.isEven ? Colors.grey.shade50 : Colors.white,
      ),
      child: ListTile(
        dense: true,
        leading: Hero(
          tag: 'packet-$index',
          child: CircleAvatar(
            radius: 16,
            backgroundColor: _getProtocolColor(packet.protocol),
            child: Text(
              packet.protocol.substring(0, 1),
              style: TextStyle(
                fontSize: 12,
                color: Colors.white,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ),
        title: Text(
          '${packet.sourceIp}:${packet.sourcePort} → ${packet.destinationIp}:${packet.destinationPort}',
          style: TextStyle(
            fontSize: 12,
            fontFamily: 'monospace',
            fontWeight: FontWeight.w500,
          ),
        ),
        subtitle: Row(
          children: [
            Container(
              padding: EdgeInsets.symmetric(horizontal: 6, vertical: 2),
              decoration: BoxDecoration(
                color: _getProtocolColor(packet.protocol).withOpacity(0.2),
                borderRadius: BorderRadius.circular(4),
              ),
              child: Text(
                packet.protocol,
                style: TextStyle(
                  fontSize: 10,
                  fontWeight: FontWeight.bold,
                  color: _getProtocolColor(packet.protocol),
                ),
              ),
            ),
            SizedBox(width: 8),
            Text('${packet.size} bytes', style: TextStyle(fontSize: 10)),
            SizedBox(width: 8),
            Text(
              packet.timestamp,
              style: TextStyle(fontSize: 10, color: Colors.grey.shade600),
            ),
          ],
        ),
        trailing: Icon(Icons.chevron_right, color: Colors.grey.shade400),
        onTap: () => _showPacketDetails(packet, index),
      ),
    );
  }

  Color _getProtocolColor(String protocol) {
    switch (protocol.toUpperCase()) {
      case 'TCP':
        return Colors.blue;
      case 'UDP':
        return Colors.green;
      case 'HTTP':
        return Colors.orange;
      case 'HTTPS':
        return Colors.purple;
      case 'DNS':
        return Colors.teal;
      case 'ICMP':
        return Colors.red;
      default:
        return Colors.grey;
    }
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '${bytes}B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)}KB';
    return '${(bytes / (1024 * 1024)).toStringAsFixed(1)}MB';
  }

  void _showPacketDetails(PacketInfo packet, int index) {
    showDialog(
      context: context,
      builder: (context) => Dialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        child: SizedBox(
          width: MediaQuery.of(context).size.width * 0.9,
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              // Header
              Container(
                padding: EdgeInsets.all(16),
                decoration: BoxDecoration(
                  color: _getProtocolColor(packet.protocol),
                  borderRadius: BorderRadius.only(
                    topLeft: Radius.circular(12),
                    topRight: Radius.circular(12),
                  ),
                ),
                child: Row(
                  children: [
                    Hero(
                      tag: 'packet-$index',
                      child: CircleAvatar(
                        radius: 20,
                        backgroundColor: Colors.white.withOpacity(0.2),
                        child: Text(
                          packet.protocol.substring(0, 1),
                          style: TextStyle(
                            fontSize: 16,
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ),
                    ),
                    SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'Packet Details',
                            style: TextStyle(
                              color: Colors.white,
                              fontSize: 18,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          Text(
                            packet.protocol.toUpperCase(),
                            style: TextStyle(
                              color: Colors.white.withOpacity(0.8),
                              fontSize: 14,
                            ),
                          ),
                        ],
                      ),
                    ),
                    IconButton(
                      icon: Icon(Icons.close, color: Colors.white),
                      onPressed: () => Navigator.pop(context),
                    ),
                  ],
                ),
              ),
              // Content
              Container(
                padding: EdgeInsets.all(16),
                child: SingleChildScrollView(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      _buildDetailRow(
                        'Source',
                        '${packet.sourceIp}:${packet.sourcePort}',
                        Icons.arrow_upward,
                      ),
                      _buildDetailRow(
                        'Destination',
                        '${packet.destinationIp}:${packet.destinationPort}',
                        Icons.arrow_downward,
                      ),
                      _buildDetailRow(
                        'Protocol',
                        packet.protocol,
                        Icons.language,
                      ),
                      _buildDetailRow(
                        'Size',
                        '${packet.size} bytes',
                        Icons.data_usage,
                      ),
                      _buildDetailRow(
                        'Timestamp',
                        packet.timestamp,
                        Icons.access_time,
                      ),
                      SizedBox(height: 16),
                      if (packet.payload.isNotEmpty) ...[
                        Text(
                          'Payload Data:',
                          style: TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                            color: Colors.grey.shade700,
                          ),
                        ),
                        SizedBox(height: 8),
                        Container(
                          width: double.infinity,
                          padding: EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: Colors.grey.shade100,
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(color: Colors.grey.shade300),
                          ),
                          child: SelectableText(
                            packet.payload,
                            style: TextStyle(
                              fontFamily: 'monospace',
                              fontSize: 12,
                              color: Colors.grey.shade800,
                            ),
                          ),
                        ),
                      ] else ...[
                        Container(
                          width: double.infinity,
                          padding: EdgeInsets.all(20),
                          decoration: BoxDecoration(
                            color: Colors.grey.shade50,
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: Column(
                            children: [
                              Icon(
                                Icons.info_outline,
                                color: Colors.grey.shade400,
                                size: 32,
                              ),
                              SizedBox(height: 8),
                              Text(
                                'No payload data available',
                                style: TextStyle(
                                  color: Colors.grey.shade600,
                                  fontSize: 14,
                                ),
                              ),
                            ],
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

  Widget _buildDetailRow(String label, String value, IconData icon) {
    return Padding(
      padding: EdgeInsets.only(bottom: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: EdgeInsets.all(6),
            decoration: BoxDecoration(
              color: Colors.indigo.shade50,
              borderRadius: BorderRadius.circular(6),
            ),
            child: Icon(icon, size: 16, color: Colors.indigo),
          ),
          SizedBox(width: 12),
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
                SizedBox(height: 2),
                SelectableText(
                  value,
                  style: TextStyle(
                    fontSize: 14,
                    fontWeight: FontWeight.w600,
                    color: Colors.grey.shade800,
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  void _showAboutDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
        title: Row(
          children: [
            Icon(Icons.info, color: Colors.indigo),
            SizedBox(width: 8),
            Text('About'),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Mobile Network Packet Analyzer',
              style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
            ),
            SizedBox(height: 8),
            Text('Version 1.0.0'),
            SizedBox(height: 12),
            Text(
              'A comprehensive network packet analysis tool supporting both rooted and unrooted Android devices.',
              style: TextStyle(color: Colors.grey.shade700),
            ),
            SizedBox(height: 12),
            Text('Features:', style: TextStyle(fontWeight: FontWeight.bold)),
            Text('• Real-time packet capture'),
            Text('• VPN-based traffic proxy'),
            Text('• libpcap integration (rooted)'),
            Text('• Protocol statistics'),
            Text('• Deep packet inspection'),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: Text('Close'),
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _packetSubscription?.cancel();
    _statsSubscription?.cancel();
    _statusAnimationController.dispose();
    _statsAnimationController.dispose();
    super.dispose();
  }
}
