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
      debugShowCheckedModeBanner: false, // Remove debug banner
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

// Service with proper error handling
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
    } on MissingPluginException {
      print(
        'clearPackets method not implemented in native code - clearing local data only',
      );
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
      // Added hamburger menu drawer
      drawer: Drawer(
        child: SafeArea(
          child: ListView(
            padding: EdgeInsets.zero,
            children: <Widget>[
              Container(
                height: 120,
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [Colors.indigo, Colors.indigoAccent],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                ),
                child: Center(
                  child: Column(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(Icons.network_check, color: Colors.white, size: 40),
                      SizedBox(height: 8),
                      Text(
                        'Packet Analyzer',
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ],
                  ),
                ),
              ),

              // Root Status Toggle
              ListTile(
                leading: Icon(
                  _isRooted ? Icons.security : Icons.smartphone,
                  color: _isRooted ? Colors.green : Colors.orange,
                ),
                title: Text('Root Access'),
                subtitle: Text(
                  _isRooted ? 'Device is rooted' : 'Device is unrooted',
                ),
                trailing: Switch(
                  value: _isRooted,
                  activeColor: Colors.green,
                  onChanged: _isCapturing
                      ? null
                      : (bool value) {
                          setState(() {
                            _isRooted = value;
                            if (!value) {
                              _useRootedMode = false;
                            }
                          });
                          _showSnackBar(
                            value ? 'Root mode enabled' : 'Root mode disabled',
                            value ? Colors.green : Colors.orange,
                          );
                        },
                ),
              ),

              Divider(),

              // Capture Mode (only show if rooted)
              if (_isRooted) ...[
                ListTile(
                  leading: Icon(Icons.swap_horiz, color: Colors.indigo),
                  title: Text('Capture Mode'),
                  subtitle: Text(
                    _useRootedMode ? 'libpcap (Root)' : 'VPN Proxy',
                  ),
                  trailing: Switch(
                    value: _useRootedMode,
                    activeColor: Colors.green,
                    onChanged: _isCapturing
                        ? null
                        : (bool value) {
                            setState(() {
                              _useRootedMode = value;
                            });
                          },
                  ),
                ),
                Divider(),
              ],

              // Clear Packets
              ListTile(
                leading: Icon(Icons.clear, color: Colors.blue),
                title: Text('Clear Packets'),
                onTap: () {
                  Navigator.pop(context);
                  _clearPackets();
                },
              ),

              // About
              ListTile(
                leading: Icon(Icons.info_outline, color: Colors.grey),
                title: Text('About'),
                onTap: () {
                  Navigator.pop(context);
                  _showAboutDialog();
                },
              ),

              // Exit
              ListTile(
                leading: Icon(Icons.exit_to_app, color: Colors.red),
                title: Text('Exit'),
                onTap: () {
                  SystemNavigator.pop();
                },
              ),
            ],
          ),
        ),
      ),

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
          // Status indicator
          Container(
            margin: EdgeInsets.only(right: 16),
            child: Center(
              child: Row(
                children: [
                  Container(
                    width: 8,
                    height: 8,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: _isCapturing ? Colors.green : Colors.grey,
                    ),
                  ),
                  SizedBox(width: 4),
                  Text(
                    _isCapturing ? 'LIVE' : 'OFF',
                    style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold),
                  ),
                ],
              ),
            ),
          ),
        ],
      ),

      body: SafeArea(
        child: Column(
          children: [
            _buildControlPanel(),
            _buildStatsPanel(),
            _buildProtocolFilter(),
            Expanded(child: _buildPacketList()),
          ],
        ),
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
            margin: EdgeInsets.all(8),
            elevation: 4,
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
                padding: EdgeInsets.all(12),
                child: Column(
                  children: [
                    // Device Status Row
                    Row(
                      children: [
                        Icon(
                          _isRooted ? Icons.security : Icons.smartphone,
                          color: _isRooted ? Colors.green : Colors.orange,
                          size: 20,
                        ),
                        SizedBox(width: 8),
                        Text(
                          'Device: ',
                          style: TextStyle(
                            fontSize: 14,
                            fontWeight: FontWeight.w500,
                          ),
                        ),
                        Container(
                          padding: EdgeInsets.symmetric(
                            horizontal: 6,
                            vertical: 2,
                          ),
                          decoration: BoxDecoration(
                            color: _isRooted
                                ? Colors.green.shade100
                                : Colors.orange.shade100,
                            borderRadius: BorderRadius.circular(6),
                          ),
                          child: Text(
                            _isRooted ? 'Rooted' : 'Unrooted',
                            style: TextStyle(
                              fontSize: 12,
                              fontWeight: FontWeight.bold,
                              color: _isRooted
                                  ? Colors.green.shade700
                                  : Colors.orange.shade700,
                            ),
                          ),
                        ),
                        Spacer(),
                        if (_isRooted)
                          Container(
                            padding: EdgeInsets.symmetric(
                              horizontal: 6,
                              vertical: 2,
                            ),
                            decoration: BoxDecoration(
                              color: _useRootedMode
                                  ? Colors.green.shade100
                                  : Colors.blue.shade100,
                              borderRadius: BorderRadius.circular(6),
                            ),
                            child: Text(
                              _useRootedMode ? 'libpcap' : 'VPN',
                              style: TextStyle(
                                fontSize: 12,
                                fontWeight: FontWeight.bold,
                                color: _useRootedMode
                                    ? Colors.green.shade700
                                    : Colors.blue.shade700,
                              ),
                            ),
                          ),
                      ],
                    ),

                    SizedBox(height: 12),

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
                              fontSize: 14,
                              fontWeight: FontWeight.w500,
                              color: _isCapturing
                                  ? Colors.green.shade700
                                  : Colors.grey.shade600,
                            ),
                          ),
                          Spacer(),
                          if (_isCapturing)
                            SizedBox(
                              width: 16,
                              height: 16,
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
              margin: EdgeInsets.symmetric(horizontal: 8),
              elevation: 4,
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(12),
              ),
              child: Padding(
                padding: EdgeInsets.all(12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Icon(Icons.analytics, color: Colors.indigo, size: 20),
                        SizedBox(width: 8),
                        Text(
                          'Protocol Statistics',
                          style: TextStyle(
                            fontSize: 16,
                            fontWeight: FontWeight.bold,
                            color: Colors.indigo,
                          ),
                        ),
                        Spacer(),
                        Container(
                          padding: EdgeInsets.symmetric(
                            horizontal: 6,
                            vertical: 2,
                          ),
                          decoration: BoxDecoration(
                            color: Colors.indigo.shade100,
                            borderRadius: BorderRadius.circular(8),
                          ),
                          child: Text(
                            'Total: ${_packets.length}',
                            style: TextStyle(
                              fontSize: 12,
                              fontWeight: FontWeight.bold,
                              color: Colors.indigo.shade700,
                            ),
                          ),
                        ),
                      ],
                    ),
                    SizedBox(height: 8),
                    if (_stats.isEmpty)
                      Container(
                        padding: EdgeInsets.all(16),
                        child: Center(
                          child: Column(
                            children: [
                              Icon(
                                Icons.inbox,
                                size: 32,
                                color: Colors.grey.shade400,
                              ),
                              SizedBox(height: 8),
                              Text(
                                'No data captured yet',
                                style: TextStyle(
                                  color: Colors.grey.shade600,
                                  fontSize: 14,
                                ),
                              ),
                            ],
                          ),
                        ),
                      )
                    else
                      Column(
                        children: _stats
                            .take(3)
                            .map(
                              (stat) => Padding(
                                padding: EdgeInsets.symmetric(vertical: 2),
                                child: Container(
                                  padding: EdgeInsets.all(8),
                                  decoration: BoxDecoration(
                                    color: _getProtocolColor(
                                      stat.protocol,
                                    ).withOpacity(0.1),
                                    borderRadius: BorderRadius.circular(6),
                                  ),
                                  child: Row(
                                    children: [
                                      CircleAvatar(
                                        radius: 8,
                                        backgroundColor: _getProtocolColor(
                                          stat.protocol,
                                        ),
                                        child: Text(
                                          stat.protocol.isNotEmpty
                                              ? stat.protocol.substring(0, 1)
                                              : '?',
                                          style: TextStyle(
                                            fontSize: 8,
                                            color: Colors.white,
                                            fontWeight: FontWeight.bold,
                                          ),
                                        ),
                                      ),
                                      SizedBox(width: 8),
                                      Text(
                                        stat.protocol,
                                        style: TextStyle(
                                          fontWeight: FontWeight.bold,
                                          fontSize: 12,
                                        ),
                                      ),
                                      Spacer(),
                                      Text(
                                        '${stat.packetCount}',
                                        style: TextStyle(
                                          fontSize: 10,
                                          color: Colors.grey.shade600,
                                        ),
                                      ),
                                      SizedBox(width: 8),
                                      Text(
                                        _formatBytes(stat.totalBytes),
                                        style: TextStyle(
                                          fontSize: 10,
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
      height: 40,
      margin: EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      child: ListView(
        scrollDirection: Axis.horizontal,
        children: protocols
            .map(
              (protocol) => Padding(
                padding: EdgeInsets.only(right: 6),
                child: FilterChip(
                  label: Text(protocol, style: TextStyle(fontSize: 12)),
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

  Widget _buildPacketList() {
    final filteredPackets = _filteredPackets;
    return Card(
      margin: EdgeInsets.all(8),
      elevation: 4,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: Colors.indigo.shade50,
              borderRadius: BorderRadius.only(
                topLeft: Radius.circular(12),
                topRight: Radius.circular(12),
              ),
            ),
            child: Row(
              children: [
                Icon(Icons.list, color: Colors.indigo, size: 20),
                SizedBox(width: 8),
                Text(
                  'Live Packets',
                  style: TextStyle(
                    fontSize: 16,
                    fontWeight: FontWeight.bold,
                    color: Colors.indigo,
                  ),
                ),
                Spacer(),
                Container(
                  padding: EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                    color: Colors.indigo,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Text(
                    '${filteredPackets.length}',
                    style: TextStyle(
                      color: Colors.white,
                      fontSize: 12,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ],
            ),
          ),
          Expanded(
            child: filteredPackets.isEmpty
                ? Container(
                    padding: EdgeInsets.all(32),
                    child: Center(
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(
                            Icons.network_check,
                            size: 48,
                            color: Colors.grey.shade400,
                          ),
                          SizedBox(height: 12),
                          Text(
                            'No packets captured',
                            style: TextStyle(
                              fontSize: 16,
                              color: Colors.grey.shade600,
                              fontWeight: FontWeight.w500,
                            ),
                          ),
                          SizedBox(height: 6),
                          Text(
                            'Start capturing to see network traffic',
                            style: TextStyle(
                              fontSize: 12,
                              color: Colors.grey.shade500,
                            ),
                          ),
                        ],
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
      margin: EdgeInsets.symmetric(horizontal: 6, vertical: 1),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(6),
        color: index.isEven ? Colors.grey.shade50 : Colors.white,
      ),
      child: ListTile(
        dense: true,
        contentPadding: EdgeInsets.symmetric(horizontal: 8, vertical: 2),
        leading: CircleAvatar(
          radius: 12,
          backgroundColor: _getProtocolColor(packet.protocol),
          child: Text(
            packet.protocol.isNotEmpty ? packet.protocol.substring(0, 1) : '?',
            style: TextStyle(
              fontSize: 10,
              color: Colors.white,
              fontWeight: FontWeight.bold,
            ),
          ),
        ),
        title: Text(
          '${packet.sourceIp}:${packet.sourcePort} → ${packet.destinationIp}:${packet.destinationPort}',
          style: TextStyle(
            fontSize: 11,
            fontFamily: 'monospace',
            fontWeight: FontWeight.w500,
          ),
        ),
        subtitle: Row(
          children: [
            Container(
              padding: EdgeInsets.symmetric(horizontal: 4, vertical: 1),
              decoration: BoxDecoration(
                color: _getProtocolColor(packet.protocol).withOpacity(0.2),
                borderRadius: BorderRadius.circular(3),
              ),
              child: Text(
                packet.protocol,
                style: TextStyle(
                  fontSize: 9,
                  fontWeight: FontWeight.bold,
                  color: _getProtocolColor(packet.protocol),
                ),
              ),
            ),
            SizedBox(width: 6),
            Text('${packet.size}B', style: TextStyle(fontSize: 9)),
            SizedBox(width: 6),
            Text(
              packet.timestamp,
              style: TextStyle(fontSize: 9, color: Colors.grey.shade600),
            ),
          ],
        ),
        trailing: Icon(
          Icons.chevron_right,
          color: Colors.grey.shade400,
          size: 16,
        ),
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
      case 'PROTOCOL':
        return Colors.brown;
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
        child: Container(
          constraints: BoxConstraints(
            maxHeight: MediaQuery.of(context).size.height * 0.8,
            maxWidth: MediaQuery.of(context).size.width * 0.9,
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
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
                    CircleAvatar(
                      radius: 16,
                      backgroundColor: Colors.white.withOpacity(0.2),
                      child: Text(
                        packet.protocol.isNotEmpty
                            ? packet.protocol.substring(0, 1)
                            : '?',
                        style: TextStyle(
                          fontSize: 14,
                          color: Colors.white,
                          fontWeight: FontWeight.bold,
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
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          Text(
                            packet.protocol.toUpperCase(),
                            style: TextStyle(
                              color: Colors.white.withOpacity(0.8),
                              fontSize: 12,
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
              Flexible(
                child: Container(
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
                              fontSize: 14,
                              fontWeight: FontWeight.bold,
                              color: Colors.grey.shade700,
                            ),
                          ),
                          SizedBox(height: 8),
                          Container(
                            width: double.infinity,
                            padding: EdgeInsets.all(8),
                            decoration: BoxDecoration(
                              color: Colors.grey.shade100,
                              borderRadius: BorderRadius.circular(6),
                              border: Border.all(color: Colors.grey.shade300),
                            ),
                            child: SelectableText(
                              packet.payload,
                              style: TextStyle(
                                fontFamily: 'monospace',
                                fontSize: 10,
                                color: Colors.grey.shade800,
                              ),
                            ),
                          ),
                        ] else ...[
                          Container(
                            width: double.infinity,
                            padding: EdgeInsets.all(16),
                            decoration: BoxDecoration(
                              color: Colors.grey.shade50,
                              borderRadius: BorderRadius.circular(6),
                            ),
                            child: Column(
                              children: [
                                Icon(
                                  Icons.info_outline,
                                  color: Colors.grey.shade400,
                                  size: 24,
                                ),
                                SizedBox(height: 6),
                                Text(
                                  'No payload data available',
                                  style: TextStyle(
                                    color: Colors.grey.shade600,
                                    fontSize: 12,
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
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildDetailRow(String label, String value, IconData icon) {
    return Padding(
      padding: EdgeInsets.only(bottom: 8),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: EdgeInsets.all(4),
            decoration: BoxDecoration(
              color: Colors.indigo.shade50,
              borderRadius: BorderRadius.circular(4),
            ),
            child: Icon(icon, size: 14, color: Colors.indigo),
          ),
          SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  label,
                  style: TextStyle(
                    fontSize: 10,
                    color: Colors.grey.shade600,
                    fontWeight: FontWeight.w500,
                  ),
                ),
                SizedBox(height: 2),
                SelectableText(
                  value,
                  style: TextStyle(
                    fontSize: 12,
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
