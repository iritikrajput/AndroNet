import 'package:flutter/material.dart';
import 'dart:math' as math;

// ================= DATA MODELS =================

class PacketInfo {
  final String sourceIp, destinationIp, protocol, timestamp, payload;
  final int sourcePort, destinationPort, size;
  final String? direction, flags, appName;
  final Map<String, dynamic>? dpiData;
  final Map<String, dynamic>? payloadAnalysis;
  final double? anomalyScore;
  final Map<String, dynamic>? httpData;
  final Map<String, dynamic>? dnsData;
  final Map<String, dynamic>? tlsData;
  final Map<String, dynamic>? quicData;
  final String? domain;
  final String? domainFriendly;
  final String? sourceDomain;

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
    this.dpiData,
    this.payloadAnalysis,
    this.anomalyScore,
    this.httpData,
    this.dnsData,
    this.tlsData,
    this.quicData,
    this.domain,
    this.domainFriendly,
    this.sourceDomain,
  });

  factory PacketInfo.fromMap(Map<String, dynamic> map) {
    // Extract DPI fields (http_, dns_, tls_, dhcp_)
    final dpiFields = <String, dynamic>{};
    for (final entry in map.entries) {
      if (entry.key.startsWith('http_') ||
          entry.key.startsWith('dns_') ||
          entry.key.startsWith('tls_') ||
          entry.key.startsWith('dhcp_')) {
        dpiFields[entry.key] = entry.value;
      }
    }

    return PacketInfo(
      sourceIp:
          map['sourceIp']?.toString() ?? map['sourceAddress']?.toString() ?? '',
      destinationIp:
          map['destinationIp']?.toString() ??
          map['destinationAddress']?.toString() ??
          '',
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
      dpiData: dpiFields.isNotEmpty ? dpiFields : null,
      payloadAnalysis: map['payloadAnalysis'] as Map<String, dynamic>?,
      httpData: map['httpData'] != null
          ? Map<String, dynamic>.from(map['httpData'] as Map)
          : null,
      dnsData: map['dnsData'] != null
          ? Map<String, dynamic>.from(map['dnsData'] as Map)
          : null,
      tlsData: map['tlsData'] != null
          ? Map<String, dynamic>.from(map['tlsData'] as Map)
          : null,
      quicData: map['quicData'] != null
          ? Map<String, dynamic>.from(map['quicData'] as Map)
          : null,
      // anomalyScore (0.0-1.0) is populated by AnomalyDetector.calculateAnomalyScore() on Android side
      anomalyScore: map['anomalyScore'] != null
          ? (map['anomalyScore'] as num).toDouble()
          : null,
      domain: map['domain']?.toString(),
      domainFriendly: map['domainFriendly']?.toString(),
      sourceDomain: map['sourceDomain']?.toString(),
    );
  }

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
  bool get hasDpiData => dpiData != null && dpiData!.isNotEmpty;
}

class AnomalyInfo {
  final String type;
  final String severity;
  final String title; // ADDED THIS PROPERTY - FIXES ERROR 1
  final String description;
  final String sourceIp;
  final String destinationIp;
  final String timestamp; // CHANGED FROM int TO String - FIXES ERROR 4
  final Map<String, dynamic>? details;

  const AnomalyInfo({
    required this.type,
    required this.severity,
    required this.title, // ADDED THIS PARAMETER - FIXES ERROR 1
    required this.description,
    required this.sourceIp,
    required this.destinationIp,
    required this.timestamp, // Now String instead of int - FIXES ERROR 4
    this.details,
  });

  factory AnomalyInfo.fromMap(Map<String, dynamic> map) {
    return AnomalyInfo(
      type: map['type']?.toString() ?? 'UNKNOWN',
      severity: map['severity']?.toString() ?? 'LOW',
      title:
          map['title']?.toString() ??
          'Security Alert', // ADDED THIS LINE - FIXES ERROR 1
      description:
          map['description']?.toString() ?? 'Security anomaly detected',
      sourceIp: map['sourceIp']?.toString() ?? '',
      destinationIp: map['destinationIp']?.toString() ?? '',
      timestamp:
          map['timestamp']?.toString() ??
          DateTime.now().millisecondsSinceEpoch
              .toString(), // String format - FIXES ERROR 4
      details: map['details'] as Map<String, dynamic>?,
    );
  }

  String get formattedTime {
    try {
      // Handle both String timestamp and int timestamp
      final timestampInt = int.tryParse(timestamp);
      if (timestampInt != null) {
        final time = DateTime.fromMillisecondsSinceEpoch(timestampInt);
        return '${time.hour.toString().padLeft(2, '0')}:${time.minute.toString().padLeft(2, '0')}:${time.second.toString().padLeft(2, '0')}';
      } else {
        // If timestamp is already formatted, return as is
        return timestamp;
      }
    } catch (e) {
      return DateTime.now().toString().substring(11, 19);
    }
  }

  String get formattedDate {
    try {
      final timestampInt = int.tryParse(timestamp);
      if (timestampInt != null) {
        final time = DateTime.fromMillisecondsSinceEpoch(timestampInt);
        return '${time.day.toString().padLeft(2, '0')}/${time.month.toString().padLeft(2, '0')}/${time.year}';
      } else {
        return DateTime.now().toString().substring(0, 10);
      }
    } catch (e) {
      return '';
    }
  }

  Color get severityColor {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return const Color(0xFFD32F2F); // Dark red
      case 'HIGH':
        return const Color(0xFFFF5722); // Orange-red
      case 'MEDIUM':
        return const Color(0xFFFF9800); // Orange
      case 'LOW':
        return const Color(0xFFFFC107); // Yellow
      default:
        return const Color(0xFF9E9E9E); // Gray
    }
  }

  IconData get typeIcon {
    switch (type.toUpperCase()) {
      case 'PORT_SCAN':
        return Icons.radar;
      case 'SYN_FLOOD':
        return Icons.water_damage;
      case 'ARP_SPOOFING':
        return Icons.warning_amber;
      case 'DNS_TUNNELING':
        return Icons.dns;
      case 'CONNECTION_FLOOD':
        return Icons.flood;
      case 'UNUSUAL_TRAFFIC':
        return Icons.traffic;
      case 'MALFORMED_PACKET':
        return Icons.broken_image;
      default:
        return Icons.security;
    }
  }

  String get friendlyType {
    switch (type.toUpperCase()) {
      case 'PORT_SCAN':
        return 'Port Scan';
      case 'SYN_FLOOD':
        return 'SYN Flood Attack';
      case 'ARP_SPOOFING':
        return 'ARP Spoofing';
      case 'DNS_TUNNELING':
        return 'DNS Tunneling';
      case 'CONNECTION_FLOOD':
        return 'Connection Flood';
      case 'UNUSUAL_TRAFFIC':
        return 'Unusual Traffic';
      case 'MALFORMED_PACKET':
        return 'Malformed Packet';
      default:
        return type.replaceAll('_', ' ');
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

class PcapExportStatus {
  final bool isExporting;
  final String? filePath;

  const PcapExportStatus({this.isExporting = false, this.filePath});
}
