import 'package:flutter/material.dart';
import 'dart:math' as math;

// ================= DATA MODELS =================

/// Safely coerces a native-bridge value to an int. Values may arrive as
/// int, double, or String depending on the platform-channel path — `as
/// num?` throws (rather than returning null) for a non-null non-num value
/// like a String, which used to skip the int.tryParse fallback entirely.
int _asInt(dynamic v) {
  if (v is num) return v.toInt();
  return int.tryParse(v?.toString() ?? '') ?? 0;
}

/// As [_asInt], but returns null (rather than 0) when [v] is absent/unparsable
/// — used for optional numeric fields where "unknown" and "zero" mean
/// different things (e.g. anomalyScore).
double? _asDoubleOrNull(dynamic v) {
  if (v == null) return null;
  if (v is num) return v.toDouble();
  return double.tryParse(v.toString());
}

class PacketInfo {
  final String sourceIp, destinationIp, protocol, timestamp, payload;
  final int sourcePort, destinationPort, size;
  final String? direction, flags, appName, owningApp;
  final Map<String, dynamic>? dpiData;
  final Map<String, dynamic>? payloadAnalysis;
  final double? anomalyScore;
  final double? entropyScore;
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
    this.owningApp,
    this.dpiData,
    this.payloadAnalysis,
    this.anomalyScore,
    this.entropyScore,
    this.httpData,
    this.dnsData,
    this.tlsData,
    this.quicData,
    this.domain,
    this.domainFriendly,
    this.sourceDomain,
  });

  factory PacketInfo.empty() => PacketInfo(
        sourceIp: '0.0.0.0',
        destinationIp: '0.0.0.0',
        sourcePort: 0,
        destinationPort: 0,
        protocol: 'UNK',
        size: 0,
        timestamp: DateTime.now().millisecondsSinceEpoch.toString(),
        payload: '',
      );

  factory PacketInfo.fromMap(Map<String, dynamic> map) {
    if (map.isEmpty) return PacketInfo.empty();

    // Extract DPI fields (http_, dns_, tls_, dhcp_)
    final dpiFields = <String, dynamic>{};
    try {
      for (final entry in map.entries) {
        if (entry.key.startsWith('http_') ||
            entry.key.startsWith('dns_') ||
            entry.key.startsWith('tls_') ||
            entry.key.startsWith('dhcp_')) {
          dpiFields[entry.key] = entry.value;
        }
      }
    } catch (_) {}

    Map<String, dynamic>? safeMap(dynamic v) {
      if (v == null) return null;
      try {
        return Map<String, dynamic>.from(v as Map);
      } catch (_) {
        return null;
      }
    }

    return PacketInfo(
      sourceIp:
          map['sourceIp']?.toString() ??
          map['sourceAddress']?.toString() ??
          '0.0.0.0',
      destinationIp:
          map['destinationIp']?.toString() ??
          map['destinationAddress']?.toString() ??
          '0.0.0.0',
      sourcePort: _asInt(map['sourcePort']),
      destinationPort: _asInt(map['destinationPort']),
      protocol: map['protocol']?.toString() ?? 'UNK',
      size: _asInt(map['size']),
      timestamp:
          map['timestamp']?.toString() ??
          DateTime.now().millisecondsSinceEpoch.toString(),
      payload: map['payload']?.toString() ?? '',
      direction: map['direction']?.toString(),
      flags: map['flags']?.toString(),
      appName: map['appName']?.toString(),
      // Native side sends "" (not null) when the owning app couldn't be
      // resolved — normalize to null so the UI can just check for presence.
      owningApp: (map['owningApp']?.toString().isNotEmpty ?? false)
          ? map['owningApp'].toString()
          : null,
      dpiData: dpiFields.isNotEmpty ? dpiFields : null,
      payloadAnalysis: safeMap(map['payloadAnalysis']),
      httpData: safeMap(map['httpData']),
      dnsData: safeMap(map['dnsData']),
      tlsData: safeMap(map['tlsData']),
      quicData: safeMap(map['quicData']),
      anomalyScore: _asDoubleOrNull(map['anomalyScore']),
      entropyScore: _asDoubleOrNull(map['entropyScore']),
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
      details: map['details'] is Map
          ? Map<String, dynamic>.from(map['details'] as Map)
          : null,
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
    int toInt(dynamic v) =>
        (v is int) ? v : int.tryParse(v?.toString() ?? "0") ?? 0;
    double toDouble(dynamic v) =>
        (v is double) ? v : double.tryParse(v?.toString() ?? "0") ?? 0;

    return NetworkMetrics(
      totalPackets: toInt(map['totalPackets']),
      packetsPerSecond: toDouble(map['packetsPerSecond']),
      totalSessions: toInt(map['totalSessions']),
      dataRate: toDouble(map['dataRate']),
    );
  }
}

class PcapExportStatus {
  final bool isExporting;
  final String? filePath;

  const PcapExportStatus({this.isExporting = false, this.filePath});
}
