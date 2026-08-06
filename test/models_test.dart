import 'package:flutter_test/flutter_test.dart';
import 'package:packet_analyzer/models.dart';

void main() {
  group('PacketInfo.fromMap', () {
    test('empty map falls back to PacketInfo.empty()', () {
      final packet = PacketInfo.fromMap({});
      expect(packet.sourceIp, '0.0.0.0');
      expect(packet.destinationIp, '0.0.0.0');
      expect(packet.protocol, 'UNK');
      expect(packet.size, 0);
    });

    test('parses a well-formed map', () {
      final packet = PacketInfo.fromMap({
        'sourceIp': '10.0.0.2',
        'destinationIp': '8.8.8.8',
        'sourcePort': 51234,
        'destinationPort': 443,
        'protocol': 'TCP',
        'size': 1500,
        'timestamp': '1700000000000',
        'payload': 'hello',
        'direction': 'outgoing',
      });

      expect(packet.sourceIp, '10.0.0.2');
      expect(packet.destinationIp, '8.8.8.8');
      expect(packet.sourcePort, 51234);
      expect(packet.destinationPort, 443);
      expect(packet.protocol, 'TCP');
      expect(packet.size, 1500);
      expect(packet.isOutgoing, isTrue);
      expect(packet.displayDirection, 'OUT');
    });

    test('falls back to sourceAddress/destinationAddress field names', () {
      final packet = PacketInfo.fromMap({
        'sourceAddress': '192.168.1.5',
        'destinationAddress': '1.1.1.1',
      });
      expect(packet.sourceIp, '192.168.1.5');
      expect(packet.destinationIp, '1.1.1.1');
    });

    test('coerces string port/size values instead of crashing', () {
      final packet = PacketInfo.fromMap({
        'sourcePort': '8080',
        'destinationPort': 'not-a-number',
        'size': '2048',
      });
      expect(packet.sourcePort, 8080);
      expect(packet.destinationPort, 0); // unparsable -> safe default
      expect(packet.size, 2048);
    });

    test('malformed nested maps do not throw and are dropped', () {
      final packet = PacketInfo.fromMap({
        'sourceIp': '10.0.0.1',
        'httpData': 'not-a-map', // wrong type on purpose
        'dnsData': 12345, // wrong type on purpose
      });
      expect(packet.httpData, isNull);
      expect(packet.dnsData, isNull);
    });

    test('collects DPI-prefixed fields into dpiData', () {
      final packet = PacketInfo.fromMap({
        'http_method': 'GET',
        'dns_query': 'example.com',
        'unrelated_field': 'ignored',
      });
      expect(packet.hasDpiData, isTrue);
      expect(packet.dpiData!['http_method'], 'GET');
      expect(packet.dpiData!['dns_query'], 'example.com');
      expect(packet.dpiData!.containsKey('unrelated_field'), isFalse);
    });

    test('isOutgoing recognizes both OUT and OUTGOING direction values', () {
      expect(PacketInfo.fromMap({'direction': 'OUT'}).isOutgoing, isTrue);
      expect(
        PacketInfo.fromMap({'direction': 'outgoing'}).isOutgoing,
        isTrue,
      );
      expect(PacketInfo.fromMap({'direction': 'incoming'}).isOutgoing, isFalse);
    });
  });

  group('AnomalyInfo.fromMap', () {
    test('missing fields fall back to safe defaults', () {
      final anomaly = AnomalyInfo.fromMap({});
      expect(anomaly.type, 'UNKNOWN');
      expect(anomaly.severity, 'LOW');
      expect(anomaly.title, 'Security Alert');
      expect(anomaly.description, 'Security anomaly detected');
      expect(anomaly.sourceIp, '');
      expect(anomaly.details, isNull);
    });

    test('parses a well-formed anomaly map', () {
      final anomaly = AnomalyInfo.fromMap({
        'type': 'PORT_SCAN',
        'severity': 'HIGH',
        'title': 'Port Scan Detected',
        'description': '20 ports probed in 10s',
        'sourceIp': '10.0.0.5',
        'destinationIp': '10.0.0.1',
        'timestamp': '1700000000000',
        'details': {'portsScanned': 25},
      });

      expect(anomaly.type, 'PORT_SCAN');
      expect(anomaly.severity, 'HIGH');
      expect(anomaly.friendlyType, 'Port Scan');
      expect(anomaly.details!['portsScanned'], 25);
    });

    test('non-map details value is dropped instead of throwing', () {
      final anomaly = AnomalyInfo.fromMap({'details': 'not-a-map'});
      expect(anomaly.details, isNull);
    });

    test('severityColor and typeIcon have a safe default for unknown values', () {
      final anomaly = AnomalyInfo.fromMap({
        'type': 'SOMETHING_NEW',
        'severity': 'UNRANKED',
      });
      // Should not throw, and should fall through to the default branch.
      expect(anomaly.severityColor, isNotNull);
      expect(anomaly.typeIcon, isNotNull);
      expect(anomaly.friendlyType, 'SOMETHING NEW');
    });
  });

  group('NetworkMetrics.fromMap', () {
    test('coerces numeric-looking strings', () {
      final metrics = NetworkMetrics.fromMap({
        'totalPackets': '100',
        'packetsPerSecond': '12.5',
        'totalSessions': 3,
        'dataRate': 45.2,
      });
      expect(metrics.totalPackets, 100);
      expect(metrics.packetsPerSecond, 12.5);
      expect(metrics.totalSessions, 3);
      expect(metrics.dataRate, 45.2);
    });

    test('missing fields default to zero', () {
      final metrics = NetworkMetrics.fromMap({});
      expect(metrics.totalPackets, 0);
      expect(metrics.packetsPerSecond, 0.0);
    });
  });
}
