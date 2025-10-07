import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:async';
import 'dart:convert';
import 'dart:math' as math;
import 'models.dart';

// Enhanced UI Components for Advanced Features

// ================= ENHANCED PACKET VISUALIZATION =================

class EnhancedPacketCard extends StatelessWidget {
  final PacketInfo packet;

  const EnhancedPacketCard({
    Key? key,
    required this.packet,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final protocolColor = _getEnhancedProtocolColor(packet.protocol);
    final securityLevel = _getSecurityLevel(packet);
    final hasPayloadAnalysis = packet.payloadAnalysis != null;

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      elevation: securityLevel > 0 ? 3 : 1,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(
          color: securityLevel > 0
              ? _getSecurityColor(securityLevel)
              : packet.directionColor.withOpacity(0.3),
          width: securityLevel > 0 ? 2 : 1,
        ),
      ),
      child: InkWell(
        onTap: () => _showEnhancedPacketDetails(context, packet),
        borderRadius: BorderRadius.circular(12),
        child: Padding(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Enhanced Header Row
              Row(
                children: [
                  // Protocol Badge with Enhanced Styling
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: protocolColor.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(6),
                      border: Border.all(color: protocolColor.withOpacity(0.3)),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(
                          _getProtocolIcon(packet.protocol),
                          size: 12,
                          color: protocolColor,
                        ),
                        const SizedBox(width: 4),
                        Text(
                          packet.appName ?? packet.protocol,
                          style: TextStyle(
                            fontSize: 11,
                            fontWeight: FontWeight.bold,
                            color: protocolColor,
                          ),
                        ),
                      ],
                    ),
                  ),

                  const SizedBox(width: 8),

                  // Direction Indicator
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

                  // Security Alert Badge
                  if (securityLevel > 0) ...[
                    const SizedBox(width: 8),
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 6,
                        vertical: 2,
                      ),
                      decoration: BoxDecoration(
                        color: _getSecurityColor(securityLevel).withOpacity(0.1),
                        borderRadius: BorderRadius.circular(4),
                        border: Border.all(
                          color: _getSecurityColor(securityLevel),
                        ),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(
                            _getSecurityIcon(securityLevel),
                            size: 10,
                            color: _getSecurityColor(securityLevel),
                          ),
                          const SizedBox(width: 2),
                          Text(
                            _getSecurityLabel(securityLevel),
                            style: TextStyle(
                              fontSize: 8,
                              fontWeight: FontWeight.bold,
                              color: _getSecurityColor(securityLevel),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],

                  // File Detection Badge
                  if (hasPayloadAnalysis &&
                      (packet.payloadAnalysis!['detectedFiles'] as List?)?.isNotEmpty == true) ...[
                    const SizedBox(width: 8),
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 6,
                        vertical: 2,
                      ),
                      decoration: BoxDecoration(
                        color: Colors.purple.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(4),
                        border: Border.all(color: Colors.purple),
                      ),
                      child: const Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Icon(Icons.attach_file, size: 10, color: Colors.purple),
                          SizedBox(width: 2),
                          Text(
                            'FILE',
                            style: TextStyle(
                              fontSize: 8,
                              fontWeight: FontWeight.bold,
                              color: Colors.purple,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],

                  const Spacer(),

                  // Timestamp with Enhanced Formatting
                  Text(
                    packet.formattedTime,
                    style: TextStyle(
                      fontSize: 11,
                      color: Theme.of(context).colorScheme.onSurface.withOpacity(0.6),
                      fontFamily: 'monospace',
                    ),
                  ),
                ],
              ),

              const SizedBox(height: 12),

              // Connection Info
              Text(
                '${packet.sourceIp}:${packet.sourcePort} → ${packet.destinationIp}:${packet.destinationPort}',
                style: const TextStyle(
                  fontSize: 13,
                  fontFamily: 'monospace',
                  fontWeight: FontWeight.w500,
                ),
              ),

              const SizedBox(height: 8),

              // Enhanced Footer Row
              Row(
                children: [
                  // Packet Size with Visual Indicator
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 8,
                      vertical: 2,
                    ),
                    decoration: BoxDecoration(
                      color: _getSizeColor(packet.size),
                      borderRadius: BorderRadius.circular(4),
                    ),
                    child: Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        Icon(Icons.data_usage, size: 12, color: Colors.white),
                        const SizedBox(width: 4),
                        Text(
                          '${packet.size} bytes',
                          style: const TextStyle(
                            fontSize: 10,
                            color: Colors.white,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                  ),

                  // Flags Indicator
                  if (packet.flags != null) ...[
                    const SizedBox(width: 8),
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 6,
                        vertical: 2,
                      ),
                      decoration: BoxDecoration(
                        color: Colors.orange.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(4),
                        border: Border.all(color: Colors.orange),
                      ),
                      child: Text(
                        packet.flags!,
                        style: const TextStyle(
                          fontSize: 9,
                          color: Colors.orange,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                  ],

                  // Anomaly Score Indicator
                  if (packet.anomalyScore != null && packet.anomalyScore! > 0.5) ...[
                    const SizedBox(width: 8),
                    Container(
                      padding: const EdgeInsets.symmetric(
                        horizontal: 6,
                        vertical: 2,
                      ),
                      decoration: BoxDecoration(
                        color: Colors.red.withOpacity(0.1),
                        borderRadius: BorderRadius.circular(4),
                        border: Border.all(color: Colors.red),
                      ),
                      child: Text(
                        'ML:${(packet.anomalyScore! * 100).toStringAsFixed(0)}%',
                        style: const TextStyle(
                          fontSize: 8,
                          color: Colors.red,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                    ),
                  ],

                  const Spacer(),

                  // Expand Icon
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

  Color _getEnhancedProtocolColor(String protocol) {
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

  IconData _getProtocolIcon(String protocol) {
    switch (protocol.toUpperCase()) {
      case 'HTTP':
      case 'HTTPS':
        return Icons.http;
      case 'DNS':
        return Icons.dns;
      case 'TLS':
      case 'SSL':
        return Icons.lock;
      case 'QUIC':
        return Icons.flash_on;
      case 'SIP':
        return Icons.phone;
      case 'RTP':
        return Icons.play_circle;
      case 'SMB':
        return Icons.folder;
      case 'NTP':
        return Icons.access_time;
      case 'TCP':
        return Icons.call_made;
      case 'UDP':
        return Icons.call_received;
      default:
        return Icons.help_outline;
    }
  }

  int _getSecurityLevel(PacketInfo packet) {
    // Check for security flags in payload analysis
    if (packet.payloadAnalysis?['securityFlags'] != null) {
      final flags = packet.payloadAnalysis!['securityFlags'] as List;
      if (flags.contains('EXECUTABLE_CONTENT_DETECTED')) return 3;
      if (flags.contains('SUSPICIOUS_CODE_EXECUTION')) return 2;
      if (flags.contains('POTENTIAL_SQL_INJECTION')) return 2;
      if (flags.contains('POTENTIAL_XSS')) return 1;
    }

    // Check anomaly score
    if (packet.anomalyScore != null && packet.anomalyScore! > 0.8) return 2;
    if (packet.anomalyScore != null && packet.anomalyScore! > 0.6) return 1;

    return 0;
  }

  Color _getSecurityColor(int level) {
    switch (level) {
      case 3:
        return Colors.red;
      case 2:
        return Colors.orange;
      case 1:
        return Colors.yellow.shade700;
      default:
        return Colors.grey;
    }
  }

  IconData _getSecurityIcon(int level) {
    switch (level) {
      case 3:
        return Icons.warning;
      case 2:
        return Icons.error_outline;
      case 1:
        return Icons.info_outline;
      default:
        return Icons.check_circle;
    }
  }

  String _getSecurityLabel(int level) {
    switch (level) {
      case 3:
        return 'HIGH';
      case 2:
        return 'MEDIUM';
      case 1:
        return 'LOW';
      default:
        return 'SAFE';
    }
  }

  Color _getSizeColor(int size) {
    if (size > 50000) return Colors.red;
    if (size > 10000) return Colors.orange;
    if (size > 1500) return Colors.blue;
    return Colors.green;
  }

  void _showEnhancedPacketDetails(BuildContext context, PacketInfo packet) {
    showDialog(
      context: context,
      builder: (context) => EnhancedPacketDetailsDialog(packet: packet),
    );
  }
}

// ================= ENHANCED PACKET DETAILS DIALOG =================

class EnhancedPacketDetailsDialog extends StatefulWidget {
  final PacketInfo packet;

  const EnhancedPacketDetailsDialog({
    Key? key,
    required this.packet,
  }) : super(key: key);

  @override
  State<EnhancedPacketDetailsDialog> createState() => _EnhancedPacketDetailsDialogState();
}

class _EnhancedPacketDetailsDialogState extends State<EnhancedPacketDetailsDialog> {
  bool _showHexView = false;

  @override
  Widget build(BuildContext context) {
    return Dialog(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
      child: Container(
        constraints: BoxConstraints(
          maxHeight: MediaQuery.of(context).size.height * 0.8,
          maxWidth: MediaQuery.of(context).size.width * 0.9,
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            _buildEnhancedHeader(context),
            Flexible(
              child: SingleChildScrollView(
                padding: const EdgeInsets.all(20),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _buildSecurityAnalysisSection(context),
                    const SizedBox(height: 16),
                    _buildNetworkInformationSection(context),
                    const SizedBox(height: 16),
                    _buildProtocolDetailsSection(context),
                    const SizedBox(height: 16),
                    _buildPayloadDataSection(context),
                    const SizedBox(height: 16),
                    _buildPayloadAnalysisSection(context),
                  ],
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildEnhancedHeader(BuildContext context) {
    final protocolColor = _getProtocolColor(widget.packet.protocol);
    final securityLevel = _getSecurityLevel();

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [
            protocolColor.withOpacity(0.8),
            protocolColor,
          ],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
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
            child: Icon(
              _getProtocolIcon(widget.packet.protocol),
              size: 24,
              color: Colors.white,
            ),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Enhanced Packet Analysis',
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 18,
                    fontWeight: FontWeight.bold,
                  ),
                ),
                Text(
                  '${widget.packet.appName ?? widget.packet.protocol} • ${widget.packet.displayDirection} • ${widget.packet.formattedTime}',
                  style: TextStyle(
                    color: Colors.white.withOpacity(0.8),
                    fontSize: 12,
                  ),
                ),
              ],
            ),
          ),
          if (securityLevel > 0) ...[
            Container(
              padding: const EdgeInsets.symmetric(
                horizontal: 8,
                vertical: 4,
              ),
              decoration: BoxDecoration(
                color: _getSecurityColor(securityLevel),
                borderRadius: BorderRadius.circular(12),
              ),
              child: Text(
                _getSecurityLabel(securityLevel),
                style: const TextStyle(
                  color: Colors.white,
                  fontSize: 10,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ),
          ],
          IconButton(
            icon: const Icon(Icons.close, color: Colors.white),
            onPressed: () => Navigator.pop(context),
          ),
        ],
      ),
    );
  }

  Widget _buildSecurityAnalysisSection(BuildContext context) {
    final securityLevel = _getSecurityLevel();
    final payloadAnalysis = widget.packet.payloadAnalysis;

    if (securityLevel == 0 && payloadAnalysis == null) {
      return const SizedBox.shrink();
    }

    return _buildDetailSection(context,
      '🔒 Security Analysis',
      [
        if (widget.packet.anomalyScore != null) ...[
          _buildDetailRow(
            'ML Anomaly Score',
            '${(widget.packet.anomalyScore! * 100).toStringAsFixed(1)}%',
            valueColor: _getAnomalyScoreColor(widget.packet.anomalyScore!),
          ),
          _buildDetailRow(
            'Detection Algorithm',
            _getAnomalyDetectionMethod(widget.packet),
          ),
        ],
        if (payloadAnalysis?['securityFlags'] != null) ...[
          ...(payloadAnalysis!['securityFlags'] as List).map((flag) =>
            _buildDetailRow(
              'Security Flag',
              flag.toString(),
              valueColor: Colors.red,
            ),
          ),
        ],
        if (securityLevel > 0) ...[
          _buildDetailRow(
            'Risk Assessment',
            _getSecurityDescription(securityLevel),
            valueColor: _getSecurityColor(securityLevel),
          ),
        ],
      ],
    );
  }

  Widget _buildNetworkInformationSection(BuildContext context) {
    return _buildDetailSection(context,
      '🌐 Network Information',
      [
        _buildDetailRow('Source', '${widget.packet.sourceIp}:${widget.packet.sourcePort}'),
        _buildDetailRow('Destination', '${widget.packet.destinationIp}:${widget.packet.destinationPort}'),
        _buildDetailRow('Protocol', '${widget.packet.protocol} (${widget.packet.appName ?? 'Unknown'})'),
        _buildDetailRow('Direction', widget.packet.displayDirection),
        _buildDetailRow('Packet Size', '${widget.packet.size} bytes'),
        _buildDetailRow('Captured', widget.packet.formattedTime),
        if (widget.packet.flags != null) _buildDetailRow('TCP Flags', widget.packet.flags!),
      ],
    );
  }

  Widget _buildProtocolDetailsSection(BuildContext context) {
    final protocolDetails = _getProtocolSpecificDetails();

    if (protocolDetails.isEmpty) {
      return const SizedBox.shrink();
    }

    return _buildDetailSection(context,
      '📋 Protocol Details',
      protocolDetails.map((detail) => _buildDetailRow(detail['label']!, detail['value']!)).toList(),
    );
  }

  Widget _buildPayloadDataSection(BuildContext context) {
    if (widget.packet.payload.isEmpty) {
      return const SizedBox.shrink();
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          children: [
            Text(
              '📦 Payload Data',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.bold,
                color: Theme.of(context).colorScheme.primary,
              ),
            ),
            const Spacer(),
            Container(
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surfaceVariant,
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  _ViewToggleButton(
                    label: 'ASCII',
                    isSelected: !_showHexView,
                    onTap: () => setState(() => _showHexView = false),
                  ),
                  _ViewToggleButton(
                    label: 'HEX',
                    isSelected: _showHexView,
                    onTap: () => setState(() => _showHexView = true),
                  ),
                ],
              ),
            ),
          ],
        ),
        const SizedBox(height: 8),
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surfaceVariant.withOpacity(0.3),
            borderRadius: BorderRadius.circular(8),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  Icon(Icons.data_usage, size: 16, color: Colors.blue),
                  const SizedBox(width: 8),
                  Text(
                    'Size: ${widget.packet.payload.length} bytes',
                    style: const TextStyle(
                      fontSize: 12,
                      fontWeight: FontWeight.w500,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 12),
              Container(
                constraints: const BoxConstraints(maxHeight: 300),
                decoration: BoxDecoration(
                  color: Colors.black87,
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: Colors.grey.shade700),
                ),
                child: SingleChildScrollView(
                  padding: const EdgeInsets.all(12),
                  child: SelectableText(
                    _showHexView ? _toHexView(widget.packet.payload) : _toAsciiView(widget.packet.payload),
                    style: const TextStyle(
                      fontFamily: 'monospace',
                      fontSize: 11,
                      color: Colors.greenAccent,
                      height: 1.5,
                    ),
                  ),
                ),
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildPayloadAnalysisSection(BuildContext context) {
    final payloadAnalysis = widget.packet.payloadAnalysis;

    if (payloadAnalysis == null) {
      return const SizedBox.shrink();
    }

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          '📦 Payload Analysis',
          style: TextStyle(
            fontSize: 16,
            fontWeight: FontWeight.bold,
            color: Theme.of(context).colorScheme.primary,
          ),
        ),
        const SizedBox(height: 8),
        if (payloadAnalysis['detectedFiles'] != null) ...[
          _buildFileDetectionSection(payloadAnalysis['detectedFiles'] as List),
        ],
        if (payloadAnalysis['extractedFiles'] != null) ...[
          _buildExtractedFilesSection(payloadAnalysis['extractedFiles'] as List),
        ],
        if (payloadAnalysis['entropy'] != null) ...[
          _buildEntropyAnalysisSection(payloadAnalysis['entropy'] as Map),
        ],
      ],
    );
  }

  Widget _buildFileDetectionSection(List detectedFiles) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.purple.withOpacity(0.05),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Colors.purple.withOpacity(0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Detected Files',
            style: TextStyle(fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          ...detectedFiles.map((file) => _buildFileItem(file as Map)),
        ],
      ),
    );
  }

  Widget _buildExtractedFilesSection(List extractedFiles) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.green.withOpacity(0.05),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Colors.green.withOpacity(0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Extracted Content',
            style: TextStyle(fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          ...extractedFiles.map((file) => _buildExtractedFileItem(file as Map)),
        ],
      ),
    );
  }

  Widget _buildEntropyAnalysisSection(Map entropy) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.blue.withOpacity(0.05),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Colors.blue.withOpacity(0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            'Entropy Analysis',
            style: TextStyle(fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 8),
          _buildDetailRow('Shannon Entropy', entropy['value']?.toStringAsFixed(3) ?? 'N/A'),
          _buildDetailRow('Interpretation', entropy['interpretation'] ?? 'Normal'),
        ],
      ),
    );
  }

  Widget _buildFileItem(Map file) {
    return Container(
      margin: const EdgeInsets.only(bottom: 4),
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: Colors.purple.withOpacity(0.2)),
      ),
      child: Row(
        children: [
          Icon(Icons.insert_drive_file, size: 16, color: Colors.purple),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              file['description'] ?? file['mimeType'] ?? 'Unknown File',
              style: const TextStyle(fontSize: 12),
            ),
          ),
          Text(
            '${file['size'] ?? 0} bytes',
            style: TextStyle(
              fontSize: 10,
              color: Colors.grey.shade600,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildExtractedFileItem(Map file) {
    return Container(
      margin: const EdgeInsets.only(bottom: 4),
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: Colors.green.withOpacity(0.2)),
      ),
      child: Row(
        children: [
          Icon(Icons.download, size: 16, color: Colors.green),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              file['filename'] ?? file['type'] ?? 'Extracted Content',
              style: const TextStyle(fontSize: 12),
            ),
          ),
          Text(
            '${file['size'] ?? 0} bytes',
            style: TextStyle(
              fontSize: 10,
              color: Colors.grey.shade600,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDetailSection(BuildContext context, String title, List<Widget> children) {
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
            color: Theme.of(context).colorScheme.surfaceVariant.withOpacity(0.3),
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

  Widget _buildDetailRow(String label, String value, {Color? valueColor}) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 100,
            child: Text(
              '$label:',
              style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500),
            ),
          ),
          Expanded(
            child: SelectableText(
              value,
              style: TextStyle(
                fontSize: 12,
                color: valueColor,
              ),
            ),
          ),
        ],
      ),
    );
  }

  // Helper methods
  Color _getProtocolColor(String protocol) {
    // Implementation similar to EnhancedPacketCard
    switch (protocol.toUpperCase()) {
      case 'HTTP': return Colors.blue;
      case 'HTTPS': return Colors.green;
      case 'DNS': return Colors.orange;
      case 'TLS': return Colors.teal;
      case 'QUIC': return Colors.purple;
      case 'SIP': return Colors.cyan;
      case 'RTP': return Colors.indigo;
      case 'SMB': return Colors.brown;
      case 'NTP': return Colors.lime;
      default: return Colors.grey;
    }
  }

  IconData _getProtocolIcon(String protocol) {
    // Implementation similar to EnhancedPacketCard
    switch (protocol.toUpperCase()) {
      case 'HTTP': return Icons.http;
      case 'DNS': return Icons.dns;
      case 'TLS': return Icons.lock;
      case 'QUIC': return Icons.flash_on;
      case 'SIP': return Icons.phone;
      case 'RTP': return Icons.play_circle;
      case 'SMB': return Icons.folder;
      case 'NTP': return Icons.access_time;
      default: return Icons.help_outline;
    }
  }

  int _getSecurityLevel() {
    if (widget.packet.payloadAnalysis?['securityFlags'] != null) {
      final flags = widget.packet.payloadAnalysis!['securityFlags'] as List;
      if (flags.contains('EXECUTABLE_CONTENT_DETECTED')) return 3;
      if (flags.contains('SUSPICIOUS_CODE_EXECUTION')) return 2;
    }
    return widget.packet.anomalyScore != null && widget.packet.anomalyScore! > 0.8 ? 2 : 0;
  }

  Color _getSecurityColor(int level) {
    switch (level) {
      case 3: return Colors.red;
      case 2: return Colors.orange;
      default: return Colors.grey;
    }
  }

  String _getSecurityLabel(int level) {
    switch (level) {
      case 3: return 'CRITICAL';
      case 2: return 'WARNING';
      default: return 'SAFE';
    }
  }

  String _getSecurityDescription(int level) {
    switch (level) {
      case 3: return 'High-risk content detected';
      case 2: return 'Suspicious patterns found';
      default: return 'No security concerns';
    }
  }

  Color _getAnomalyScoreColor(double score) {
    if (score > 0.8) return Colors.red;
    if (score > 0.6) return Colors.orange;
    if (score > 0.4) return Colors.yellow.shade700;
    return Colors.green;
  }

  String _getAnomalyDetectionMethod(PacketInfo packet) {
    if (packet.anomalyScore != null) {
      // Determine which ML algorithm detected the anomaly
      if (packet.protocol == 'TCP' && packet.flags != null) return 'Connection Pattern Analysis';
      if (packet.size > 10000) return 'Statistical Size Analysis';
      if (packet.payloadAnalysis?['entropy'] != null) return 'Entropy Analysis';
      return 'Behavioral Analysis';
    }
    return 'Not Applicable';
  }

  List<Map<String, String>> _getProtocolSpecificDetails() {
    final details = <Map<String, String>>[];

    if (widget.packet.httpData != null) {
      final http = widget.packet.httpData!;
      details.addAll([
        {'label': 'HTTP Method', 'value': http['method']?.toString() ?? 'Unknown'},
        {'label': 'URI', 'value': http['uri']?.toString() ?? 'Unknown'},
        {'label': 'Status', 'value': '${http['statusCode']?.toString() ?? ''} ${http['statusMessage']?.toString() ?? ''}'},
        if (http['contentType'] != null) {'label': 'Content-Type', 'value': http['contentType']!.toString()},
      ]);
    }

    if (widget.packet.dnsData != null) {
      final dns = widget.packet.dnsData!;
      details.addAll([
        {'label': 'Query Type', 'value': dns['queryType']?.toString() ?? 'Unknown'},
        {'label': 'Query Name', 'value': dns['queryName']?.toString() ?? 'Unknown'},
        {'label': 'Response Code', 'value': dns['responseCode']?.toString() ?? 'Unknown'},
      ]);
    }

    if (widget.packet.tlsData != null) {
      final tls = widget.packet.tlsData!;
      details.addAll([
        {'label': 'TLS Version', 'value': tls['version']?.toString() ?? 'Unknown'},
        {'label': 'Handshake Type', 'value': tls['handshakeType']?.toString() ?? 'Unknown'},
      ]);
    }

    if (widget.packet.quicData != null) {
      final quic = widget.packet.quicData!;
      details.addAll([
        {'label': 'QUIC Version', 'value': quic['version']?.toString() ?? 'Unknown'},
        {'label': 'Connection ID', 'value': quic['destinationConnectionId']?.toString() ?? 'Unknown'},
      ]);
    }

    return details;
  }

  // Helper methods for payload formatting
  String _toAsciiView(String payload) {
    if (payload.isEmpty) return 'Empty payload';

    // Replace non-printable characters with dots
    final buffer = StringBuffer();
    for (int i = 0; i < payload.length; i++) {
      final char = payload[i];
      final code = char.codeUnitAt(0);
      if (code >= 32 && code <= 126) {
        buffer.write(char);
      } else if (code == 10) {
        buffer.write('\n');
      } else if (code == 13) {
        buffer.write('\r');
      } else if (code == 9) {
        buffer.write('\t');
      } else {
        buffer.write('.');
      }
    }
    return buffer.toString();
  }

  String _toHexView(String payload) {
    if (payload.isEmpty) return 'Empty payload';

    final buffer = StringBuffer();
    final bytes = payload.codeUnits;

    for (int i = 0; i < bytes.length; i += 16) {
      // Offset
      buffer.write('${i.toRadixString(16).padLeft(8, '0')}  ');

      // Hex values
      for (int j = 0; j < 16; j++) {
        if (i + j < bytes.length) {
          buffer.write('${bytes[i + j].toRadixString(16).padLeft(2, '0')} ');
        } else {
          buffer.write('   ');
        }
        if (j == 7) buffer.write(' ');
      }

      buffer.write(' |');

      // ASCII representation
      for (int j = 0; j < 16 && i + j < bytes.length; j++) {
        final code = bytes[i + j];
        if (code >= 32 && code <= 126) {
          buffer.write(String.fromCharCode(code));
        } else {
          buffer.write('.');
        }
      }

      buffer.write('|\n');
    }

    return buffer.toString();
  }
}

// Helper widget for view toggle buttons
class _ViewToggleButton extends StatelessWidget {
  final String label;
  final bool isSelected;
  final VoidCallback onTap;

  const _ViewToggleButton({
    required this.label,
    required this.isSelected,
    required this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(6),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        decoration: BoxDecoration(
          color: isSelected
              ? Theme.of(context).colorScheme.primary
              : Colors.transparent,
          borderRadius: BorderRadius.circular(6),
        ),
        child: Text(
          label,
          style: TextStyle(
            fontSize: 11,
            fontWeight: FontWeight.bold,
            color: isSelected
                ? Colors.white
                : Theme.of(context).colorScheme.onSurface.withOpacity(0.6),
          ),
        ),
      ),
    );
  }
}

// ================= ANOMALY DETECTION VISUALIZATION =================

class AnomalyDetectionPanel extends StatelessWidget {
  final List<AnomalyInfo> anomalies;
  final VoidCallback onClearAnomalies;

  const AnomalyDetectionPanel({
    Key? key,
    required this.anomalies,
    required this.onClearAnomalies,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.red.withOpacity(0.05),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.red.withOpacity(0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.warning, color: Colors.red),
              const SizedBox(width: 8),
              Text(
                'Anomaly Detection Alerts',
                style: TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                  color: Colors.red,
                ),
              ),
              const Spacer(),
              TextButton(
                onPressed: onClearAnomalies,
                child: const Text('Clear'),
              ),
            ],
          ),
          const SizedBox(height: 12),
          if (anomalies.isEmpty)
            const Text(
              'No anomalies detected',
              style: TextStyle(color: Colors.grey),
            )
          else
            Column(
              children: anomalies.take(5).map((anomaly) =>
                _buildAnomalyItem(anomaly),
              ).toList(),
            ),
        ],
      ),
    );
  }

  Widget _buildAnomalyItem(AnomalyInfo anomaly) {
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: _getAnomalyColor(anomaly.severity),
        borderRadius: BorderRadius.circular(8),
      ),
      child: Row(
        children: [
          Icon(_getAnomalyIcon(anomaly.type), size: 16, color: Colors.white),
          const SizedBox(width: 8),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  anomaly.title,
                  style: const TextStyle(
                    color: Colors.white,
                    fontWeight: FontWeight.bold,
                    fontSize: 12,
                  ),
                ),
                Text(
                  anomaly.description,
                  style: TextStyle(
                    color: Colors.white.withOpacity(0.8),
                    fontSize: 10,
                  ),
                ),
              ],
            ),
          ),
          Text(
            anomaly.timestamp,
            style: TextStyle(
              color: Colors.white.withOpacity(0.7),
              fontSize: 9,
            ),
          ),
        ],
      ),
    );
  }

  Color _getAnomalyColor(String severity) {
    switch (severity.toLowerCase()) {
      case 'critical': return Colors.red.shade700;
      case 'high': return Colors.orange.shade700;
      case 'medium': return Colors.yellow.shade700;
      case 'low': return Colors.blue.shade700;
      default: return Colors.grey.shade700;
    }
  }

  IconData _getAnomalyIcon(String type) {
    switch (type.toLowerCase()) {
      case 'port_scan': return Icons.scanner;
      case 'syn_flood': return Icons.flood;
      case 'unusual_traffic': return Icons.warning;
      case 'malicious_content': return Icons.security;
      default: return Icons.error;
    }
  }
}

// ================= FILE CARVING VISUALIZATION =================

class FileCarvingPanel extends StatelessWidget {
  final Map<String, dynamic> payloadAnalysis;

  const FileCarvingPanel({
    Key? key,
    required this.payloadAnalysis,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    final detectedFiles = payloadAnalysis['detectedFiles'] as List? ?? [];
    final extractedFiles = payloadAnalysis['extractedFiles'] as List? ?? [];

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: Colors.purple.withOpacity(0.05),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.purple.withOpacity(0.3)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.inventory_2, color: Colors.purple),
              const SizedBox(width: 8),
              Text(
                'File Carving Results',
                style: TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                  color: Colors.purple,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          if (detectedFiles.isEmpty && extractedFiles.isEmpty)
            const Text(
              'No files detected in payload',
              style: TextStyle(color: Colors.grey),
            )
          else ...[
            if (detectedFiles.isNotEmpty) ...[
              Text(
                'Detected Files (${detectedFiles.length})',
                style: const TextStyle(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              ...detectedFiles.map((file) => _buildFileItem(file as Map)),
            ],
            if (extractedFiles.isNotEmpty) ...[
              if (detectedFiles.isNotEmpty) const SizedBox(height: 16),
              Text(
                'Extracted Content (${extractedFiles.length})',
                style: const TextStyle(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              ...extractedFiles.map((file) => _buildExtractedItem(file as Map)),
            ],
          ],
        ],
      ),
    );
  }

  Widget _buildFileItem(Map file) {
    return Container(
      margin: const EdgeInsets.only(bottom: 4),
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: Colors.purple.withOpacity(0.2)),
      ),
      child: Row(
        children: [
          Icon(_getFileIcon(file['mimeType']), size: 16, color: Colors.purple),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              file['description'] ?? 'Unknown File',
              style: const TextStyle(fontSize: 12),
            ),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
            decoration: BoxDecoration(
              color: _getFileTypeColor(file['mimeType']),
              borderRadius: BorderRadius.circular(4),
            ),
            child: Text(
              '${(file['size'] / 1024).toStringAsFixed(1)}KB',
              style: const TextStyle(
                fontSize: 9,
                color: Colors.white,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildExtractedItem(Map file) {
    return Container(
      margin: const EdgeInsets.only(bottom: 4),
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: Colors.green.withOpacity(0.2)),
      ),
      child: Row(
        children: [
          Icon(Icons.download, size: 16, color: Colors.green),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              file['filename'] ?? 'Extracted Content',
              style: const TextStyle(fontSize: 12),
            ),
          ),
          Text(
            '${file['size']} bytes',
            style: TextStyle(
              fontSize: 10,
              color: Colors.grey.shade600,
            ),
          ),
        ],
      ),
    );
  }

  IconData _getFileIcon(String? mimeType) {
    if (mimeType == null) return Icons.insert_drive_file;

    if (mimeType.startsWith('image/')) return Icons.image;
    if (mimeType.startsWith('video/')) return Icons.video_file;
    if (mimeType.startsWith('audio/')) return Icons.audio_file;
    if (mimeType == 'application/pdf') return Icons.picture_as_pdf;
    if (mimeType.contains('zip') || mimeType.contains('rar')) return Icons.archive;
    if (mimeType.startsWith('text/')) return Icons.text_snippet;
    if (mimeType.contains('executable')) return Icons.computer;

    return Icons.insert_drive_file;
  }

  Color _getFileTypeColor(String? mimeType) {
    if (mimeType == null) return Colors.grey;

    if (mimeType.startsWith('image/')) return Colors.blue;
    if (mimeType.startsWith('video/')) return Colors.purple;
    if (mimeType.startsWith('audio/')) return Colors.green;
    if (mimeType == 'application/pdf') return Colors.red;
    if (mimeType.contains('zip') || mimeType.contains('rar')) return Colors.orange;
    if (mimeType.startsWith('text/')) return Colors.teal;
    if (mimeType.contains('executable')) return Colors.red;

    return Colors.grey;
  }
}
