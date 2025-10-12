import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:async';
import 'dart:math' as math;
import 'models.dart';

class AnomalyDashboard extends StatefulWidget {
  final Stream<AnomalyInfo> anomalyStream;

  const AnomalyDashboard({Key? key, required this.anomalyStream})
    : super(key: key);

  @override
  State<AnomalyDashboard> createState() => _AnomalyDashboardState();
}

class _AnomalyDashboardState extends State<AnomalyDashboard>
    with TickerProviderStateMixin {
  final List<AnomalyInfo> _anomalies = [];
  StreamSubscription<AnomalyInfo>? _anomalySubscription;
  String _selectedSeverityFilter = 'ALL';
  String _selectedTypeFilter = 'ALL';
  late AnimationController _alertAnimationController;
  late Animation<double> _alertAnimation;

  final List<String> _severityFilters = [
    'ALL',
    'CRITICAL',
    'HIGH',
    'MEDIUM',
    'LOW',
  ];
  final List<String> _typeFilters = [
    'ALL',
    'PORT_SCAN',
    'SYN_FLOOD',
    'ARP_SPOOFING',
    'DNS_TUNNELING',
    'CONNECTION_FLOOD',
    'UNUSUAL_TRAFFIC',
    'MALFORMED_PACKET',
  ];

  @override
  void initState() {
    super.initState();
    _setupAnimations();
    _setupAnomalyStream();
  }

  void _setupAnimations() {
    _alertAnimationController = AnimationController(
      duration: const Duration(milliseconds: 800),
      vsync: this,
    );

    _alertAnimation = Tween<double>(begin: 0.8, end: 1.2).animate(
      CurvedAnimation(
        parent: _alertAnimationController,
        curve: Curves.elasticOut,
      ),
    );
  }

  void _setupAnomalyStream() {
    _anomalySubscription = widget.anomalyStream.listen((anomaly) {
      if (mounted) {
        setState(() {
          _anomalies.insert(0, anomaly);
          if (_anomalies.length > 500) {
            _anomalies.removeRange(250, _anomalies.length);
          }
        });

        // Trigger alert animation for high severity anomalies
        if (anomaly.severity.toUpperCase() == 'CRITICAL' ||
            anomaly.severity.toUpperCase() == 'HIGH') {
          _alertAnimationController.forward().then((_) {
            _alertAnimationController.reverse();
          });
        }

        // Show system notification for critical anomalies
        if (anomaly.severity.toUpperCase() == 'CRITICAL') {
          _showCriticalAnomalyNotification(anomaly);
        }
      }
    });
  }

  void _showCriticalAnomalyNotification(AnomalyInfo anomaly) {
    HapticFeedback.vibrate();
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        content: Row(
          children: [
            Icon(Icons.warning, color: Colors.white, size: 20),
            const SizedBox(width: 12),
            Expanded(
              child: Text(
                '🚨 CRITICAL: ${anomaly.title}',
                style: const TextStyle(
                  fontWeight: FontWeight.bold,
                  color: Colors.white,
                ),
              ),
            ),
          ],
        ),
        backgroundColor: Colors.red.shade700,
        behavior: SnackBarBehavior.floating,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        duration: const Duration(seconds: 5),
        action: SnackBarAction(
          label: 'VIEW',
          textColor: Colors.white,
          onPressed: () => _showAnomalyDetails(anomaly),
        ),
      ),
    );
  }

  List<AnomalyInfo> get _filteredAnomalies {
    return _anomalies.where((anomaly) {
      final severityMatch =
          _selectedSeverityFilter == 'ALL' ||
          anomaly.severity.toUpperCase() == _selectedSeverityFilter;
      final typeMatch =
          _selectedTypeFilter == 'ALL' ||
          anomaly.type.toUpperCase() == _selectedTypeFilter;
      return severityMatch && typeMatch;
    }).toList();
  }

  Map<String, int> get _severityStats {
    final stats = <String, int>{};
    for (final anomaly in _anomalies) {
      final severity = anomaly.severity.toUpperCase();
      stats[severity] = (stats[severity] ?? 0) + 1;
    }
    return stats;
  }

  Map<String, int> get _typeStats {
    final stats = <String, int>{};
    for (final anomaly in _anomalies) {
      final type = anomaly.friendlyType;
      stats[type] = (stats[type] ?? 0) + 1;
    }
    return stats;
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: Theme.of(context).colorScheme.surface,
      appBar: _buildAppBar(),
      body: Column(
        children: [
          _buildStatsOverview(),
          _buildFilters(),
          Expanded(child: _buildAnomalyList()),
        ],
      ),
    );
  }

  PreferredSizeWidget _buildAppBar() {
    return AppBar(
      title: Row(
        children: [
          AnimatedBuilder(
            animation: _alertAnimation,
            builder: (context, child) {
              return Transform.scale(
                scale: _alertAnimation.value,
                child: Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: Colors.red.shade100,
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Icon(
                    Icons.security,
                    color: Colors.red.shade700,
                    size: 20,
                  ),
                ),
              );
            },
          ),
          const SizedBox(width: 12),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            mainAxisSize: MainAxisSize.min,
            children: [
              const Text(
                'Anomaly Dashboard',
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
              ),
              Text(
                '${_anomalies.length} total detections',
                style: TextStyle(
                  fontSize: 12,
                  color: Theme.of(
                    context,
                  ).colorScheme.onSurface.withValues(alpha: 0.7),
                ),
              ),
            ],
          ),
        ],
      ),
      backgroundColor: Theme.of(context).colorScheme.surface,
      elevation: 0,
      actions: [
        if (_anomalies.isNotEmpty)
          IconButton(
            icon: const Icon(Icons.clear_all),
            onPressed: _clearAllAnomalies,
            tooltip: 'Clear All',
          ),
        PopupMenuButton<String>(
          icon: const Icon(Icons.more_vert),
          onSelected: _handleMenuSelection,
          itemBuilder: (context) => [
            const PopupMenuItem(
              value: 'export',
              child: Row(
                children: [
                  Icon(Icons.file_download, size: 16),
                  SizedBox(width: 8),
                  Text('Export Anomalies'),
                ],
              ),
            ),
            const PopupMenuItem(
              value: 'settings',
              child: Row(
                children: [
                  Icon(Icons.settings, size: 16),
                  SizedBox(width: 8),
                  Text('Detection Settings'),
                ],
              ),
            ),
            const PopupMenuItem(
              value: 'help',
              child: Row(
                children: [
                  Icon(Icons.help_outline, size: 16),
                  SizedBox(width: 8),
                  Text('Help'),
                ],
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildStatsOverview() {
    final severityStats = _severityStats;
    final criticalCount = severityStats['CRITICAL'] ?? 0;
    final highCount = severityStats['HIGH'] ?? 0;
    final mediumCount = severityStats['MEDIUM'] ?? 0;
    final lowCount = severityStats['LOW'] ?? 0;

    return Container(
      margin: const EdgeInsets.all(16),
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        gradient: LinearGradient(
          colors: [Colors.red.shade50, Colors.orange.shade50],
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
        ),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: Colors.red.withValues(alpha: 0.2)),
      ),
      child: Column(
        children: [
          Row(
            children: [
              Icon(Icons.analytics, color: Colors.red.shade700, size: 20),
              const SizedBox(width: 8),
              Text(
                'Threat Overview',
                style: TextStyle(
                  fontSize: 16,
                  fontWeight: FontWeight.bold,
                  color: Colors.red.shade700,
                ),
              ),
              const Spacer(),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                decoration: BoxDecoration(
                  color: _anomalies.isNotEmpty ? Colors.red : Colors.green,
                  borderRadius: BorderRadius.circular(12),
                ),
                child: Text(
                  _anomalies.isNotEmpty ? 'THREATS DETECTED' : 'SECURE',
                  style: const TextStyle(
                    color: Colors.white,
                    fontSize: 10,
                    fontWeight: FontWeight.bold,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Row(
            children: [
              _buildSeverityMetric(
                'CRITICAL',
                criticalCount,
                Colors.red.shade700,
              ),
              const SizedBox(width: 12),
              _buildSeverityMetric('HIGH', highCount, Colors.red.shade500),
              const SizedBox(width: 12),
              _buildSeverityMetric(
                'MEDIUM',
                mediumCount,
                Colors.orange.shade600,
              ),
              const SizedBox(width: 12),
              _buildSeverityMetric('LOW', lowCount, Colors.yellow.shade700),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildSeverityMetric(String severity, int count, Color color) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: color.withValues(alpha: 0.3)),
        ),
        child: Column(
          children: [
            Text(
              count.toString(),
              style: TextStyle(
                fontSize: 18,
                fontWeight: FontWeight.bold,
                color: color,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              severity,
              style: TextStyle(
                fontSize: 10,
                fontWeight: FontWeight.w600,
                color: color,
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFilters() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16),
      child: Row(
        children: [
          Expanded(
            child: _buildFilterChips(
              'Severity',
              _selectedSeverityFilter,
              _severityFilters,
              (value) {
                setState(() => _selectedSeverityFilter = value);
              },
            ),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: _buildFilterChips(
              'Type',
              _selectedTypeFilter,
              _typeFilters,
              (value) {
                setState(() => _selectedTypeFilter = value);
              },
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildFilterChips(
    String label,
    String selected,
    List<String> options,
    Function(String) onChanged,
  ) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: TextStyle(
            fontSize: 12,
            fontWeight: FontWeight.w600,
            color: Theme.of(
              context,
            ).colorScheme.onSurface.withValues(alpha: 0.7),
          ),
        ),
        const SizedBox(height: 8),
        SizedBox(
          height: 36,
          child: ListView.builder(
            scrollDirection: Axis.horizontal,
            itemCount: options.length,
            itemBuilder: (context, index) {
              final option = options[index];
              final isSelected = selected == option;

              return Container(
                margin: const EdgeInsets.only(right: 8),
                child: FilterChip(
                  label: Text(
                    option == 'ALL'
                        ? 'All'
                        : option.toLowerCase().replaceAll('_', ' '),
                    style: TextStyle(
                      fontSize: 10,
                      fontWeight: isSelected
                          ? FontWeight.w600
                          : FontWeight.normal,
                    ),
                  ),
                  selected: isSelected,
                  onSelected: (_) => onChanged(option),
                  materialTapTargetSize: MaterialTapTargetSize.shrinkWrap,
                  visualDensity: VisualDensity.compact,
                ),
              );
            },
          ),
        ),
      ],
    );
  }

  Widget _buildAnomalyList() {
    final filteredAnomalies = _filteredAnomalies;

    if (filteredAnomalies.isEmpty) {
      return _buildEmptyState();
    }

    return ListView.builder(
      padding: const EdgeInsets.all(16),
      itemCount: filteredAnomalies.length,
      itemBuilder: (context, index) {
        final anomaly = filteredAnomalies[index];
        return _buildAnomalyCard(anomaly, index);
      },
    );
  }

  Widget _buildAnomalyCard(AnomalyInfo anomaly, int index) {
    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      child: Card(
        elevation: 2,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(12),
          side: BorderSide(
            color: anomaly.severityColor.withValues(alpha: 0.3),
            width: 1,
          ),
        ),
        child: InkWell(
          onTap: () => _showAnomalyDetails(anomaly),
          borderRadius: BorderRadius.circular(12),
          child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Container(
                      padding: const EdgeInsets.all(8),
                      decoration: BoxDecoration(
                        color: anomaly.severityColor.withValues(alpha: 0.1),
                        borderRadius: BorderRadius.circular(8),
                      ),
                      child: Icon(
                        anomaly.typeIcon,
                        color: anomaly.severityColor,
                        size: 20,
                      ),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            anomaly.title,
                            style: const TextStyle(
                              fontSize: 16,
                              fontWeight: FontWeight.bold,
                            ),
                            maxLines: 2,
                            overflow: TextOverflow.ellipsis,
                          ),
                          const SizedBox(height: 4),
                          Text(
                            anomaly.friendlyType,
                            style: TextStyle(
                              fontSize: 12,
                              color: Theme.of(
                                context,
                              ).colorScheme.onSurface.withValues(alpha: 0.6),
                              fontWeight: FontWeight.w500,
                            ),
                          ),
                        ],
                      ),
                    ),
                    Column(
                      children: [
                        Container(
                          padding: const EdgeInsets.symmetric(
                            horizontal: 8,
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
                              fontSize: 10,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          anomaly.formattedTime,
                          style: TextStyle(
                            fontSize: 10,
                            color: Theme.of(
                              context,
                            ).colorScheme.onSurface.withValues(alpha: 0.5),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
                const SizedBox(height: 12),
                Text(
                  anomaly.description,
                  style: TextStyle(
                    fontSize: 14,
                    color: Theme.of(
                      context,
                    ).colorScheme.onSurface.withValues(alpha: 0.8),
                    height: 1.3,
                  ),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
                const SizedBox(height: 8),
                Row(
                  children: [
                    if (anomaly.sourceIp.isNotEmpty) ...[
                      _buildIpChip('SRC', anomaly.sourceIp),
                      const SizedBox(width: 8),
                    ],
                    if (anomaly.destinationIp.isNotEmpty) ...[
                      _buildIpChip('DST', anomaly.destinationIp),
                      const SizedBox(width: 8),
                    ],
                    const Spacer(),
                    Text(
                      anomaly.formattedDate,
                      style: TextStyle(
                        fontSize: 11,
                        color: Theme.of(
                          context,
                        ).colorScheme.onSurface.withValues(alpha: 0.5),
                      ),
                    ),
                  ],
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildIpChip(String label, String ip) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerHighest,
        borderRadius: BorderRadius.circular(4),
      ),
      child: Text(
        '$label: $ip',
        style: TextStyle(
          fontSize: 10,
          fontWeight: FontWeight.w500,
          color: Theme.of(context).colorScheme.onSurface.withValues(alpha: 0.7),
        ),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.shield_outlined, size: 80, color: Colors.green.shade300),
          const SizedBox(height: 16),
          Text(
            'No Anomalies Detected',
            style: Theme.of(context).textTheme.headlineSmall?.copyWith(
              color: Colors.green.shade700,
              fontWeight: FontWeight.bold,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            _selectedSeverityFilter == 'ALL' && _selectedTypeFilter == 'ALL'
                ? 'Your network is secure'
                : 'No anomalies match the current filters',
            style: Theme.of(context).textTheme.bodyMedium?.copyWith(
              color: Theme.of(
                context,
              ).colorScheme.onSurface.withValues(alpha: 0.7),
            ),
            textAlign: TextAlign.center,
          ),
          if (_selectedSeverityFilter != 'ALL' ||
              _selectedTypeFilter != 'ALL') ...[
            const SizedBox(height: 16),
            ElevatedButton.icon(
              onPressed: () {
                setState(() {
                  _selectedSeverityFilter = 'ALL';
                  _selectedTypeFilter = 'ALL';
                });
              },
              icon: const Icon(Icons.clear),
              label: const Text('Clear Filters'),
              style: ElevatedButton.styleFrom(
                backgroundColor: Theme.of(context).colorScheme.primary,
                foregroundColor: Colors.white,
              ),
            ),
          ],
        ],
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
            padding: const EdgeInsets.all(24),
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
                            style: const TextStyle(
                              fontSize: 20,
                              fontWeight: FontWeight.bold,
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
                _buildDetailRow('Type', anomaly.friendlyType),
                const SizedBox(height: 12),
                _buildDetailRow('Description', anomaly.description),
                const SizedBox(height: 12),
                _buildDetailRow(
                  'Date & Time',
                  '${anomaly.formattedDate} at ${anomaly.formattedTime}',
                ),
                if (anomaly.sourceIp.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  _buildDetailRow('Source IP', anomaly.sourceIp),
                ],
                if (anomaly.destinationIp.isNotEmpty) ...[
                  const SizedBox(height: 12),
                  _buildDetailRow('Destination IP', anomaly.destinationIp),
                ],
                if (anomaly.details != null &&
                    anomaly.details?.isNotEmpty == true) ...[
                  const SizedBox(height: 16),
                  Text(
                    'Additional Details',
                    style: TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                      color: Theme.of(context).colorScheme.primary,
                    ),
                  ),
                  const SizedBox(height: 8),
                  ...anomaly.details!.entries.map(
                    (entry) => Padding(
                      padding: const EdgeInsets.symmetric(vertical: 4),
                      child: _buildDetailRow(
                        entry.key.replaceAll('_', ' ').toUpperCase(),
                        entry.value.toString(),
                      ),
                    ),
                  ),
                ],
                const SizedBox(height: 16),
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton.icon(
                    onPressed: () {
                      Clipboard.setData(
                        ClipboardData(text: _getAnomalyReport(anomaly)),
                      );
                      Navigator.pop(context);
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(
                          content: Text('Anomaly report copied to clipboard'),
                          duration: Duration(seconds: 2),
                        ),
                      );
                    },
                    icon: const Icon(Icons.copy),
                    label: const Text('Copy Report'),
                    style: ElevatedButton.styleFrom(
                      backgroundColor: Theme.of(context).colorScheme.primary,
                      foregroundColor: Colors.white,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildDetailRow(String label, String value) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        SizedBox(
          width: 120,
          child: Text(
            label,
            style: TextStyle(
              fontSize: 14,
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
              fontSize: 14,
              color: Theme.of(context).colorScheme.onSurface,
            ),
          ),
        ),
      ],
    );
  }

  String _getAnomalyReport(AnomalyInfo anomaly) {
    final buffer = StringBuffer();
    buffer.writeln('=== ANDRONET ANOMALY REPORT ===');
    buffer.writeln('Title: ${anomaly.title}');
    buffer.writeln('Type: ${anomaly.friendlyType}');
    buffer.writeln('Severity: ${anomaly.severity.toUpperCase()}');
    buffer.writeln('Description: ${anomaly.description}');
    buffer.writeln('Date: ${anomaly.formattedDate}');
    buffer.writeln('Time: ${anomaly.formattedTime}');
    if (anomaly.sourceIp.isNotEmpty) {
      buffer.writeln('Source IP: ${anomaly.sourceIp}');
    }
    if (anomaly.destinationIp.isNotEmpty) {
      buffer.writeln('Destination IP: ${anomaly.destinationIp}');
    }
    if (anomaly.details != null && anomaly.details!.isNotEmpty) {
      buffer.writeln('Additional Details:');
      anomaly.details!.forEach((key, value) {
        buffer.writeln('  $key: $value');
      });
    }
    buffer.writeln('=== END REPORT ===');
    return buffer.toString();
  }

  void _clearAllAnomalies() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Clear All Anomalies'),
        content: const Text(
          'Are you sure you want to clear all anomaly records? This action cannot be undone.',
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          ElevatedButton(
            onPressed: () {
              setState(() {
                _anomalies.clear();
              });
              Navigator.pop(context);
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('All anomaly records cleared'),
                  duration: Duration(seconds: 2),
                ),
              );
            },
            style: ElevatedButton.styleFrom(
              backgroundColor: Colors.red,
              foregroundColor: Colors.white,
            ),
            child: const Text('Clear All'),
          ),
        ],
      ),
    );
  }

  void _handleMenuSelection(String value) {
    switch (value) {
      case 'export':
        _exportAnomalies();
        break;
      case 'settings':
        _showDetectionSettings();
        break;
      case 'help':
        _showHelpDialog();
        break;
    }
  }

  void _exportAnomalies() {
    if (_anomalies.isEmpty) {
      ScaffoldMessenger.of(context).showSnackBar(
        const SnackBar(
          content: Text('No anomalies to export'),
          duration: Duration(seconds: 2),
        ),
      );
      return;
    }

    final buffer = StringBuffer();
    buffer.writeln('ANDRONET ANOMALY EXPORT');
    buffer.writeln('Export Date: ${DateTime.now().toIso8601String()}');
    buffer.writeln('Total Anomalies: ${_anomalies.length}');
    buffer.writeln('');

    for (int i = 0; i < _anomalies.length; i++) {
      final anomaly = _anomalies[i];
      buffer.writeln('=== ANOMALY ${i + 1} ===');
      buffer.write(_getAnomalyReport(anomaly));
      buffer.writeln('');
    }

    Clipboard.setData(ClipboardData(text: buffer.toString()));
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(
        content: Text('Anomaly export copied to clipboard'),
        duration: Duration(seconds: 3),
      ),
    );
  }

  void _showDetectionSettings() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Detection Settings'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            const Text(
              'Anomaly detection is handled by the native Android layer.',
            ),
            const SizedBox(height: 16),
            const Text('Current Detection Systems:'),
            const SizedBox(height: 8),
            _buildDetectionSystemRow(
              'Signature Database',
              '18 signatures',
              true,
            ),
            _buildDetectionSystemRow('Rule Engine', '10 rules', true),
            _buildDetectionSystemRow('Behavioral Analysis', 'ML-based', true),
            _buildDetectionSystemRow('Statistical Analysis', 'Real-time', true),
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

  Widget _buildDetectionSystemRow(
    String name,
    String description,
    bool enabled,
  ) {
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
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  name,
                  style: const TextStyle(
                    fontWeight: FontWeight.w600,
                    fontSize: 14,
                  ),
                ),
                Text(
                  description,
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
        ],
      ),
    );
  }

  void _showHelpDialog() {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Anomaly Dashboard Help'),
        content: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                'Severity Levels:',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              _buildHelpRow(
                'CRITICAL',
                'Immediate threat requiring action',
                Colors.red.shade700,
              ),
              _buildHelpRow(
                'HIGH',
                'Significant security concern',
                Colors.red.shade500,
              ),
              _buildHelpRow(
                'MEDIUM',
                'Moderate risk activity',
                Colors.orange.shade600,
              ),
              _buildHelpRow(
                'LOW',
                'Minor suspicious behavior',
                Colors.yellow.shade700,
              ),
              const SizedBox(height: 16),
              const Text(
                'Common Anomaly Types:',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 8),
              const Text('• Port Scan: Rapid scanning of multiple ports'),
              const Text('• SYN Flood: High volume SYN packet attacks'),
              const Text('• DNS Tunneling: Data exfiltration via DNS'),
              const Text('• ARP Spoofing: Network identity attacks'),
              const Text('• Connection Flood: Excessive connection attempts'),
              const Text('• Unusual Traffic: Abnormal network patterns'),
            ],
          ),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Got it'),
          ),
        ],
      ),
    );
  }

  Widget _buildHelpRow(String severity, String description, Color color) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
            decoration: BoxDecoration(
              color: color,
              borderRadius: BorderRadius.circular(4),
            ),
            child: Text(
              severity,
              style: const TextStyle(
                color: Colors.white,
                fontSize: 10,
                fontWeight: FontWeight.bold,
              ),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(
            child: Text(description, style: const TextStyle(fontSize: 12)),
          ),
        ],
      ),
    );
  }

  @override
  void dispose() {
    _anomalySubscription?.cancel();
    _alertAnimationController.dispose();
    super.dispose();
  }
}
