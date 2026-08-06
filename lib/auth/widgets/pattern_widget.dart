import 'package:flutter/material.dart';
import 'dart:math';

class PatternWidget extends StatefulWidget {
  final List<int> selectedPattern;
  final Function(List<int>) onPatternChanged;
  final VoidCallback? onPatternComplete;
  final bool isSetupMode;

  const PatternWidget({
    super.key,
    required this.selectedPattern,
    required this.onPatternChanged,
    this.onPatternComplete,
    this.isSetupMode = false,
  });

  @override
  State<PatternWidget> createState() => _PatternWidgetState();
}

class _PatternWidgetState extends State<PatternWidget> {
  final List<Offset> _dotPositions = [];
  final List<int> _currentPattern = [];
  bool _isDrawing = false;
  Offset? _currentPosition;

  @override
  void initState() {
    super.initState();
    _currentPattern.addAll(widget.selectedPattern);
  }

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final size = min(constraints.maxWidth, constraints.maxHeight) * 0.8;

        return SizedBox(
          width: size,
          height: size,
          child: GestureDetector(
            onPanStart: _onPanStart,
            onPanUpdate: _onPanUpdate,
            onPanEnd: _onPanEnd,
            child: CustomPaint(
              painter: PatternPainter(
                dotPositions: _dotPositions,
                selectedPattern: _currentPattern,
                currentPosition: _currentPosition,
                isDrawing: _isDrawing,
                primaryColor: Theme.of(context).colorScheme.primary,
              ),
              size: Size(size, size),
            ),
          ),
        );
      },
    );
  }

  void _onPanStart(DragStartDetails details) {
    setState(() {
      _isDrawing = true;
      _currentPattern.clear();
      _currentPosition = details.localPosition;
      _calculateDotPositions();
      _checkDotHit(details.localPosition);
    });
  }

  void _onPanUpdate(DragUpdateDetails details) {
    setState(() {
      _currentPosition = details.localPosition;
      _checkDotHit(details.localPosition);
    });
  }

  void _onPanEnd(DragEndDetails details) {
    setState(() {
      _isDrawing = false;
      _currentPosition = null;
    });

    widget.onPatternChanged(_currentPattern);

    if (_currentPattern.length >= 4 && widget.onPatternComplete != null) {
      widget.onPatternComplete!();
    }
  }

  void _calculateDotPositions() {
    _dotPositions.clear();
    const int gridSize = 3;
    final double spacing = context.size!.width / (gridSize + 1);

    for (int i = 0; i < gridSize; i++) {
      for (int j = 0; j < gridSize; j++) {
        _dotPositions.add(Offset(
          spacing * (j + 1),
          spacing * (i + 1),
        ));
      }
    }
  }

  void _checkDotHit(Offset position) {
    const double hitRadius = 30.0;

    for (int i = 0; i < _dotPositions.length; i++) {
      final distance = (position - _dotPositions[i]).distance;
      if (distance <= hitRadius && !_currentPattern.contains(i)) {
        _currentPattern.add(i);
        break;
      }
    }
  }
}

class PatternPainter extends CustomPainter {
  final List<Offset> dotPositions;
  final List<int> selectedPattern;
  final Offset? currentPosition;
  final bool isDrawing;
  final Color primaryColor;

  PatternPainter({
    required this.dotPositions,
    required this.selectedPattern,
    this.currentPosition,
    this.isDrawing = false,
    required this.primaryColor,
  });

  @override
  void paint(Canvas canvas, Size size) {
    // Ensure dot positions are calculated
    if (dotPositions.isEmpty) {
      _calculateDotPositions(size);
    }

    // Draw connecting lines
    _drawLines(canvas);

    // Draw dots
    _drawDots(canvas);
  }

  void _calculateDotPositions(Size size) {
    dotPositions.clear();
    const int gridSize = 3;
    final double spacing = size.width / (gridSize + 1);

    for (int i = 0; i < gridSize; i++) {
      for (int j = 0; j < gridSize; j++) {
        dotPositions.add(Offset(
          spacing * (j + 1),
          spacing * (i + 1),
        ));
      }
    }
  }

  void _drawLines(Canvas canvas) {
    if (selectedPattern.length < 2) return;

    final paint = Paint()
      ..color = primaryColor.withValues(alpha: 0.6)
      ..strokeWidth = 4.0
      ..strokeCap = StrokeCap.round;

    // Draw lines between selected dots
    for (int i = 0; i < selectedPattern.length - 1; i++) {
      final start = dotPositions[selectedPattern[i]];
      final end = dotPositions[selectedPattern[i + 1]];
      canvas.drawLine(start, end, paint);
    }

    // Draw line to current position if drawing
    if (isDrawing && currentPosition != null && selectedPattern.isNotEmpty) {
      final lastDot = dotPositions[selectedPattern.last];
      canvas.drawLine(lastDot, currentPosition!, paint);
    }
  }

  void _drawDots(Canvas canvas) {
    for (int i = 0; i < dotPositions.length; i++) {
      final position = dotPositions[i];
      final isSelected = selectedPattern.contains(i);

      // Draw outer circle
      final outerPaint = Paint()
        ..color = isSelected ? primaryColor : primaryColor.withValues(alpha: 0.3)
        ..style = PaintingStyle.stroke
        ..strokeWidth = 2.0;

      canvas.drawCircle(position, 20, outerPaint);

      // Draw inner circle
      if (isSelected) {
        final innerPaint = Paint()
          ..color = primaryColor
          ..style = PaintingStyle.fill;

        canvas.drawCircle(position, 8, innerPaint);

        // Draw selection number
        final textPainter = TextPainter(
          text: TextSpan(
            text: (selectedPattern.indexOf(i) + 1).toString(),
            style: const TextStyle(
              color: Colors.white,
              fontSize: 12,
              fontWeight: FontWeight.bold,
            ),
          ),
          textDirection: TextDirection.ltr,
        );

        textPainter.layout();
        textPainter.paint(
          canvas,
          Offset(
            position.dx - textPainter.width / 2,
            position.dy - textPainter.height / 2,
          ),
        );
      } else {
        final innerPaint = Paint()
          ..color = primaryColor.withValues(alpha: 0.3)
          ..style = PaintingStyle.fill;

        canvas.drawCircle(position, 4, innerPaint);
      }
    }
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => true;
}