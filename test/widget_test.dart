import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:andronet/main.dart';

void main() {
  testWidgets('Packet Analyzer app smoke test', (WidgetTester tester) async {
    // Build the app and trigger a frame.
    await tester.pumpWidget(const PacketAnalyzerApp());

    // Verify that the app shows the main title.
    expect(find.text('Packet Analyzer'), findsOneWidget);

    // Verify that control buttons are present.
    expect(find.byIcon(Icons.clear), findsOneWidget);
    expect(find.byIcon(Icons.info_outline), findsOneWidget);
    expect(find.byType(FloatingActionButton), findsOneWidget);
  });
}
