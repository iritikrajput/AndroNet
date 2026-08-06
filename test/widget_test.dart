import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:packet_analyzer/auth/auth_service.dart';
import 'package:packet_analyzer/main.dart';
import 'package:packet_analyzer/theme_service.dart';

Widget _wrapApp() => MultiProvider(
  providers: [
    ChangeNotifierProvider(create: (_) => AuthenticationService()),
    ChangeNotifierProvider(create: (_) => ThemeService()),
  ],
  child: const PacketAnalyzerApp(),
);

void main() {
  setUp(() {
    // AuthWrapper.initState() kicks off AuthenticationService.initialize(),
    // which calls SharedPreferences.getInstance() — needs the plugin mocked
    // to run under flutter_test without a real platform.
    SharedPreferences.setMockInitialValues({});
  });

  testWidgets('App boots to the AuthWrapper loading screen', (tester) async {
    // main() wraps PacketAnalyzerApp in these same providers — pumping the
    // app widget alone (as the original version of this test did) throws
    // ProviderNotFoundException as soon as AuthWrapper/PacketAnalyzerApp look
    // up their services.
    await tester.pumpWidget(_wrapApp());

    // Before AuthenticationService.initialize() resolves, AuthWrapper shows
    // its own loading screen (AuthState.unauthenticated + AuthMethod.none).
    expect(find.text('Andronet'), findsOneWidget);
    expect(find.text('Initializing Security...'), findsOneWidget);
    expect(find.byType(CircularProgressIndicator), findsOneWidget);
  });

  testWidgets('AuthenticationService.initialize() resolves without throwing', (
    tester,
  ) async {
    await tester.pumpWidget(_wrapApp());

    // A handful of bounded pumps (rather than pumpAndSettle) let the async
    // AuthenticationService.initialize() call resolve without the test
    // hanging on the main screen's own animation controllers/periodic
    // timers, which never "settle" by design.
    for (var i = 0; i < 5; i++) {
      await tester.pump(const Duration(milliseconds: 50));
    }

    expect(tester.takeException(), isNull);
  });
}
