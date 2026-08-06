import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:packet_analyzer/auth/auth_service.dart';
import 'package:shared_preferences/shared_preferences.dart';

/// In-memory fake for the flutter_secure_storage platform channel, since
/// AuthenticationService talks to real secure storage (backed by Android
/// Keystore/iOS Keychain in production) which isn't available in a plain
/// `flutter_test` unit test run.
void _installFakeSecureStorage(TestDefaultBinaryMessengerBinding binding) {
  final store = <String, String>{};
  const channel = MethodChannel('plugins.it_nomads.com/flutter_secure_storage');

  binding.defaultBinaryMessenger.setMockMethodCallHandler(channel, (
    MethodCall call,
  ) async {
    switch (call.method) {
      case 'write':
        store[call.arguments['key'] as String] = call.arguments['value'] as String;
        return null;
      case 'read':
        return store[call.arguments['key'] as String];
      case 'delete':
        store.remove(call.arguments['key'] as String);
        return null;
      case 'deleteAll':
        store.clear();
        return null;
      case 'containsKey':
        return store.containsKey(call.arguments['key'] as String);
      case 'readAll':
        return store;
      default:
        return null;
    }
  });
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  final binding = TestDefaultBinaryMessengerBinding.instance;

  setUp(() async {
    SharedPreferences.setMockInitialValues({});
    _installFakeSecureStorage(binding);
  });

  Future<AuthenticationService> makeService() async {
    final service = AuthenticationService();
    await service.initialize();
    return service;
  }

  group('PIN setup and authentication', () {
    test('rejects a PIN shorter than 4 digits', () async {
      final service = await makeService();
      expect(await service.setupPin('123'), isFalse);
    });

    test('round-trips a valid PIN', () async {
      final service = await makeService();
      expect(await service.setupPin('1234'), isTrue);
      expect(await service.authenticateWithPin('1234'), isTrue);
      expect(service.authState, AuthState.authenticated);
    });

    test('rejects an incorrect PIN without authenticating', () async {
      final service = await makeService();
      await service.setupPin('1234');
      // A fresh service instance simulates "app restarted, come back to
      // unlock" — auth state resets but the stored credential persists.
      final relaunched = await makeService();
      expect(await relaunched.authenticateWithPin('9999'), isFalse);
      expect(relaunched.authState, isNot(AuthState.authenticated));
    });
  });

  group('lockout after repeated failures', () {
    test('locks out after 5 failed attempts and blocks further tries', () async {
      final service = await makeService();
      await service.setupPin('1234');

      for (var i = 0; i < 5; i++) {
        expect(await service.authenticateWithPin('0000'), isFalse);
      }

      expect(service.isLocked, isTrue);
      expect(service.lockTimeRemaining, isNotNull);
      expect(service.lockTimeRemaining!.inMinutes, lessThanOrEqualTo(5));

      // Even the *correct* PIN must be rejected while locked out.
      expect(await service.authenticateWithPin('1234'), isFalse);
    });

    test('a successful auth resets the failed-attempt counter', () async {
      final service = await makeService();
      await service.setupPin('1234');

      expect(await service.authenticateWithPin('0000'), isFalse);
      expect(await service.authenticateWithPin('0000'), isFalse);
      expect(await service.authenticateWithPin('1234'), isTrue);

      // Counter reset -> two more wrong guesses shouldn't trigger a lockout
      // (lockout only fires at 5 consecutive recorded failures).
      expect(await service.authenticateWithPin('0000'), isFalse);
      expect(await service.authenticateWithPin('0000'), isFalse);
      expect(service.isLocked, isFalse);
    });
  });

  group('auto-lock timing', () {
    test('stays authenticated immediately after a successful auth', () async {
      final service = await makeService();
      await service.setupPin('1234');
      await service.authenticateWithPin('1234');

      service.checkAutoLock();
      expect(service.authState, AuthState.authenticated);
    });

    test('an auto-lock time of 0 minutes locks out on the next check', () async {
      final service = await makeService();
      await service.setupPin('1234');
      await service.authenticateWithPin('1234');
      await service.setAutoLockTime(0);

      service.checkAutoLock();
      expect(service.authState, AuthState.unauthenticated);
    });
  });

  group('pattern authentication', () {
    test('rejects a pattern shorter than 4 dots', () async {
      final service = await makeService();
      expect(await service.setupPattern([1, 2, 3]), isFalse);
    });

    test('round-trips a valid pattern', () async {
      final service = await makeService();
      expect(await service.setupPattern([0, 1, 2, 5, 8]), isTrue);
      expect(await service.authenticateWithPattern([0, 1, 2, 5, 8]), isTrue);
      expect(await service.authenticateWithPattern([1, 2, 3, 4]), isFalse);
    });
  });

  group('disableAuthentication', () {
    test('clears stored credentials and returns to "none"', () async {
      final service = await makeService();
      await service.setupPin('1234');
      await service.disableAuthentication();

      expect(service.currentAuthMethod, AuthMethod.none);
      expect(service.authState, AuthState.authenticated);
      expect(service.isLocked, isFalse);
    });
  });
}
