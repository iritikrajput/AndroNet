import 'dart:convert';
import 'dart:math';
import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:local_auth/local_auth.dart';
import 'package:shared_preferences/shared_preferences.dart';

enum AuthMethod { pin, password, pattern, biometric, none }

enum AuthState { authenticated, unauthenticated, locked }

class AuthenticationService extends ChangeNotifier {
  static const String _pinKey = 'auth_pin';
  static const String _passwordKey = 'auth_password';
  static const String _patternKey = 'auth_pattern';
  static const String _authMethodKey = 'auth_method';
  static const String _biometricEnabledKey = 'biometric_enabled';
  static const String _autoLockTimeKey = 'auto_lock_time';
  static const String _failedAttemptsKey = 'failed_attempts';
  static const String _lockUntilKey = 'lock_until';
  static const String _lastAuthKey = 'last_auth_time';

  final FlutterSecureStorage _secureStorage = const FlutterSecureStorage(
    aOptions: AndroidOptions(
      encryptedSharedPreferences: true,
    ),
  );

  final LocalAuthentication _localAuth = LocalAuthentication();
  SharedPreferences? _prefs;

  AuthState _authState = AuthState.unauthenticated;
  AuthMethod _currentAuthMethod = AuthMethod.none;
  bool _biometricEnabled = false;
  int _autoLockTime = 5; // minutes
  int _failedAttempts = 0;
  DateTime? _lockUntil;
  DateTime? _lastAuthTime;

  AuthState get authState => _authState;
  AuthMethod get currentAuthMethod => _currentAuthMethod;
  bool get biometricEnabled => _biometricEnabled;
  int get autoLockTime => _autoLockTime;
  bool get isLocked => _lockUntil != null && DateTime.now().isBefore(_lockUntil!);
  Duration? get lockTimeRemaining => _lockUntil != null && DateTime.now().isBefore(_lockUntil!)
      ? _lockUntil!.difference(DateTime.now())
      : null;

  Future<void> initialize() async {
    _prefs = await SharedPreferences.getInstance();
    await _loadSettings();
    await _checkAuthState();
  }

  Future<void> _loadSettings() async {
    final methodString = _prefs?.getString(_authMethodKey) ?? 'none';
    _currentAuthMethod = AuthMethod.values.firstWhere(
      (e) => e.toString() == methodString,
      orElse: () => AuthMethod.none,
    );

    _biometricEnabled = _prefs?.getBool(_biometricEnabledKey) ?? false;
    _autoLockTime = _prefs?.getInt(_autoLockTimeKey) ?? 5;
    _failedAttempts = _prefs?.getInt(_failedAttemptsKey) ?? 0;

    final lockUntilMs = _prefs?.getInt(_lockUntilKey);
    if (lockUntilMs != null) {
      _lockUntil = DateTime.fromMillisecondsSinceEpoch(lockUntilMs);
      if (DateTime.now().isAfter(_lockUntil!)) {
        _lockUntil = null;
        await _prefs?.remove(_lockUntilKey);
        _failedAttempts = 0;
        await _prefs?.setInt(_failedAttemptsKey, 0);
      }
    }

    final lastAuthMs = _prefs?.getInt(_lastAuthKey);
    if (lastAuthMs != null) {
      _lastAuthTime = DateTime.fromMillisecondsSinceEpoch(lastAuthMs);
    }
  }

  Future<void> _checkAuthState() async {
    if (isLocked) {
      _authState = AuthState.locked;
    } else if (_currentAuthMethod == AuthMethod.none) {
      _authState = AuthState.authenticated;
    } else if (_lastAuthTime != null &&
               DateTime.now().difference(_lastAuthTime!).inMinutes < _autoLockTime) {
      _authState = AuthState.authenticated;
    } else {
      _authState = AuthState.unauthenticated;
    }
    notifyListeners();
  }

  String _hashCredential(String credential) {
    final bytes = utf8.encode(credential);
    final digest = sha256.convert(bytes);
    return digest.toString();
  }

  Future<bool> setupPin(String pin) async {
    if (pin.length < 4) return false;

    final hashedPin = _hashCredential(pin);
    await _secureStorage.write(key: _pinKey, value: hashedPin);
    await _prefs?.setString(_authMethodKey, AuthMethod.pin.toString());
    _currentAuthMethod = AuthMethod.pin;
    return true;
  }

  Future<bool> setupPassword(String password) async {
    if (password.length < 6) return false;

    final hashedPassword = _hashCredential(password);
    await _secureStorage.write(key: _passwordKey, value: hashedPassword);
    await _prefs?.setString(_authMethodKey, AuthMethod.password.toString());
    _currentAuthMethod = AuthMethod.password;
    return true;
  }

  Future<bool> setupPattern(List<int> pattern) async {
    if (pattern.length < 4) return false;

    final patternString = pattern.join(',');
    final hashedPattern = _hashCredential(patternString);
    await _secureStorage.write(key: _patternKey, value: hashedPattern);
    await _prefs?.setString(_authMethodKey, AuthMethod.pattern.toString());
    _currentAuthMethod = AuthMethod.pattern;
    return true;
  }

  Future<bool> enableBiometric() async {
    try {
      final bool isAvailable = await _localAuth.canCheckBiometrics;
      if (!isAvailable) return false;

      final List<BiometricType> availableBiometrics = await _localAuth.getAvailableBiometrics();
      if (availableBiometrics.isEmpty) return false;

      await _prefs?.setBool(_biometricEnabledKey, true);
      _biometricEnabled = true;
      notifyListeners();
      return true;
    } catch (e) {
      debugPrint('Error enabling biometric: $e');
      return false;
    }
  }

  Future<bool> authenticateWithPin(String pin) async {
    if (isLocked) return false;

    try {
      final storedPin = await _secureStorage.read(key: _pinKey);
      if (storedPin == null) return false;

      final hashedPin = _hashCredential(pin);
      if (hashedPin == storedPin) {
        await _onSuccessfulAuth();
        return true;
      } else {
        await _onFailedAuth();
        return false;
      }
    } catch (e) {
      debugPrint('Error authenticating with PIN: $e');
      return false;
    }
  }

  Future<bool> authenticateWithPassword(String password) async {
    if (isLocked) return false;

    try {
      final storedPassword = await _secureStorage.read(key: _passwordKey);
      if (storedPassword == null) return false;

      final hashedPassword = _hashCredential(password);
      if (hashedPassword == storedPassword) {
        await _onSuccessfulAuth();
        return true;
      } else {
        await _onFailedAuth();
        return false;
      }
    } catch (e) {
      debugPrint('Error authenticating with password: $e');
      return false;
    }
  }

  Future<bool> authenticateWithPattern(List<int> pattern) async {
    if (isLocked) return false;

    try {
      final storedPattern = await _secureStorage.read(key: _patternKey);
      if (storedPattern == null) return false;

      final patternString = pattern.join(',');
      final hashedPattern = _hashCredential(patternString);
      if (hashedPattern == storedPattern) {
        await _onSuccessfulAuth();
        return true;
      } else {
        await _onFailedAuth();
        return false;
      }
    } catch (e) {
      debugPrint('Error authenticating with pattern: $e');
      return false;
    }
  }

  Future<bool> authenticateWithBiometric() async {
    if (isLocked || !_biometricEnabled) return false;

    try {
      final bool isAuthenticated = await _localAuth.authenticate(
        localizedReason: 'Access Andronet by CipherSec',
        options: const AuthenticationOptions(
          stickyAuth: true,
          biometricOnly: true,
        ),
      );

      if (isAuthenticated) {
        await _onSuccessfulAuth();
        return true;
      }
      return false;
    } catch (e) {
      debugPrint('Error authenticating with biometric: $e');
      return false;
    }
  }

  Future<void> _onSuccessfulAuth() async {
    _authState = AuthState.authenticated;
    _failedAttempts = 0;
    _lockUntil = null;
    _lastAuthTime = DateTime.now();

    await _prefs?.setInt(_failedAttemptsKey, 0);
    await _prefs?.remove(_lockUntilKey);
    await _prefs?.setInt(_lastAuthKey, _lastAuthTime!.millisecondsSinceEpoch);

    notifyListeners();
  }

  Future<void> _onFailedAuth() async {
    _failedAttempts++;
    await _prefs?.setInt(_failedAttemptsKey, _failedAttempts);

    if (_failedAttempts >= 5) {
      _lockUntil = DateTime.now().add(const Duration(minutes: 5));
      await _prefs?.setInt(_lockUntilKey, _lockUntil!.millisecondsSinceEpoch);
      _authState = AuthState.locked;
    }

    notifyListeners();
  }

  Future<void> logout() async {
    _authState = AuthState.unauthenticated;
    _lastAuthTime = null;
    await _prefs?.remove(_lastAuthKey);
    notifyListeners();
  }

  Future<void> setAutoLockTime(int minutes) async {
    _autoLockTime = minutes;
    await _prefs?.setInt(_autoLockTimeKey, minutes);
    notifyListeners();
  }

  Future<void> disableAuthentication() async {
    await _secureStorage.deleteAll();
    await _prefs?.remove(_authMethodKey);
    await _prefs?.remove(_biometricEnabledKey);
    await _prefs?.remove(_failedAttemptsKey);
    await _prefs?.remove(_lockUntilKey);
    await _prefs?.remove(_lastAuthKey);

    _currentAuthMethod = AuthMethod.none;
    _biometricEnabled = false;
    _authState = AuthState.authenticated;
    _failedAttempts = 0;
    _lockUntil = null;
    _lastAuthTime = null;

    notifyListeners();
  }

  Future<bool> isBiometricAvailable() async {
    try {
      final bool isAvailable = await _localAuth.canCheckBiometrics;
      final List<BiometricType> availableBiometrics = await _localAuth.getAvailableBiometrics();
      return isAvailable && availableBiometrics.isNotEmpty;
    } catch (e) {
      return false;
    }
  }

  void checkAutoLock() {
    if (_authState == AuthState.authenticated &&
        _lastAuthTime != null &&
        DateTime.now().difference(_lastAuthTime!).inMinutes >= _autoLockTime) {
      _authState = AuthState.unauthenticated;
      notifyListeners();
    }
  }
}