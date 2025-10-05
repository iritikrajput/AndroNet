# AndroNet Development Setup Guide

## 🚀 Contributor's Guide to Setting Up AndroNet Development Environment

This comprehensive guide will walk you through setting up your development environment for contributing to AndroNet, a professional-grade mobile network packet analyzer.

---

## 📋 Prerequisites

### System Requirements

**Operating System:**
- Windows 10/11 (recommended for Flutter development)
- Linux (Ubuntu 20.04+ recommended)
- macOS 12.0+ (Monterey or later)

**Hardware:**
- Minimum 8GB RAM (16GB recommended)
- 10GB free disk space
- Intel i5 or equivalent processor

### Required Software

#### 1. Flutter SDK (3.32.8+)
```bash
# Download Flutter SDK
git clone https://github.com/flutter/flutter.git -b 3.32.8
export PATH="$PATH:`pwd`/flutter/bin"
flutter doctor
```

#### 2. Android Studio
- **Download**: [Android Studio](https://developer.android.com/studio)
- **Version**: Arctic Fox (2020.3.1) or later
- **Components to install**:
  - Android SDK (API level 21+)
  - Android SDK Build-Tools
  - Android Emulator
  - Android SDK Platform-Tools
  - Google USB Driver (Windows only)

#### 3. Android NDK
```bash
# In Android Studio SDK Manager
SDK Tools → NDK (Side by side) → Install NDK version r21e or later
```

#### 4. CMake (3.22.1+)
```bash
# Windows (Chocolatey)
choco install cmake

# Ubuntu/Debian
sudo apt install cmake

# macOS (Homebrew)
brew install cmake
```

#### 5. Visual Studio Build Tools (Windows only)
- Install Visual Studio 2022 with C++ build tools
- Or install Build Tools for Visual Studio 2022

#### 6. Git
- Latest version with LFS support

#### 7. Java Development Kit
- OpenJDK 11 or 17
- Set JAVA_HOME environment variable

---

## 🛠️ Environment Setup

### Step 1: Flutter Configuration

```bash
# Clone AndroNet repository
git clone https://github.com/your-username/AndroNet.git
cd AndroNet

# Get Flutter dependencies
flutter pub get

# Verify Flutter setup
flutter doctor
flutter devices
```

**Expected output:**
```
Doctor summary (to see all details, run flutter doctor -v):
[✓] Flutter (Channel stable, 3.32.8, on Windows 11)
[✓] Android toolchain - develop for Android devices (Android SDK version 34.0.0)
[✓] Android Studio (version 2022.3)
[✓] VS Code (version 1.85.0)
[✓] Connected device (1 available)
```

### Step 2: Android Studio Configuration

1. **Launch Android Studio**
2. **Open Project**: File → Open → Select `AndroNet/android/`
3. **Accept Gradle Sync**: Allow Gradle to download dependencies
4. **Configure SDK**: Tools → SDK Manager
   - Android API 34 (Android 14)
   - Android API 21+ (for compatibility)

### Step 3: Native Library Setup

#### Initialize Submodules
```bash
# Initialize zdtun library (required for VPN mode)
git submodule update --init --recursive
```

#### Build Native Libraries
```bash
# Windows
.\gradlew assembleDebug

# Linux/macOS
./gradlew assembleDebug
```

### Step 4: Environment Variables

**Windows:**
```cmd
set ANDROID_HOME=C:\Users\Username\AppData\Local\Android\Sdk
set JAVA_HOME=C:\Program Files\Java\jdk-17
set PATH=%PATH%;%ANDROID_HOME%\platform-tools;%ANDROID_HOME%\tools
```

**Linux/macOS:**
```bash
export ANDROID_HOME=$HOME/Android/Sdk
export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
export PATH=$PATH:$ANDROID_HOME/platform-tools:$ANDROID_HOME/tools
```

---

## 🏗️ Building AndroNet

### Debug Build

```bash
# Build debug APK
flutter build apk --debug

# Install on connected device
flutter install

# Or manually
adb install build/app/outputs/flutter-apk/app-debug.apk
```

### Release Build

```bash
# Build release APK
flutter build apk --release

# Build app bundle (Play Store)
flutter build appbundle --release
```

### Development Build with Hot Reload

```bash
# Start Flutter development server
flutter run

# For specific device
flutter run -d <device_id>

# For emulator
flutter run -d emulator-5554
```

---

## 🧪 Testing Setup

### Unit Tests

```bash
# Run all tests
flutter test

# Run specific test file
flutter test test/unit/packet_parser_test.dart

# Run with coverage
flutter test --coverage
```

### Integration Tests

```bash
# Run integration tests
flutter test integration_test/

# Run on specific device
flutter test integration_test/ -d <device_id>
```

### Native Code Testing

```bash
# Run Kotlin tests
./gradlew testDebugUnitTest

# Run with coverage (if configured)
./gradlew testDebugUnitTest jacocoTestReport
```

---

## 🔧 Development Workflow

### Code Organization

```
AndroNet/
├── lib/                          # Flutter Dart code
│   ├── main.dart                # Main application entry
│   ├── auth/                    # Authentication system
│   ├── widgets/                 # Reusable UI components
│   └── services/                # Business logic services
├── android/                     # Android native code
│   ├── app/src/main/kotlin/     # Kotlin source files
│   ├── app/src/main/jni/        # C/C++ native code
│   └── build.gradle             # Android build config
├── docs/                        # Documentation
├── test/                        # Flutter tests
└── android/app/src/androidTest/ # Android instrumented tests
```

### Key Development Areas

#### 1. Flutter UI Development
- **File**: `lib/main.dart` - Main application logic
- **File**: `lib/enhanced_ui_components.dart` - Advanced UI widgets
- **File**: `lib/auth/` - Authentication system

#### 2. Kotlin Native Services
- **File**: `android/app/src/main/kotlin/com/example/packet_analyzer/CompleteVpnService.kt`
- **File**: `android/app/src/main/kotlin/com/example/packet_analyzer/PacketDissector.kt`
- **File**: `android/app/src/main/kotlin/com/example/packet_analyzer/AnomalyDetector.kt`

#### 3. Native C/C++ Code
- **File**: `android/app/src/main/jni/pcap_writer.c` - PCAP export
- **File**: `android/app/src/main/jni/zdtun_vpn.c` - VPN tunneling

### Development Tools Setup

#### Visual Studio Code (Recommended)

**Extensions:**
- Flutter (Dart Code)
- Kotlin
- Android Debug Bridge
- CMake Tools
- Gradle for Java

**Settings:**
```json
{
  "dart.flutterSdkPath": "/path/to/flutter",
  "kotlin.compiler.jvm.target": "11",
  "cmake.configureOnOpen": true
}
```

#### Android Studio

**Recommended Plugins:**
- Flutter
- Kotlin
- ADB Idea
- CMake

---

## 🐛 Debugging AndroNet

### Flutter Debugging

```bash
# Enable debug logging
flutter run --verbose

# Debug specific device
flutter run -d <device_id> --debug

# Profile mode for performance
flutter run --profile
```

### Android Native Debugging

#### Logcat Debugging
```bash
# View all logs
adb logcat

# Filter by tag
adb logcat -s CompleteVpnService
adb logcat -s PacketDissector
adb logcat -s AnomalyDetector

# Filter by priority
adb logcat *:E    # Errors only
adb logcat *:W    # Warnings and above
adb logcat *:D    # Debug and above
```

#### Breakpoints in Android Studio

1. Set breakpoints in Kotlin files
2. Run in debug mode: `flutter run --debug`
3. Use Android Studio's debugger

### Native Code Debugging

#### GDB Debugging (Linux/macOS)
```bash
# Attach to running process
gdb --pid=$(adb shell pidof com.example.packet_analyzer)

# Set breakpoints
break pcap_writer.c:100
break zdtun_vpn.c:50
```

#### Visual Studio Debugger (Windows)
- Use Visual Studio's native debugger
- Attach to Android process via ADB

---

## 📝 Contributing Workflow

### 1. Fork and Clone

```bash
# Fork on GitHub
git clone https://github.com/your-username/AndroNet.git
cd AndroNet

# Add upstream remote
git remote add upstream https://github.com/iritikrajput/AndroNet.git
```

### 2. Create Feature Branch

```bash
# Create and switch to feature branch
git checkout -b feature/amazing-new-feature

# Or for bug fixes
git checkout -b fix/bug-description
```

### 3. Make Changes

Follow the existing code style:
- **Dart**: Use `flutter format`
- **Kotlin**: Follow Android Kotlin style guide
- **C/C++**: Follow project's coding standards

### 4. Test Changes

```bash
# Run tests
flutter test

# Run on device/emulator
flutter run

# Check for linting issues
flutter analyze
```

### 5. Commit and Push

```bash
# Stage changes
git add .

# Commit with descriptive message
git commit -m "feat: add amazing new feature

- Add feature description
- Explain implementation details
- Reference related issues"

# Push to fork
git push origin feature/amazing-new-feature
```

### 6. Create Pull Request

1. Go to GitHub repository
2. Click "Compare & pull request"
3. Fill out PR template
4. Request review from maintainers

---

## 🔍 Code Quality Tools

### Static Analysis

```bash
# Dart analysis
flutter analyze

# Kotlin linting (via Android Studio)
Code → Inspect Code

# C/C++ linting
cppcheck android/app/src/main/jni/
```

### Code Formatting

```bash
# Format Dart code
flutter format lib/

# Format Kotlin code (via Android Studio)
Code → Reformat Code

# Format C/C++ code
clang-format -i android/app/src/main/jni/*.c
```

### Pre-commit Hooks

Install pre-commit hooks for automated quality checks:

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run manually
pre-commit run --all-files
```

---

## 🚨 Troubleshooting

### Common Issues

#### Flutter Issues

**Problem**: `flutter doctor` shows missing Android SDK
**Solution**:
```bash
# Update Android licenses
flutter doctor --android-licenses

# Reinstall Android SDK components
flutter config --android-sdk /path/to/android/sdk
```

**Problem**: Build fails with "NDK not configured"
**Solution**:
```bash
# Configure NDK path
flutter config --android-ndk /path/to/ndk

# Clean and rebuild
flutter clean
flutter pub get
```

#### Android Issues

**Problem**: VPN permission not granted
**Solution**:
```bash
# Check permissions
adb shell dumpsys package com.example.packet_analyzer | grep permission

# Grant manually if needed
adb shell pm grant com.example.packet_analyzer android.permission.BIND_VPN_SERVICE
```

**Problem**: Native library loading fails
**Solution**:
```bash
# Check ABI compatibility
adb shell getprop ro.product.cpu.abi

# Verify library exists
adb shell ls -la /data/data/com.example.packet_analyzer/lib/
```

#### Development Issues

**Problem**: Hot reload not working
**Solution**:
```bash
# Clean build cache
flutter clean

# Restart development server
flutter run --hot
```

---

## 📚 Additional Resources

### Documentation
- [API Documentation](API_DOCUMENTATION.md) - Complete Kotlin service APIs
- [Architecture Decisions](ARCHITECTURE_DECISIONS.md) - Key architectural choices
- [Implementation Guide](IMPLEMENTATION_GUIDE.md) - Technical implementation details

### External References
- [Flutter Documentation](https://docs.flutter.dev/)
- [Android VpnService API](https://developer.android.com/reference/android/net/VpnService)
- [PCAPdroid Source](https://github.com/emanuele-f/PCAPdroid) - Reference implementation
- [Kotlin Coroutines Guide](https://kotlinlang.org/docs/coroutines-overview.html)

### Community
- **GitHub Issues**: [AndroNet Issues](https://github.com/iritikrajput/AndroNet/issues)
- **Discussions**: [GitHub Discussions](https://github.com/iritikrajput/AndroNet/discussions)
- **Discord**: Join our development community

---

## 🎯 Best Practices

### Code Style
1. **Follow existing patterns** - Study existing code before making changes
2. **Write descriptive commit messages** - Use conventional commit format
3. **Add comments for complex logic** - Especially in native code
4. **Use meaningful variable names** - Avoid abbreviations

### Testing
1. **Write tests for new features** - Unit and integration tests
2. **Test on multiple devices** - Different Android versions and screen sizes
3. **Test both capture modes** - VPN and libpcap modes
4. **Performance testing** - Monitor CPU and memory usage

### Performance
1. **Profile packet processing** - Use Android Profiler
2. **Optimize memory usage** - Monitor for leaks
3. **Efficient data structures** - Use appropriate collections
4. **Background processing** - Offload heavy work from UI thread

### Security
1. **No hardcoded credentials** - Use secure storage
2. **Input validation** - Validate all packet data
3. **Error handling** - Graceful degradation
4. **Permission checks** - Verify required permissions

---

## 🚀 Getting Help

If you encounter issues:

1. **Check existing documentation** - API docs, implementation guides
2. **Search GitHub issues** - Your problem might be documented
3. **Check build logs** - Look for specific error messages
4. **Ask the community** - GitHub discussions or Discord
5. **Create detailed issue** - Include logs, steps to reproduce, environment info

**Happy contributing to AndroNet!** 🎉

*Made with ❤️ for the cybersecurity community*
