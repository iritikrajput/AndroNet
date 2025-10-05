# AndroNet Deployment Guide

## 🚀 Deploying AndroNet to Different Environments

This comprehensive guide covers deployment strategies for AndroNet across development, staging, and production environments, including various distribution channels and deployment automation.

---

## 📋 Deployment Overview

### Deployment Environments

| Environment | Purpose | Access Level | Testing Level |
|-------------|---------|--------------|---------------|
| **Development** | Feature development | Developers only | Unit tests |
| **Staging** | Integration testing | Internal team | Full test suite |
| **Production** | End users | Public | All tests + monitoring |
| **Kali NetHunter** | Penetration testing | Security professionals | Specialized tests |

### Distribution Channels

1. **Google Play Store** - Public Android app distribution
2. **GitHub Releases** - Open source distribution
3. **APK Direct Download** - Development/testing
4. **F-Droid** - Open source app store
5. **Enterprise Distribution** - Internal deployment

---

## 🛠️ Build Configuration

### Flutter Build Commands

#### Development Builds
```bash
# Debug build for development
flutter build apk --debug

# Development with debugging enabled
flutter build apk --debug --verbose

# Split ABI for faster builds during development
flutter build apk --debug --split-per-abi
```

#### Release Builds
```bash
# Standard release build
flutter build apk --release

# App Bundle for Google Play (recommended)
flutter build appbundle --release

# Split APK by ABI for optimized distribution
flutter build apk --release --split-per-abi

# Obfuscated release build
flutter build apk --release --obfuscate --split-debug-info=build/debug-info/
```

### Build Optimization

#### Reduce APK Size
```bash
# Analyze APK contents
flutter build apk --analyze-size

# Build with minimal dependencies
flutter build apk --release --shrink

# Split by ABI for smaller downloads
flutter build apk --release --split-per-abi --target-platform android-arm,android-arm64,android-x64
```

#### Signing Configuration

**Create Keystore:**
```bash
# Generate keystore for release signing
keytool -genkey -v -keystore android/app/release-keystore.jks \
  -storetype JKS -keyalg RSA -keysize 2048 -validity 10000 \
  -alias release \
  -dname "CN=AndroNet, OU=Development, O=AndroNet, L=Unknown, ST=Unknown, C=US"
```

**Configure Signing in build.gradle:**
```kotlin
android {
    signingConfigs {
        release {
            storeFile file('release-keystore.jks')
            storePassword System.getenv("KEYSTORE_PASSWORD")
            keyAlias System.getenv("KEY_ALIAS")
            keyPassword System.getenv("KEY_PASSWORD")
        }
    }

    buildTypes {
        release {
            signingConfig signingConfigs.release
            minifyEnabled true
            proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
        }
    }
}
```

---

## 📦 Distribution Methods

### 1. Google Play Store Deployment

#### Prerequisites
- Google Developer Console account
- App signing key
- Privacy policy and compliance documentation

#### Deployment Steps

**1. Prepare Release:**
```bash
# Build app bundle for Play Store
flutter build appbundle --release

# Verify bundle contents
bundletool validate --bundle build/app/outputs/bundle/release/app-release.aab
```

**2. Create Release in Play Console:**
- Go to Google Play Console
- Select AndroNet app
- Navigate to Release Management → Internal Testing
- Create new release
- Upload `app-release.aab`
- Add release notes and screenshots

**3. Internal Testing:**
```bash
# Create internal test release
# Upload to "Internal Testing" track first
# Test with up to 100 internal testers
```

**4. Production Release:**
```bash
# Promote to production after testing
# Follow staged rollout strategy (10% → 25% → 50% → 100%)
# Monitor crash reports and user feedback
```

#### Play Store Configuration

**App Information:**
- **Title**: AndroNet - Mobile Network Packet Analyzer
- **Short Description**: Professional network analysis for Android
- **Full Description**: Comprehensive packet capture and analysis tool for penetration testers and network administrators
- **Category**: Tools/Productivity
- **Content Rating**: Everyone (no restricted content)

**Feature Graphic & Screenshots:**
- Feature graphic (1024x500px)
- Phone screenshots (at least 2, up to 8)
- 7-inch tablet screenshots (optional)
- 10-inch tablet screenshots (optional)

### 2. GitHub Releases

#### Automated Release Process

**1. Create Release Branch:**
```bash
git checkout -b release/v1.2.0
git push origin release/v1.2.0
```

**2. Update Version:**
```kotlin
// android/app/build.gradle
android {
    defaultConfig {
        versionCode 12
        versionName "1.2.0"
    }
}
```

**3. Build Release Artifacts:**
```bash
# Build all variants
flutter build apk --release --split-per-abi
flutter build appbundle --release

# Generate checksums
cd build/app/outputs/flutter-apk/
sha256sum app-armeabi-v7a-release.apk > checksums.txt
sha256sum app-arm64-v8a-release.apk >> checksums.txt
sha256sum app-x86_64-release.apk >> checksums.txt
```

**4. Create GitHub Release:**
- Go to GitHub repository
- Navigate to Releases
- Click "Create new release"
- Tag: `v1.2.0`
- Title: `AndroNet v1.2.0 - Enhanced DPI & Performance`
- Upload APK files and checksums
- Add detailed release notes

### 3. F-Droid Deployment

#### F-Droid Requirements
- Open source license (MIT compatible)
- No proprietary dependencies
- Reproducible builds
- F-Droid metadata files

**Create F-Droid Metadata:**
```yaml
# metadata/com.example.packet_analyzer.yml
Categories:
  - Internet
  - Security
License: MIT
SourceCode: https://github.com/iritikrajput/AndroNet
IssueTracker: https://github.com/iritikrajput/AndroNet/issues

RepoType: git
Repo: https://github.com/iritikrajput/AndroNet.git

Builds:
  - versionName: 1.2.0
    versionCode: 12
    commit: v1.2.0
    subdir: android
    gradle:
      - yes

AutoUpdateMode: Version v%v
UpdateCheckMode: Tags
CurrentVersion: 1.2.0
CurrentVersionCode: 12
```

**Build for F-Droid:**
```bash
# Ensure reproducible builds
flutter build apk --release --deterministic

# Test with F-Droid tools
fdroid build --latest
```

### 4. Enterprise Distribution

#### Internal App Sharing

**Google Play Internal Testing:**
```bash
# Upload to internal testing track
# Share testing link with organization
# Supports up to 100 testers
```

**Custom Enterprise Distribution:**
```bash
# Generate enterprise APK
flutter build apk --release

# Host on internal server
# Implement app update mechanism
# Use MDM solutions for deployment
```

---

## 🔄 CI/CD Pipeline

### GitHub Actions Workflow

#### Complete CI/CD Pipeline
```yaml
# .github/workflows/deploy.yml
name: Deploy AndroNet
on:
  push:
    tags:
      - 'v*'
  workflow_dispatch:

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-java@v3
        with:
          java-version: '11'
      - uses: subosito/flutter-action@v2
        with:
          flutter-version: '3.32.8'

      - name: Run tests
        run: |
          flutter pub get
          flutter test
          ./gradlew testDebugUnitTest

      - name: Build APK
        run: flutter build apk --release --split-per-abi

      - name: Build App Bundle
        run: flutter build appbundle --release

      - name: Upload artifacts
        uses: actions/upload-artifact@v3
        with:
          name: andronet-builds
          path: |
            build/app/outputs/flutter-apk/
            build/app/outputs/bundle/release/

  deploy:
    needs: test
    runs-on: ubuntu-latest
    if: startsWith(github.ref, 'refs/tags/v')

    steps:
      - uses: actions/download-artifact@v3
        with:
          name: andronet-builds

      - name: Create GitHub Release
        uses: softprops/action-gh-release@v1
        with:
          files: |
            app-*-release.apk
            app-release.aab
          generate_release_notes: true
          draft: false
          prerelease: ${{ contains(github.ref, 'beta') || contains(github.ref, 'alpha') }}

      - name: Deploy to Play Store
        if: github.event_name == 'push' && !contains(github.ref, 'beta') && !contains(github.ref, 'alpha')
        uses: google-github-actions/release-please-action@v3
        with:
          command: github-release
```

### Automated Deployment Features

#### Version Management
```kotlin
// Version management in build.gradle
def versionMajor = 1
def versionMinor = 2
def versionPatch = 0

android {
    defaultConfig {
        versionCode versionMajor * 10000 + versionMinor * 100 + versionPatch
        versionName "${versionMajor}.${versionMinor}.${versionPatch}"
    }
}
```

#### Release Notes Generation
```yaml
# Generate release notes from commits
name: Generate Release Notes
on:
  push:
    tags:
      - 'v*'

jobs:
  release-notes:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
        with:
          fetch-depth: 0

      - name: Generate changelog
        run: |
          git log --oneline --pretty=format:"- %s" $(git describe --tags --abbrev=0 HEAD^)..HEAD > RELEASE_NOTES.md

      - uses: softprops/action-gh-release@v1
        with:
          body_path: RELEASE_NOTES.md
          append_body: true
```

---

## 🧪 Staging & Testing

### Staging Environment Setup

#### Internal Testing Track (Play Store)
```bash
# Upload to internal testing first
# Test with internal users
# Gather feedback before production
```

#### Beta Testing
```bash
# Create beta release
# Distribute to beta testers via Play Store
# Collect crash reports and feedback
```

### Automated Testing in Staging

#### Integration Tests
```yaml
# Test app functionality after deployment
name: Staging Tests
on:
  deployment_status:

jobs:
  test-staging:
    runs-on: ubuntu-latest
    steps:
      - name: Install app on test device
        run: |
          adb install staging/app-release.apk

      - name: Run integration tests
        run: |
          flutter test integration_test/ -d <test_device_id>

      - name: Performance tests
        run: |
          # Monitor app performance in staging
          # Check memory usage, battery impact
```

---

## 📊 Monitoring & Analytics

### Crash Reporting

#### Firebase Crashlytics Setup

**1. Add Firebase Configuration:**
```kotlin
// android/app/build.gradle
dependencies {
    implementation 'com.google.firebase:firebase-crashlytics:18.3.7'
    implementation 'com.google.firebase:firebase-analytics:21.3.0'
}
```

**2. Initialize in MainActivity:**
```kotlin
class MainActivity : FlutterActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        FirebaseApp.initializeApp(this)
    }
}
```

**3. Add Crash Reporting:**
```kotlin
// Report unhandled exceptions
FirebaseCrashlytics.getInstance().recordException(exception)
```

### Performance Monitoring

#### Firebase Performance Monitoring
```kotlin
// Monitor custom traces
val trace = FirebasePerformance.getInstance().newTrace("packet_analysis")
trace.start()

// ... packet analysis code ...

trace.stop()
```

#### Custom Analytics Events
```kotlin
// Track user interactions
FirebaseAnalytics.getInstance(this).logEvent("packet_capture_started") {
    param("mode", captureMode)
    param("duration", captureDuration)
}
```

### Health Monitoring

#### App Health Metrics
- Crash-free users percentage
- ANR (Application Not Responding) rate
- Slow rendering frames
- Frozen frames
- Memory usage trends

#### Business Metrics
- Daily active users
- Session duration
- Feature usage statistics
- Error rates by feature

---

## 🔒 Security & Compliance

### App Security

#### Code Obfuscation
```kotlin
// ProGuard rules for release builds
buildTypes {
    release {
        minifyEnabled true
        proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
    }
}
```

**ProGuard Rules (proguard-rules.pro):**
```
# Keep Flutter wrapper
-keep class io.flutter.app.** { *; }
-keep class io.flutter.plugin.** { *; }
-keep class io.flutter.util.** { *; }
-keep class io.flutter.view.** { *; }

# Keep VPN service
-keep class com.example.packet_analyzer.CompleteVpnService { *; }

# Keep packet analysis classes
-keep class com.example.packet_analyzer.** { *; }
```

#### Runtime Security
```kotlin
// Runtime integrity checks
class SecurityManager {
    fun verifyAppIntegrity(): Boolean {
        // Check package signature
        // Verify critical files
        // Detect rooting (if needed)
        return true
    }
}
```

### Compliance

#### Privacy Compliance
- [ ] GDPR compliance for EU users
- [ ] CCPA compliance for California users
- [ ] Privacy policy accessible in app
- [ ] Data collection transparency

#### Security Compliance
- [ ] OWASP Mobile Top 10 compliance
- [ ] Regular security audits
- [ ] Secure coding practices
- [ ] Dependency vulnerability scanning

---

## 🚨 Rollback Procedures

### Emergency Rollback

#### Immediate Rollback
```bash
# Disable current version in Play Console
# Halt rollout if in staged release
# Promote previous stable version
```

#### Database Rollback (if applicable)
```kotlin
// Rollback user preferences/settings if needed
// Restore previous app configuration
```

### Post-Mortem Analysis

#### Rollback Checklist
- [ ] Identify root cause of issues
- [ ] Document fix implementation
- [ ] Test fix thoroughly in staging
- [ ] Deploy fix with monitoring
- [ ] Update deployment procedures

---

## 📚 Deployment Checklist

### Pre-Deployment
- [ ] All tests passing (unit, integration, performance)
- [ ] Code review completed
- [ ] Security audit passed
- [ ] Performance benchmarks met
- [ ] Documentation updated

### Deployment Day
- [ ] Build artifacts generated and tested
- [ ] Release notes prepared
- [ ] Monitoring and alerting configured
- [ ] Rollback plan ready
- [ ] Team notified of deployment

### Post-Deployment
- [ ] Monitor crash reports and user feedback
- [ ] Verify all features working correctly
- [ ] Performance metrics within acceptable ranges
- [ ] User adoption and satisfaction tracked

---

## 🔧 Environment-Specific Configuration

### Development Environment
```kotlin
// Development configuration
buildTypes {
    debug {
        buildConfigField "String", "API_ENDPOINT", "\"https://dev-api.andronet.example.com\""
        buildConfigField "boolean", "ENABLE_ANALYTICS", "false"
        buildConfigField "boolean", "ENABLE_CRASH_REPORTING", "false"
    }
}
```

### Staging Environment
```kotlin
// Staging configuration
buildTypes {
    release {
        buildConfigField "String", "API_ENDPOINT", "\"https://staging-api.andronet.example.com\""
        buildConfigField "boolean", "ENABLE_ANALYTICS", "true"
        buildConfigField "boolean", "ENABLE_CRASH_REPORTING", "true"
        signingConfig signingConfigs.release
    }
}
```

### Production Environment
```kotlin
// Production configuration
buildTypes {
    release {
        buildConfigField "String", "API_ENDPOINT", "\"https://api.andronet.example.com\""
        buildConfigField "boolean", "ENABLE_ANALYTICS", "true"
        buildConfigField "boolean", "ENABLE_CRASH_REPORTING", "true"
        minifyEnabled true
        zipAlignEnabled true
    }
}
```

---

## 🎯 Deployment Best Practices

### Release Strategy
1. **Semantic Versioning**: Use MAJOR.MINOR.PATCH format
2. **Staged Rollouts**: 10% → 25% → 50% → 100% user rollout
3. **Feature Flags**: Enable/disable features remotely
4. **Rollback Plan**: Always have a rollback strategy

### Quality Assurance
1. **Automated Testing**: Comprehensive test suite
2. **Manual Testing**: Real device testing across scenarios
3. **Performance Testing**: Load testing before release
4. **Security Testing**: Vulnerability assessment

### Monitoring & Alerting
1. **Real-time Monitoring**: Crash reports, performance metrics
2. **User Feedback**: App store reviews, in-app feedback
3. **Error Tracking**: Detailed error logging and analysis
4. **Performance Alerts**: Automated alerts for issues

### Documentation Updates
1. **Release Notes**: Detailed feature descriptions
2. **User Documentation**: Updated guides and tutorials
3. **Developer Documentation**: API changes and migration guides
4. **Changelog**: Complete version history

---

## 📞 Support & Communication

### User Communication
- **Release Announcements**: Blog posts, social media, email newsletters
- **In-App Updates**: Feature highlights and changelog
- **Support Channels**: Help center, community forums, email support

### Developer Communication
- **Internal Documentation**: Updated deployment guides
- **Team Notifications**: Slack/Discord channels for deployment status
- **Incident Response**: Clear communication during issues

---

## 🚀 Quick Deployment Commands

### Development
```bash
flutter build apk --debug
flutter install
```

### Staging
```bash
flutter build apk --release
# Upload to internal testing track
```

### Production
```bash
flutter build appbundle --release
# Upload to production track
```

### Emergency
```bash
# Rollback to previous version
# Disable problematic release
# Enable previous stable version
```

---

*Happy deploying! 🚀*
