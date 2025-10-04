# Contributing to AndroNet

<p align="center">
  <strong>A mobile network packet analyzer for Kali NetHunter</strong>
</p>

Thank you for your interest in contributing to AndroNet! This document provides guidelines for contributing to the project.

## 📋 Table of Contents

- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Issue Reporting](#issue-reporting)
- [Feature Requests](#feature-requests)
- [Security Issues](#security-issues)

## 🚀 Getting Started

### Prerequisites

- **Flutter SDK** 3.0+
- **Android Studio** with NDK
- **Java 17+** (for Android development)
- **Git** and **GitHub** account
- **Kali NetHunter** (optional, for testing libpcap mode)

### Repository Setup

1. **Fork** the repository on GitHub
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/AndroNet.git
   cd AndroNet
   ```
3. **Add** upstream remote:
   ```bash
   git remote add upstream https://github.com/iritikrajput/AndroNet.git
   ```

### Development Branches

- **`main`**: Production-ready code (stable releases)
- **`development`**: Active development (latest features)
- **Feature branches**: `feature/feature-name` for new features
- **Bug fix branches**: `fix/issue-description` for bug fixes

## 🛠️ Development Setup

### Environment Setup

1. **Install dependencies:**
   ```bash
   flutter pub get
   ```

2. **Initialize submodules:**
   ```bash
   git submodule update --init --recursive
   ```

3. **Android Setup:**
   ```bash
   # Ensure Java 17+ is configured in android/gradle.properties
   # org.gradle.java.home=/usr/lib/jvm/java-17-openjdk-amd64
   cd android && ./gradlew build
   ```

### IDE Configuration

#### Android Studio
- Install **Flutter** and **Dart** plugins
- Configure **Android NDK** for native code development
- Set **Java 17+** as the project JDK

#### VS Code
```json
{
  "java.configuration.runtimes": [
    {
      "name": "JavaSE-17",
      "path": "/usr/lib/jvm/java-17-openjdk-amd64"
    }
  ]
}
```

### Building and Running

```bash
# Debug build
flutter build apk --debug

# Release build
flutter build apk --release

# Run on connected device
flutter run

# Run tests
flutter test
```

## 📝 Coding Standards

### General Guidelines

- **Follow Dart/Flutter best practices**
- **Write self-documenting code** with clear variable and method names
- **Keep functions small** and focused on single responsibilities
- **Use meaningful commit messages** following [Conventional Commits](https://conventionalcommits.org/)

### Commit Message Format

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

**Examples:**
```
feat: Add QUIC protocol support to DPI
fix: Resolve memory leak in packet processing
docs: Update API documentation for anomaly detection
test: Add unit tests for PayloadAnalyzer
```

### Code Style

#### Dart/Flutter
- Use **`dart format`** for consistent formatting
- Follow **effective Dart** guidelines
- Use **`const`** constructors where possible
- Prefer **`final`** over `var` when possible

#### Kotlin (Android Native)
- Follow **Kotlin coding conventions**
- Use **coroutines** for async operations
- Handle **null safety** explicitly
- Use **meaningful package names**

#### Documentation
- **Document public APIs** with triple-slash comments (`///`)
- **Include examples** in documentation
- **Update README.md** for significant changes

## 🧪 Testing Guidelines

### Testing Structure

```
test/
├── unit/           # Unit tests
├── integration/    # Integration tests
└── widget/         # Widget tests (Flutter)
```

### Writing Tests

#### Unit Tests
```dart
void main() {
  group('PacketDissector', () {
    test('should parse HTTP packets correctly', () {
      // Test implementation
    });
  });
}
```

#### Integration Tests
```dart
void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('end-to-end test', () {
    testWidgets('should capture and analyze packets', (tester) async {
      // Integration test implementation
    });
  });
}
```

### Running Tests

```bash
# Run all tests
flutter test

# Run with coverage
flutter test --coverage

# Run integration tests
flutter test integration_test/

# Run on specific file
flutter test test/unit/packet_analyzer_test.dart
```

## 🔄 Pull Request Process

### Before Submitting

1. **Create a feature branch** from `development`:
   ```bash
   git checkout development
   git pull upstream development
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following coding standards

3. **Add tests** for new functionality

4. **Update documentation** if needed

5. **Test thoroughly**:
   ```bash
   flutter analyze    # Static analysis
   flutter test       # Run tests
   flutter build apk  # Ensure builds successfully
   ```

### Submitting a PR

1. **Push your branch**:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create Pull Request** on GitHub:
   - **Base branch**: `development` (not `main`)
   - **Title**: Clear, descriptive title
   - **Description**: Explain what changes were made and why

3. **Fill out PR template** (will be provided)

4. **Address review feedback** promptly

5. **Ensure CI/CD passes** (GitHub Actions)

### PR Approval Process

- **Automated checks** must pass
- **At least one maintainer** approval required
- **Tests** must be included for new features
- **Documentation** updated if needed

## 🐛 Issue Reporting

### Bug Reports

**Before reporting:**
- Check if issue already exists
- Try the latest `development` branch
- Include **complete reproduction steps**

**Good Bug Report:**
```markdown
## Description
Brief description of the bug

## Steps to Reproduce
1. Step one
2. Step two
3. Expected vs actual behavior

## Environment
- Device: [e.g., Pixel 5]
- OS: [e.g., Android 12]
- AndroNet Version: [e.g., 1.0.0]
- Branch: [e.g., development]

## Logs
[Include relevant logs]
```

### Enhancement Requests

**Good Feature Request:**
```markdown
## Problem
Describe the problem this feature would solve

## Proposed Solution
Describe your proposed solution

## Alternatives Considered
Other solutions you've considered

## Additional Context
Any additional information
```

## ✨ Feature Requests

### Submitting Feature Requests

1. **Check existing issues** for similar requests
2. **Use the feature request template**
3. **Provide clear use cases**
4. **Consider implementation complexity**

### Feature Request Template

```markdown
## Feature Description
Clear description of the proposed feature

## Use Cases
- Primary use case
- Secondary use cases

## Implementation Ideas
How you think this could be implemented

## Alternatives
Alternative solutions if this isn't feasible

## Priority
- High/Medium/Low priority justification
```

## 🔒 Security Issues

### Reporting Security Vulnerabilities

**DO NOT** create public issues for security vulnerabilities.

**Instead:**
1. Email: [security contact]
2. **Do not disclose** the vulnerability publicly until fixed
3. **Provide detailed reproduction steps**
4. **Allow reasonable time** for fix before disclosure

### Security Guidelines

- **Validate all inputs** thoroughly
- **Use HTTPS** for all network communications
- **Store sensitive data securely**
- **Follow principle of least privilege**
- **Keep dependencies updated**

## 📞 Getting Help

### Communication Channels

- **GitHub Issues**: For bugs and feature requests
- **GitHub Discussions**: For questions and discussions
- **Email**: For private communications

### Development Support

- **Check existing documentation** first
- **Search closed issues** for similar problems
- **Ask questions** in GitHub Discussions
- **Provide complete context** when asking for help

## 🎉 Recognition

Contributors who make significant improvements will be:
- **Listed in README.md**
- **Mentioned in release notes**
- **Granted commit access** (after consistent contributions)

---

<p align="center">
  <strong>Thank you for contributing to AndroNet! 🚀</strong>
</p>
