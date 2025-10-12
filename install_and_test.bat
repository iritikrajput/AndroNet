@echo off
REM AndroNet - Install and Test Script
REM This script installs the APK and starts monitoring logs

echo ========================================
echo AndroNet - Signature/Rule Detection Test
echo ========================================
echo.

REM Check device connection
echo [1/5] Checking device connection...
adb devices
echo.

REM Ask for confirmation
set /p confirm="Device should show as 'device' (not 'unauthorized'). Continue? (Y/N): "
if /i not "%confirm%"=="Y" (
    echo Installation cancelled.
    pause
    exit /b
)
echo.

REM Install APK
echo [2/5] Installing APK...
adb install -r "build\app\outputs\flutter-apk\app-debug.apk"
if %errorlevel% neq 0 (
    echo ERROR: Installation failed!
    pause
    exit /b 1
)
echo.

REM Clear old logs
echo [3/5] Clearing old logs...
adb logcat -c
echo.

REM Start app
echo [4/5] Launching AndroNet...
adb shell am start -n com.example.packet_analyzer/.MainActivity
timeout /t 3 /nobreak > nul
echo.

REM Start monitoring
echo [5/5] Starting log monitoring...
echo.
echo ========================================
echo Monitoring AndroNet Detection Logs
echo ========================================
echo.
echo Look for these messages:
echo   - "Loaded 18 signatures"
echo   - "Loaded 10 detection rules"
echo   - "🚨 Anomaly detected:"
echo.
echo Press Ctrl+C to stop monitoring
echo ========================================
echo.

adb logcat -s AnomalyDetector:D SignatureDatabase:D RuleEngine:D PacketAnalysisManager:I

pause
