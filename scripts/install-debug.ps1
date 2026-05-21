# install-debug.ps1 — Build (debug) and install AndroNet on a connected device.
# Usage: .\scripts\install-debug.ps1
# Prerequisites: adb in PATH, Android SDK set up, connected device with USB debugging on.

param(
    [string]$Device = ""   # Optional: pass -Device <serial> to target a specific device
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot

Set-Location $Root

Write-Host "=== AndroNet debug install ===" -ForegroundColor Cyan

# Confirm at least one device is reachable
$adbArgs = if ($Device) { @("-s", $Device) } else { @() }
$devices = & adb $adbArgs devices 2>&1
if ($devices -notmatch "device$") {
    Write-Error "No Android device found. Connect a device with USB debugging enabled."
}

# Build the debug APK via Flutter
Write-Host "> flutter build apk --debug" -ForegroundColor Yellow
& flutter build apk --debug
if ($LASTEXITCODE -ne 0) { Write-Error "flutter build apk failed." }

$Apk = Join-Path $Root "build\app\outputs\flutter-apk\app-debug.apk"
if (-not (Test-Path $Apk)) {
    Write-Error "APK not found at: $Apk"
}

# Install (replace existing install)
Write-Host "> adb install -r $Apk" -ForegroundColor Yellow
& adb $adbArgs install -r $Apk
if ($LASTEXITCODE -ne 0) { Write-Error "adb install failed." }

Write-Host "=== Install complete ===" -ForegroundColor Green

# Launch the app
Write-Host "> Launching com.example.packet_analyzer..." -ForegroundColor Yellow
& adb $adbArgs shell am start -n "com.example.packet_analyzer/.MainActivity"
