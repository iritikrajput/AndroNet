# get-crash-log.ps1 — Pull the last AndroNet crash log from a connected device.
# Usage: .\scripts\get-crash-log.ps1
# The output is saved to crash-log-<timestamp>.txt in the project root.

param(
    [string]$Device = "",        # Optional: -Device <serial>
    [int]$Lines    = 500,        # How many logcat lines to capture
    [switch]$Live               # Stream live instead of dumping last session
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$adbArgs = if ($Device) { @("-s", $Device) } else { @() }
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$OutFile = Join-Path $Root "crash-log-$Timestamp.txt"

Write-Host "=== AndroNet crash log ===" -ForegroundColor Cyan

if ($Live) {
    Write-Host "Streaming live logcat — Ctrl+C to stop." -ForegroundColor Yellow
    & adb $adbArgs logcat -v time *:W `
        | Select-String -Pattern "packet_analyzer|AndroNet|ANDRONET|ZdtunVpn|CaptureService|NetHunterService|Fatal|FATAL|crash|ANR"
} else {
    Write-Host "Dumping last $Lines lines from logcat..." -ForegroundColor Yellow
    $log = & adb $adbArgs logcat -d -v time -t $Lines *:W 2>&1
    $filtered = $log | Select-String -Pattern "packet_analyzer|AndroNet|ANDRONET|ZdtunVpn|CaptureService|NetHunterService|Fatal|FATAL|crash|ANR|AndroidRuntime|System.err"
    $filtered | Out-File -FilePath $OutFile -Encoding utf8
    Write-Host "Saved to: $OutFile" -ForegroundColor Green
    Write-Host "--- Preview (last 40 matching lines) ---" -ForegroundColor DarkGray
    $filtered | Select-Object -Last 40 | ForEach-Object { Write-Host $_ }
}
