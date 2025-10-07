# Remove debug logs from main.dart
$file = "lib\main.dart"
$content = Get-Content $file -Raw

# Remove specific debug log blocks
$content = $content -replace '(?m)^\s*print\("🚀 Flutter flushing.*?\r?\n', ''
$content = $content -replace '(?m)^\s*// Debug: Check if DPI data is in the map\r?\n', ''
$content = $content -replace '(?m)^\s*if \(m\.containsKey\(''httpData''\).*?\r?\n\s*print\("🔍 DPI DATA FOUND.*?\r?\n\s*print\("🔍 httpData:.*?\r?\n\s*print\("🔍 dnsData:.*?\r?\n\s*print\("🔍 tlsData:.*?\r?\n\s*\}\r?\n', ''
$content = $content -replace '(?m)^\s*// Debug: Check payload data\r?\n', ''
$content = $content -replace '(?m)^\s*print\("📦 Payload in map:.*?\r?\n', ''
$content = $content -replace '(?m)^\s*print\("📦 PayloadHex in map:.*?\r?\n', ''
$content = $content -replace '(?m)^\s*print\("📦 PayloadSize in map:.*?\r?\n', ''
$content = $content -replace '(?m)^\s*print\("✅ Created PacketInfo:.*?\r?\n', ''
$content = $content -replace '(?m)^\s*// Debug: Check if DPI data made it to PacketInfo\r?\n', ''
$content = $content -replace '(?m)^\s*if \(packet\.httpData != null.*?\r?\n\s*print\("🎉 DPI DATA IN PACKET.*?\r?\n\s*print\("🎉 httpData:.*?\r?\n\s*print\("🎉 dnsData:.*?\r?\n\s*print\("🎉 tlsData:.*?\r?\n\s*\}\r?\n', ''
$content = $content -replace '(?m)^\s*print\("❌ Problematic map:.*?\r?\n', ''

# Also remove excessive blank lines
$content = $content -replace '(?m)^\s*\r?\n\s*\r?\n\s*\r?\n', "`r`n`r`n"

Set-Content $file -Value $content -NoNewline

Write-Host "✅ Removed debug logs from main.dart"
