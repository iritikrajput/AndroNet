# Testing Signature and Rule-Based Detection

## Prerequisites

1. **Device Authorization Required**
   - Connect your Android device via USB
   - Enable USB debugging in Developer Options
   - When prompted on device, tap "Allow" for USB debugging authorization
   - Verify authorization: `adb devices` should show device as "device" not "unauthorized"

2. **Install APK**
   ```bash
   cd andronet
   adb install -r "build\app\outputs\flutter-apk\app-debug.apk"
   ```

## Testing Overview

The AndroNet app now includes three layers of anomaly detection:
1. **Layer 1: Statistical Detection** - Port scans, SYN floods, connection floods, DNS tunneling, ARP spoofing
2. **Layer 2: Signature-Based Detection** - 18 attack signatures across 8 categories
3. **Layer 3: Rule-Based Detection** - 10 complex multi-condition rules

## Real-Time Monitoring

Start monitoring logs before launching the app:

```bash
# Monitor all anomaly detection components
adb logcat -s AnomalyDetector:D SignatureDatabase:D RuleEngine:D PacketAnalysisManager:D

# Or monitor everything with color
adb logcat -v color '*:D'

# Save logs to file
adb logcat -s AnomalyDetector:D SignatureDatabase:D RuleEngine:D > detection_test.log
```

Expected startup messages:
```
SignatureDatabase: Loaded 18 signatures
RuleEngine: Loaded 10 detection rules
AnomalyDetector: Initialization complete
```

## Test Cases

### Test 1: Basic Functionality
**Goal:** Verify packet capture and processing works

1. Launch AndroNet app
2. Tap "Start Capture"
3. Open Chrome and visit `https://www.google.com`
4. Stop capture after 10 seconds

**Expected Results:**
- Packets appear in real-time
- Domain names show "Google" with globe icon
- No false positives in logs

**Log Check:**
```bash
adb logcat -s PacketAnalysisManager:D | grep "Packet processed"
```

---

### Test 2: Port Scan Detection (Statistical)
**Goal:** Trigger port scan anomaly

**Method 1: Using nmap (if available on another device)**
```bash
# From another device on same network, scan your phone's IP
nmap -p 1-100 <phone_ip>
```

**Method 2: Simulate by visiting multiple services**
- Visit different websites on various ports
- Open multiple apps that connect to different services

**Expected Log:**
```
AnomalyDetector: 🚨 Anomaly detected: Port scan detected from <ip>
```

---

### Test 3: Signature Detection - User-Agent Patterns
**Goal:** Test signature matching on User-Agent headers

**Signatures that can be tested:**
- **RECON-001:** Nmap Scanner
- **RECON-002:** Nikto Scanner
- **RECON-003:** SQLMap Scanner
- **NET-002:** Shellshock exploit

**Method:** These require custom HTTP requests (difficult to test on Android without tools)

**Expected Log Format:**
```
AnomalyDetector: 🚨 Anomaly detected: [RECON-001] Nmap Scan: Nmap network scanner detected
SignatureDatabase: Signature match: RECON-001
```

---

### Test 4: Rule Detection - SQL Injection (RULE-002)
**Goal:** Test rule-based detection for SQL injection patterns

**Conditions:**
- Protocol = HTTP
- Destination port = 80 or 443
- URL or payload contains SQL keywords: `UNION SELECT`, `' OR '1'='1`, `DROP TABLE`, etc.

**Method:** Visit a test site with SQL injection in URL
```
http://testphp.vulnweb.com/artists.php?artist=1' OR '1'='1
```

**Expected Log:**
```
RuleEngine: Rule matched: RULE-002 - SQL Injection Attempt
AnomalyDetector: 🚨 Anomaly detected: [RULE-002] SQL Injection Attempt
```

---

### Test 5: Rule Detection - Advanced Port Scan (RULE-001)
**Goal:** Test advanced port scanning rule

**Conditions:**
- Protocol = TCP
- SYN flag set
- 15+ unique destination IPs in 60 seconds

**Method:**
- Rapidly open many different websites/apps
- Use browser to open 20+ different sites quickly

**Expected Log:**
```
RuleEngine: Rule matched: RULE-001 - Advanced Port Scan
AnomalyDetector: 🚨 Anomaly detected: [RULE-001] Advanced Port Scan: Multiple unique destinations with SYN scanning pattern
```

---

### Test 6: Rule Detection - DNS Tunneling (RULE-004)
**Goal:** Test DNS tunneling detection

**Conditions:**
- Protocol = UDP
- Destination port = 53
- Payload size > 100 bytes OR DNS query rate > 10/sec

**Method:**
- Visit sites with long domain names
- Rapidly switch between multiple sites (generates DNS queries)

**Expected Log:**
```
RuleEngine: Rule matched: RULE-004 - DNS Tunneling
AnomalyDetector: 🚨 Anomaly detected: [RULE-004] DNS Tunneling: Suspicious DNS activity detected
```

---

### Test 7: Signature Detection - Known Malicious Domain (C2-002)
**Goal:** Test domain blacklist matching

**Malicious domains in database:**
- malware-test.com
- evil-command-control.net
- phishing-site.org
- ransomware-c2.com

**Method:** Try to resolve these domains (they're fake test domains)
```bash
# From device terminal or another device
nslookup malware-test.com
```

**Expected Log:**
```
SignatureDatabase: Signature match: C2-002 - Known C&C Domain
AnomalyDetector: 🚨 Anomaly detected: [C2-002] Known C&C Domain: Connection to known command and control server
```

---

### Test 8: Rule Detection - Cryptomining (RULE-006)
**Goal:** Test cryptomining detection

**Conditions:**
- Protocol = TCP
- Destination port = 3333, 4444, or 5555
- Payload contains "stratum"

**Method:** This requires actual mining traffic (very difficult to test safely)

**Expected Log:**
```
RuleEngine: Rule matched: RULE-006 - Cryptomining Activity
AnomalyDetector: 🚨 Anomaly detected: [RULE-006] Cryptomining Activity: Cryptocurrency mining detected
```

---

### Test 9: Signature Detection - Exploit Ports (BRUTE-001, BRUTE-002)
**Goal:** Test suspicious port detection

**Signatures:**
- **BRUTE-001:** SSH (port 22)
- **BRUTE-002:** RDP (port 3389)
- **Port patterns:** 1337, 4444, 5555, 6666, 6667, 31337

**Method:**
- Connect to SSH server (if available)
- Visit site running on suspicious ports

**Expected Log:**
```
SignatureDatabase: Signature match: BRUTE-001 - SSH Brute Force
AnomalyDetector: 🚨 Anomaly detected: [BRUTE-001] SSH Brute Force: Possible SSH brute force attack
```

---

### Test 10: Statistical Detection - Connection Flood
**Goal:** Test high connection rate detection

**Threshold:** 50 connections/second from single IP

**Method:**
- Rapidly scroll through social media feeds (Instagram, Twitter)
- Watch YouTube videos (generates many connections)
- Use apps that make frequent API calls

**Expected Log:**
```
AnomalyDetector: 🚨 Anomaly detected: Connection flood detected
```

---

## Understanding Log Output

### Signature Match Format
```
I/SignatureDatabase: Loaded 18 signatures
D/SignatureDatabase: Checking packet against signatures...
W/AnomalyDetector: 🚨 Anomaly detected: [MAL-001] Metasploit Meterpreter: Metasploit Meterpreter payload detected
```

### Rule Match Format
```
I/RuleEngine: Loaded 10 detection rules
D/RuleEngine: Evaluating 10 rules for packet...
D/RuleEngine: Rule RULE-001 condition match: ProtocolEquals
D/RuleEngine: Rule RULE-001 condition match: UniqueDestinations
W/AnomalyDetector: 🚨 Anomaly detected: [RULE-001] Advanced Port Scan: Multiple unique destinations
```

### Statistical Detection Format
```
W/AnomalyDetector: 🚨 Anomaly detected: Port scan detected from 192.168.1.100
W/AnomalyDetector: 🚨 Anomaly detected: Possible SYN flood
W/AnomalyDetector: 🚨 Anomaly detected: Connection flood detected
```

---

## Signature Database Content

### 18 Signatures Loaded:

**MALWARE (3):**
- MAL-001: Metasploit Meterpreter
- MAL-002: WannaCry Ransomware
- MAL-003: Cobalt Strike Beacon

**EXPLOITS (4):**
- EXP-001: SQL Injection
- EXP-002: Directory Traversal
- EXP-003: Remote Code Execution
- EXP-004: XXE Attack

**RECONNAISSANCE (3):**
- RECON-001: Nmap Scanner
- RECON-002: Nikto Scanner
- RECON-003: SQLMap Scanner

**COMMAND & CONTROL (3):**
- C2-001: TOR Network
- C2-002: Known C&C Domain
- C2-003: IRC Bot

**DATA EXFILTRATION (1):**
- EXFIL-001: Base64 Exfiltration

**BRUTE FORCE (2):**
- BRUTE-001: SSH Brute Force
- BRUTE-002: RDP Brute Force

**NETWORK ATTACKS (2):**
- NET-001: EternalBlue Exploit
- NET-002: Shellshock

---

## Rule Engine Content

### 10 Rules Loaded:

1. **RULE-001:** Advanced Port Scan (TCP + 15+ destinations + SYN flags)
2. **RULE-002:** SQL Injection (HTTP + SQL keywords in URL/payload)
3. **RULE-003:** Malicious File Download (.exe, .scr, .bat extensions)
4. **RULE-004:** DNS Tunneling (UDP port 53 + large payload or high rate)
5. **RULE-005:** Brute Force (SSH/RDP/FTP + 20+ attempts in 60s)
6. **RULE-006:** Cryptomining (TCP ports 3333/4444/5555 + "stratum")
7. **RULE-007:** Suspicious Outbound Traffic (non-standard ports + large uploads)
8. **RULE-008:** Shellcode Pattern (executable patterns in payload)
9. **RULE-009:** Suspicious User-Agent (curl, wget, python)
10. **RULE-010:** ICMP Tunneling (large ICMP payloads > 64 bytes)

---

## Performance Monitoring

### Check Detection Performance
```bash
# Monitor packet processing rate
adb logcat -s PacketAnalysisManager:D | grep "Packet processed"

# Check signature matching time
adb logcat -s SignatureDatabase:D

# Check rule evaluation time
adb logcat -s RuleEngine:D

# Monitor memory usage
adb shell dumpsys meminfo com.example.packet_analyzer
```

### Expected Performance:
- Signature matching: < 5ms per packet
- Rule evaluation: < 10ms per packet
- Total overhead: < 15ms per packet
- Memory impact: ~10-20MB additional

---

## Troubleshooting

### No Signatures Loading
**Symptom:** Log doesn't show "Loaded 18 signatures"

**Check:**
```bash
adb logcat -s SignatureDatabase:E
```

**Solution:** Verify SignatureDatabase.kt compiled correctly

---

### No Rules Loading
**Symptom:** Log doesn't show "Loaded 10 detection rules"

**Check:**
```bash
adb logcat -s RuleEngine:E
```

**Solution:** Verify RuleEngine.kt compiled correctly

---

### No Anomalies Detected
**Symptom:** Traffic flows but no anomalies reported

**Possible Causes:**
1. Traffic is legitimate (expected!)
2. Thresholds too high
3. Detection not integrated properly

**Check Integration:**
```bash
adb logcat -s AnomalyDetector:D | grep "analyzePacket"
```

Should see: "Analyzing packet..." messages

---

### Too Many False Positives
**Symptom:** Every packet triggers anomaly

**Solution:** Adjust thresholds in AnomalyDetector.kt:
```kotlin
private const val PORT_SCAN_THRESHOLD = 20  // Increase if needed
private const val SYN_FLOOD_THRESHOLD = 100
private const val CONNECTION_RATE_THRESHOLD = 50
```

---

## Next Steps After Testing

Once signature/rule detection is verified working:

1. **UI Integration** - Display anomalies in Flutter UI
   - Add anomaly notification channel in MainActivity
   - Create anomaly alert screen in Flutter
   - Show anomaly badges on packets

2. **Persistence** - Save detected anomalies
   - Store in SQLite database
   - Show anomaly history
   - Export anomaly reports

3. **Customization** - Allow user-defined rules
   - UI for creating custom signatures
   - Import/export signature packs
   - Enable/disable specific rules

4. **Threat Intelligence** - Auto-update signatures
   - Download signature updates from server
   - Community-contributed signatures
   - Real-time threat feeds

---

## Quick Test Commands

```bash
# Install and start monitoring in one go
adb install -r "build\app\outputs\flutter-apk\app-debug.apk" && adb logcat -c && adb logcat -s AnomalyDetector:D SignatureDatabase:D RuleEngine:D

# Generate test traffic
adb shell am start -a android.intent.action.VIEW -d "https://www.google.com"
adb shell am start -a android.intent.action.VIEW -d "https://www.facebook.com"
adb shell am start -a android.intent.action.VIEW -d "https://www.youtube.com"

# Check detection statistics
adb logcat -s AnomalyDetector:D | grep "🚨"

# Count anomalies detected
adb logcat -d -s AnomalyDetector:D | grep "🚨" | wc -l
```

---

## Success Criteria

✅ **Minimal Success:**
- App installs and runs without crashes
- Packets captured and displayed
- At least 1 statistical anomaly detected during testing
- Signature database loads (18 signatures)
- Rule engine loads (10 rules)

✅ **Full Success:**
- All 3 detection layers working
- At least 3 different anomaly types detected
- Signature matches logged correctly
- Rule matches logged correctly
- No significant performance degradation
- No false positives on normal traffic

✅ **Excellent:**
- Real-world anomaly detection working
- Multiple signature categories triggered
- Complex rule conditions evaluating correctly
- Performance under 20ms overhead per packet
- Zero false positives on legitimate traffic

---

## Contact and Issues

If you encounter issues:
1. Save full logcat output: `adb logcat -d > full_log.txt`
2. Check for exceptions: `adb logcat -s AndroidRuntime:E`
3. Review packet flow: `adb logcat -s PacketAnalysisManager:D`
4. Check system resources: `adb shell top -n 1`

For questions about specific signatures or rules, see:
- `SIGNATURE_RULE_DETECTION.md` - Complete signature/rule documentation
- `ANOMALY_DETECTION_ARCHITECTURE.md` - Full architecture overview
