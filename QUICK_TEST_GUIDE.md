# Quick Testing Guide - AndroNet Signature/Rule Detection

## Prerequisites - MUST DO FIRST!

### 1. Authorize USB Debugging

**Current Issue:** Your device shows as "unauthorized"

**Fix:**
1. **Look at your phone screen** - There should be a popup dialog
2. The dialog says: "Allow USB debugging?"
3. **Tap "Allow"**
4. (Optional) Check "Always allow from this computer"

**Verify it worked:**
```bash
adb devices
```

Should show:
```
List of devices attached
GA7L555TMBFELZVC    device    ← Should say "device" NOT "unauthorized"
```

If still showing "unauthorized":
- Unplug and replug USB cable
- Try a different USB port
- Disable and re-enable Developer Options on phone
- Run: `adb kill-server && adb start-server`

---

## Step 2: Install AndroNet

### Option A: Automated Install (Easiest)

Just double-click this file:
```
install_and_test.bat
```

This will:
- Check device connection
- Install the APK
- Launch the app
- Start monitoring logs automatically

### Option B: Manual Install

```bash
cd C:\Users\ritik\Downloads\AppDev\APP\andronet
adb install -r "build\app\outputs\flutter-apk\app-debug.apk"
```

---

## Step 3: Start Monitoring Logs

**Open a new terminal/command prompt** and run:

```bash
cd C:\Users\ritik\Downloads\AppDev\APP\andronet
adb logcat -s AnomalyDetector:D SignatureDatabase:D RuleEngine:D
```

**Expected startup messages:**
```
I/SignatureDatabase: Loaded 18 signatures
I/RuleEngine: Loaded 10 detection rules
I/AnomalyDetector: Initialization complete
```

If you see these messages, the detection system is working! ✅

---

## Step 4: Test Detection Systems

### Test 1: Basic Packet Capture (2 minutes)

**Do this:**
1. Open AndroNet app
2. Tap "Start Capture" button
3. Open Chrome browser on phone
4. Visit: `https://www.google.com`
5. Wait 10 seconds
6. Stop capture

**What to check:**
- ✅ Packets appear in app
- ✅ Domain shows "Google" with globe icon
- ✅ No errors in logcat

**Log command:**
```bash
adb logcat -s PacketAnalysisManager:D | grep "Packet processed"
```

---

### Test 2: Port Scan Detection (3 minutes)

**Do this:**
1. Start packet capture in AndroNet
2. Quickly open 10+ different apps/websites:
   - Chrome → google.com
   - Chrome → facebook.com
   - Chrome → youtube.com
   - Chrome → twitter.com
   - Open Instagram app
   - Open WhatsApp
   - Open Telegram
   - Open Gmail
   - Open Maps
   - etc.
3. Do this rapidly (within 30 seconds)

**Expected result:**
```
W/AnomalyDetector: 🚨 Anomaly detected: Port scan detected
```
OR
```
W/AnomalyDetector: 🚨 Anomaly detected: [RULE-001] Advanced Port Scan
```

**Why this works:** Opening many apps quickly creates connections to multiple different IPs, triggering port scan detection.

---

### Test 3: DNS Tunneling Detection (2 minutes)

**Do this:**
1. Start packet capture
2. In Chrome, rapidly visit 20+ different websites one after another:
   - google.com
   - facebook.com
   - youtube.com
   - amazon.com
   - netflix.com
   - twitter.com
   - instagram.com
   - reddit.com
   - wikipedia.org
   - github.com
   - stackoverflow.com
   - linkedin.com
   - etc. (keep going fast!)

3. Try to visit them as fast as possible (generates many DNS queries)

**Expected result:**
```
W/AnomalyDetector: 🚨 Anomaly detected: Possible DNS tunneling detected
```
OR
```
W/RuleEngine: Rule matched: RULE-004 - DNS Tunneling
W/AnomalyDetector: 🚨 Anomaly detected: [RULE-004] DNS Tunneling
```

**Why this works:** Rapid DNS queries trigger the DNS tunneling detection rule.

---

### Test 4: SQL Injection Detection (Advanced - 5 minutes)

**Do this:**
1. Start packet capture
2. Open Chrome on your phone
3. Visit this test URL (safe vulnerability testing site):
```
http://testphp.vulnweb.com/artists.php?artist=1' OR '1'='1
```

**Expected result:**
```
W/RuleEngine: Rule matched: RULE-002 - SQL Injection Attempt
W/AnomalyDetector: 🚨 Anomaly detected: [RULE-002] SQL Injection Attempt
```

**Alternative test URLs:**
```
http://testphp.vulnweb.com/listproducts.php?cat=1 UNION SELECT null,null,null
http://testphp.vulnweb.com/artists.php?artist=1'; DROP TABLE users--
```

**Why this works:** The URL contains SQL injection keywords that trigger RULE-002.

---

### Test 5: Suspicious User-Agent Detection (Advanced)

**Do this:**
1. Start packet capture
2. You need to make an HTTP request with curl/wget/python User-Agent

**If you have ADB shell access:**
```bash
adb shell
# On device shell:
curl http://example.com
```

**Expected result:**
```
W/RuleEngine: Rule matched: RULE-009 - Suspicious User-Agent
W/AnomalyDetector: 🚨 Anomaly detected: [RULE-009] Suspicious User-Agent
```

**Why this works:** curl/wget/python User-Agents are considered suspicious.

---

### Test 6: High Connection Rate (Easy - 3 minutes)

**Do this:**
1. Start packet capture
2. Open Instagram or Twitter app
3. Rapidly scroll through your feed as fast as possible
4. Keep scrolling for 30 seconds non-stop

**Expected result:**
```
W/AnomalyDetector: 🚨 Anomaly detected: Connection flood detected
```

**Why this works:** Social media apps make many rapid API calls when scrolling, triggering connection flood detection.

---

## Viewing Detection Results

### Real-Time Monitoring

**Best command for testing:**
```bash
adb logcat -s AnomalyDetector:D SignatureDatabase:D RuleEngine:D PacketAnalysisManager:I
```

### See Only Anomaly Alerts

**To see just the 🚨 alerts:**
```bash
adb logcat -s AnomalyDetector:D | findstr "🚨"
```

**Or on Windows:**
```bash
adb logcat -s AnomalyDetector:D | findstr "Anomaly detected"
```

### Count Total Anomalies Detected

```bash
adb logcat -d -s AnomalyDetector:D | findstr /C:"🚨" | find /C "🚨"
```

### Save Logs to File

```bash
adb logcat -s AnomalyDetector:D SignatureDatabase:D RuleEngine:D > test_results.log
```

Then open `test_results.log` in notepad to review.

---

## Understanding Log Messages

### Signature Detection Example
```
D/SignatureDatabase: Checking packet against signatures...
D/SignatureDatabase: Signature match: RECON-001 - Nmap Scan
W/AnomalyDetector: 🚨 Anomaly detected: [RECON-001] Nmap Scan: Nmap network scanner detected
```

**What happened:** Packet matched signature RECON-001 (Nmap Scanner)

### Rule Detection Example
```
D/RuleEngine: Evaluating 10 rules for packet...
D/RuleEngine: Rule RULE-002 checking conditions...
D/RuleEngine: ✓ Condition matched: ProtocolEquals(HTTP)
D/RuleEngine: ✓ Condition matched: PortIn([80, 443])
D/RuleEngine: ✓ Condition matched: UrlContains(UNION SELECT)
W/RuleEngine: Rule matched: RULE-002 - SQL Injection Attempt
W/AnomalyDetector: 🚨 Anomaly detected: [RULE-002] SQL Injection Attempt: SQL injection pattern detected
```

**What happened:** Packet satisfied all conditions of RULE-002, triggered SQL injection alert.

### Statistical Detection Example
```
D/AnomalyDetector: Port scan check: source 192.168.1.100 accessed 18 unique destinations
W/AnomalyDetector: 🚨 Anomaly detected: Port scan detected from 192.168.1.100 (18 unique ports/IPs)
```

**What happened:** One source IP connected to 18+ different destinations, triggered port scan detection.

---

## Common Issues & Solutions

### Issue: No logs appearing

**Check:**
```bash
adb logcat -s "*:E"  # Show all errors
```

**Solution:**
- App might have crashed - check for exceptions
- VPN service might not be running - restart capture

### Issue: No anomalies detected

**This is normal!** Most traffic is legitimate. To force detection:
- Do Test 2 (rapid app opening)
- Do Test 3 (rapid website visiting)
- Do Test 6 (rapid social media scrolling)

### Issue: Too many false positives

**Examples:**
```
W/AnomalyDetector: 🚨 Anomaly detected: Port scan detected (every few seconds)
```

**This can happen with:**
- Social media apps (they connect to many servers)
- News apps (many ad/tracking connections)
- Games (many API endpoints)

**This is expected!** You can adjust thresholds later in AnomalyDetector.kt.

### Issue: Device still unauthorized

**Try these in order:**
1. Unplug and replug USB cable
2. `adb kill-server` then `adb start-server`
3. On phone: Developer Options → Revoke USB debugging authorizations → Re-enable USB debugging
4. Try different USB cable
5. Try different USB port on computer
6. Restart phone
7. Restart computer

---

## Success Criteria

### ✅ Minimum Success
- [x] Device authorized
- [x] App installs without errors
- [x] App launches and starts capture
- [x] Packets appear in app
- [x] Logs show "Loaded 18 signatures"
- [x] Logs show "Loaded 10 detection rules"
- [x] At least 1 anomaly detected during testing

### ✅ Good Success
- [x] All of the above, plus:
- [x] Multiple anomaly types detected (port scan, DNS, connection flood)
- [x] Signature matches logged correctly
- [x] Rule matches logged correctly
- [x] No app crashes
- [x] Packet capture still works normally

### ✅ Excellent Success
- [x] All of the above, plus:
- [x] SQL injection test triggers RULE-002
- [x] Performance feels smooth (no lag)
- [x] Domain names still showing correctly
- [x] HTTP payload formatting still works
- [x] Only real anomalies detected (few false positives)

---

## Quick Reference - All Test Commands

```bash
# 1. Check device
adb devices

# 2. Install app
cd C:\Users\ritik\Downloads\AppDev\APP\andronet
adb install -r "build\app\outputs\flutter-apk\app-debug.apk"

# 3. Monitor logs
adb logcat -s AnomalyDetector:D SignatureDatabase:D RuleEngine:D

# 4. See only alerts
adb logcat -s AnomalyDetector:D | findstr "🚨"

# 5. Count anomalies
adb logcat -d -s AnomalyDetector:D | findstr "Anomaly detected" | find /C "Anomaly"

# 6. Save to file
adb logcat -s AnomalyDetector:D SignatureDatabase:D RuleEngine:D > test_results.log

# 7. Clear logs before test
adb logcat -c

# 8. Launch app
adb shell am start -n com.example.packet_analyzer/.MainActivity
```

---

## What Detection Looks Like (Real Examples)

### Example 1: Port Scan Detected
```
D/AnomalyDetector: Analyzing packet: TCP 192.168.1.100:54321 → 93.184.216.34:443
D/AnomalyDetector: Port scan check: 192.168.1.100 has accessed 16 unique destinations
W/AnomalyDetector: 🚨 Anomaly detected: Port scan detected from 192.168.1.100 (16 unique ports/IPs)
```

### Example 2: SQL Injection Detected
```
D/RuleEngine: Evaluating packet: HTTP GET /artists.php?artist=1' OR '1'='1
D/RuleEngine: RULE-002 conditions: [✓] Protocol=HTTP [✓] Port=80 [✓] URL contains "' OR '1'='1"
W/RuleEngine: Rule matched: RULE-002 - SQL Injection Attempt
W/AnomalyDetector: 🚨 Anomaly detected: [RULE-002] SQL Injection Attempt: SQL injection pattern detected in HTTP request
```

### Example 3: DNS Tunneling Detected
```
D/AnomalyDetector: DNS query rate: 15 queries/sec
W/AnomalyDetector: 🚨 Anomaly detected: Possible DNS tunneling detected (high query rate: 15/sec)
```

### Example 4: Connection Flood Detected
```
D/AnomalyDetector: Connection rate from 192.168.1.100: 62 connections/sec
W/AnomalyDetector: 🚨 Anomaly detected: Connection flood detected from 192.168.1.100 (62 connections/sec, threshold: 50)
```

---

## Next Steps After Testing

Once you confirm detection is working:

1. **Take screenshots** of anomaly logs
2. **Note which tests worked** and which didn't
3. **Check for false positives** (anomalies on normal traffic)

Then we can move to **Phase 2: Flutter UI Integration** so you can see anomalies in the app itself (not just in logs)!

---

## Need Help?

**Can't get device authorized?** See "Issue: Device still unauthorized" section above

**No anomalies showing?** Try Test 2 (rapid app opening) - this almost always triggers something

**Too many logs?** Use: `adb logcat -s AnomalyDetector:W` (shows only warnings = anomalies)

**Want to see everything?** Use: `adb logcat -v color` (colorized full logs)
