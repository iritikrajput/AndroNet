package com.example.packet_analyzer

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Handler
import android.os.Looper
import android.util.Log
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.EventChannel

class MainActivity : FlutterFragmentActivity() {
    private val CHANNEL = "packet_analyzer"
    private val VPN_REQUEST_CODE = 1001
    private var pendingVpnAction: String? = null  // "startVpn" or "startCapture"
    private var biometricPrompt: BiometricPrompt? = null
    private var pendingBiometricResult: MethodChannel.Result? = null
    // mainHandler ensures anomaly notifications are posted on the main thread for UI updates
    private val mainHandler = Handler(Looper.getMainLooper())
    private lateinit var methodChannel: MethodChannel

    // Anomaly Detection Integration
    private var anomalyEventSink: EventChannel.EventSink? = null
    private var packetEventSink: EventChannel.EventSink? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        Log.i("MainActivity", "🔧 Configuring Flutter engine...")
        val methodChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
        this.methodChannel = methodChannel
        Log.i("MainActivity", "📡 Method channel created for: $CHANNEL")

        // Set the method channel for service communication
        ZdtunVpnService.setMethodChannel(methodChannel)
        Log.i("MainActivity", "✅ Method channel set for ZdtunVpnService")

        // Initialize PacketAnalysisManager with context and channel
        PacketAnalysisManager.initialize(this, methodChannel)
        Log.i("MainActivity", "✅ PacketAnalysisManager initialized")

        // === ANOMALY DETECTION SETUP ===
        setupAnomalyDetection()
        Log.i("MainActivity", "🚨 Anomaly detection system initialized")

        // Setup EventChannel for live packet streaming
        val packetEventChannel = EventChannel(flutterEngine.dartExecutor.binaryMessenger, "packet_stream")
        packetEventChannel.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                Log.i("MainActivity", "📡 Packet stream listener attached")
                packetEventSink = events
                ZdtunVpnService.setPacketSink(events)
            }
            override fun onCancel(arguments: Any?) {
                Log.i("MainActivity", "📡 Packet stream listener detached")
                packetEventSink = null
                ZdtunVpnService.setPacketSink(null)
            }
        })

        // Setup EventChannel for anomaly alerts - ENHANCED
        val anomalyEventChannel = EventChannel(flutterEngine.dartExecutor.binaryMessenger, "anomaly_stream")
        anomalyEventChannel.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                Log.i("MainActivity", "🚨 Anomaly stream listener attached")
                anomalyEventSink = events
                ZdtunVpnService.setAnomalySink(events)
                
                // Register anomaly detection listener
                AnomalyDetector.addAnomalyListener(::onAnomalyDetected)
                Log.i("MainActivity", "🚨 Anomaly detector listener registered")
            }
            override fun onCancel(arguments: Any?) {
                Log.i("MainActivity", "🚨 Anomaly stream listener detached")
                anomalyEventSink = null
                ZdtunVpnService.setAnomalySink(null)
                
                // Unregister anomaly detection listener
                AnomalyDetector.removeAnomalyListener(::onAnomalyDetected)
                Log.i("MainActivity", "🚨 Anomaly detector listener unregistered")
            }
        })

        methodChannel.setMethodCallHandler { call, result ->
            when (call.method) {
                "prepareVpn" -> {
                    val intent = VpnService.prepare(this)
                    if (intent != null) {
                        startActivityForResult(intent, VPN_REQUEST_CODE)
                        result.success(false) // Permission request launched
                    } else {
                        result.success(true) // Already granted
                    }
                }
                "startVpn" -> {
                    try {
                        val vpnIntent = VpnService.prepare(this)
                        if (vpnIntent != null) {
                            pendingVpnAction = "startVpn"
                            startActivityForResult(vpnIntent, VPN_REQUEST_CODE)
                            result.success("VPN permission requested")
                        } else {
                            setupAnomalyListener()
                            val intent = Intent(this, ZdtunVpnService::class.java)
                            startService(intent)
                            startAnomalyDetection()
                            result.success("VPN started with zdtun packet forwarding and anomaly detection")
                        }
                    } catch (e: Exception) {
                        Log.e("AndroNet", "VPN start failed: ${e.message}", e)
                        mainHandler.post {
                            methodChannel.invokeMethod("onCaptureError",
                                mapOf("error" to (e.message ?: "Failed to start VPN")))
                        }
                        result.error("VPN_ERROR", e.message, null)
                    }
                }
                "stopVpn" -> {
                    try {
                        val intent = Intent(this, ZdtunVpnService::class.java)
                        intent.action = "STOP_VPN"
                        startService(intent)
                        stopAnomalyDetection()
                        result.success("VPN stop requested")
                    } catch (e: Exception) {
                        Log.e("AndroNet", "VPN stop failed: ${e.message}", e)
                        result.error("VPN_ERROR", e.message, null)
                    }
                }
                "startCapture" -> {
                    try {
                        val vpnIntent = VpnService.prepare(this)
                        if (vpnIntent != null) {
                            pendingVpnAction = "startCapture"
                            startActivityForResult(vpnIntent, VPN_REQUEST_CODE)
                            result.success("VPN permission requested")
                        } else {
                            setupAnomalyListener()
                            val intent = Intent(this, CaptureService::class.java)
                            intent.action = "START_CAPTURE"
                            startService(intent)
                            startAnomalyDetection()
                            result.success("Enhanced capture started with anomaly detection")
                        }
                    } catch (e: Exception) {
                        Log.e("AndroNet", "Capture start failed: ${e.message}", e)
                        mainHandler.post {
                            methodChannel.invokeMethod("onCaptureError",
                                mapOf("error" to (e.message ?: "Failed to start capture")))
                        }
                        result.error("CAPTURE_ERROR", e.message, null)
                    }
                }
                "stopCapture" -> {
                    try {
                        val intent = Intent(this, CaptureService::class.java)
                        intent.action = "STOP_CAPTURE"
                        startService(intent)
                        stopAnomalyDetection()
                        result.success("Enhanced capture stopped")
                    } catch (e: Exception) {
                        Log.e("AndroNet", "Capture stop failed: ${e.message}", e)
                        result.error("CAPTURE_ERROR", e.message, null)
                    }
                }
                "checkBiometricAvailability" -> {
                    val biometricManager = BiometricManager.from(this)
                    when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)) {
                        BiometricManager.BIOMETRIC_SUCCESS -> result.success(true)
                        BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE -> result.success(false)
                        BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> result.success(false)
                        BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> result.success(false)
                        else -> result.success(false)
                    }
                }
                "authenticateBiometric" -> {
                    authenticateWithBiometric(result)
                }
                "checkRootAccess" -> {
                    result.success(checkRootAccess())
                }
                "startLibpcapCapture" -> {
                    if (checkRootAccess()) {
                        startLibpcapCapture(result)
                    } else {
                        result.error("ROOT_REQUIRED", "Root access required for libpcap", null)
                    }
                }
                "stopLibpcapCapture" -> {
                    stopLibpcapCapture(result)
                }
                "getDeviceInfo" -> {
                    result.success("${android.os.Build.MANUFACTURER} ${android.os.Build.MODEL} (Android ${android.os.Build.VERSION.RELEASE})")
                }
                "getNetworkInterfaces" -> {
                    try {
                        val interfaces = java.net.NetworkInterface.getNetworkInterfaces()
                            .toList()
                            .map { "${it.name}: ${it.displayName}" }
                        result.success(interfaces)
                    } catch (e: Exception) {
                        result.success(listOf("Unable to get network interfaces"))
                    }
                }
                "getSystemStats" -> {
                    result.success(mapOf(
                        "totalMemory" to Runtime.getRuntime().totalMemory(),
                        "freeMemory" to Runtime.getRuntime().freeMemory(),
                        "availableProcessors" to Runtime.getRuntime().availableProcessors()
                    ))
                }
                // Phase 2: Analysis methods
                "startAnalysis" -> {
                    PacketAnalysisManager.getInstance().startAnalysis()
                    startAnomalyDetection() // Also start anomaly detection
                    result.success("Analysis and anomaly detection started")
                }
                "stopAnalysis" -> {
                    PacketAnalysisManager.getInstance().stopAnalysis()
                    stopAnomalyDetection() // Also stop anomaly detection
                    result.success("Analysis and anomaly detection stopped")
                }
                "getDashboardData" -> {
                    val dashboardData = PacketAnalysisManager.getInstance().getDashboardData()
                    // Add anomaly statistics to dashboard data
                    val anomalyStats = AnomalyDetector.getStatistics()
                    val enhancedData = dashboardData.toMutableMap()
                    enhancedData["anomalyStats"] = anomalyStats
                    enhancedData["ruleEngineStats"] = RuleEngine.getStatistics()
                    enhancedData["signatureStats"] = SignatureDatabase.getStatistics()
                    result.success(enhancedData)
                }
                "startPcapExport" -> {
                    val filename = call.argument<String>("filename") ?: "capture.pcap"
                    val success = PacketAnalysisManager.getInstance().startPcapExport(filename)
                    result.success(if (success) "PCAP export started" else null)
                }
                "stopPcapExport" -> {
                    PacketAnalysisManager.getInstance().stopPcapExport()
                    result.success("PCAP export stopped")
                }
                // Commit 10 — PCAP stats and path exposed to Flutter
                "getPcapStats" -> {
                    result.success(PacketAnalysisManager.getInstance().getPcapStats())
                }
                "getCurrentPcapPath" -> {
                    val stats = PacketAnalysisManager.getInstance().getPcapStats()
                    val path = stats["currentFilePath"] as? String ?: ""
                    result.success(path)
                }
                // === NEW ANOMALY DETECTION METHODS ===
                "getAnomalyStatistics" -> {
                    val stats = mapOf(
                        "anomalyDetector" to AnomalyDetector.getStatistics(),
                        "ruleEngine" to RuleEngine.getStatistics(),
                        "signatureDatabase" to SignatureDatabase.getStatistics()
                    )
                    result.success(stats)
                }
                "resetAnomalyDetection" -> {
                    AnomalyDetector.reset()
                    RuleEngine.clearState()
                    result.success("Anomaly detection system reset")
                }
                "generateTestAnomaly" -> {
                    // Generate a test anomaly for UI testing
                    generateTestAnomaly()
                    result.success("Test anomaly generated")
                }
                // COMMIT 12: expose adaptive threshold values to Flutter UI
                "getThresholdStatus" -> {
                    result.success(AnomalyDetector.adaptiveThresholds.getStatus())
                }
                else -> result.notImplemented()
            }
        }

        setupBiometricPrompt()
    }

    // === ANOMALY DETECTION METHODS ===
    
    private fun setupAnomalyDetection() {
        Log.i("MainActivity", "🚨 Setting up anomaly detection system...")
        
        // Initialize all components
        try {
            // AnomalyDetector is already initialized as an object
            Log.i("MainActivity", "✅ AnomalyDetector ready")
            
            // RuleEngine is already initialized as an object  
            Log.i("MainActivity", "✅ RuleEngine ready with ${RuleEngine.getStatistics()["totalRules"]} rules")
            
            // SignatureDatabase is already initialized as an object
            Log.i("MainActivity", "✅ SignatureDatabase ready with ${SignatureDatabase.getStatistics()["totalSignatures"]} signatures")
            
            Log.i("MainActivity", "🚨 Anomaly detection system setup complete")
        } catch (e: Exception) {
            Log.e("MainActivity", "❌ Error setting up anomaly detection: ${e.message}")
        }
    }
    
    private fun startAnomalyDetection() {
        Log.i("MainActivity", "🚨 Starting anomaly detection...")
        // COMMIT 9: begin the 60-second adaptive baseline learning period
        AnomalyDetector.adaptiveThresholds.startLearning()
        Log.i("AndroNet", "Adaptive threshold learning started — 60 second baseline period")
    }

    private fun stopAnomalyDetection() {
        Log.i("MainActivity", "🚨 Stopping anomaly detection...")
        AnomalyDetector.cleanup()
        RuleEngine.clearState()
        // COMMIT 9: reset adaptive thresholds so next session starts fresh
        AnomalyDetector.adaptiveThresholds.reset()
    }

    private fun setupAnomalyListener() {
        AnomalyDetector.addAnomalyListener { anomaly ->
            mainHandler.post {
                methodChannel.invokeMethod(
                    "onAnomalyDetected",
                    mapOf(
                        "type" to anomaly.type.name,
                        "severity" to anomaly.severity.name,
                        "description" to anomaly.description,
                        "sourceIp" to (anomaly.sourceIp ?: ""),
                        "destinationIp" to (anomaly.destinationIp ?: ""),
                        "timestamp" to anomaly.timestamp
                    )
                )
            }
        }
    }

    private fun onAnomalyDetected(anomaly: AnomalyDetector.Anomaly) {
        try {
            val anomalyMap = mapOf(
                "type" to anomaly.type.name,
                "severity" to anomaly.severity.name,
                "title" to getAnomalyTitle(anomaly),
                "description" to anomaly.description,
                "sourceIp" to (anomaly.sourceIp ?: ""),
                "destinationIp" to (anomaly.destinationIp ?: ""),
                "timestamp" to anomaly.timestamp.toString(),
                "details" to anomaly.details
            )
            
            // Send to Flutter on main thread
            Handler(Looper.getMainLooper()).post {
                anomalyEventSink?.success(anomalyMap)
            }
            
            Log.w("MainActivity", "🚨 Anomaly sent to Flutter: ${anomaly.description}")
        } catch (e: Exception) {
            Log.e("MainActivity", "❌ Error sending anomaly to Flutter: ${e.message}")
        }
    }
    
    private fun getAnomalyTitle(anomaly: AnomalyDetector.Anomaly): String {
        val description = anomaly.description
        
        // Check if this is from SignatureDatabase (format: [SIG-001] Name: Description)
        if (description.startsWith("[") && description.contains("]")) {
            val endBracket = description.indexOf("]")
            if (endBracket > 0) {
                val afterBracket = description.substring(endBracket + 1).trim()
                val colonIndex = afterBracket.indexOf(":")
                if (colonIndex > 0) {
                    return afterBracket.substring(0, colonIndex).trim()
                }
            }
        }
        
        // Check if this is from RuleEngine and extract meaningful titles
        val rulePatterns = mapOf(
            "port scan" to "Port Scan Attack",
            "sql injection" to "SQL Injection Attack", 
            "malicious file" to "Malware Download Detected",
            "dns tunneling" to "DNS Tunneling Attack",
            "brute force" to "Brute Force Attack",
            "cryptomining" to "Cryptocurrency Mining",
            "suspicious outbound" to "Data Exfiltration Attempt",
            "shellcode" to "Code Injection Attack",
            "user-agent" to "Suspicious Scanner Detected",
            "icmp tunneling" to "ICMP Tunnel Detected"
        )
        
        for ((keyword, title) in rulePatterns) {
            if (description.contains(keyword, ignoreCase = true)) {
                return title
            }
        }
        
        // Default titles based on anomaly type
        return when (anomaly.type) {
            AnomalyDetector.AnomalyType.PORT_SCAN -> "Port Scan Detected"
            AnomalyDetector.AnomalyType.SYN_FLOOD -> "SYN Flood Attack"
            AnomalyDetector.AnomalyType.ARP_SPOOFING -> "ARP Spoofing Attack"
            AnomalyDetector.AnomalyType.DNS_TUNNELING -> "DNS Tunneling Detected"
            AnomalyDetector.AnomalyType.CONNECTION_FLOOD -> "Connection Flood Attack"
            AnomalyDetector.AnomalyType.UNUSUAL_TRAFFIC -> "Suspicious Network Activity"
            AnomalyDetector.AnomalyType.MALFORMED_PACKET -> "Malformed Packet Detected"
            AnomalyDetector.AnomalyType.HIGH_ENTROPY_PAYLOAD -> "High Entropy Payload Detected"
            AnomalyDetector.AnomalyType.COVERT_CHANNEL -> "Covert Channel Detected"
        }
    }
    
    private fun generateTestAnomaly() {
        // Generate a test anomaly for debugging/testing
        val testAnomaly = AnomalyDetector.Anomaly(
            type = AnomalyDetector.AnomalyType.UNUSUAL_TRAFFIC,
            severity = AnomalyDetector.Severity.MEDIUM,
            description = "Test anomaly generated from MainActivity for UI testing",
            sourceIp = "192.168.1.100",
            destinationIp = "8.8.8.8",
            details = mapOf(
                "testMode" to true,
                "generatedBy" to "MainActivity",
                "purpose" to "UI Testing"
            )
        )
        
        // Trigger the anomaly
        onAnomalyDetected(testAnomaly)
        Log.i("MainActivity", "🧪 Test anomaly generated for UI testing")
    }

    // === EXISTING METHODS (Updated) ===

    private fun setupBiometricPrompt() {
        val executor = ContextCompat.getMainExecutor(this)

        biometricPrompt = BiometricPrompt(this, executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    pendingBiometricResult?.success(false)
                    pendingBiometricResult = null
                }

                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    pendingBiometricResult?.success(true)
                    pendingBiometricResult = null
                }

                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    pendingBiometricResult?.success(false)
                    pendingBiometricResult = null
                }
            })
    }

    private fun authenticateWithBiometric(result: MethodChannel.Result) {
        val biometricManager = BiometricManager.from(this)

        when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)) {
            BiometricManager.BIOMETRIC_SUCCESS -> {
                pendingBiometricResult = result

                val promptInfo = BiometricPrompt.PromptInfo.Builder()
                    .setTitle("Biometric Authentication")
                    .setSubtitle("Access Andronet by CipherSec")
                    .setNegativeButtonText("Cancel")
                    .build()

                biometricPrompt?.authenticate(promptInfo)
            }
            else -> result.success(false)
        }
    }

    private fun checkRootAccess(): Boolean {
        return try {
            val process = Runtime.getRuntime().exec("su -c 'id'")
            process.waitFor() == 0
        } catch (e: Exception) {
            false
        }
    }

    private fun startLibpcapCapture(result: MethodChannel.Result) {
        try {
            // Start libpcap capture using NetHunterService
            val intent = Intent(this, NetHunterService::class.java)
            intent.action = "START_CAPTURE"
            startService(intent)
            
            // Start anomaly detection for libpcap capture
            startAnomalyDetection()
            
            result.success("Libpcap capture started with anomaly detection")
        } catch (e: Exception) {
            result.error("LIBPCAP_ERROR", "Failed to start libpcap: ${e.message}", null)
        }
    }

    private fun stopLibpcapCapture(result: MethodChannel.Result) {
        try {
            val intent = Intent(this, NetHunterService::class.java)
            intent.action = "STOP_CAPTURE"
            startService(intent)
            
            // Stop anomaly detection
            stopAnomalyDetection()
            
            result.success("Libpcap capture stopped")
        } catch (e: Exception) {
            result.error("LIBPCAP_ERROR", "Failed to stop libpcap: ${e.message}", null)
        }
    }
    
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == Activity.RESULT_OK) {
                Log.i("AndroNet", "VPN permission granted — starting pending action: $pendingVpnAction")
                try {
                    when (pendingVpnAction) {
                        "startVpn" -> {
                            setupAnomalyListener()
                            startService(Intent(this, ZdtunVpnService::class.java))
                            startAnomalyDetection()
                            mainHandler.post {
                                methodChannel.invokeMethod("onVpnPermissionGranted", null)
                            }
                        }
                        "startCapture" -> {
                            setupAnomalyListener()
                            val intent = Intent(this, CaptureService::class.java)
                            intent.action = "START_CAPTURE"
                            startService(intent)
                            startAnomalyDetection()
                            mainHandler.post {
                                methodChannel.invokeMethod("onVpnPermissionGranted", null)
                            }
                        }
                    }
                } catch (e: Exception) {
                    Log.e("AndroNet", "Failed to start service after VPN grant: ${e.message}", e)
                    mainHandler.post {
                        methodChannel.invokeMethod("onCaptureError",
                            mapOf("error" to (e.message ?: "Failed to start after permission grant")))
                    }
                } finally {
                    pendingVpnAction = null
                }
            } else {
                Log.w("AndroNet", "VPN permission denied by user")
                pendingVpnAction = null
                mainHandler.post {
                    methodChannel.invokeMethod("onCaptureError",
                        mapOf("error" to "VPN permission denied by user"))
                }
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        stopAnomalyDetection()
        AnomalyDetector.removeAnomalyListener(::onAnomalyDetected)
        Log.i("MainActivity", "🚨 Anomaly detection cleaned up")
    }
}
