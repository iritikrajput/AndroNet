package com.example.packet_analyzer

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
                    // Use ZdtunVpnService with zdtun library
                    val intent = Intent(this, ZdtunVpnService::class.java)
                    // Register anomaly listener before starting capture to ensure alerts are sent to Flutter
                    setupAnomalyListener()
                    startService(intent)

                    // Start anomaly detection when VPN starts
                    startAnomalyDetection()
                    
                    result.success("VPN started with zdtun packet forwarding and anomaly detection")
                }
                "stopVpn" -> {
                    // Stop ZdtunVpnService properly
                    val intent = Intent(this, ZdtunVpnService::class.java)
                    intent.action = "STOP_VPN"
                    startService(intent) // Send stop command to service
                    
                    // Stop anomaly detection when VPN stops
                    stopAnomalyDetection()
                    
                    result.success("VPN stop requested")
                }
                "startCapture" -> {
                    val intent = Intent(this, CaptureService::class.java)
                    intent.action = "START_CAPTURE"
                    // Register anomaly listener before starting capture to ensure alerts are sent to Flutter
                    setupAnomalyListener()
                    startService(intent)

                    // Start anomaly detection for enhanced capture
                    startAnomalyDetection()
                    
                    result.success("Enhanced capture started with anomaly detection")
                }
                "stopCapture" -> {
                    val intent = Intent(this, CaptureService::class.java)
                    intent.action = "STOP_CAPTURE"
                    startService(intent)
                    
                    // Stop anomaly detection
                    stopAnomalyDetection()
                    
                    result.success("Enhanced capture stopped")
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
        // The detection systems are always ready, just need to ensure packet flow
        // Packets will be analyzed in ZdtunVpnService.onPacketReceived()
    }
    
    private fun stopAnomalyDetection() {
        Log.i("MainActivity", "🚨 Stopping anomaly detection...")
        // Clean up detection state
        AnomalyDetector.cleanup()
        RuleEngine.clearState()
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
    
    override fun onDestroy() {
        super.onDestroy()
        // Clean up anomaly detection on app destruction
        stopAnomalyDetection()
        AnomalyDetector.removeAnomalyListener(::onAnomalyDetected)
        Log.i("MainActivity", "🚨 Anomaly detection cleaned up")
    }
}
