package com.example.packet_analyzer

import android.content.Intent
import android.net.VpnService
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

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)

        Log.i("MainActivity", "🔧 Configuring Flutter engine...")
        val methodChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
        Log.i("MainActivity", "📡 Method channel created for: $CHANNEL")

        // Set the method channel for service communication
        ZdtunVpnService.setMethodChannel(methodChannel)
        Log.i("MainActivity", "✅ Method channel set for ZdtunVpnService")

        // Initialize PacketAnalysisManager with context and channel
        PacketAnalysisManager.initialize(this, methodChannel)
        Log.i("MainActivity", "✅ PacketAnalysisManager initialized")

        // Setup EventChannel for live packet streaming
        val packetEventChannel = EventChannel(flutterEngine.dartExecutor.binaryMessenger, "packet_stream")
        packetEventChannel.setStreamHandler(object : EventChannel.StreamHandler {
            override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
                Log.i("MainActivity", "📡 Packet stream listener attached")
                events?.let { ZdtunVpnService.setPacketSink(it) }
            }
            override fun onCancel(arguments: Any?) {
                Log.i("MainActivity", "📡 Packet stream listener detached")
                ZdtunVpnService.setPacketSink(null)
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
                        startService(intent)
                        result.success("VPN started with zdtun packet forwarding")
                    }
                    "stopVpn" -> {
                        // Stop ZdtunVpnService properly
                        val intent = Intent(this, ZdtunVpnService::class.java)
                        intent.action = "STOP_VPN"
                        startService(intent) // Send stop command to service
                        result.success("VPN stop requested")
                    }
                    "startCapture" -> {
                        val intent = Intent(this, CaptureService::class.java)
                        intent.action = "START_CAPTURE"
                        startService(intent)
                        result.success("Enhanced capture started")
                    }
                    "stopCapture" -> {
                        val intent = Intent(this, CaptureService::class.java)
                        intent.action = "STOP_CAPTURE"
                        startService(intent)
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
                        result.success("Analysis started")
                    }
                    "stopAnalysis" -> {
                        PacketAnalysisManager.getInstance().stopAnalysis()
                        result.success("Analysis stopped")
                    }
                    "getDashboardData" -> {
                        val dashboardData = PacketAnalysisManager.getInstance().getDashboardData()
                        result.success(dashboardData)
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
                    else -> result.notImplemented()
                }
            }

        setupBiometricPrompt()
    }

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
            result.success("Libpcap capture started")
        } catch (e: Exception) {
            result.error("LIBPCAP_ERROR", "Failed to start libpcap: ${e.message}", null)
        }
    }

    private fun stopLibpcapCapture(result: MethodChannel.Result) {
        try {
            val intent = Intent(this, NetHunterService::class.java)
            intent.action = "STOP_CAPTURE"
            startService(intent)
            result.success("Libpcap capture stopped")
        } catch (e: Exception) {
            result.error("LIBPCAP_ERROR", "Failed to stop libpcap: ${e.message}", null)
        }
    }
}
