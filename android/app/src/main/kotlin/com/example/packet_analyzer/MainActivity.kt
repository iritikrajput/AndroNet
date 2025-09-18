package com.example.packet_analyzer

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.util.Log
import androidx.core.content.ContextCompat
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {
    private val CHANNEL = "packet_analyzer"
    private val TAG = "MainActivity"
    private val VPN_REQUEST_CODE = 1000

    private var pendingResult: MethodChannel.Result? = null
    private lateinit var methodChannel: MethodChannel

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        Log.d(TAG, "Configuring Flutter engine")

        methodChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
        PacketVpnService.methodChannel = methodChannel

        // Register channel with NativeInterface (so C++ can send packets/stats/status)
        NativeInterface.setMethodChannel(methodChannel)

        methodChannel.setMethodCallHandler { call, result ->
            Log.d(TAG, "Received method call: ${call.method}")
            when (call.method) {
                // VPN handling
                "startVpnService" -> startVpnService(result)
                "stopVpnService" -> stopVpnService(result)

                // Rooted capture handling
                "startRootedCapture" -> {
                    NativeInterface.nativeStartRootedCapture()
                    result.success(true)
                }
                "stopRootedCapture" -> {
                    NativeInterface.nativeStopRootedCapture()
                    result.success(true)
                }

                else -> result.notImplemented()
            }
        }
    }

    // ---- VPN management ----
    private fun startVpnService(result: MethodChannel.Result) {
        Log.d(TAG, "Starting VPN service")
        if (pendingResult != null) {
            result.error("BUSY", "VPN request already pending", null)
            return
        }
        val intent = VpnService.prepare(this)
        if (intent != null) {
            Log.d(TAG, "VPN permission required, requesting…")
            pendingResult = result
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            Log.d(TAG, "VPN permission already granted, starting service")
            startVpnForeground()
            result.success(true)
        }
    }

    private fun stopVpnService(result: MethodChannel.Result) {
        Log.d(TAG, "Stopping VPN service")
        val vpnIntent = Intent(this, PacketVpnService::class.java)
        stopService(vpnIntent)
        result.success(true)
    }

    private fun startVpnForeground() {
        val vpnIntent = Intent(this, PacketVpnService::class.java)
        ContextCompat.startForegroundService(this, vpnIntent)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == Activity.RESULT_OK) {
                Log.d(TAG, "VPN permission granted, starting service")
                startVpnForeground()
                pendingResult?.success(true)
            } else {
                Log.d(TAG, "VPN permission denied")
                pendingResult?.success(false)
            }
            pendingResult = null
        }
    }
}
