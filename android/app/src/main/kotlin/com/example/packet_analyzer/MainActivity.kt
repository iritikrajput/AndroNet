package com.example.packet_analyzer

import android.content.Intent
import android.net.VpnService
import android.util.Log
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity : FlutterActivity() {

    private val CHANNEL = "packet_analyzer"
    private val VPN_REQUEST_CODE = 1000
    private val TAG = "MainActivity"

    private lateinit var nativeInterface: NativeInterface
    private var pendingResult: MethodChannel.Result? = null
    private lateinit var methodChannel: MethodChannel

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        Log.d(TAG, "Configuring Flutter engine")

        nativeInterface = NativeInterface()
        
        methodChannel = MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL)
        
        // Set the method channel for both VPN service and native interface
        PacketVpnService.methodChannel = methodChannel
        NativeInterface.setMethodChannel(methodChannel)

        methodChannel.setMethodCallHandler { call, result ->
            Log.d(TAG, "Received method call: ${call.method}")
            when (call.method) {
                "startVpnService" -> {
                    startVpnService(result)
                }
                "stopVpnService" -> {
                    stopVpnService(result)
                }
                "startRootedCapture" -> {
                    startRootedCapture(result)
                }
                "stopRootedCapture" -> {
                    stopRootedCapture(result)
                }
                "isDeviceRooted" -> {
                    val isRooted = nativeInterface.isDeviceRooted()
                    Log.d(TAG, "Device rooted: $isRooted")
                    result.success(isRooted)
                }
                "clearPackets" -> {
                    try {
                        nativeInterface.clearPackets()
                        result.success(true)
                    } catch (e: Exception) {
                        Log.e(TAG, "Error clearing packets", e)
                        result.success(true) // Return success even if native clear fails
                    }
                }
                else -> {
                    result.notImplemented()
                }
            }
        }
    }

    private fun startVpnService(result: MethodChannel.Result) {
        Log.d(TAG, "Starting VPN service")
        val intent = VpnService.prepare(this)
        if (intent != null) {
            Log.d(TAG, "VPN permission required, requesting...")
            startActivityForResult(intent, VPN_REQUEST_CODE)
            pendingResult = result
        } else {
            Log.d(TAG, "VPN permission already granted, starting service")
            val vpnIntent = Intent(this, PacketVpnService::class.java)
            startService(vpnIntent)
            result.success(true)
        }
    }

    private fun stopVpnService(result: MethodChannel.Result) {
        Log.d(TAG, "Stopping VPN service")
        val vpnIntent = Intent(this, PacketVpnService::class.java)
        stopService(vpnIntent)
        result.success(true)
    }

    private fun startRootedCapture(result: MethodChannel.Result) {
        Log.d(TAG, "Starting rooted capture")
        val success = nativeInterface.startRootedCapture()
        result.success(success)
    }

    private fun stopRootedCapture(result: MethodChannel.Result) {
        Log.d(TAG, "Stopping rooted capture")
        val success = nativeInterface.stopRootedCapture()
        result.success(success)
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                Log.d(TAG, "VPN permission granted, starting service")
                val vpnIntent = Intent(this, PacketVpnService::class.java)
                startService(vpnIntent)
                pendingResult?.success(true)
            } else {
                Log.d(TAG, "VPN permission denied")
                pendingResult?.success(false)
            }
            pendingResult = null
        }
    }
}
