package com.example.packet_analyzer

import android.content.Intent
import android.net.VpnService
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

class MainActivity: FlutterActivity() {
    private val CHANNEL = "packet_analyzer"
    private val VPN_REQUEST_CODE = 1000
    
    private lateinit var nativeInterface: NativeInterface
    private var vpnService: PacketVpnService? = null

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        
        nativeInterface = NativeInterface()
        
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
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
                    result.success(nativeInterface.isDeviceRooted())
                }
                "clearPackets" -> {
                    // TODO: Clear packets in your native code if needed
                    nativeInterface.clearPackets() // If you have such a method
                    result.success(null)
                }
                else -> {
                    result.notImplemented()
                }
            }
        }
    }

    private fun startVpnService(result: MethodChannel.Result) {
        val intent = VpnService.prepare(this)
        if (intent != null) {
            startActivityForResult(intent, VPN_REQUEST_CODE)
            // Store the result for later use
            pendingResult = result
        } else {
            // VPN permission already granted
            val vpnIntent = Intent(this, PacketVpnService::class.java)
            startService(vpnIntent)
            result.success(true)
        }
    }

    private fun stopVpnService(result: MethodChannel.Result) {
        val vpnIntent = Intent(this, PacketVpnService::class.java)
        stopService(vpnIntent)
        result.success(true)
    }

    private fun startRootedCapture(result: MethodChannel.Result) {
        val success = nativeInterface.startRootedCapture()
        result.success(success)
    }

    private fun stopRootedCapture(result: MethodChannel.Result) {
        val success = nativeInterface.stopRootedCapture()
        result.success(success)
    }

    private var pendingResult: MethodChannel.Result? = null

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == VPN_REQUEST_CODE) {
            if (resultCode == RESULT_OK) {
                val vpnIntent = Intent(this, PacketVpnService::class.java)
                startService(vpnIntent)
                pendingResult?.success(true)
            } else {
                pendingResult?.success(false)
            }
            pendingResult = null
        }
    }
}
