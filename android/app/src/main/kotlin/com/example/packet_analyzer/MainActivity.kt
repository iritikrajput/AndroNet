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
        NativeInterface.setMethodChannel(methodChannel)

        methodChannel.setMethodCallHandler { call, result ->
            Log.d(TAG, "Received method call: ${call.method}")
            when (call.method) {
                "startVpnService" -> startVpnService(result)
                "stopVpnService" -> stopVpnService(result)

                "startRootedCapture" -> {
                    NativeInterface.nativeStartRootedCapture()
                    result.success(true)
                }
                "stopRootedCapture" -> {
                    NativeInterface.nativeStopRootedCapture()
                    result.success(true)
                }
                "startPcapCapture" -> {
                    try {
                        NativeInterface.nativeStartRootedCapture()
                        result.success(true)
                    } catch (e: Exception) {
                        Log.e(TAG, "Error starting PCAP capture", e)
                        result.success(false)
                    }
                }
                "stopPcapCapture" -> {
                    try {
                        NativeInterface.nativeStopRootedCapture()
                        result.success(true)
                    } catch (e: Exception) {
                        Log.e(TAG, "Error stopping PCAP capture", e)
                        result.success(false)
                    }
                }
                "isDeviceRooted" -> {
                    val rooted = NativeInterface.isDeviceRooted()
                    result.success(rooted)
                }
                "getAvailableInterfaces" -> {
                    val interfaces = NativeInterface.getAvailableInterfaces()
                    result.success(interfaces)
                }
                "exportPackets" -> {
                    val path = NativeInterface.exportPackets(applicationContext)
                    if (path != null) {
                        result.success(path)
                    } else {
                        result.error("EXPORT_FAILED", "Unable to export packets", null)
                    }
                }
                else -> result.notImplemented()
            }
        }
    }

    private fun startVpnService(result: MethodChannel.Result) {
        Log.d(TAG, "Starting VPN service")
        if (pendingResult != null) {
            result.error("BUSY", "VPN request already pending", null)
            return
        }
        val intent = VpnService.prepare(this)
        if (intent != null) {
            pendingResult = result
            startActivityForResult(intent, VPN_REQUEST_CODE)
        } else {
            startVpnForeground()
            result.success(true)
        }
    }

    private fun stopVpnService(result: MethodChannel.Result) {
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
                startVpnForeground()
                pendingResult?.success(true)
            } else {
                pendingResult?.success(false)
            }
            pendingResult = null
        }
    }
}
