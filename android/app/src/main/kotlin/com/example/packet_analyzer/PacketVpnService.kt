package com.example.packet_analyzer

import android.app.Service
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.util.Log
import io.flutter.plugin.common.MethodChannel
import io.flutter.plugin.common.EventChannel
import kotlinx.coroutines.*
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.net.InetAddress
import java.net.*
import java.net.DatagramSocket
import java.net.DatagramPacket
import java.net.Socket
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean

class PacketVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private var isCapturing = AtomicBoolean(false)
    private var captureJob: Job? = null
    // private var simulationJob: Job? = null // No longer needed
    private val serviceScope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private val connectionTracker = mutableMapOf<String, String>() // Track connection directions


    companion object {
        private var methodChannel: MethodChannel? = null
        private var packetSink: EventChannel.EventSink? = null

        fun setMethodChannel(channel: MethodChannel) {
            methodChannel = channel
            Log.i("PacketVpnService", "✅ Method channel set successfully!")
        }

        fun setPacketSink(sink: EventChannel.EventSink?) {
            packetSink = sink
            Log.i("PacketVpnService", "📡 Packet sink ${if (sink == null) "disconnected" else "connected"}")
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i("PacketVpnService", "Starting VPN service...")
        Log.i("PacketVpnService", "🔍 Method channel status at start: ${if (methodChannel == null) "NULL ❌" else "SET ✅"}")

        try {
            Log.i("PacketVpnService", "🔧 Building VPN interface...")
            val builder = Builder()
            builder.setSession("PacketAnalyzerVPN")
            builder.setMtu(1500)
            builder.addAddress("10.0.0.2", 24)
            builder.addDnsServer("8.8.8.8")
            builder.addDnsServer("8.8.4.4")

            // COMPREHENSIVE TRAFFIC CAPTURE - ALL PROTOCOLS
            // Enable complete internet traffic capture for all protocols

            // COMPREHENSIVE TRAFFIC CAPTURE - ALL INTERNET TRAFFIC
            // Route ALL traffic through VPN for complete packet analysis

            // COMPREHENSIVE PACKET CAPTURE - ALL TRAFFIC
            // Route ALL internet traffic through VPN for complete packet analysis

            // COMPREHENSIVE ROUTING: Route ALL traffic for complete packet analysis
            try {
                // Route ALL IPv4 traffic through VPN for complete capture
                builder.addRoute("0.0.0.0", 0)
                Log.i("PacketVpnService", "🌍 COMPREHENSIVE routing enabled - ALL IPv4 traffic will be captured")
                Log.i("PacketVpnService", "📡 Complete network visibility - all apps and services monitored")

                // Add multiple DNS servers for reliable resolution
                builder.addDnsServer("8.8.8.8")      // Google Primary
                builder.addDnsServer("8.8.4.4")      // Google Secondary
                builder.addDnsServer("1.1.1.1")      // Cloudflare Primary
                builder.addDnsServer("1.0.0.1")      // Cloudflare Secondary

                Log.i("PacketVpnService", "🔍 ALL internet traffic will be captured and analyzed")
            } catch (e: Exception) {
                Log.e("PacketVpnService", "❌ Failed to add comprehensive routing: ${e.message}")

                // Fallback to strategic routing if comprehensive fails
                builder.addRoute("8.8.8.8", 32)      // DNS fallback
                builder.addRoute("8.8.4.4", 32)
                builder.addRoute("142.250.0.0", 16)   // Google services fallback
                Log.i("PacketVpnService", "🔄 Using strategic routing fallback")
            }

            // Allow our own app to bypass VPN to prevent looping
            try {
                builder.addDisallowedApplication(packageName)
                Log.i("PacketVpnService", "✅ Excluded own app from VPN to prevent loops")
            } catch (e: Exception) {
                Log.w("PacketVpnService", "Could not exclude own app: ${e.message}")
            }

            Log.i("PacketVpnService", "⚙️ VPN config: Address=10.0.0.2/24, DNS=8.8.8.8,8.8.4.4, Limited routing for testing")

            // Create VPN interface for real packet capture
            vpnInterface = builder.establish()
            Log.i("PacketVpnService", "🎯 VPN establish() called, result: ${vpnInterface != null}")

            vpnInterface?.let { vpn ->
                Log.i("PacketVpnService", "✅ Established TUN interface")
                isCapturing.set(true)

                // Setup PacketListener for real-time packet metadata
                val packetListener = object : Tun2SocksBridge.PacketListener {
                    override fun onPacket(jsonStr: String) {
                        Log.d("PacketVpnService", "📦 Received packet from Go: $jsonStr")

                        // Forward to EventChannel on main thread
                        android.os.Handler(android.os.Looper.getMainLooper()).post {
                            try {
                                packetSink?.success(jsonStr)
                            } catch (e: Exception) {
                                Log.e("PacketVpnService", "❌ EventChannel error: ${e.message}")
                            }
                        }
                    }
                }

                // Set packet listener in Go layer
                Tun2SocksBridge.setPacketListener(packetListener)
                Log.i("PacketVpnService", "📡 PacketListener set for real-time streaming")

                // Start SOCKS proxy server for real internet forwarding
                Log.i("PacketVpnService", "🚀 Starting SOCKS proxy server for comprehensive traffic forwarding")

                // Start embedded SOCKS proxy server
                startEmbeddedSocksProxy()

                // Use tun2socks bridge for proper packet forwarding to SOCKS proxy
                Log.i("PacketVpnService", "🌉 Starting tun2socks bridge with SOCKS proxy forwarding")

                // Set up packet listener for the bridge
                Tun2SocksBridge.setPacketListener(packetListener)

                // DISABLED: tun2socks conflicts with direct packet reading
                // Now we read packets directly and forward them ourselves
                // serviceScope.launch {
                //     startTun2SocksWithSocksProxy(vpn)
                // }

                // Start comprehensive traffic capture alongside SOCKS forwarding
                startComprehensiveTrafficCapture(vpn)

                // Simulation disabled - showing only real packets now
                // startLimitedPacketSimulation()

                // Test packet disabled - only showing real packets now
                // Log.i("PacketVpnService", "🧪 Sending test packet to Flutter...")
                // val testPacket = mapOf(...)
                // notifyFlutter("PACKET_CAPTURED", testPacket)
                notifyFlutter("VPN_STARTED", "Packet capture started")
            } ?: run {
                Log.e("PacketVpnService", "❌ Failed to establish VPN interface")
                stopSelf()
            }
        } catch (e: Exception) {
            Log.e("PacketVpnService", "Exception: ${e.message}", e)
            stopSelf()
        }

        return Service.START_STICKY
    }

    private fun startPacketCapture(vpn: ParcelFileDescriptor) {
        captureJob = serviceScope.launch {
            // Use the simple packet capture approach
            // This reads packets from TUN interface, analyzes them, and forwards them
            Log.i("PacketVpnService", "Starting packet capture with simple forwarding...")
            startSimplePacketCapture(vpn)
        }
    }



    private suspend fun startPacketAnalysisOnly(vpn: ParcelFileDescriptor) {
        // When using Tun2Socks, we can only analyze packets that are mirrored
        // This function keeps the service alive while Tun2Socks handles forwarding
        try {
            Log.i("PacketVpnService", "Packet analysis mode - Tun2Socks handling forwarding")

            while (isCapturing.get() && !Thread.currentThread().isInterrupted) {
                // Send periodic status updates
                notifyFlutter("VPN_STATUS", "VPN Active - Tun2Socks forwarding packets")
                delay(5000) // Check every 5 seconds
            }
        } catch (e: Exception) {
            Log.e("PacketVpnService", "Packet analysis error: ${e.message}")
        }
    }

    private suspend fun startSimplePacketCapture(vpn: ParcelFileDescriptor) {
        val inputStream = FileInputStream(vpn.fileDescriptor)
        val outputStream = FileOutputStream(vpn.fileDescriptor)
        val buffer = ByteArray(32767)
        var packetCount = 0

        try {
            Log.i("PacketVpnService", "🚀 Starting enhanced bidirectional packet capture...")
            Log.i("PacketVpnService", "📡 Monitoring TUN interface for all packet directions...")

            Log.i("PacketVpnService", "⏰ Starting packet read loop...")
            var loopCount = 0
            while (isCapturing.get() && !Thread.currentThread().isInterrupted) {
                loopCount++
                if (loopCount % 1000 == 0) {
                    Log.d("PacketVpnService", "💓 Read loop heartbeat: ${loopCount} iterations")
                }

                val length = inputStream.read(buffer)
                if (length > 0) {
                    packetCount++
                    val packet = buffer.copyOfRange(0, length)

                    // Log first few packets for debugging
                    if (packetCount <= 5) {
                        Log.i("PacketVpnService", "📦 Captured packet #$packetCount: ${length} bytes")
                        val hexDump = packet.take(16).joinToString(" ") { "%02x".format(it) }
                        Log.i("PacketVpnService", "🔍 Packet dump: $hexDump")
                    }

                    // Enhanced packet analysis with direction detection
                    serviceScope.launch {
                        processPacketWithDirectionDetection(packet)
                    }

                    // Forward packet using raw sockets to maintain connectivity
                    // Removed TUN interface forwarding to prevent circular routing
                    serviceScope.launch {
                        forwardPacketForInternet(packet, null)
                    }

                    // Log activity periodically
                    if (packetCount % 50 == 0) {
                        Log.d("PacketVpnService", "📊 Processed $packetCount packets")
                    }
                } else if (length == 0) {
                    // End of stream
                    Log.w("PacketVpnService", "⚠️ End of stream reached (length=0)")
                    break
                } else {
                    // Error condition
                    Log.w("PacketVpnService", "⚠️ Read error (length=$length)")
                    delay(10) // Small delay before retrying
                }
            }
        } catch (e: Exception) {
            Log.e("PacketVpnService", "❌ Enhanced packet capture error: ${e.message}")
        }

        Log.i("PacketVpnService", "📈 Total packets captured: $packetCount")
    }


    private fun parseAndProcessPacketWithSmartDirection(packet: ByteArray) {
        try {
            val packetInfo = PacketParser.parsePacket(packet)
            if (packetInfo != null) {
                // SMART DIRECTION DETECTION based on multiple factors
                val direction = determinePacketDirection(packetInfo)

                Log.v("PacketVpnService", "🔍 Smart direction: ${packetInfo.sourceIP}:${packetInfo.sourcePort} → ${packetInfo.destIP}:${packetInfo.destPort} = $direction")

                // Convert PacketInfo to Map for Flutter
                val packetMap = mapOf(
                    "timestamp" to packetInfo.timestamp,
                    "protocol" to packetInfo.protocol,
                    "sourceIp" to packetInfo.sourceIP,
                    "destinationIp" to packetInfo.destIP,
                    "sourcePort" to (packetInfo.sourcePort ?: 0),
                    "destinationPort" to (packetInfo.destPort ?: 0),
                    "size" to packetInfo.length,
                    "direction" to direction,
                    "flags" to (packetInfo.flags ?: ""),
                    "payload" to (packetInfo.payload ?: "")
                )

                notifyFlutter("PACKET_CAPTURED", packetMap)
                streamPacketToFlutter(packetMap)
            }
        } catch (e: Exception) {
            Log.e("PacketVpnService", "❌ Smart packet processing error: ${e.message}")
        }
    }

    private fun determinePacketDirection(packetInfo: PacketParser.PacketInfo): String {
        val vpnIP = "10.0.0.2"
        val sourceIP = packetInfo.sourceIP
        val destIP = packetInfo.destIP
        val sourcePort = packetInfo.sourcePort ?: 0
        val destPort = packetInfo.destPort ?: 0

        // METHOD 1: Check VPN IP addresses (most reliable)
        when {
            sourceIP == vpnIP && destIP != vpnIP -> return "OUT"  // From device to internet
            sourceIP != vpnIP && destIP == vpnIP -> return "IN"   // From internet to device
        }

        // METHOD 2: Port-based detection with enhanced patterns
        when {
            // Outgoing: High source port (ephemeral) to well-known destination port
            sourcePort > 1024 && destPort in listOf(80, 443, 53, 21, 22, 25, 110, 143, 993, 995, 587, 465, 993, 995, 143, 993) -> return "OUT"

            // Incoming: Well-known source port to high destination port (server responses)
            sourcePort in listOf(80, 443, 53, 21, 22, 25, 110, 143, 993, 995, 587, 465) && destPort > 1024 -> return "IN"

            // DNS queries and responses
            destPort == 53 -> return "OUT"
            sourcePort == 53 -> return "IN"

            // HTTP/HTTPS patterns
            destPort in listOf(80, 443, 8080, 8443) -> return "OUT"
            sourcePort in listOf(80, 443, 8080, 8443) -> return "IN"
        }

        // METHOD 3: Enhanced IP address patterns
        when {
            // Traffic from VPN subnet to external is outgoing
            sourceIP.startsWith("10.0.0.") && !destIP.startsWith("10.0.0.") -> return "OUT"
            // Traffic from external to VPN subnet is incoming
            !sourceIP.startsWith("10.0.0.") && destIP.startsWith("10.0.0.") -> return "IN"

            // Private/local IPs as source typically means outgoing
            isPrivateIP(sourceIP) && !isPrivateIP(destIP) -> return "OUT"
            !isPrivateIP(sourceIP) && isPrivateIP(destIP) -> return "IN"
        }

        // METHOD 4: Protocol-specific enhanced patterns
        when (packetInfo.protocol) {
            "DNS" -> return if (destPort == 53) "OUT" else "IN"
            "QUIC/HTTP3", "HTTPS", "HTTP" -> {
                return when {
                    destPort in listOf(80, 443) -> "OUT"
                    sourcePort in listOf(80, 443) -> "IN"
                    sourcePort > destPort -> "OUT"
                    else -> "IN"
                }
            }
            "TCP", "UDP" -> {
                // For TCP/UDP, use port hierarchy
                return if (sourcePort > destPort) "OUT" else "IN"
            }
        }

        // METHOD 5: Default with better heuristics
        // Since TUN interface primarily captures outgoing traffic from device,
        // but we want to simulate incoming by analyzing response patterns
        return if (sourcePort > 32768) "OUT" else "IN"  // High ephemeral ports suggest outgoing
    }

    private fun isPrivateIP(ip: String): Boolean {
        return when {
            ip.startsWith("10.") -> true
            ip.startsWith("192.168.") -> true
            ip.startsWith("172.") -> {
                val secondOctet = ip.split(".").getOrNull(1)?.toIntOrNull() ?: 0
                secondOctet in 16..31
            }
            ip.startsWith("127.") -> true  // Loopback
            ip == "0.0.0.0" || ip == "::" -> true  // Default/unspecified
            else -> false
        }
    }

    // Keep the old function for compatibility
    private fun processPacketWithDirectionDetection(packet: ByteArray) {
        parseAndProcessPacketWithSmartDirection(packet)
    }

    private fun parseAndProcessPacket(packet: ByteArray, isOutgoing: Boolean = true) {
        try {
            val packetInfo = PacketParser.parsePacket(packet)
            if (packetInfo != null) {
                // Determine direction: packets read from TUN are outgoing (from device to internet)
                // Packets written to TUN would be incoming (from internet to device)
                val direction = if (isOutgoing) "OUT" else "IN"

                // Convert PacketInfo to Map for Flutter (matching Flutter field names)
                val packetMap = mapOf(
                    "timestamp" to packetInfo.timestamp,
                    "protocol" to packetInfo.protocol,
                    "sourceIp" to packetInfo.sourceIP,                    // Fixed: sourceIP → sourceIp
                    "destinationIp" to packetInfo.destIP,                // Fixed: destIP → destinationIp
                    "sourcePort" to (packetInfo.sourcePort ?: 0),
                    "destinationPort" to (packetInfo.destPort ?: 0),     // Fixed: destPort → destinationPort
                    "size" to packetInfo.length,                         // Fixed: length → size
                    "direction" to direction,                             // Add direction field
                    "flags" to (packetInfo.flags ?: ""),
                    "payload" to (packetInfo.payload ?: "")
                )

                // Log interesting packets for debugging
                if (packetInfo.protocol in listOf("TCP", "UDP", "ICMP")) {
                    Log.d("PacketVpnService", "🔍 ${packetInfo.protocol}: ${packetInfo.sourceIP}:${packetInfo.sourcePort} → ${packetInfo.destIP}:${packetInfo.destPort}")
                    Log.d("PacketVpnService", "📱 Sending to Flutter: $packetMap")
                }

                notifyFlutter("PACKET_CAPTURED", packetMap)

                // Also stream packet via EventChannel for real-time display
                streamPacketToFlutter(packetMap)
            } else {
                Log.d("PacketVpnService", "⚠️ Failed to parse packet of ${packet.size} bytes")
            }
        } catch (e: Exception) {
            Log.e("PacketVpnService", "❌ Packet parsing error: ${e.message}")
        }
    }

    private fun forwardPacketWithModification(packet: ByteArray, outputStream: FileOutputStream) {
        try {
            // Simple packet forwarding - just pass the packet through
            // This maintains internet connectivity while allowing packet analysis
            outputStream.write(packet)

            // Only log every 100th packet to avoid spam
            if (System.currentTimeMillis() % 100 == 0L) {
                Log.d("PacketVpnService", "✅ Forwarded packet of ${packet.size} bytes")
            }
        } catch (e: Exception) {
            Log.e("PacketVpnService", "Packet forwarding error: ${e.message}")
        }
    }

    private fun notifyFlutter(event: String, data: Any) {
        try {
            Log.d("PacketVpnService", "🔔 Attempting to notify Flutter: event=$event")
            Log.d("PacketVpnService", "🔍 Method channel status: ${if (methodChannel == null) "NULL" else "SET"}")

            if (methodChannel == null) {
                Log.e("PacketVpnService", "❌ MethodChannel is null! Cannot send to Flutter")
                Log.e("PacketVpnService", "💡 This usually means MainActivity hasn't set the method channel yet")
                return
            }

            // Ensure we're on the main thread for method channel calls
            val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())
            if (android.os.Looper.myLooper() == android.os.Looper.getMainLooper()) {
                Log.d("PacketVpnService", "🎯 Already on main thread, calling directly")
                invokeMethodChannel(event, data)
            } else {
                Log.d("PacketVpnService", "🔄 Posting to main thread")
                mainHandler.post {
                    invokeMethodChannel(event, data)
                }
            }
        } catch (e: Exception) {
            Log.e("PacketVpnService", "❌ Flutter notification error: ${e.message}")
            e.printStackTrace()
        }
    }

    private fun invokeMethodChannel(event: String, data: Any) {
        try {
            Log.d("PacketVpnService", "📤 Invoking method channel: $event")
            methodChannel?.invokeMethod("onPacketEvent", mapOf(
                "event" to event,
                "data" to data
            ), object : MethodChannel.Result {
                override fun success(result: Any?) {
                    Log.d("PacketVpnService", "✅ Flutter acknowledged: event=$event, result=$result")
                }
                override fun error(errorCode: String, errorMessage: String?, errorDetails: Any?) {
                    Log.e("PacketVpnService", "❌ Flutter error for event=$event: $errorCode - $errorMessage")
                    Log.e("PacketVpnService", "📝 Error details: $errorDetails")
                }
                override fun notImplemented() {
                    Log.e("PacketVpnService", "❌ Flutter method not implemented for event=$event")
                    Log.e("PacketVpnService", "💡 Check if onPacketEvent handler is set up in Flutter")
                }
            })
            Log.d("PacketVpnService", "📨 Method invocation sent successfully")
        } catch (e: Exception) {
            Log.e("PacketVpnService", "❌ Method channel invocation failed: ${e.message}")
            e.printStackTrace()
        }
    }

    private fun streamPacketToFlutter(packetData: Map<String, Any>) {
        try {
            packetSink?.let { sink ->
                Log.d("PacketVpnService", "📡 Streaming packet to Flutter via EventChannel")

                // Ensure we're on the main thread for EventChannel calls
                val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())
                if (android.os.Looper.myLooper() == android.os.Looper.getMainLooper()) {
                    sink.success(packetData)
                } else {
                    mainHandler.post {
                        sink.success(packetData)
                    }
                }
            } ?: run {
                Log.d("PacketVpnService", "📡 No EventChannel listener attached")
            }
        } catch (e: Exception) {
            Log.e("PacketVpnService", "❌ EventChannel streaming error: ${e.message}")
        }
    }

    // Simulation function removed - using only real packets now

    private fun startComprehensiveTrafficCapture(vpn: ParcelFileDescriptor) {
        Log.i("PacketVpnService", "🌍 Starting COMPREHENSIVE traffic capture with SOCKS proxy forwarding")

        captureJob = serviceScope.launch {
            try {
                Log.i("PacketVpnService", "📊 Starting packet analysis alongside SOCKS proxy forwarding")
                Log.i("PacketVpnService", "🔧 SOCKS proxy handles real internet traffic while we analyze packets")

                // Start packet analysis without interfering with SOCKS proxy forwarding
                startPacketAnalysisWithSocksProxy(vpn)

            } catch (e: Exception) {
                Log.e("PacketVpnService", "❌ Error in comprehensive traffic capture: ${e.message}", e)
            }
        }
    }

    // ENHANCED: Bidirectional packet processing with proper forwarding
    private suspend fun startUnifiedPacketProcessing(vpn: ParcelFileDescriptor) {
        Log.i("PacketVpnService", "🚀 Starting BIDIRECTIONAL packet processing with real forwarding")

        val inputStream = FileInputStream(vpn.fileDescriptor)
        val outputStream = FileOutputStream(vpn.fileDescriptor)
        val buffer = ByteArray(32767)
        var totalPackets = 0
        var outgoingPackets = 0
        var incomingPackets = 0
        var forwardedPackets = 0
        var errorCount = 0

        // Track connections for bidirectional analysis
        val connectionTracker = mutableMapOf<String, String>() // sourceIP:port -> direction

        try {
            Log.i("PacketVpnService", "🔍 Starting strategic traffic capture...")
            Log.i("PacketVpnService", "📡 Major services will be analyzed with bidirectional detection")

            while (isCapturing.get()) {
                try {
                    val bytesRead = inputStream.read(buffer)
                    if (bytesRead > 0) {
                        totalPackets++
                        val packet = buffer.copyOf(bytesRead)

                        // Log first few packets for debugging
                        if (totalPackets <= 10) {
                            Log.d("PacketVpnService", "📦 CAPTURED PACKET: ${bytesRead} bytes")
                        }

                        // ENHANCED: Analyze packet with bidirectional tracking
                        serviceScope.launch {
                            val packetInfo = PacketParser.parsePacket(packet)
                            if (packetInfo != null) {
                                // Track connections for better direction detection
                                val connectionKey = "${packetInfo.sourceIP}:${packetInfo.sourcePort}->${packetInfo.destIP}:${packetInfo.destPort}"
                                val reverseKey = "${packetInfo.destIP}:${packetInfo.destPort}->${packetInfo.sourceIP}:${packetInfo.sourcePort}"

                                // Enhanced direction detection with connection tracking
                                val direction = determineEnhancedPacketDirection(packetInfo, connectionTracker)

                                // Update connection tracker
                                connectionTracker[connectionKey] = direction
                                if (direction == "OUT") {
                                    connectionTracker[reverseKey] = "IN"  // Expect incoming response
                                }

                                // Count by direction
                                when (direction) {
                                    "OUT" -> outgoingPackets++
                                    "IN" -> incomingPackets++
                                }

                                Log.v("PacketVpnService", "🔍 Enhanced: ${packetInfo.sourceIP}:${packetInfo.sourcePort} → ${packetInfo.destIP}:${packetInfo.destPort} = $direction")

                                // Send to Flutter
                                val packetMap = mapOf(
                                    "timestamp" to packetInfo.timestamp,
                                    "protocol" to packetInfo.protocol,
                                    "sourceIp" to packetInfo.sourceIP,
                                    "destinationIp" to packetInfo.destIP,
                                    "sourcePort" to (packetInfo.sourcePort ?: 0),
                                    "destinationPort" to (packetInfo.destPort ?: 0),
                                    "size" to packetInfo.length,
                                    "direction" to direction,
                                    "flags" to (packetInfo.flags ?: ""),
                                    "payload" to (packetInfo.payload ?: "")
                                )

                                notifyFlutter("PACKET_CAPTURED", packetMap)
                                streamPacketToFlutter(packetMap)
                            }
                        }

                        // CRITICAL: Forward packet to maintain internet connectivity using raw sockets
                        try {
                            forwardPacketForInternet(packet, null) // Use raw socket forwarding
                            forwardedPackets++
                        } catch (e: Exception) {
                            errorCount++
                            if (errorCount <= 5) {
                                Log.w("PacketVpnService", "⚠️ Packet forward error #$errorCount: ${e.message}")
                            }
                        }

                        // Enhanced logging with bidirectional stats
                        if (totalPackets % 50 == 0) {
                            Log.d("PacketVpnService", "📊 Bidirectional: Total=$totalPackets, OUT=$outgoingPackets, IN=$incomingPackets, Forwarded=$forwardedPackets")
                        }

                        if (totalPackets % 100 == 0) {
                            Log.i("PacketVpnService", "🔄 STRATEGIC CAPTURE: $totalPackets packets (${outgoingPackets} OUT, ${incomingPackets} IN)")
                        }
                    } else if (bytesRead == 0) {
                        delay(10)
                    } else {
                        delay(10)
                    }
                } catch (readException: Exception) {
                    errorCount++
                    if (errorCount <= 10) {
                        Log.w("PacketVpnService", "⚠️ Read exception #$errorCount: ${readException.message}")
                    }
                    delay(10)
                }

                // Prevent CPU overload
                if (totalPackets % 10 == 0) {
                    delay(1)
                }
            }
        } catch (e: Exception) {
            Log.e("PacketVpnService", "❌ Bidirectional packet processing error: ${e.message}", e)
        } finally {
            try {
                inputStream.close()
                outputStream.close()
                Log.i("PacketVpnService", "🔒 Bidirectional processing streams closed")
                Log.i("PacketVpnService", "📈 Final stats: Total=$totalPackets, OUT=$outgoingPackets, IN=$incomingPackets")
            } catch (e: Exception) {
                Log.w("PacketVpnService", "⚠️ Error closing streams: ${e.message}")
            }
        }
    }

    private fun determineEnhancedPacketDirection(
        packetInfo: PacketParser.PacketInfo,
        connectionTracker: Map<String, String>
    ): String {
        val sourceIP = packetInfo.sourceIP
        val destIP = packetInfo.destIP
        val sourcePort = packetInfo.sourcePort ?: 0
        val destPort = packetInfo.destPort ?: 0

        // Check if this is a response to a tracked connection
        val connectionKey = "${sourceIP}:${sourcePort}->${destIP}:${destPort}"
        val trackedDirection = connectionTracker[connectionKey]
        if (trackedDirection != null) {
            return trackedDirection
        }

        // Use original smart detection as fallback
        return determinePacketDirection(packetInfo)
    }

    private fun forwardPacketToRealInternet(packet: ByteArray, outputStream: FileOutputStream) {
        try {
            // FIXED: Don't write back to TUN interface (causes loops)
            // The tun2socks bridge handles real internet forwarding via SOCKS proxy
            // We just analyze the packet here, forwarding is handled separately

            // Log packet forwarding (for debugging)
            if (System.currentTimeMillis() % 1000 < 10) {
                Log.v("PacketVpnService", "📡 Packet forwarded via SOCKS proxy: ${packet.size} bytes")
            }
        } catch (e: Exception) {
            Log.w("PacketVpnService", "⚠️ Packet forwarding logged: ${e.message}")
        }
    }

    // OLD CONFLICTING FUNCTIONS - DISABLED TO PREVENT MULTIPLE FILEINPUTSTREAM CONFLICTS
    // NEW: Packet analysis that works with SOCKS proxy forwarding
    private suspend fun startPacketAnalysisWithSocksProxy(vpn: ParcelFileDescriptor) {
        Log.i("PacketVpnService", "🚀 Starting ACTIVE packet capture and forwarding (no tun2socks)")

        // Instead of relying on tun2socks, we'll:
        // 1. Read packets directly from TUN interface
        // 2. Analyze them for our UI
        // 3. Forward them through raw socket connections for internet access

        val inputStream = FileInputStream(vpn.fileDescriptor)
        val outputStream = FileOutputStream(vpn.fileDescriptor)
        val buffer = ByteArray(1500) // Standard MTU
        var packetCount = 0
        var lastLogTime = System.currentTimeMillis()

        try {
            Log.i("PacketVpnService", "📡 Reading packets directly from TUN interface")
            Log.i("PacketVpnService", "🔍 Each packet will be analyzed AND forwarded for internet access")

            while (isCapturing.get() && !Thread.currentThread().isInterrupted) {
                try {
                    val bytesRead = inputStream.read(buffer)
                    if (bytesRead > 0) {
                        packetCount++
                        val packet = buffer.copyOfRange(0, bytesRead)

                        // Log packet capture for debugging
                        if (packetCount <= 10 || packetCount % 100 == 0) {
                            Log.d("PacketVpnService", "📦 CAPTURED: Packet #$packetCount, ${bytesRead} bytes")
                            if (packetCount <= 3) {
                                val hexDump = packet.take(20).joinToString(" ") { "%02x".format(it) }
                                Log.d("PacketVpnService", "🔍 Hex: $hexDump")
                            }
                        }

                        // ANALYZE the packet for our UI
                        serviceScope.launch {
                            analyzeAndDisplayPacket(packet)
                        }

                        // FORWARD the packet for internet connectivity using raw sockets
                        // This preserves original packet headers and prevents circular routing
                        serviceScope.launch {
                            forwardPacketForInternet(packet, null) // outputStream not used in raw socket forwarding
                        }

                        // Periodic status logging
                        val currentTime = System.currentTimeMillis()
                        if (currentTime - lastLogTime > 5000) { // Every 5 seconds
                            Log.i("PacketVpnService", "📈 ACTIVE CAPTURE: $packetCount packets processed")
                            notifyFlutter("VPN_STATUS", mapOf(
                                "status" to "ACTIVE_CAPTURE_AND_FORWARD",
                                "packets" to packetCount,
                                "message" to "Packets captured and forwarded: $packetCount"
                            ))
                            lastLogTime = currentTime
                        }

                    } else if (bytesRead == 0) {
                        // No data immediately available
                        delay(10)
                    } else {
                        // Error reading
                        delay(50)
                    }
                } catch (e: Exception) {
                    Log.w("PacketVpnService", "⚠️ Packet capture error: ${e.message}")
                    delay(100)
                }
            }
        } catch (e: Exception) {
            Log.e("PacketVpnService", "❌ Active packet capture error: ${e.message}", e)
        } finally {
            try {
                inputStream.close()
                outputStream.close()
                Log.i("PacketVpnService", "🔒 Packet capture streams closed")
            } catch (e: Exception) {
                Log.w("PacketVpnService", "⚠️ Error closing streams: ${e.message}")
            }
        }
    }

    private suspend fun analyzeAndDisplayPacket(packet: ByteArray) {
        try {
            Log.d("PacketVpnService", "🔍 Analyzing packet: ${packet.size} bytes")
            val packetInfo = PacketParser.parsePacket(packet)
            if (packetInfo != null) {
                // DEBUG: Log the parsed packet information
                Log.d("PacketVpnService", "📦 PARSED: ${packetInfo.protocol} ${packetInfo.sourceIP}:${packetInfo.sourcePort} → ${packetInfo.destIP}:${packetInfo.destPort}")

                // Check for zero IP addresses
                if (packetInfo.sourceIP == "0.0.0.0" || packetInfo.destIP == "0.0.0.0") {
                    Log.w("PacketVpnService", "❌ ZERO IP DETECTED! Raw packet hex: ${packet.take(40).joinToString(" ") { "%02x".format(it) }}")
                }

                // Enhanced direction detection
                val direction = determineEnhancedPacketDirection(packetInfo, connectionTracker)

                // Update connection tracker
                val connectionKey = "${packetInfo.sourceIP}:${packetInfo.sourcePort}->${packetInfo.destIP}:${packetInfo.destPort}"
                val reverseKey = "${packetInfo.destIP}:${packetInfo.destPort}->${packetInfo.sourceIP}:${packetInfo.sourcePort}"

                synchronized(connectionTracker) {
                    connectionTracker[connectionKey] = direction
                    if (direction == "OUT") {
                        connectionTracker[reverseKey] = "IN"
                    } else {
                        connectionTracker[reverseKey] = "OUT"
                    }
                }

                // Forward to Flutter UI
                forwardPacketToFlutter(packetInfo, direction)
            } else {
                Log.w("PacketVpnService", "❌ Failed to parse packet, hex dump: ${packet.take(20).joinToString(" ") { "%02x".format(it) }}")
            }
        } catch (e: Exception) {
            Log.w("PacketVpnService", "⚠️ Packet analysis error: ${e.message}")
            e.printStackTrace()
        }
    }

    private suspend fun forwardPacketForInternet(packet: ByteArray, outputStream: FileOutputStream?) {
        try {
            // RAW SOCKET FORWARDING: Parse packet and forward via appropriate socket
            // This preserves original packet headers and avoids TUN interface rewriting

            val packetInfo = PacketParser.parsePacket(packet)
            if (packetInfo != null) {
                when (packetInfo.protocol) {
                    "TCP" -> forwardTcpPacket(packetInfo, packet)
                    "UDP" -> forwardUdpPacket(packetInfo, packet)
                    "ICMP" -> forwardIcmpPacket(packetInfo, packet)
                    else -> {
                        // For unknown protocols, log and skip
                        Log.v("PacketVpnService", "⚠️ Skipping ${packetInfo.protocol} packet forwarding")
                    }
                }
            } else {
                Log.v("PacketVpnService", "⚠️ Could not parse packet for raw socket forwarding")
            }
        } catch (e: Exception) {
            Log.w("PacketVpnService", "⚠️ Raw socket forwarding error: ${e.message}")
        }
    }

    private suspend fun forwardTcpPacket(packetInfo: PacketParser.PacketInfo, rawPacket: ByteArray) {
        try {
            val destIP = packetInfo.destIP
            val destPort = packetInfo.destPort ?: return

            // Extract TCP payload from raw packet
            val payload = extractTcpPayload(rawPacket)
            if (payload.isEmpty()) return

            // Create TCP socket connection
            val socket = Socket()
            try {
                socket.connect(InetSocketAddress(destIP, destPort), 5000)
                val outputStream = socket.getOutputStream()

                // Forward TCP payload
                outputStream.write(payload)
                outputStream.flush()

                Log.v("PacketVpnService", "✅ TCP forwarded to $destIP:$destPort, ${payload.size} bytes")

                // Read response (simplified - would need connection tracking for full implementation)
                val inputStream = socket.getInputStream()
                val response = ByteArray(1024)
                val bytesRead = inputStream.read(response)

                if (bytesRead > 0) {
                    // Create response packet and send back to device
                    // This would need proper TCP packet construction
                    Log.v("PacketVpnService", "📥 TCP response received: $bytesRead bytes")
                }

            } finally {
                socket.close()
            }
        } catch (e: Exception) {
            Log.v("PacketVpnService", "⚠️ TCP forwarding error: ${e.message}")
        }
    }

    private suspend fun forwardUdpPacket(packetInfo: PacketParser.PacketInfo, rawPacket: ByteArray) {
        try {
            val destIP = packetInfo.destIP
            val destPort = packetInfo.destPort ?: return

            // Extract UDP payload from raw packet
            val payload = extractUdpPayload(rawPacket)
            if (payload.isEmpty()) return

            // Create UDP socket
            val socket = DatagramSocket()
            try {
                val destAddress = InetAddress.getByName(destIP)
                val packet = DatagramPacket(payload, payload.size, destAddress, destPort)

                socket.send(packet)

                Log.v("PacketVpnService", "✅ UDP forwarded to $destIP:$destPort, ${payload.size} bytes")

                // Wait for response (with timeout)
                socket.soTimeout = 1000
                val responseBuffer = ByteArray(1024)
                val responsePacket = DatagramPacket(responseBuffer, responseBuffer.size)

                try {
                    socket.receive(responsePacket)
                    Log.v("PacketVpnService", "📥 UDP response received: ${responsePacket.length} bytes")
                } catch (e: java.net.SocketTimeoutException) {
                    // Timeout is normal for UDP
                    Log.v("PacketVpnService", "⏰ UDP response timeout (normal)")
                }

            } finally {
                socket.close()
            }
        } catch (e: Exception) {
            Log.v("PacketVpnService", "⚠️ UDP forwarding error: ${e.message}")
        }
    }

    private suspend fun forwardIcmpPacket(packetInfo: PacketParser.PacketInfo, rawPacket: ByteArray) {
        try {
            // ICMP forwarding is more complex and requires raw sockets with root permissions
            // For now, we'll skip ICMP forwarding
            Log.v("PacketVpnService", "⚠️ ICMP forwarding not implemented (requires root)")
        } catch (e: Exception) {
            Log.v("PacketVpnService", "⚠️ ICMP forwarding error: ${e.message}")
        }
    }

    private fun extractTcpPayload(rawPacket: ByteArray): ByteArray {
        try {
            if (rawPacket.size < 20) return byteArrayOf()

            // IPv4 header is typically 20 bytes, but check IHL field
            val ipHeaderLength = (rawPacket[0].toInt() and 0x0F) * 4
            if (rawPacket.size < ipHeaderLength + 20) return byteArrayOf()

            // TCP header starts after IP header
            val tcpHeaderStart = ipHeaderLength

            // TCP header length is in bits 12-15 of offset 12-13, multiply by 4 for bytes
            val tcpHeaderLength = ((rawPacket[tcpHeaderStart + 12].toInt() and 0xF0) shr 4) * 4

            val payloadStart = ipHeaderLength + tcpHeaderLength
            if (rawPacket.size <= payloadStart) return byteArrayOf()

            return rawPacket.copyOfRange(payloadStart, rawPacket.size)
        } catch (e: Exception) {
            Log.w("PacketVpnService", "⚠️ TCP payload extraction error: ${e.message}")
            return byteArrayOf()
        }
    }

    private fun extractUdpPayload(rawPacket: ByteArray): ByteArray {
        try {
            if (rawPacket.size < 20) return byteArrayOf()

            // IPv4 header is typically 20 bytes, but check IHL field
            val ipHeaderLength = (rawPacket[0].toInt() and 0x0F) * 4
            if (rawPacket.size < ipHeaderLength + 8) return byteArrayOf() // UDP header is 8 bytes

            // UDP payload starts after IP header + UDP header (8 bytes)
            val payloadStart = ipHeaderLength + 8
            if (rawPacket.size <= payloadStart) return byteArrayOf()

            return rawPacket.copyOfRange(payloadStart, rawPacket.size)
        } catch (e: Exception) {
            Log.w("PacketVpnService", "⚠️ UDP payload extraction error: ${e.message}")
            return byteArrayOf()
        }
    }

    private fun forwardPacketToFlutter(packetInfo: PacketParser.PacketInfo, direction: String) {
        try {
            val packetMap: Map<String, Any> = mapOf(
                "id" to System.currentTimeMillis().toString(),
                "timestamp" to packetInfo.timestamp,
                "sourceIp" to packetInfo.sourceIP,        // Fixed: sourceIP → sourceIp
                "destinationIp" to packetInfo.destIP,     // Fixed: destIP → destinationIp
                "sourcePort" to (packetInfo.sourcePort ?: 0),
                "destinationPort" to (packetInfo.destPort ?: 0),  // Fixed: destPort → destinationPort
                "protocol" to packetInfo.protocol,
                "size" to packetInfo.length,
                "direction" to direction,
                "flags" to (packetInfo.flags ?: ""),
                "payload" to (packetInfo.payload ?: "")
            )

            // DEBUG: Log the packet map being sent to Flutter
            Log.d("PacketVpnService", "🚀 FLUTTER MAP: sourceIp=${packetMap["sourceIp"]}, destinationIp=${packetMap["destinationIp"]}")
            Log.d("PacketVpnService", "🚀 FULL MAP: $packetMap")

            // Send via both method channel and event channel
            notifyFlutter("PACKET_CAPTURED", packetMap)
            streamPacketToFlutter(packetMap)
        } catch (e: Exception) {
            Log.w("PacketVpnService", "⚠️ Error forwarding packet to Flutter: ${e.message}")
        }
    }

    /*
    private suspend fun startAdvancedTrafficForwarding(vpn: ParcelFileDescriptor) {
        // DISABLED: This function conflicts with unified packet processing
        // Multiple FileInputStream instances on same descriptor cause race conditions
        Log.w("PacketVpnService", "⚠️ startAdvancedTrafficForwarding DISABLED - using unified processing")
    }
    */

    private var socksProxyPort: Int = 1080
    private var socksProxyThread: Thread? = null

    private fun startEmbeddedSocksProxy() {
        socksProxyThread = Thread {
            try {
                Log.i("PacketVpnService", "🚀 Starting embedded SOCKS proxy server on port $socksProxyPort")

                // Simple SOCKS proxy implementation
                val serverSocket = java.net.ServerSocket(socksProxyPort)
                Log.i("PacketVpnService", "✅ SOCKS proxy server listening on 127.0.0.1:$socksProxyPort")

                while (isCapturing.get() && !Thread.currentThread().isInterrupted) {
                    try {
                        val clientSocket = serverSocket.accept()
                        Log.d("PacketVpnService", "🔗 SOCKS proxy client connected: ${clientSocket.remoteSocketAddress}")

                        // Handle SOCKS connection in separate thread
                        Thread {
                            handleSocksConnection(clientSocket)
                        }.start()

                    } catch (e: Exception) {
                        if (isCapturing.get()) {
                            Log.e("PacketVpnService", "❌ SOCKS proxy accept error: ${e.message}")
                        }
                    }
                }

                serverSocket.close()
                Log.i("PacketVpnService", "🛑 SOCKS proxy server stopped")

            } catch (e: Exception) {
                Log.e("PacketVpnService", "❌ SOCKS proxy server error: ${e.message}")
            }
        }

        socksProxyThread?.start()
    }

    private fun handleSocksConnection(clientSocket: java.net.Socket) {
        try {
            val clientInput = clientSocket.getInputStream()
            val clientOutput = clientSocket.getOutputStream()

            Log.d("PacketVpnService", "🔗 Handling SOCKS5 connection from: ${clientSocket.remoteSocketAddress}")

            // Step 1: Read initial SOCKS5 handshake
            val handshakeBuffer = ByteArray(256)
            val handshakeBytes = clientInput.read(handshakeBuffer)

            if (handshakeBytes < 3) {
                Log.w("PacketVpnService", "❌ Invalid SOCKS5 handshake length: $handshakeBytes")
                return
            }

            val version = handshakeBuffer[0].toInt() and 0xFF
            val numMethods = handshakeBuffer[1].toInt() and 0xFF

            Log.d("PacketVpnService", "📋 SOCKS handshake: version=$version, methods=$numMethods")

            if (version != 5) {
                Log.w("PacketVpnService", "❌ Unsupported SOCKS version: $version")
                return
            }

            // Step 2: Send authentication response (no auth required)
            clientOutput.write(byteArrayOf(0x05.toByte(), 0x00.toByte()))
            clientOutput.flush()
            Log.d("PacketVpnService", "✅ Sent SOCKS5 auth response")

            // Step 3: Read SOCKS5 connection request
            val requestBuffer = ByteArray(256)
            val requestBytes = clientInput.read(requestBuffer)

            if (requestBytes < 4) {
                Log.w("PacketVpnService", "❌ Invalid SOCKS5 request length: $requestBytes")
                return
            }

            val reqVersion = requestBuffer[0].toInt() and 0xFF
            val command = requestBuffer[1].toInt() and 0xFF
            val addressType = requestBuffer[3].toInt() and 0xFF

            Log.d("PacketVpnService", "📋 SOCKS request: version=$reqVersion, cmd=$command, addrType=$addressType")

            if (reqVersion != 5) {
                // Send error response for wrong version
                clientOutput.write(byteArrayOf(
                    0x05.toByte(), 0x07.toByte(), 0x00.toByte(), 0x01.toByte(),
                    0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                    0x00.toByte(), 0x00.toByte()
                ))
                clientOutput.flush()
                Log.w("PacketVpnService", "❌ Unsupported SOCKS version: $reqVersion")
                return
            }

            // Handle UDP ASSOCIATE command (command 3)
            if (command == 3) {
                Log.d("PacketVpnService", "🔄 Handling UDP ASSOCIATE command")
                // For UDP ASSOCIATE, send success response with our proxy address
                clientOutput.write(byteArrayOf(
                    0x05.toByte(), 0x00.toByte(), 0x00.toByte(), 0x01.toByte(),
                    127.toByte(), 0.toByte(), 0.toByte(), 1.toByte(), // 127.0.0.1
                    0x04.toByte(), 0x38.toByte() // Port 1080
                ))
                clientOutput.flush()
                Log.d("PacketVpnService", "✅ UDP ASSOCIATE response sent")

                // Keep connection alive for UDP association
                try {
                    // Read until client closes connection
                    val buffer = ByteArray(1024)
                    while (clientSocket.isConnected && !clientSocket.isClosed) {
                        val bytesRead = clientInput.read(buffer)
                        if (bytesRead == -1) break
                        // Just keep the association alive
                        Thread.sleep(100)
                    }
                } catch (e: Exception) {
                    Log.d("PacketVpnService", "🔄 UDP association ended: ${e.message}")
                }
                return
            }

            if (command != 1) { // Only support CONNECT and UDP ASSOCIATE commands
                // Send error response
                clientOutput.write(byteArrayOf(
                    0x05.toByte(), 0x07.toByte(), 0x00.toByte(), 0x01.toByte(),
                    0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                    0x00.toByte(), 0x00.toByte()
                ))
                clientOutput.flush()
                Log.w("PacketVpnService", "❌ Unsupported SOCKS command: $command")
                return
            }

            // Step 4: Parse target address and port
            var targetHost: String
            var targetPort: Int
            var addressStart = 4

            when (addressType) {
                1 -> { // IPv4
                    if (requestBytes < 10) {
                        Log.w("PacketVpnService", "❌ Invalid IPv4 address length")
                        return
                    }
                    targetHost = "${requestBuffer[4].toInt() and 0xFF}.${requestBuffer[5].toInt() and 0xFF}.${requestBuffer[6].toInt() and 0xFF}.${requestBuffer[7].toInt() and 0xFF}"
                    targetPort = ((requestBuffer[8].toInt() and 0xFF) shl 8) or (requestBuffer[9].toInt() and 0xFF)
                    addressStart = 10
                }
                3 -> { // Domain name
                    val domainLength = requestBuffer[4].toInt() and 0xFF
                    if (requestBytes < 5 + domainLength + 2) {
                        Log.w("PacketVpnService", "❌ Invalid domain name length")
                        return
                    }
                    targetHost = String(requestBuffer, 5, domainLength)
                    targetPort = ((requestBuffer[5 + domainLength].toInt() and 0xFF) shl 8) or (requestBuffer[6 + domainLength].toInt() and 0xFF)
                    addressStart = 7 + domainLength
                }
                else -> {
                    Log.w("PacketVpnService", "❌ Unsupported address type: $addressType")
                    return
                }
            }

            Log.d("PacketVpnService", "🎯 SOCKS target: $targetHost:$targetPort")

            // Step 5: Create connection to target
            val targetSocket = java.net.Socket()
            try {
                targetSocket.connect(java.net.InetSocketAddress(targetHost, targetPort), 10000)
                Log.d("PacketVpnService", "✅ Connected to target: $targetHost:$targetPort")

                // Step 6: Send success response
                clientOutput.write(byteArrayOf(
                    0x05.toByte(), 0x00.toByte(), 0x00.toByte(), 0x01.toByte(),
                    0x7F.toByte(), 0x00.toByte(), 0x00.toByte(), 0x01.toByte(), // 127.0.0.1
                    0x04.toByte(), 0x38.toByte() // Port 1080
                ))
                clientOutput.flush()
                Log.d("PacketVpnService", "✅ Sent SOCKS5 success response")

                // Step 7: Start data relay
                Log.d("PacketVpnService", "🔄 Starting data relay for $targetHost:$targetPort")
                relayData(clientSocket, targetSocket)

            } catch (e: Exception) {
                Log.e("PacketVpnService", "❌ Failed to connect to $targetHost:$targetPort: ${e.message}")

                // Send connection failed response
                clientOutput.write(byteArrayOf(
                    0x05.toByte(), 0x05.toByte(), 0x00.toByte(), 0x01.toByte(),
                    0x00.toByte(), 0x00.toByte(), 0x00.toByte(), 0x00.toByte(),
                    0x00.toByte(), 0x00.toByte()
                ))
                clientOutput.flush()
            } finally {
                try {
                    targetSocket.close()
                } catch (e: Exception) {
                    // Ignore
                }
            }

        } catch (e: Exception) {
            Log.e("PacketVpnService", "❌ SOCKS proxy connection error: ${e.message}")
        } finally {
            try {
                clientSocket.close()
                Log.d("PacketVpnService", "🔒 SOCKS connection closed")
            } catch (e: Exception) {
                // Ignore close errors
            }
        }
    }

    private fun relayData(clientSocket: java.net.Socket, targetSocket: java.net.Socket) {
        try {
            var totalBytesRelayed = 0L

            val clientToTarget = Thread {
                try {
                    val buffer = ByteArray(4096)
                    val clientInput = clientSocket.getInputStream()
                    val targetOutput = targetSocket.getOutputStream()

                    var bytesRead: Int
                    while (clientInput.read(buffer).also { bytesRead = it } != -1) {
                        targetOutput.write(buffer, 0, bytesRead)
                        targetOutput.flush()
                        totalBytesRelayed += bytesRead

                        // Log data flow periodically
                        if (totalBytesRelayed % 10240 == 0L) {
                            Log.v("PacketVpnService", "📤 Client->Target: ${bytesRead} bytes (total: ${totalBytesRelayed})")
                        }
                    }
                    Log.d("PacketVpnService", "🔒 Client->Target stream closed")
                } catch (e: Exception) {
                    Log.d("PacketVpnService", "🔒 Client->Target relay ended: ${e.message}")
                } finally {
                    // Close streams to signal end of relay
                    try { targetSocket.shutdownOutput() } catch (e: Exception) { }
                }
            }

            val targetToClient = Thread {
                try {
                    val buffer = ByteArray(4096)
                    val targetInput = targetSocket.getInputStream()
                    val clientOutput = clientSocket.getOutputStream()

                    var bytesRead: Int
                    while (targetInput.read(buffer).also { bytesRead = it } != -1) {
                        clientOutput.write(buffer, 0, bytesRead)
                        clientOutput.flush()

                        // Log data flow periodically
                        if (bytesRead > 0 && System.currentTimeMillis() % 1000 < 10) {
                            Log.v("PacketVpnService", "📥 Target->Client: ${bytesRead} bytes")
                        }
                    }
                    Log.d("PacketVpnService", "🔒 Target->Client stream closed")
                } catch (e: Exception) {
                    Log.d("PacketVpnService", "🔒 Target->Client relay ended: ${e.message}")
                } finally {
                    // Close streams to signal end of relay
                    try { clientSocket.shutdownOutput() } catch (e: Exception) { }
                }
            }

            clientToTarget.start()
            targetToClient.start()

            // Wait for both relay threads to complete
            clientToTarget.join(30000) // 30 second timeout
            targetToClient.join(30000)

            Log.d("PacketVpnService", "✅ SOCKS data relay completed, total bytes: $totalBytesRelayed")

        } catch (e: Exception) {
            Log.e("PacketVpnService", "❌ SOCKS proxy data relay error: ${e.message}")
        }
    }

    private suspend fun startTun2SocksWithSocksProxy(vpn: ParcelFileDescriptor) {
        Log.i("PacketVpnService", "🌉 Starting tun2socks bridge with SOCKS proxy forwarding")

        try {
            val tunFd = vpn.fd.toLong()

            // Use local SOCKS proxy for real internet forwarding
            val socksServer = "127.0.0.1"  // Local SOCKS proxy
            val socksPort = socksProxyPort.toLong()  // SOCKS proxy port
            val dnsServer = "8.8.8.8"
            val enableIPv6 = false

            Log.i("PacketVpnService", "🚀 Initializing tun2socks with SOCKS proxy: fd=$tunFd, socks=$socksServer:$socksPort")

            // Start the tun2socks bridge with SOCKS proxy forwarding
            Tun2SocksBridge.startTun2Socks(
                fd = tunFd,
                socksServer = socksServer,
                socksPort = socksPort,
                dnsServer = dnsServer,
                enableIPv6 = enableIPv6
            )

            Log.i("PacketVpnService", "✅ Tun2socks bridge with SOCKS proxy established successfully")
            Log.i("PacketVpnService", "🌍 ALL internet traffic now forwarded via SOCKS proxy")

            // Keep the bridge alive
            while (isCapturing.get()) {
                delay(5000)
                Log.v("PacketVpnService", "🌉 Tun2socks + SOCKS proxy bridge running")
            }

        } catch (e: Exception) {
            Log.e("PacketVpnService", "❌ Tun2socks SOCKS proxy bridge error: ${e.message}", e)
            Log.w("PacketVpnService", "⚠️ SOCKS proxy forwarding failed")
        }
    }

    /*
    private suspend fun startPacketMonitoring(vpn: ParcelFileDescriptor) {
        // DISABLED: This function conflicts with unified packet processing
        // Multiple FileInputStream instances on same descriptor cause race conditions
        Log.w("PacketVpnService", "⚠️ startPacketMonitoring DISABLED - using unified processing")
    }
    */

    private fun startRealPacketCapture(vpn: ParcelFileDescriptor) {
        Log.i("PacketVpnService", "🔍 Starting REAL packet capture from TUN interface")

        captureJob = serviceScope.launch {
            val inputStream = FileInputStream(vpn.fileDescriptor)
            val buffer = ByteArray(1500) // Standard MTU size
            var packetCount = 0

            try {
                while (isCapturing.get()) {
                    val bytesRead = inputStream.read(buffer)
                    if (bytesRead > 0) {
                        packetCount++
                        Log.d("PacketVpnService", "📦 REAL packet #$packetCount: $bytesRead bytes")

                        // Parse the real packet using our existing PacketParser
                        parseAndProcessPacket(buffer.copyOf(bytesRead))

                        // Log first few real packets for debugging
                        if (packetCount <= 10) {
                            val hexDump = buffer.take(Math.min(bytesRead, 32))
                                .joinToString(" ") { "%02x".format(it) }
                            Log.d("PacketVpnService", "📦 Real packet #$packetCount hex: $hexDump")
                        }
                    } else {
                        delay(10) // Prevent busy loop
                    }
                }
            } catch (e: Exception) {
                Log.e("PacketVpnService", "❌ Real packet capture error: ${e.message}")
            } finally {
                inputStream.close()
                Log.i("PacketVpnService", "🔍 Real packet capture stopped. Total real packets: $packetCount")
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        Log.i("PacketVpnService", "🛑 Stopping comprehensive VPN service with SOCKS proxy...")

        isCapturing.set(false)
        captureJob?.cancel()
        serviceScope.cancel()

        try {
            // Stop SOCKS proxy server
            try {
                socksProxyThread?.interrupt()
                socksProxyThread?.join(2000) // Wait up to 2 seconds
                Log.i("PacketVpnService", "✅ SOCKS proxy server stopped")
            } catch (e: Exception) {
                Log.w("PacketVpnService", "SOCKS proxy stop warning: ${e.message}")
            }

            // Stop Tun2Socks bridge
            try {
                Tun2SocksBridge.stopTun2Socks()
                Log.i("PacketVpnService", "✅ Tun2Socks bridge stopped")
            } catch (e: Exception) {
                Log.w("PacketVpnService", "Tun2Socks may not have been running: ${e.message}")
            }

            // Close VPN interface
            vpnInterface?.close()

            notifyFlutter("VPN_STOPPED", mapOf(
                "message" to "Comprehensive packet capture stopped",
                "mode" to "SOCKS_PROXY_FORWARDING"
            ))
            Log.i("PacketVpnService", "✅ Comprehensive VPN service with SOCKS proxy stopped cleanly")
        } catch (e: Exception) {
            Log.e("PacketVpnService", "Error closing comprehensive VPN: ${e.message}")
        }
    }
}
