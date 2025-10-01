package com.example.packet_analyzer

import android.util.Log
import java.net.Socket
import java.util.concurrent.atomic.AtomicLong

/**
 * Complete TCP connection state management
 * Handles full TCP state machine with sequence number tracking
 */
class TcpConnection(
    val sourceIP: String,
    val sourcePort: Int,
    val destIP: String,
    val destPort: Int,
    val socket: Socket
) {
    companion object {
        private const val TAG = "TcpConnection"

        // TCP States
        const val CLOSED = 0
        const val SYN_SENT = 1
        const val SYN_RECEIVED = 2
        const val ESTABLISHED = 3
        const val FIN_WAIT_1 = 4
        const val FIN_WAIT_2 = 5
        const val CLOSING = 6
        const val TIME_WAIT = 7
        const val CLOSE_WAIT = 8
        const val LAST_ACK = 9
    }

    // TCP sequence numbers (32-bit wraparound)
    var clientSeq = AtomicLong(0)  // Client -> Server
    var serverSeq = AtomicLong(0)  // Server -> Client
    var clientAck = AtomicLong(0)
    var serverAck = AtomicLong(0)

    // TCP state
    @Volatile var state = CLOSED
    @Volatile var isActive = true

    // Timing
    val startTime = System.currentTimeMillis()
    @Volatile var lastActivity = System.currentTimeMillis()

    // Statistics
    @Volatile var bytesOut = 0L
    @Volatile var bytesIn = 0L
    @Volatile var packetsOut = 0L
    @Volatile var packetsIn = 0L

    /**
     * Initialize sequence numbers from SYN packet
     */
    fun initializeFromSyn(initialSeq: Long) {
        clientSeq.set(initialSeq)
        clientAck.set(0)
        state = SYN_SENT
        Log.d(TAG, "TCP SYN: $sourceIP:$sourcePort -> $destIP:$destPort, seq=$initialSeq")
    }

    /**
     * Process SYN-ACK from server
     */
    fun processSynAck(serverInitSeq: Long, ack: Long) {
        serverSeq.set(serverInitSeq)
        serverAck.set(ack)
        clientAck.set(serverInitSeq + 1)
        state = ESTABLISHED
        Log.d(TAG, "TCP ESTABLISHED: $sourceIP:$sourcePort <-> $destIP:$destPort")
    }

    /**
     * Update sequence numbers on data transmission
     */
    fun updateOnClientData(dataLength: Int) {
        clientSeq.addAndGet(dataLength.toLong())
        bytesOut += dataLength
        packetsOut++
        lastActivity = System.currentTimeMillis()
    }

    /**
     * Update sequence numbers on server response
     */
    fun updateOnServerData(dataLength: Int) {
        serverSeq.addAndGet(dataLength.toLong())
        clientAck.set(serverSeq.get())
        bytesIn += dataLength
        packetsIn++
        lastActivity = System.currentTimeMillis()
    }

    /**
     * Process FIN packet
     */
    fun processFin(fromClient: Boolean) {
        when {
            fromClient && state == ESTABLISHED -> state = FIN_WAIT_1
            !fromClient && state == ESTABLISHED -> state = CLOSE_WAIT
            fromClient && state == CLOSE_WAIT -> state = LAST_ACK
            !fromClient && state == FIN_WAIT_1 -> state = CLOSING
        }
        Log.d(TAG, "TCP FIN received, new state: $state")
    }

    /**
     * Check if connection should be closed
     */
    fun shouldClose(): Boolean {
        return state in listOf(TIME_WAIT, CLOSED, LAST_ACK) ||
               !isActive ||
               (System.currentTimeMillis() - lastActivity > 120000) // 2 min timeout
    }

    /**
     * Get connection key for tracking
     */
    fun getKey(): String {
        return "$sourceIP:$sourcePort-$destIP:$destPort"
    }

    override fun toString(): String {
        return "TcpConnection(${getKey()}, state=$state, out=$bytesOut, in=$bytesIn)"
    }
}
