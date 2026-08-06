package com.example.packet_analyzer

import android.os.Build
import java.io.File

/**
 * Single source of truth for root detection. Previously duplicated three ways
 * (MainActivity, NetHunterService, and a dead NativeInterface) with three
 * different, inconsistent heuristics — consolidated here.
 */
object RootChecker {

    private val SU_PATHS = arrayOf(
        "/system/app/Superuser.apk",
        "/sbin/su",
        "/system/bin/su",
        "/system/xbin/su",
        "/data/local/xbin/su",
        "/data/local/bin/su",
        "/system/sd/xbin/su",
        "/system/bin/failsafe/su",
        "/data/local/su",
        "/su/bin/su"
    )

    fun isRooted(): Boolean {
        if (Build.TAGS?.contains("test-keys") == true) return true
        if (SU_PATHS.any { File(it).exists() }) return true
        return canExecuteSu()
    }

    private fun canExecuteSu(): Boolean {
        return try {
            // Array form (not a single shell string) avoids quote-parsing ambiguity.
            val process = ProcessBuilder("su", "-c", "id").redirectErrorStream(true).start()
            val output = process.inputStream.bufferedReader().readText()
            val exitCode = process.waitFor()
            exitCode == 0 && output.contains("uid=0")
        } catch (e: Exception) {
            false
        }
    }
}
