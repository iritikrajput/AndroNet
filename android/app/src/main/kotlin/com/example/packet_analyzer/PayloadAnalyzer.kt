package com.example.packet_analyzer

import android.util.Log
import java.nio.charset.StandardCharsets

/**
 * Payload Analyzer - File carving and content analysis
 * Extracts files from network payloads and analyzes content for security threats
 */
object PayloadAnalyzer {
    private const val TAG = "PayloadAnalyzer"

    // File type signatures (magic bytes)
    private val FILE_SIGNATURES = mapOf(
        "image/jpeg" to byteArrayOf(0xFF.toByte(), 0xD8.toByte(), 0xFF.toByte()),
        "image/png" to byteArrayOf(0x89.toByte(), 0x50.toByte(), 0x4E.toByte(), 0x47.toByte()),
        "image/gif" to byteArrayOf(0x47.toByte(), 0x49.toByte(), 0x46.toByte()),
        "application/pdf" to byteArrayOf(0x25.toByte(), 0x50.toByte(), 0x44.toByte(), 0x46.toByte()),
        "application/zip" to byteArrayOf(0x50.toByte(), 0x4B.toByte(), 0x03.toByte(), 0x04.toByte()),
        "application/x-rar-compressed" to byteArrayOf(0x52.toByte(), 0x61.toByte(), 0x72.toByte(), 0x21.toByte()),
        "application/x-7z-compressed" to byteArrayOf(0x37.toByte(), 0x7A.toByte(), 0xBC.toByte(), 0xAF.toByte()),
        "application/x-executable" to byteArrayOf(0x4D.toByte(), 0x5A.toByte()), // Windows PE
        "application/x-mach-binary" to byteArrayOf(0xFE.toByte(), 0xED.toByte(), 0xFA.toByte()), // Mach-O (macOS)
        "application/x-elf" to byteArrayOf(0x7F.toByte(), 0x45.toByte(), 0x4C.toByte(), 0x46.toByte()), // ELF (Linux)
        "text/html" to byteArrayOf(0x3C.toByte(), 0x21.toByte(), 0x44.toByte(), 0x4F.toByte(), 0x43.toByte()),
        "text/xml" to byteArrayOf(0x3C.toByte(), 0x3F.toByte(), 0x78.toByte(), 0x6D.toByte()),
        "application/json" to byteArrayOf(0x7B.toByte()), // Starts with '{'
        "text/javascript" to byteArrayOf(0x66.toByte(), 0x75.toByte(), 0x6E.toByte(), 0x63.toByte()) // 'func'
    )

    // Dangerous file extensions that should be flagged
    private val DANGEROUS_EXTENSIONS = setOf(
        "exe", "bat", "cmd", "com", "pif", "scr", "vbs", "js", "jar", "ps1", "sh",
        "dll", "sys", "drv", "ocx", "cpl", "xll", "wsc", "msc", "msi", "msp"
    )

    /**
     * Analyze payload for file content and extract embedded files
     */
    fun analyzePayload(payload: ByteArray, packetInfo: Map<String, Any>): Map<String, Any> {
        val result = mutableMapOf<String, Any>()

        try {
            // Detect file types in payload
            val fileInfo = detectFilesInPayload(payload)
            if (fileInfo.isNotEmpty()) {
                result["detectedFiles"] = fileInfo
            }

            // Extract file content if present
            val extractedFiles = extractFilesFromPayload(payload, packetInfo)
            if (extractedFiles.isNotEmpty()) {
                result["extractedFiles"] = extractedFiles
            }

            // Check for suspicious content
            val securityFlags = analyzeSecurityRisks(payload, packetInfo)
            if (securityFlags.isNotEmpty()) {
                result["securityFlags"] = securityFlags
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error analyzing payload: ${e.message}")
        }

        return result
    }

    /**
     * Detect file types based on magic bytes/signatures
     */
    private fun detectFilesInPayload(payload: ByteArray): List<Map<String, Any>> {
        val detectedFiles = mutableListOf<Map<String, Any>>()

        try {
            for ((mimeType, signature) in FILE_SIGNATURES) {
                if (payload.size >= signature.size) {
                    var found = true
                    for (i in signature.indices) {
                        if (payload[i] != signature[i]) {
                            found = false
                            break
                        }
                    }

                    if (found) {
                        val fileInfo = mapOf(
                            "mimeType" to mimeType,
                            "signature" to signature.joinToString("") { "%02x".format(it) },
                            "offset" to 0,
                            "size" to payload.size,
                            "description" to getFileDescription(mimeType)
                        )
                        detectedFiles.add(fileInfo)
                    }
                }
            }

            // Look for multiple files in payload (e.g., HTTP multipart)
            if (detectedFiles.isEmpty()) {
                detectedFiles.addAll(findEmbeddedFiles(payload))
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error detecting files: ${e.message}")
        }

        return detectedFiles
    }

    /**
     * Extract files from network payload
     */
    private fun extractFilesFromPayload(payload: ByteArray, packetInfo: Map<String, Any>): List<Map<String, Any>> {
        val extractedFiles = mutableListOf<Map<String, Any>>()

        try {
            val protocol = packetInfo["protocol"] as? String ?: return extractedFiles

            when {
                protocol == "TCP" -> {
                    val destPort = (packetInfo["destinationPort"] as? Int) ?: 0
                    when (destPort) {
                        80, 8080 -> extractedFiles.addAll(extractFromHttp(payload, packetInfo))
                        25, 587 -> extractedFiles.addAll(extractFromSmtp(payload, packetInfo))
                        110, 995 -> extractedFiles.addAll(extractFromPop3(payload, packetInfo))
                    }
                }
                protocol == "UDP" -> {
                    val destPort = (packetInfo["destinationPort"] as? Int) ?: 0
                    if (destPort == 53) {
                        extractedFiles.addAll(extractFromDns(payload, packetInfo))
                    }
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error extracting files: ${e.message}")
        }

        return extractedFiles
    }

    /**
     * Extract files from HTTP payload (e.g., downloads, uploads)
     */
    private fun extractFromHttp(payload: ByteArray, packetInfo: Map<String, Any>): List<Map<String, Any>> {
        val extractedFiles = mutableListOf<Map<String, Any>>()

        try {
            val httpText = String(payload, StandardCharsets.UTF_8)
            val contentType = extractHttpContentType(httpText)

            if (contentType != null && isBinaryContent(contentType)) {
                // Extract binary file content
                val fileData = extractHttpBody(payload, httpText)
                if (fileData.isNotEmpty()) {
                    val fileInfo = mapOf(
                        "type" to "http_download",
                        "contentType" to contentType,
                        "size" to fileData.size,
                        "data" to fileData,
                        "filename" to extractHttpFilename(httpText),
                        "isBinary" to true
                    )
                    extractedFiles.add(fileInfo)
                }
            }

            // Check for multipart form data
            if (httpText.contains("Content-Type: multipart/form-data")) {
                extractedFiles.addAll(extractMultipartFiles(httpText, payload))
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error extracting HTTP files: ${e.message}")
        }

        return extractedFiles
    }

    /**
     * Extract files from email protocols (SMTP, POP3)
     */
    private fun extractFromSmtp(payload: ByteArray, packetInfo: Map<String, Any>): List<Map<String, Any>> {
        val extractedFiles = mutableListOf<Map<String, Any>>()

        try {
            val emailText = String(payload, StandardCharsets.UTF_8)

            // Look for MIME attachments
            if (emailText.contains("Content-Type:") && emailText.contains("Content-Transfer-Encoding:")) {
                val attachments = extractMimeAttachments(emailText, payload)
                extractedFiles.addAll(attachments)
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error extracting SMTP files: ${e.message}")
        }

        return extractedFiles
    }

    /**
     * Extract files from POP3 protocol
     */
    private fun extractFromPop3(payload: ByteArray, packetInfo: Map<String, Any>): List<Map<String, Any>> {
        // Similar to SMTP but for retrieval
        return extractFromSmtp(payload, packetInfo)
    }

    /**
     * Extract files from DNS (e.g., DNS tunneling with file data)
     */
    private fun extractFromDns(payload: ByteArray, packetInfo: Map<String, Any>): List<Map<String, Any>> {
        val extractedFiles = mutableListOf<Map<String, Any>>()

        try {
            // Check for suspicious DNS queries that might contain encoded file data
            val dnsData = packetInfo["dnsData"] as? Map<String, String>
            val queryName = dnsData?.get("queryName") ?: ""

            if (queryName.length > 100) { // Suspiciously long domain name
                val decodedData = tryDecodeBase64Domain(queryName)
                if (decodedData.isNotEmpty()) {
                    val fileInfo = mapOf(
                        "type" to "dns_tunnel",
                        "size" to decodedData.size,
                        "data" to decodedData,
                        "encoding" to "base64",
                        "isSuspicious" to true
                    )
                    extractedFiles.add(fileInfo)
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error extracting DNS files: ${e.message}")
        }

        return extractedFiles
    }

    /**
     * Look for embedded files in payload (e.g., ZIP files containing other files)
     */
    private fun findEmbeddedFiles(payload: ByteArray): List<Map<String, Any>> {
        val embeddedFiles = mutableListOf<Map<String, Any>>()

        try {
            // Look for ZIP file signatures within payload
            for (i in 0 until payload.size - 4) {
                if (payload[i] == 0x50.toByte() && payload[i + 1] == 0x4B.toByte() &&
                    payload[i + 2] == 0x03.toByte() && payload[i + 3] == 0x04.toByte()) {

                    // Found ZIP signature, try to extract embedded files
                    val embeddedContent = extractZipContent(payload, i)
                    if (embeddedContent.isNotEmpty()) {
                        embeddedFiles.add(mapOf(
                            "type" to "embedded_zip",
                            "offset" to i,
                            "size" to embeddedContent.size,
                            "content" to embeddedContent
                        ))
                    }
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error finding embedded files: ${e.message}")
        }

        return embeddedFiles
    }

    /**
     * Analyze payload for security risks
     */
    private fun analyzeSecurityRisks(payload: ByteArray, packetInfo: Map<String, Any>): List<String> {
        val securityFlags = mutableListOf<String>()

        try {
            // Check for executable content
            for ((mimeType, signature) in FILE_SIGNATURES) {
                if (mimeType.startsWith("application/x-") && mimeType.contains("executable") ||
                    mimeType.contains("dll") || mimeType.contains("mach-binary") || mimeType.contains("elf")) {

                    if (payload.size >= signature.size) {
                        var found = true
                        for (i in signature.indices) {
                            if (payload[i] != signature[i]) {
                                found = false
                                break
                            }
                        }

                        if (found) {
                            securityFlags.add("EXECUTABLE_CONTENT_DETECTED")
                            break
                        }
                    }
                }
            }

            // Check for suspicious patterns
            val payloadString = String(payload, StandardCharsets.UTF_8).lowercase()

            if (payloadString.contains("eval(") || payloadString.contains("system(") ||
                payloadString.contains("exec(") || payloadString.contains("shell_exec(")) {
                securityFlags.add("SUSPICIOUS_CODE_EXECUTION")
            }

            if (payloadString.contains("password") && payloadString.contains("select") ||
                payloadString.contains("union") && payloadString.contains("select")) {
                securityFlags.add("POTENTIAL_SQL_INJECTION")
            }

            if (payloadString.contains("script") && payloadString.contains("alert(")) {
                securityFlags.add("POTENTIAL_XSS")
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error analyzing security risks: ${e.message}")
        }

        return securityFlags
    }

    /**
     * Extract HTTP body content
     */
    private fun extractHttpBody(payload: ByteArray, httpText: String): ByteArray {
        try {
            val bodyStart = httpText.indexOf("\r\n\r\n")
            if (bodyStart != -1 && bodyStart + 4 < payload.size) {
                return payload.copyOfRange(bodyStart + 4, payload.size)
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting HTTP body: ${e.message}")
        }
        return byteArrayOf()
    }

    /**
     * Extract content type from HTTP headers
     */
    private fun extractHttpContentType(httpText: String): String? {
        try {
            val lines = httpText.split("\r\n")
            for (line in lines) {
                if (line.startsWith("Content-Type:", ignoreCase = true)) {
                    val contentType = line.substringAfter(":").trim()
                    return contentType.substringBefore(";")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting content type: ${e.message}")
        }
        return null
    }

    /**
     * Extract filename from HTTP headers
     */
    private fun extractHttpFilename(httpText: String): String? {
        try {
            val lines = httpText.split("\r\n")
            for (line in lines) {
                if (line.startsWith("Content-Disposition:", ignoreCase = true)) {
                    val regex = "filename=\"([^\"]+)\"".toRegex()
                    val match = regex.find(line)
                    if (match != null) {
                        return match.groupValues[1]
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting filename: ${e.message}")
        }
        return null
    }

    /**
     * Extract files from multipart HTTP data
     */
    private fun extractMultipartFiles(httpText: String, payload: ByteArray): List<Map<String, Any>> {
        val extractedFiles = mutableListOf<Map<String, Any>>()

        try {
            val boundary = extractMultipartBoundary(httpText)
            if (boundary != null) {
                val parts = httpText.split("--$boundary")
                for (part in parts) {
                    if (part.contains("Content-Type:") && part.contains("filename=")) {
                        val fileInfo = extractMultipartFile(part, payload)
                        if (fileInfo.isNotEmpty()) {
                            extractedFiles.add(fileInfo)
                        }
                    }
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error extracting multipart files: ${e.message}")
        }

        return extractedFiles
    }

    /**
     * Extract MIME attachments from email
     */
    private fun extractMimeAttachments(emailText: String, payload: ByteArray): List<Map<String, Any>> {
        val attachments = mutableListOf<Map<String, Any>>()

        try {
            val boundary = extractMimeBoundary(emailText)
            if (boundary != null) {
                val parts = emailText.split("--$boundary")
                for (part in parts) {
                    if (part.contains("Content-Type:") && part.contains("name=")) {
                        val attachment = extractMimeAttachment(part, payload)
                        if (attachment.isNotEmpty()) {
                            attachments.add(attachment)
                        }
                    }
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error extracting MIME attachments: ${e.message}")
        }

        return attachments
    }

    /**
     * Try to decode base64-encoded data from domain name (DNS tunneling)
     */
    private fun tryDecodeBase64Domain(domain: String): ByteArray {
        try {
            // Remove non-base64 characters and try to decode
            val base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
            val cleanedDomain = domain.filter { it in base64Chars }

            if (cleanedDomain.length % 4 == 0 && cleanedDomain.length >= 4) {
                return java.util.Base64.getDecoder().decode(cleanedDomain)
            }

        } catch (e: Exception) {
            // Not valid base64 or not encoded data
        }

        return byteArrayOf()
    }

    /**
     * Extract ZIP content from payload
     */
    private fun extractZipContent(payload: ByteArray, offset: Int): ByteArray {
        try {
            // Simple ZIP extraction - find next file header or end of central directory
            val endSignature = byteArrayOf(0x50.toByte(), 0x4B.toByte(), 0x05.toByte(), 0x06.toByte())

            for (i in offset until payload.size - 4) {
                if (payload[i] == endSignature[0] && payload[i + 1] == endSignature[1] &&
                    payload[i + 2] == endSignature[2] && payload[i + 3] == endSignature[3]) {

                    return payload.copyOfRange(offset, i + 4)
                }
            }

            // If no end found, return until end of payload
            return payload.copyOfRange(offset, payload.size)

        } catch (e: Exception) {
            Log.e(TAG, "Error extracting ZIP content: ${e.message}")
        }

        return byteArrayOf()
    }

    /**
     * Check if content type indicates binary data
     */
    private fun isBinaryContent(contentType: String): Boolean {
        val binaryTypes = setOf(
            "application/octet-stream", "application/pdf", "image/", "video/", "audio/",
            "application/zip", "application/x-rar-compressed", "application/x-7z-compressed"
        )

        return binaryTypes.any { contentType.startsWith(it) }
    }

    /**
     * Get human-readable description for file type
     */
    private fun getFileDescription(mimeType: String): String {
        return when {
            mimeType.startsWith("image/") -> "Image file"
            mimeType.startsWith("video/") -> "Video file"
            mimeType.startsWith("audio/") -> "Audio file"
            mimeType == "application/pdf" -> "PDF document"
            mimeType.startsWith("application/") && mimeType.contains("zip") -> "Archive file"
            mimeType.startsWith("application/x-executable") -> "Executable file"
            mimeType.startsWith("text/") -> "Text file"
            else -> "Binary file"
        }
    }

    /**
     * Extract multipart boundary from HTTP headers
     */
    private fun extractMultipartBoundary(httpText: String): String? {
        try {
            val lines = httpText.split("\r\n")
            for (line in lines) {
                if (line.startsWith("Content-Type:", ignoreCase = true) &&
                    line.contains("boundary=")) {
                    return line.substringAfter("boundary=").trim().removeSurrounding("\"")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting multipart boundary: ${e.message}")
        }
        return null
    }

    /**
     * Extract MIME boundary from email headers
     */
    private fun extractMimeBoundary(emailText: String): String? {
        return extractMultipartBoundary(emailText)
    }

    /**
     * Extract individual file from multipart data
     */
    private fun extractMultipartFile(partText: String, payload: ByteArray): Map<String, Any> {
        try {
            // This is a simplified implementation
            // In practice, you'd need to parse the multipart structure properly
            val filename = extractFilenameFromPart(partText)
            val contentType = extractContentTypeFromPart(partText)

            return mapOf(
                "type" to "multipart_file",
                "filename" to (filename ?: "unknown"),
                "contentType" to (contentType ?: "application/octet-stream"),
                "size" to 0 // Would need proper parsing to determine size
            )

        } catch (e: Exception) {
            Log.e(TAG, "Error extracting multipart file: ${e.message}")
        }

        return emptyMap()
    }

    /**
     * Extract MIME attachment
     */
    private fun extractMimeAttachment(partText: String, payload: ByteArray): Map<String, Any> {
        return extractMultipartFile(partText, payload)
    }

    /**
     * Extract filename from multipart part
     */
    private fun extractFilenameFromPart(partText: String): String? {
        try {
            val regex = "filename=\"([^\"]+)\"".toRegex()
            val match = regex.find(partText)
            return match?.groupValues?.get(1)
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting filename: ${e.message}")
        }
        return null
    }

    /**
     * Extract content type from part
     */
    private fun extractContentTypeFromPart(partText: String): String? {
        try {
            val lines = partText.split("\r\n")
            for (line in lines) {
                if (line.startsWith("Content-Type:", ignoreCase = true)) {
                    return line.substringAfter(":").trim().substringBefore(";")
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Error extracting content type: ${e.message}")
        }
        return null
    }
}
