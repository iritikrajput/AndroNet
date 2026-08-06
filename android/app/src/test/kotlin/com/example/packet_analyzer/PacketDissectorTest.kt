package com.example.packet_analyzer

import org.junit.Assert.*
import org.junit.Test

class PacketDissectorTest {

    // ---- Small byte-array builder used to hand-construct protocol packets ----

    private class ByteBuf {
        private val list = mutableListOf<Byte>()
        fun u8(v: Int): ByteBuf { list.add(v.toByte()); return this }
        fun u16(v: Int): ByteBuf {
            list.add(((v shr 8) and 0xFF).toByte())
            list.add((v and 0xFF).toByte())
            return this
        }
        fun u24(v: Int): ByteBuf {
            list.add(((v shr 16) and 0xFF).toByte())
            list.add(((v shr 8) and 0xFF).toByte())
            list.add((v and 0xFF).toByte())
            return this
        }
        fun bytes(b: ByteArray): ByteBuf { b.forEach { list.add(it) }; return this }
        fun fill(v: Int, n: Int): ByteBuf { repeat(n) { list.add(v.toByte()) }; return this }
        fun size() = list.size
        fun toByteArray(): ByteArray = list.toByteArray()
    }

    private fun packet(
        protocol: String = "TCP",
        destPort: Int = 0,
        sourcePort: Int = 0,
        destIp: String = "192.0.2.10",
        sourceIp: String = "192.0.2.20"
    ): Map<String, Any> = mapOf(
        "protocol" to protocol,
        "destinationPort" to destPort,
        "sourcePort" to sourcePort,
        "destinationIp" to destIp,
        "sourceIp" to sourceIp
    )

    // ---- Guard clauses -----------------------------------------------------

    @Test
    fun `dissect returns original packetInfo unchanged when payload is null`() {
        val info = packet(protocol = "TCP", destPort = 80)
        val result = PacketDissector.dissect(info, null)
        assertEquals(info, result)
        assertFalse(result.containsKey("payload"))
    }

    @Test
    fun `dissect returns original packetInfo unchanged when payload is empty`() {
        val info = packet(protocol = "TCP", destPort = 80)
        val result = PacketDissector.dissect(info, ByteArray(0))
        assertEquals(info, result)
    }

    @Test
    fun `dissect returns original packetInfo unchanged when protocol key is missing`() {
        val info = mapOf<String, Any>("destinationPort" to 80)
        val payload = "GET / HTTP/1.1\r\n\r\n".toByteArray()
        val result = PacketDissector.dissect(info, payload)
        assertEquals(info, result)
        assertFalse(result.containsKey("payload"))
    }

    // ---- HTTP ----------------------------------------------------------------

    @Test
    fun `dissect parses an HTTP GET request line and headers`() {
        val payload = (
            "GET /index.html HTTP/1.1\r\n" +
                "Host: example.com\r\n" +
                "User-Agent: TestAgent/1.0\r\n" +
                "Content-Type: text/html\r\n" +
                "\r\n"
            ).toByteArray()
        val info = packet(protocol = "TCP", destPort = 80)

        val result = PacketDissector.dissect(info, payload)

        assertEquals("HTTP", result["appName"])
        @Suppress("UNCHECKED_CAST")
        val httpData = result["httpData"] as Map<String, String>
        assertEquals("request", httpData["type"])
        assertEquals("GET", httpData["method"])
        assertEquals("/index.html", httpData["uri"])
        assertEquals("example.com", httpData["host"])
        assertEquals("TestAgent/1.0", httpData["userAgent"])
        assertEquals("text/html", httpData["contentType"])
        assertEquals("GET /index.html", httpData["summary"])
    }

    @Test
    fun `dissect parses an HTTP response status line`() {
        val payload = (
            "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/json\r\n" +
                "Content-Length: 15\r\n" +
                "\r\n" +
                "{\"ok\":true}"
            ).toByteArray()
        val info = packet(protocol = "TCP", sourcePort = 80, destPort = 52345)

        val result = PacketDissector.dissect(info, payload)

        @Suppress("UNCHECKED_CAST")
        val httpData = result["httpData"] as Map<String, String>
        assertEquals("response", httpData["type"])
        assertEquals("200", httpData["statusCode"])
        assertEquals("OK", httpData["statusMessage"])
        assertEquals("application/json", httpData["contentType"])
        assertEquals("15", httpData["contentLength"])
    }

    // ---- DNS -------------------------------------------------------------

    private fun dnsName(buf: ByteBuf, domain: String) {
        for (label in domain.split(".")) {
            buf.u8(label.length)
            buf.bytes(label.toByteArray(Charsets.US_ASCII))
        }
        buf.u8(0)
    }

    private fun buildDnsQuery(domain: String, qType: Int = 1): ByteArray {
        val buf = ByteBuf()
        buf.u16(0x1234)  // transaction id
        buf.u16(0x0100)  // flags: standard query, recursion desired
        buf.u16(1)       // qdcount
        buf.u16(0)       // ancount
        buf.u16(0)       // nscount
        buf.u16(0)       // arcount
        dnsName(buf, domain)
        buf.u16(qType)   // qtype
        buf.u16(1)       // qclass IN
        return buf.toByteArray()
    }

    private fun buildDnsResponse(domain: String, ip: String): ByteArray {
        val buf = ByteBuf()
        buf.u16(0x1234)  // transaction id
        buf.u16(0x8180)  // flags: response, recursion desired+available, no error
        buf.u16(1)       // qdcount
        buf.u16(1)       // ancount
        buf.u16(0)       // nscount
        buf.u16(0)       // arcount
        dnsName(buf, domain)
        buf.u16(1)       // qtype A
        buf.u16(1)       // qclass IN
        // Answer: pointer to name at offset 12, type A, class IN, ttl, rdlength, ip
        buf.u8(0xC0).u8(0x0C)
        buf.u16(1)       // type A
        buf.u16(1)       // class IN
        buf.u8(0).u8(0).u8(0x01).u8(0x2C) // ttl = 300 (4 bytes)
        buf.u16(4)       // rdlength
        ip.split(".").forEach { buf.u8(it.toInt()) }
        return buf.toByteArray()
    }

    @Test
    fun `dissect parses a DNS query for the question name and type`() {
        val payload = buildDnsQuery("example.com", qType = 1)
        val info = packet(protocol = "UDP", destPort = 53)

        val result = PacketDissector.dissect(info, payload)

        assertEquals("DNS", result["appName"])
        @Suppress("UNCHECKED_CAST")
        val dnsData = result["dnsData"] as Map<String, String>
        assertEquals("Query", dnsData["type"])
        assertEquals("example.com", dnsData["queryName"])
        assertEquals("A (IPv4)", dnsData["queryType"])
        assertEquals("1", dnsData["questions"])
        assertEquals("No Error", dnsData["responseCode"])
    }

    @Test
    fun `dissect parses a DNS response and extracts the resolved IP`() {
        val payload = buildDnsResponse("example.com", "93.184.216.34")
        val info = packet(protocol = "UDP", sourcePort = 53, destPort = 55123)

        val result = PacketDissector.dissect(info, payload)

        @Suppress("UNCHECKED_CAST")
        val dnsData = result["dnsData"] as Map<String, String>
        assertEquals("Response", dnsData["type"])
        assertEquals("example.com", dnsData["queryName"])
        assertEquals("93.184.216.34", dnsData["resolvedIps"])
    }

    @Test
    fun `dissect does not add dnsData for a DNS payload shorter than the header`() {
        val payload = byteArrayOf(1, 2, 3)
        val info = packet(protocol = "UDP", destPort = 53)

        val result = PacketDissector.dissect(info, payload)

        assertFalse(result.containsKey("dnsData"))
        // Generic payload enrichment should still occur.
        assertTrue(result.containsKey("payloadHex"))
    }

    // ---- TLS ---------------------------------------------------------------

    /**
     * Builds a minimal, well-formed TLS record containing a Handshake ClientHello
     * with a single server_name (SNI) extension, matching the exact byte layout
     * PacketDissector.extractSNI expects to walk.
     */
    private fun buildTlsClientHelloWithSni(hostname: String): ByteArray {
        val hostBytes = hostname.toByteArray(Charsets.US_ASCII)

        // server_name extension entry: name type (1) + name length (2) + name bytes
        val serverNameEntry = ByteBuf().u8(0).u16(hostBytes.size).bytes(hostBytes)
        val serverNameListLen = serverNameEntry.size()

        // server_name extension data: server name list length (2) + entry
        val sniExtensionData = ByteBuf().u16(serverNameListLen).bytes(serverNameEntry.toByteArray())

        // full extension: type (2, = 0 for server_name) + length (2) + data
        val sniExtension = ByteBuf()
            .u16(0)
            .u16(sniExtensionData.size())
            .bytes(sniExtensionData.toByteArray())
        val extensions = sniExtension.toByteArray()

        // ClientHello body (everything after the handshake type+length header)
        val body = ByteBuf()
            .u8(0x03).u8(0x03)     // client version: TLS 1.2
            .fill(0x11, 32)        // client random
            .u8(0)                 // session id length = 0
            .u16(2)                // cipher suites length
            .u8(0x00).u8(0x2F)     // one cipher suite
            .u8(1)                 // compression methods length
            .u8(0)                 // compression method = null
            .u16(extensions.size)  // extensions length
            .bytes(extensions)

        val handshake = ByteBuf()
            .u8(1)                 // handshake type = ClientHello
            .u24(body.size())      // handshake length
            .bytes(body.toByteArray())

        val record = ByteBuf()
            .u8(22)                       // content type = Handshake
            .u8(0x03).u8(0x01)            // record version
            .u16(handshake.size())        // record length
            .bytes(handshake.toByteArray())

        return record.toByteArray()
    }

    @Test
    fun `dissect extracts SNI hostname from a TLS ClientHello`() {
        val payload = buildTlsClientHelloWithSni("example.com")
        val info = packet(protocol = "TCP", destPort = 443)

        val result = PacketDissector.dissect(info, payload)

        @Suppress("UNCHECKED_CAST")
        val tlsData = result["tlsData"] as Map<String, String>
        assertEquals("Handshake", tlsData["contentType"])
        assertEquals("ClientHello", tlsData["handshakeType"])
        assertEquals("example.com", tlsData["sni"])
    }

    @Test
    fun `dissect parses a bare TLS ChangeCipherSpec record`() {
        // type=20 (ChangeCipherSpec), version 3.3 (TLS 1.2), length=1, body=0x01
        val payload = byteArrayOf(20, 3, 3, 0, 1, 1)
        val info = packet(protocol = "TCP", destPort = 443)

        val result = PacketDissector.dissect(info, payload)

        @Suppress("UNCHECKED_CAST")
        val tlsData = result["tlsData"] as Map<String, String>
        assertEquals("ChangeCipherSpec", tlsData["contentType"])
        assertEquals("TLS 1.2", tlsData["version"])
        assertFalse(tlsData.containsKey("sni"))
    }

    @Test
    fun `dissect does not add tlsData for a payload shorter than the record header`() {
        val payload = byteArrayOf(1, 2, 3)
        val info = packet(protocol = "TCP", destPort = 443)

        val result = PacketDissector.dissect(info, payload)

        assertFalse(result.containsKey("tlsData"))
    }

    // ---- Payload hex/ascii truncation ----------------------------------------

    @Test
    fun `dissect bounds payloadHex and payload ascii length for large payloads`() {
        val payload = ByteArray(5000) { (it % 256).toByte() }
        val info = packet(protocol = "TCP", destPort = 9999)

        val result = PacketDissector.dissect(info, payload)

        assertEquals(5000, result["payloadSize"])

        val hex = result["payloadHex"] as String
        val ascii = result["payload"] as String

        // Whatever the current caps are, they must be well below the full payload size,
        // and the hex string must stay internally consistent ("%02x" bytes joined by " ").
        assertTrue("payloadHex should be truncated for large payloads", hex.length < 5000 * 3)
        assertTrue("payload ascii should be truncated for large payloads", ascii.length < 5000)

        val hexByteCount = hex.split(" ").filter { it.isNotEmpty() }.size
        assertTrue("hex byte count should be bounded", hexByteCount in 1..1000)
        assertTrue("ascii char count should be bounded", ascii.length in 1..1000)
    }

    @Test
    fun `dissect does not truncate small payloads`() {
        val payload = ByteArray(50) { (it % 256).toByte() }
        val info = packet(protocol = "TCP", destPort = 9999)

        val result = PacketDissector.dissect(info, payload)

        assertEquals(50, result["payloadSize"])
        val ascii = result["payload"] as String
        assertEquals(50, ascii.length)

        val hex = result["payloadHex"] as String
        val hexByteCount = hex.split(" ").filter { it.isNotEmpty() }.size
        assertEquals(50, hexByteCount)
    }
}
