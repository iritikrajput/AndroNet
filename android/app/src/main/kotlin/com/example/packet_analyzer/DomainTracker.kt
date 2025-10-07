package com.example.packet_analyzer

import android.util.Log
import java.util.concurrent.ConcurrentHashMap

/**
 * Tracks domain names from DNS queries and maps them to IP addresses
 * Allows labeling traffic with human-readable domain names
 */
object DomainTracker {
    private const val TAG = "DomainTracker"

    // Map IP address -> Domain name
    private val ipToDomain = ConcurrentHashMap<String, DomainInfo>()

    // Map Domain name -> List of IPs (for reverse lookup)
    private val domainToIps = ConcurrentHashMap<String, MutableSet<String>>()

    // Cache size limit
    private const val MAX_CACHE_SIZE = 1000

    data class DomainInfo(
        val domain: String,
        val timestamp: Long,
        val ttl: Long = 300000 // 5 minutes default TTL
    )

    /**
     * Record a DNS resolution
     */
    fun recordDnsResolution(domain: String, ipAddress: String, ttl: Long = 300000) {
        try {
            val cleanDomain = domain.trim().lowercase()
            val cleanIp = ipAddress.trim()

            if (cleanDomain.isEmpty() || cleanIp.isEmpty()) return

            // Store IP -> Domain mapping
            val domainInfo = DomainInfo(
                domain = cleanDomain,
                timestamp = System.currentTimeMillis(),
                ttl = ttl
            )
            ipToDomain[cleanIp] = domainInfo

            // Store Domain -> IP mapping (for reverse lookup)
            domainToIps.getOrPut(cleanDomain) { ConcurrentHashMap.newKeySet() }.add(cleanIp)

            Log.d(TAG, "📝 DNS Record: $cleanIp -> $cleanDomain (TTL: ${ttl/1000}s)")

            // Cleanup if cache is too large
            if (ipToDomain.size > MAX_CACHE_SIZE) {
                cleanupOldEntries()
            }

        } catch (e: Exception) {
            Log.e(TAG, "Error recording DNS resolution: ${e.message}")
        }
    }

    /**
     * Get domain name for an IP address
     */
    fun getDomainForIp(ipAddress: String): String? {
        try {
            val cleanIp = ipAddress.trim()
            val domainInfo = ipToDomain[cleanIp] ?: return null

            // Check if entry has expired
            val age = System.currentTimeMillis() - domainInfo.timestamp
            if (age > domainInfo.ttl) {
                // Expired, remove it
                ipToDomain.remove(cleanIp)
                return null
            }

            return domainInfo.domain

        } catch (e: Exception) {
            Log.e(TAG, "Error getting domain for IP: ${e.message}")
            return null
        }
    }

    /**
     * Get all IPs for a domain name
     */
    fun getIpsForDomain(domain: String): Set<String> {
        return domainToIps[domain.trim().lowercase()] ?: emptySet()
    }

    /**
     * Get friendly name for domain (e.g., "google.com" -> "Google")
     */
    fun getFriendlyName(domain: String): String {
        return when {
            // Social Media - Check more specific patterns first!
            domain.contains("snapchat") || domain.contains("sc-cdn") || domain.contains("sc-gw") || domain.contains("sc-jpl") -> "Snapchat"
            domain.contains("telegram") || domain.contains("t.me") -> "Telegram"
            domain.contains("tiktok") || domain.contains("tiktokcdn") || domain.contains("musical.ly") -> "TikTok"
            domain.contains("twitter") || domain.contains("twimg") || domain.contains("t.co") -> "Twitter/X"
            domain.contains("facebook") || domain.contains("fbcdn") || domain.contains("fb.com") || domain.contains("fbsbx") -> "Facebook"
            domain.contains("instagram") || domain.contains("cdninstagram") -> "Instagram"
            domain.contains("whatsapp") || domain.contains("wa.me") -> "WhatsApp"
            domain.contains("linkedin") -> "LinkedIn"
            domain.contains("pinterest") || domain.contains("pinimg") -> "Pinterest"
            domain.contains("reddit") || domain.contains("redd.it") || domain.contains("redditmedia") -> "Reddit"
            domain.contains("discord") || domain.contains("discordapp") -> "Discord"
            domain.contains("wechat") || domain.contains("weixin") -> "WeChat"

            // Google Services
            domain.contains("youtube") || domain.contains("ytimg") || domain.contains("googlevideo") -> "YouTube"
            domain.contains("gmail") -> "Gmail"
            domain.contains("google") || domain.contains("gstatic") || domain.contains("googleapis") -> "Google"

            // Tech Giants
            domain.contains("microsoft") || domain.contains("msft") || domain.contains("windows") || domain.contains("live.com") || domain.contains("outlook") -> "Microsoft"
            domain.contains("apple") || domain.contains("icloud") || domain.contains("itunes") || domain.contains("appstore") -> "Apple"
            domain.contains("amazon") || domain.contains("amazonaws") || domain.contains("aws") -> "Amazon"

            // Streaming & Entertainment
            domain.contains("netflix") || domain.contains("nflx") -> "Netflix"
            domain.contains("spotify") || domain.contains("scdn") -> "Spotify"
            domain.contains("twitch") || domain.contains("ttvnw") -> "Twitch"
            domain.contains("hulu") -> "Hulu"
            domain.contains("disneyplus") || domain.contains("disney") -> "Disney+"
            domain.contains("primevideo") -> "Prime Video"
            domain.contains("hotstar") -> "Hotstar"

            // Messaging & Communication
            domain.contains("zoom") -> "Zoom"
            domain.contains("teams.microsoft") || domain.contains("skype") -> "Microsoft Teams"
            domain.contains("meet.google") -> "Google Meet"
            domain.contains("slack") -> "Slack"
            domain.contains("signal") -> "Signal"
            domain.contains("viber") -> "Viber"

            // E-commerce & Shopping
            domain.contains("ebay") -> "eBay"
            domain.contains("alibaba") || domain.contains("aliexpress") -> "Alibaba"
            domain.contains("flipkart") -> "Flipkart"
            domain.contains("myntra") -> "Myntra"
            domain.contains("shopify") -> "Shopify"

            // Cloud & CDN
            domain.contains("cloudflare") -> "Cloudflare"
            domain.contains("akamai") -> "Akamai CDN"
            domain.contains("dropbox") -> "Dropbox"
            domain.contains("onedrive") -> "OneDrive"
            domain.contains("drive.google") || domain.contains("docs.google") -> "Google Drive"

            // Search & Browsers
            domain.contains("yahoo") -> "Yahoo"
            domain.contains("bing") -> "Bing"
            domain.contains("duckduckgo") -> "DuckDuckGo"
            domain.contains("brave") -> "Brave"

            // Developer & Tech
            domain.contains("github") || domain.contains("githubusercontent") -> "GitHub"
            domain.contains("gitlab") -> "GitLab"
            domain.contains("stackoverflow") || domain.contains("stackexchange") -> "StackOverflow"
            domain.contains("wordpress") -> "WordPress"

            // News & Media
            domain.contains("bbc") -> "BBC"
            domain.contains("cnn") -> "CNN"
            domain.contains("nytimes") -> "NY Times"
            domain.contains("medium") -> "Medium"

            // Asian Services
            domain.contains("baidu") -> "Baidu"
            domain.contains("tencent") || domain.contains("qq.com") -> "Tencent"
            domain.contains("weibo") -> "Weibo"
            domain.contains("line.me") || domain.contains("line-") -> "LINE"
            domain.contains("kakao") -> "KakaoTalk"

            // Gaming
            domain.contains("steam") || domain.contains("steampowered") -> "Steam"
            domain.contains("epicgames") || domain.contains("fortnite") -> "Epic Games"
            domain.contains("roblox") -> "Roblox"
            domain.contains("minecraft") || domain.contains("mojang") -> "Minecraft"
            domain.contains("playstation") || domain.contains("sony") -> "PlayStation"
            domain.contains("xbox") -> "Xbox"

            // Other Popular Services
            domain.contains("paypal") -> "PayPal"
            domain.contains("paytm") -> "Paytm"
            domain.contains("uber") -> "Uber"
            domain.contains("ola") -> "Ola"
            domain.contains("swiggy") -> "Swiggy"
            domain.contains("zomato") -> "Zomato"
            domain.contains("airbnb") -> "Airbnb"
            else -> {
                // Extract main domain name
                val parts = domain.split(".")
                if (parts.size >= 2) {
                    // Capitalize first letter
                    parts[parts.size - 2].replaceFirstChar { it.uppercase() }
                } else {
                    domain.replaceFirstChar { it.uppercase() }
                }
            }
        }
    }

    /**
     * Cleanup old/expired entries
     */
    private fun cleanupOldEntries() {
        try {
            val now = System.currentTimeMillis()
            val expiredIps = mutableListOf<String>()

            // Find expired entries
            ipToDomain.forEach { (ip, domainInfo) ->
                val age = now - domainInfo.timestamp
                if (age > domainInfo.ttl) {
                    expiredIps.add(ip)
                }
            }

            // Remove expired entries
            expiredIps.forEach { ip ->
                val domainInfo = ipToDomain.remove(ip)
                if (domainInfo != null) {
                    domainToIps[domainInfo.domain]?.remove(ip)
                }
            }

            // If still too large, remove oldest entries
            if (ipToDomain.size > MAX_CACHE_SIZE) {
                val sortedEntries = ipToDomain.entries
                    .sortedBy { it.value.timestamp }
                    .take(ipToDomain.size - MAX_CACHE_SIZE)

                sortedEntries.forEach { entry ->
                    ipToDomain.remove(entry.key)
                    domainToIps[entry.value.domain]?.remove(entry.key)
                }
            }

            Log.d(TAG, "🧹 Cleanup: Removed ${expiredIps.size} expired entries, cache size: ${ipToDomain.size}")

        } catch (e: Exception) {
            Log.e(TAG, "Error during cleanup: ${e.message}")
        }
    }

    /**
     * Clear all cached mappings
     */
    fun clear() {
        ipToDomain.clear()
        domainToIps.clear()
        Log.d(TAG, "🗑️ Domain cache cleared")
    }

    /**
     * Get cache statistics
     */
    fun getStats(): Map<String, Any> {
        return mapOf(
            "totalMappings" to ipToDomain.size,
            "totalDomains" to domainToIps.size,
            "cacheUtilization" to (ipToDomain.size.toFloat() / MAX_CACHE_SIZE * 100).toInt()
        )
    }
}
