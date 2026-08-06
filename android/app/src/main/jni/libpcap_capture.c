#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <android/log.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/if_ether.h>

#define TAG "LibpcapCapture"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Global context
typedef struct {
    pcap_t *handle;
    JavaVM *vm;
    jobject service_obj;
    jmethodID packet_callback_mid;
    jmethodID status_callback_mid;
    pthread_t capture_thread;
    int running;
    char *interface;
} pcap_context_t;

static pcap_context_t g_pcap_ctx = {0};
static char g_pending_filter[512] = "";

static jboolean apply_bpf_filter(pcap_t *handle, const char *filter) {
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        LOGE("BPF compile failed: %s", pcap_geterr(handle));
        return JNI_FALSE;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        LOGE("BPF setfilter failed: %s", pcap_geterr(handle));
        pcap_freecode(&fp);
        return JNI_FALSE;
    }
    pcap_freecode(&fp);
    LOGI("BPF filter applied: %s", filter);
    return JNI_TRUE;
}

// Protocol detection function
const char* get_app_name_from_port(const char* protocol, int port) {
    if (strcmp(protocol, "TCP") == 0) {
        switch(port) {
            case 80: return "HTTP";
            case 443: return "HTTPS";
            case 22: return "SSH";
            case 21: return "FTP";
            case 23: return "Telnet";
            case 25: return "SMTP";
            case 53: return "DNS";
            case 110: return "POP3";
            case 143: return "IMAP";
            case 194: return "IRC";
            case 3306: return "MySQL";
            case 5432: return "PostgreSQL";
            case 6379: return "Redis";
            case 8080: return "HTTP-Proxy";
            case 3389: return "RDP";
            case 5900: return "VNC";
            case 8443: return "HTTPS-Alt";
            case 993: return "IMAPS";
            case 995: return "POP3S";
            case 465: return "SMTPS";
            case 853: return "DNS-over-TLS";
            case 1433: return "MSSQL";
            case 27017: return "MongoDB";
            default: return "TCP";
        }
    } else if (strcmp(protocol, "UDP") == 0) {
        switch(port) {
            case 53: return "DNS";
            case 67: return "DHCP";
            case 68: return "DHCP";
            case 123: return "NTP";
            case 161: return "SNMP";
            case 162: return "SNMP-Trap";
            case 443: return "QUIC/HTTP3";
            case 500: return "IPSec";
            case 4500: return "IPSec-NAT";
            case 1900: return "SSDP";
            case 5353: return "mDNS";
            case 5060: return "SIP";
            case 6881: return "BitTorrent";
            default: return "UDP";
        }
    } else if (strcmp(protocol, "ICMP") == 0) {
        return "ICMP/Ping";
    }
    return protocol;
}

// Packet handler callback
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    pcap_context_t *ctx = (pcap_context_t *)user_data;

    if (!ctx->running) return;

    JNIEnv *env;
    jint result = (*ctx->vm)->AttachCurrentThread(ctx->vm, &env, NULL);
    if (result != JNI_OK) {
        LOGE("Failed to attach thread to JVM");
        return;
    }

    // Parse Ethernet header
    struct ether_header *eth = (struct ether_header *)packet;

    // Check if IP packet
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
        return; // Skip non-IP packets for now
    }

    // Parse IP header
    struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));
    int ip_header_len = iph->ip_hl * 4;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(iph->ip_src), src_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(iph->ip_dst), dst_ip, INET_ADDRSTRLEN);

    int protocol = iph->ip_p;
    int src_port = 0;
    int dst_port = 0;
    const char *protocol_name = "Unknown";
    const char *app_name = "Unknown";
    char flags[32] = "";
    int payload_len = 0;
    char payload_hex[512] = "";

    // Parse transport layer
    if (protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
        src_port = ntohs(tcph->th_sport);
        dst_port = ntohs(tcph->th_dport);
        protocol_name = "TCP";

        // TCP flags
        snprintf(flags, sizeof(flags), "%s%s%s%s%s%s",
                tcph->th_flags & TH_SYN ? "SYN " : "",
                tcph->th_flags & TH_ACK ? "ACK " : "",
                tcph->th_flags & TH_FIN ? "FIN " : "",
                tcph->th_flags & TH_RST ? "RST " : "",
                tcph->th_flags & TH_PUSH ? "PSH " : "",
                tcph->th_flags & TH_URG ? "URG " : "");

        // Get application name
        app_name = get_app_name_from_port("TCP", dst_port);
        if (strcmp(app_name, "TCP") == 0) {
            app_name = get_app_name_from_port("TCP", src_port);
        }

        // Extract payload
        int tcp_header_len = tcph->th_off * 4;
        int total_header_len = sizeof(struct ether_header) + ip_header_len + tcp_header_len;
        payload_len = pkthdr->len - total_header_len;

        if (payload_len > 0 && payload_len < 256) {
            const u_char *payload_start = packet + total_header_len;
            for (int i = 0; i < payload_len && i < 64; i++) {
                sprintf(payload_hex + (i * 2), "%02x", payload_start[i]);
            }
        }

    } else if (protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct ether_header) + ip_header_len);
        src_port = ntohs(udph->uh_sport);
        dst_port = ntohs(udph->uh_dport);
        protocol_name = "UDP";

        app_name = get_app_name_from_port("UDP", dst_port);
        if (strcmp(app_name, "UDP") == 0) {
            app_name = get_app_name_from_port("UDP", src_port);
        }

        // Extract payload
        int total_header_len = sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr);
        payload_len = pkthdr->len - total_header_len;

        if (payload_len > 0 && payload_len < 256) {
            const u_char *payload_start = packet + total_header_len;
            for (int i = 0; i < payload_len && i < 64; i++) {
                sprintf(payload_hex + (i * 2), "%02x", payload_start[i]);
            }
        }

    } else if (protocol == IPPROTO_ICMP) {
        struct icmp *icmph = (struct icmp *)(packet + sizeof(struct ether_header) + ip_header_len);
        protocol_name = "ICMP";
        app_name = "ICMP/Ping";

        snprintf(flags, sizeof(flags), "Type:%d Code:%d", icmph->icmp_type, icmph->icmp_code);
    }

    // Create Java HashMap for packet info
    jclass hashMapClass = (*env)->FindClass(env, "java/util/HashMap");
    jmethodID hashMapInit = (*env)->GetMethodID(env, hashMapClass, "<init>", "()V");
    jmethodID hashMapPut = (*env)->GetMethodID(env, hashMapClass, "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

    jobject packetMap = (*env)->NewObject(env, hashMapClass, hashMapInit);

    // Helper to add string to map
    #define PUT_STRING(key, value) { \
        jstring jkey = (*env)->NewStringUTF(env, key); \
        jstring jvalue = (*env)->NewStringUTF(env, value); \
        (*env)->CallObjectMethod(env, packetMap, hashMapPut, jkey, jvalue); \
        (*env)->DeleteLocalRef(env, jkey); \
        (*env)->DeleteLocalRef(env, jvalue); \
    }

    // Helper to add int to map
    #define PUT_INT(key, value) { \
        jstring jkey = (*env)->NewStringUTF(env, key); \
        jclass integerClass = (*env)->FindClass(env, "java/lang/Integer"); \
        jmethodID integerInit = (*env)->GetMethodID(env, integerClass, "<init>", "(I)V"); \
        jobject jvalue = (*env)->NewObject(env, integerClass, integerInit, value); \
        (*env)->CallObjectMethod(env, packetMap, hashMapPut, jkey, jvalue); \
        (*env)->DeleteLocalRef(env, jkey); \
        (*env)->DeleteLocalRef(env, jvalue); \
    }

    // Helper to add long to map
    #define PUT_LONG(key, value) { \
        jstring jkey = (*env)->NewStringUTF(env, key); \
        jclass longClass = (*env)->FindClass(env, "java/lang/Long"); \
        jmethodID longInit = (*env)->GetMethodID(env, longClass, "<init>", "(J)V"); \
        jobject jvalue = (*env)->NewObject(env, longClass, longInit, (jlong)value); \
        (*env)->CallObjectMethod(env, packetMap, hashMapPut, jkey, jvalue); \
        (*env)->DeleteLocalRef(env, jkey); \
        (*env)->DeleteLocalRef(env, jvalue); \
    }

    // Populate packet info
    PUT_STRING("sourceIp", src_ip);
    PUT_STRING("destinationIp", dst_ip);
    PUT_INT("sourcePort", src_port);
    PUT_INT("destinationPort", dst_port);
    PUT_STRING("protocol", protocol_name);
    PUT_STRING("appName", app_name);
    PUT_INT("size", pkthdr->len);
    PUT_LONG("timestamp", pkthdr->ts.tv_sec * 1000LL + pkthdr->ts.tv_usec / 1000LL);
    PUT_STRING("flags", flags);
    PUT_STRING("payload", payload_hex);
    PUT_STRING("captureMode", "libpcap");
    PUT_STRING("direction", "both");

    #undef PUT_STRING
    #undef PUT_INT
    #undef PUT_LONG

    // Call Java callback
    (*env)->CallVoidMethod(env, ctx->service_obj, ctx->packet_callback_mid, packetMap);

    // Cleanup
    (*env)->DeleteLocalRef(env, packetMap);
}

// Capture thread function
void* capture_thread_func(void *arg) {
    pcap_context_t *ctx = (pcap_context_t *)arg;

    LOGI("Starting packet capture on interface: %s", ctx->interface);

    // Capture packets (blocking call)
    int result = pcap_loop(ctx->handle, -1, packet_handler, (u_char *)ctx);

    if (result == -1) {
        LOGE("pcap_loop failed: %s", pcap_geterr(ctx->handle));
    } else if (result == -2) {
        LOGI("Capture stopped by pcap_breakloop");
    }

    LOGI("Capture thread exiting");
    return NULL;
}

// JNI: Initialize libpcap capture
JNIEXPORT jboolean JNICALL
Java_com_example_packet_1analyzer_LibpcapBridge_nativeInit(JNIEnv *env, jobject thiz,
                                                            jobject service_obj, jstring interface_name) {
    LOGI("Initializing libpcap capture");

    // Get JavaVM
    (*env)->GetJavaVM(env, &g_pcap_ctx.vm);

    // Store service object
    g_pcap_ctx.service_obj = (*env)->NewGlobalRef(env, service_obj);

    // Get callback methods
    jclass serviceClass = (*env)->GetObjectClass(env, service_obj);
    g_pcap_ctx.packet_callback_mid = (*env)->GetMethodID(env, serviceClass,
        "onPacketCaptured", "(Ljava/util/Map;)V");
    g_pcap_ctx.status_callback_mid = (*env)->GetMethodID(env, serviceClass,
        "onStatusUpdate", "(Ljava/lang/String;)V");

    if (!g_pcap_ctx.packet_callback_mid || !g_pcap_ctx.status_callback_mid) {
        LOGE("Failed to find callback methods");
        return JNI_FALSE;
    }

    // Get interface name
    const char *iface = (*env)->GetStringUTFChars(env, interface_name, NULL);
    g_pcap_ctx.interface = strdup(iface);
    (*env)->ReleaseStringUTFChars(env, interface_name, iface);

    // Open pcap device
    char errbuf[PCAP_ERRBUF_SIZE];
    g_pcap_ctx.handle = pcap_open_live(g_pcap_ctx.interface, 65536, 1, 1000, errbuf);

    if (g_pcap_ctx.handle == NULL) {
        LOGE("pcap_open_live failed: %s", errbuf);
        free(g_pcap_ctx.interface);
        return JNI_FALSE;
    }

    // Apply any filter that was set before init
    if (g_pending_filter[0] != '\0') {
        if (apply_bpf_filter(g_pcap_ctx.handle, g_pending_filter) == JNI_FALSE) {
            LOGE("Deferred BPF filter failed — continuing without filter");
        }
    }

    LOGI("Libpcap initialized successfully on %s", g_pcap_ctx.interface);
    return JNI_TRUE;
}

// JNI: Start capture
JNIEXPORT jboolean JNICALL
Java_com_example_packet_1analyzer_LibpcapBridge_nativeStartCapture(JNIEnv *env, jobject thiz) {
    LOGI("Starting libpcap capture thread");

    if (!g_pcap_ctx.handle) {
        LOGE("Libpcap not initialized");
        return JNI_FALSE;
    }

    g_pcap_ctx.running = 1;

    // Create capture thread
    int result = pthread_create(&g_pcap_ctx.capture_thread, NULL, capture_thread_func, &g_pcap_ctx);
    if (result != 0) {
        LOGE("Failed to create capture thread: %d", result);
        g_pcap_ctx.running = 0;
        return JNI_FALSE;
    }

    LOGI("Capture thread started successfully");
    return JNI_TRUE;
}

// JNI: Stop capture
JNIEXPORT void JNICALL
Java_com_example_packet_1analyzer_LibpcapBridge_nativeStopCapture(JNIEnv *env, jobject thiz) {
    LOGI("Stopping libpcap capture");

    g_pcap_ctx.running = 0;

    if (g_pcap_ctx.handle) {
        pcap_breakloop(g_pcap_ctx.handle);
    }

    // Wait for thread to finish
    if (g_pcap_ctx.capture_thread) {
        pthread_join(g_pcap_ctx.capture_thread, NULL);
        g_pcap_ctx.capture_thread = 0;
    }

    LOGI("Capture stopped");
}

// JNI: Cleanup
JNIEXPORT void JNICALL
Java_com_example_packet_1analyzer_LibpcapBridge_nativeCleanup(JNIEnv *env, jobject thiz) {
    LOGI("Cleaning up libpcap");

    g_pcap_ctx.running = 0;

    if (g_pcap_ctx.handle) {
        pcap_close(g_pcap_ctx.handle);
        g_pcap_ctx.handle = NULL;
    }

    if (g_pcap_ctx.service_obj) {
        (*env)->DeleteGlobalRef(env, g_pcap_ctx.service_obj);
        g_pcap_ctx.service_obj = NULL;
    }

    if (g_pcap_ctx.interface) {
        free(g_pcap_ctx.interface);
        g_pcap_ctx.interface = NULL;
    }

    LOGI("Libpcap cleanup complete");
}

// JNI: Get available interfaces
JNIEXPORT jobjectArray JNICALL
Java_com_example_packet_1analyzer_LibpcapBridge_nativeGetInterfaces(JNIEnv *env, jobject thiz) {
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        LOGE("pcap_findalldevs failed: %s", errbuf);
        return NULL;
    }

    // Count devices
    int count = 0;
    for (d = alldevs; d != NULL; d = d->next) {
        count++;
    }

    // Create string array
    jclass stringClass = (*env)->FindClass(env, "java/lang/String");
    jobjectArray result = (*env)->NewObjectArray(env, count, stringClass, NULL);

    // Fill array
    int i = 0;
    for (d = alldevs; d != NULL; d = d->next) {
        jstring name = (*env)->NewStringUTF(env, d->name);
        (*env)->SetObjectArrayElement(env, result, i++, name);
        (*env)->DeleteLocalRef(env, name);
    }

    pcap_freealldevs(alldevs);
    return result;
}

// JNI: Set BPF packet filter (call after nativeInit, before nativeStartCapture)
JNIEXPORT jboolean JNICALL
Java_com_example_packet_1analyzer_LibpcapBridge_nativeSetPacketFilter(
        JNIEnv *env, jobject thiz, jstring filter_expr) {
    const char *filter = (*env)->GetStringUTFChars(env, filter_expr, NULL);
    if (!filter) return JNI_FALSE;

    if (filter[0] == '\0') {
        // Empty string = clear filter
        g_pending_filter[0] = '\0';
        (*env)->ReleaseStringUTFChars(env, filter_expr, filter);
        LOGI("BPF filter cleared");
        return JNI_TRUE;
    }

    snprintf(g_pending_filter, sizeof(g_pending_filter), "%s", filter);
    (*env)->ReleaseStringUTFChars(env, filter_expr, filter);

    if (!g_pcap_ctx.handle) {
        LOGI("BPF filter stored, will apply on nativeInit: %s", g_pending_filter);
        return JNI_TRUE;
    }

    return apply_bpf_filter(g_pcap_ctx.handle, g_pending_filter);
}
