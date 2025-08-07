#include <jni.h>
#include <string>
#include <android/log.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <thread>
#include <atomic>
#include <errno.h>

#include "packet_parser.h"
#include "session_manager.h"
#include "socket_forwarder.h"

#define TAG "PacketAnalyzer"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Forward declarations
void sendPacketToJava(const PacketInfo &packet);

// Global variables
static JavaVM *g_vm = nullptr;
static std::atomic<bool> g_capture_running{false};
static std::thread g_capture_thread;
static int g_tun_fd = -1;
static pcap_t *g_pcap_handle = nullptr;

// VPN packet processing function
void processVpnPackets()
{
    uint8_t buffer[4096];

    LOGD("Starting VPN packet processing thread");

    while (g_capture_running && g_tun_fd != -1)
    {
        ssize_t length = read(g_tun_fd, buffer, sizeof(buffer));

        if (length > 0)
        {
            PacketInfo packet = PacketParser::parsePacket(buffer, length);

            if (!packet.protocol.empty())
            {
                // Update statistics
                SessionManager::getInstance().updateProtocolStats(packet.protocol, packet.size);

                // Send to Java/Flutter
                sendPacketToJava(packet);

                // Forward packet through socket
                SessionKey key{packet.source_ip, packet.source_port,
                               packet.dest_ip, packet.dest_port, packet.protocol};
                SocketForwarder::getInstance().forwardPacket(key, buffer, length);
            }
        }
        else if (length < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
        {
            LOGE("Error reading from TUN: %d", errno);
            break;
        }

        // Small delay to prevent busy waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    LOGD("VPN packet processing thread stopped");
}

// Pcap packet handler for rooted capture
void packet_handler(u_char *user_data, const struct pcap_pkthdr *header, const u_char *packet)
{
    if (!g_capture_running)
        return;

    PacketInfo parsed_packet = PacketParser::parsePacket(packet, header->len);

    if (!parsed_packet.protocol.empty())
    {
        SessionManager::getInstance().updateProtocolStats(parsed_packet.protocol, parsed_packet.size);
        sendPacketToJava(parsed_packet);
    }
}

// Rooted capture using libpcap
void processRootedCapture()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    LOGD("Attempting to open pcap interface");

    // Try different interface names for Android
    const char *interfaces[] = {"any", "wlan0", "eth0", "rmnet0", "rmnet_data0"};
    int interface_count = sizeof(interfaces) / sizeof(interfaces[0]);

    for (int i = 0; i < interface_count && !g_pcap_handle; i++)
    {
        g_pcap_handle = pcap_open_live(interfaces[i], 65536, 1, 1000, errbuf);
        if (g_pcap_handle)
        {
            LOGD("Successfully opened pcap on interface: %s", interfaces[i]);
            break;
        }
        else
        {
            LOGD("Failed to open interface %s: %s", interfaces[i], errbuf);
        }
    }

    if (!g_pcap_handle)
    {
        LOGE("Failed to open any pcap interface");
        return;
    }

    LOGD("Started rooted packet capture");

    // Start packet capture loop
    int result = pcap_loop(g_pcap_handle, -1, packet_handler, nullptr);
    if (result < 0)
    {
        LOGE("pcap_loop failed: %s", pcap_geterr(g_pcap_handle));
    }

    LOGD("Rooted packet capture stopped");
}

// JNI function implementations
extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    g_vm = vm;
    LOGD("Native library loaded");
    return JNI_VERSION_1_6;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_packet_1analyzer_NativeInterface_initializeVpnCapture(JNIEnv *env, jobject thiz, jint fd)
{
    g_tun_fd = fd;
    LOGD("VPN capture initialized with FD: %d", fd);
    return JNI_TRUE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_packet_1analyzer_NativeInterface_processPacket(JNIEnv *env, jobject thiz, jbyteArray packet_array, jint length)
{
    if (!g_capture_running)
    {
        g_capture_running = true;
        g_capture_thread = std::thread(processVpnPackets);
        LOGD("Started VPN packet processing");
    }
    return JNI_TRUE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_packet_1analyzer_NativeInterface_startRootedCapture(JNIEnv *env, jobject thiz)
{
    if (g_capture_running)
    {
        LOGE("Capture already running");
        return JNI_FALSE;
    }

    LOGD("Starting rooted capture");
    g_capture_running = true;
    g_capture_thread = std::thread(processRootedCapture);

    return JNI_TRUE;
}

extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_packet_1analyzer_NativeInterface_stopRootedCapture(JNIEnv *env, jobject thiz)
{
    LOGD("Stopping rooted capture");
    g_capture_running = false;

    if (g_pcap_handle)
    {
        pcap_breakloop(g_pcap_handle);
        pcap_close(g_pcap_handle);
        g_pcap_handle = nullptr;
    }

    if (g_capture_thread.joinable())
    {
        g_capture_thread.join();
    }

    return JNI_TRUE;
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_packet_1analyzer_NativeInterface_cleanup(JNIEnv *env, jobject thiz)
{
    LOGD("Cleaning up native resources");
    g_capture_running = false;

    if (g_capture_thread.joinable())
    {
        g_capture_thread.join();
    }

    if (g_pcap_handle)
    {
        pcap_close(g_pcap_handle);
        g_pcap_handle = nullptr;
    }

    SocketForwarder::getInstance().cleanup();
    SessionManager::getInstance().resetStats();

    g_tun_fd = -1;
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_packet_1analyzer_NativeInterface_clearPackets(JNIEnv *env, jobject thiz)
{
    LOGD("Clearing packet statistics");
    SessionManager::getInstance().resetStats();
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_packet_1analyzer_NativeInterface_pauseCapture(JNIEnv *env, jobject thiz)
{
    LOGD("Pause capture requested");
    // Implementation can be added here if needed
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_packet_1analyzer_NativeInterface_resumeCapture(JNIEnv *env, jobject thiz)
{
    LOGD("Resume capture requested");
    // Implementation can be added here if needed
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_packet_1analyzer_NativeInterface_exportPackets(JNIEnv *env, jobject thiz)
{
    LOGD("Export packets requested");

    // Simple export implementation - can be enhanced
    auto stats = SessionManager::getInstance().getProtocolStats();
    std::string export_data = "Packet Export\n=============\n";

    for (const auto &stat : stats)
    {
        export_data += "Protocol: " + stat.protocol +
                       ", Packets: " + std::to_string(stat.packet_count) +
                       ", Bytes: " + std::to_string(stat.total_bytes) + "\n";
    }

    return env->NewStringUTF(export_data.c_str());
}

// Helper function to send packet data to Java/Flutter
void sendPacketToJava(const PacketInfo &packet)
{
    if (!g_vm)
    {
        LOGE("JavaVM not available");
        return;
    }

    JNIEnv *env;
    if (g_vm->GetEnv((void **)&env, JNI_VERSION_1_6) != JNI_OK)
    {
        if (g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK)
        {
            LOGE("Failed to attach current thread");
            return;
        }
    }

    jclass cls = env->FindClass("com/example/packet_analyzer/NativeInterface");
    if (!cls)
    {
        LOGE("Could not find NativeInterface class");
        return;
    }

    jmethodID method = env->GetStaticMethodID(cls, "sendPacketToFlutter",
                                              "(Ljava/lang/String;Ljava/lang/String;IILjava/lang/String;ILjava/lang/String;Ljava/lang/String;)V");

    if (method)
    {
        jstring sourceIp = env->NewStringUTF(packet.source_ip.c_str());
        jstring destIp = env->NewStringUTF(packet.dest_ip.c_str());
        jstring protocol = env->NewStringUTF(packet.protocol.c_str());
        jstring timestamp = env->NewStringUTF(PacketParser::getCurrentTimestamp().c_str());
        jstring payload = env->NewStringUTF(packet.payload.c_str());

        env->CallStaticVoidMethod(cls, method, sourceIp, destIp,
                                  (jint)packet.source_port, (jint)packet.dest_port,
                                  protocol, timestamp, payload);

        // Clean up local references
        env->DeleteLocalRef(sourceIp);
        env->DeleteLocalRef(destIp);
        env->DeleteLocalRef(protocol);
        env->DeleteLocalRef(timestamp);
        env->DeleteLocalRef(payload);
    }
    else
    {
        LOGE("Could not find sendPacketToFlutter method");
    }

    env->DeleteLocalRef(cls);
}

// Additional utility functions
extern "C" JNIEXPORT jboolean JNICALL
Java_com_example_packet_1analyzer_NativeInterface_isCapturing(JNIEnv *env, jobject thiz)
{
    return g_capture_running ? JNI_TRUE : JNI_FALSE;
}

extern "C" JNIEXPORT jstring JNICALL
Java_com_example_packet_1analyzer_NativeInterface_getStats(JNIEnv *env, jobject thiz)
{
    auto stats = SessionManager::getInstance().getProtocolStats();
    std::string stats_json = "[";

    for (size_t i = 0; i < stats.size(); i++)
    {
        if (i > 0)
            stats_json += ",";
        stats_json += "{";
        stats_json += "\"protocol\":\"" + stats[i].protocol + "\",";
        stats_json += "\"packetCount\":" + std::to_string(stats[i].packet_count) + ",";
        stats_json += "\"totalBytes\":" + std::to_string(stats[i].total_bytes);
        stats_json += "}";
    }

    stats_json += "]";
    return env->NewStringUTF(stats_json.c_str());
}

// Error handling helper
extern "C" JNIEXPORT void JNICALL
Java_com_example_packet_1analyzer_NativeInterface_sendError(JNIEnv *env, jobject thiz, jstring error)
{
    const char *error_str = env->GetStringUTFChars(error, nullptr);
    LOGE("Error from Java: %s", error_str);
    env->ReleaseStringUTFChars(error, error_str);
}
