#include <jni.h>
#include <string>
#include <android/log.h>

// Logging macros
#define LOG_TAG "PacketAnalyzer"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// Standard + networking headers
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>

#include "packet_parser.h"
#include "session_manager.h"
#include "socket_forwarder.h"

// ---- Globals ----
static bool g_capture_running = false;
static JavaVM *g_vm = nullptr;
static jobject g_callbackObj = nullptr;

// ---- JNI lifecycle ----
jint JNI_OnLoad(JavaVM *vm, void *reserved)
{
    g_vm = vm;
    return JNI_VERSION_1_6;
}

// Called from Java to set callback object
extern "C" JNIEXPORT void JNICALL
Java_com_example_packet_1analyzer_NativeInterface_setPacketCallback(JNIEnv *env, jobject thiz, jobject callback)
{
    if (g_callbackObj != nullptr)
    {
        env->DeleteGlobalRef(g_callbackObj);
        g_callbackObj = nullptr;
    }
    g_callbackObj = env->NewGlobalRef(callback);
}

// ---- Helper: send packet back to Java ----
void sendPacketToJava(const PacketInfo &pkt)
{
    if (!g_vm)
        return;

    JNIEnv *env = nullptr;
    if (g_vm->AttachCurrentThread(&env, nullptr) != JNI_OK)
    {
        return;
    }

    jclass cls = env->FindClass("com/example/packet_analyzer/NativeInterface");
    if (!cls)
        return;

    jmethodID mid = env->GetStaticMethodID(
        cls,
        "sendPacketToFlutter",
        "(Ljava/lang/String;Ljava/lang/String;IILjava/lang/String;ILjava/lang/String;Ljava/lang/String;)V");
    if (!mid)
        return;

    jstring jsrc = env->NewStringUTF(pkt.source_ip.c_str());
    jstring jdst = env->NewStringUTF(pkt.dest_ip.c_str());
    jstring jproto = env->NewStringUTF(pkt.protocol.c_str());

    jint jSrcPort = pkt.source_port;
    jint jDstPort = pkt.dest_port;
    jint jSize = pkt.size;

    // TODO: replace with real timestamp & payload later
    jstring jTimestamp = env->NewStringUTF("0");
    jstring jPayload = env->NewStringUTF("");

    env->CallStaticVoidMethod(cls, mid,
                              jsrc, jdst, jSrcPort, jDstPort, jproto, jSize, jTimestamp, jPayload);

    env->DeleteLocalRef(jsrc);
    env->DeleteLocalRef(jdst);
    env->DeleteLocalRef(jproto);
    env->DeleteLocalRef(jTimestamp);
    env->DeleteLocalRef(jPayload);
}

// ---- Raw PF_PACKET capture implementation ----
static int set_if_promisc_sock(const char *ifname, int sockfd)
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) < 0)
    {
        LOGE("SIOCGIFFLAGS failed: %s", strerror(errno));
        return -1;
    }
    ifr.ifr_flags |= IFF_PROMISC;
    if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) < 0)
    {
        LOGE("SIOCSIFFLAGS failed: %s", strerror(errno));
        return -1;
    }
    return 0;
}

void processRootedCaptureRawSocket()
{
    LOGD("Starting raw PF_PACKET capture (rooted)");
    const char *interfaces[] = {"wlan0", "eth0", "rmnet0", "rmnet_data0"};
    int interface_count = sizeof(interfaces) / sizeof(interfaces[0]);

    const size_t BUF_SZ = 262144;
    uint8_t *buf = (uint8_t *)malloc(BUF_SZ);
    if (!buf)
    {
        LOGE("malloc failed");
        return;
    }

    int sockfd = -1;
    for (int i = 0; i < interface_count; ++i)
    {
        const char *ifname = interfaces[i];
        sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (sockfd < 0)
        {
            LOGE("socket() failed: %s", strerror(errno));
            free(buf);
            return;
        }

        int ifindex = if_nametoindex(ifname);
        if (ifindex == 0)
        {
            close(sockfd);
            continue;
        }

        int flags = fcntl(sockfd, F_GETFL, 0);
        if (flags != -1)
            fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

        set_if_promisc_sock(ifname, sockfd);

        struct sockaddr_ll sll;
        memset(&sll, 0, sizeof(sll));
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex = ifindex;

        if (bind(sockfd, (struct sockaddr *)&sll, sizeof(sll)) == 0)
        {
            LOGD("Bound PF_PACKET socket to %s", ifname);
            break;
        }
        else
        {
            close(sockfd);
            sockfd = -1;
        }
    }

    if (sockfd < 0)
    {
        LOGE("No interface bound, exiting rooted capture");
        free(buf);
        return;
    }

    g_capture_running = true;

    while (g_capture_running)
    {
        ssize_t n = recvfrom(sockfd, buf, BUF_SZ, 0, NULL, NULL);
        if (n > 0)
        {
            const size_t ETH_HDR_SZ = 14;
            const uint8_t *payload = buf;
            int payload_len = (int)n;

            if (payload_len >= (int)ETH_HDR_SZ)
            {
                uint16_t ethertype = (buf[12] << 8) | buf[13];
                if (ethertype == 0x0800)
                {
                    payload = buf + ETH_HDR_SZ;
                    payload_len = (int)n - ETH_HDR_SZ;
                }
            }

            if (payload_len > 0)
            {
                PacketInfo pkt = PacketParser::parsePacket(payload, payload_len);
                if (!pkt.protocol.empty())
                {
                    SessionManager::getInstance().updateProtocolStats(pkt.protocol, pkt.size);
                    sendPacketToJava(pkt);

                    SessionKey key{pkt.source_ip, pkt.source_port, pkt.dest_ip, pkt.dest_port, pkt.protocol};
                    SocketForwarder::getInstance().forwardPacket(key, payload, payload_len);
                }
            }
        }
        else if (n == -1 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
        {
            LOGE("recvfrom error: %s", strerror(errno));
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }

    LOGD("Raw PF_PACKET capture stopping");
    close(sockfd);
    free(buf);
    g_capture_running = false;
}

// ---- JNI controls ----
extern "C" JNIEXPORT void JNICALL
Java_com_example_packet_1analyzer_NativeInterface_startRootedCapture(JNIEnv *env, jobject thiz)
{
    if (!g_capture_running)
    {
        std::thread t(processRootedCaptureRawSocket);
        t.detach();
    }
}

extern "C" JNIEXPORT void JNICALL
Java_com_example_packet_1analyzer_NativeInterface_stopRootedCapture(JNIEnv *env, jobject thiz)
{
    g_capture_running = false;
}
