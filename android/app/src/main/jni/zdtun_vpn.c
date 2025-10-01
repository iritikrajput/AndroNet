/*
 * zdtun VPN JNI Bridge
 * Based on PCAPdroid's capture_vpn.c implementation
 */

#include <jni.h>
#include <android/log.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <errno.h>
#include <time.h>
#include "../zdtun/zdtun.h"

#define TAG "ZdtunVPN"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define VPN_BUFFER_SIZE 32768

typedef struct {
    zdtun_t *tun;
    int tunfd;
    JavaVM *vm;
    jobject vpn_service;
    jmethodID protect_socket_mid;
    jmethodID send_packet_mid;
    int running;
} vpn_context_t;

// Global context
static vpn_context_t g_ctx = {0};

/* Callback: send packet back to VPN (remote → client) */
static int send_client_callback(zdtun_t *tun, zdtun_pkt_t *pkt, const zdtun_conn_t *conn_info) {
    vpn_context_t *ctx = (vpn_context_t*) zdtun_userdata(tun);

    if(!ctx->running) {
        return 0;
    }

    // Call Java sendPacketToVpn method which will:
    // 1. Write packet to TUN
    // 2. Parse and display in UI
    JNIEnv *env;
    jint result = (*ctx->vm)->AttachCurrentThread(ctx->vm, &env, NULL);
    if (result == JNI_OK) {
        // Create byte array from packet
        jbyteArray packetData = (*env)->NewByteArray(env, pkt->len);
        if (packetData != NULL) {
            (*env)->SetByteArrayRegion(env, packetData, 0, pkt->len, (jbyte*)pkt->buf);

            // Call sendPacketToVpn method
            (*env)->CallVoidMethod(env, ctx->vpn_service, ctx->send_packet_mid, packetData);

            if ((*env)->ExceptionCheck(env)) {
                (*env)->ExceptionDescribe(env);
                (*env)->ExceptionClear(env);
                LOGE("Exception calling sendPacketToVpn");
            }

            (*env)->DeleteLocalRef(env, packetData);
        }
    }

    return 0;
}

/* Callback: protect socket to prevent VPN loop */
static void protect_socket_callback(zdtun_t *tun, socket_t sock) {
    vpn_context_t *ctx = (vpn_context_t*) zdtun_userdata(tun);
    JNIEnv *env;

    // Attach to current thread to get valid JNIEnv
    jint result = (*ctx->vm)->AttachCurrentThread(ctx->vm, &env, NULL);
    if (result != JNI_OK) {
        LOGE("Failed to attach thread for socket protection");
        return;
    }

    // Call VpnService.protect()
    jboolean protected = (*env)->CallBooleanMethod(env, ctx->vpn_service,
                                                    ctx->protect_socket_mid, (jint)sock);

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
    }

    if (!protected) {
        LOGW("Socket protection failed for fd %d", sock);
    } else {
        LOGI("Socket protected: fd=%d", sock);
    }

    // Note: Don't detach - zdtun manages its own threads
    // Detaching here causes "attempting to detach while still running code" crash
}

/*
 * Initialize zdtun
 */
JNIEXPORT jboolean JNICALL
Java_com_example_packet_1analyzer_ZdtunVpn_nativeInit(JNIEnv *env, jobject thiz,
                                                        jobject vpn_service, jint tunfd) {
    LOGI("Initializing zdtun");

    // Save JVM reference
    if ((*env)->GetJavaVM(env, &g_ctx.vm) != JNI_OK) {
        LOGE("Failed to get JavaVM");
        return JNI_FALSE;
    }

    g_ctx.tunfd = tunfd;
    g_ctx.running = 1;

    // Save VpnService global reference
    g_ctx.vpn_service = (*env)->NewGlobalRef(env, vpn_service);
    if (g_ctx.vpn_service == NULL) {
        LOGE("Failed to create global ref for VpnService");
        return JNI_FALSE;
    }

    // Get method IDs
    jclass vpn_class = (*env)->GetObjectClass(env, vpn_service);
    g_ctx.protect_socket_mid = (*env)->GetMethodID(env, vpn_class, "protectSocket", "(I)Z");

    if (g_ctx.protect_socket_mid == NULL) {
        LOGE("Failed to get protectSocket method ID");
        (*env)->DeleteGlobalRef(env, g_ctx.vpn_service);
        return JNI_FALSE;
    }

    // Get sendPacketToVpn method ID for incoming packet display
    g_ctx.send_packet_mid = (*env)->GetMethodID(env, vpn_class, "sendPacketToVpn", "([B)V");

    if (g_ctx.send_packet_mid == NULL) {
        LOGE("Failed to get sendPacketToVpn method ID");
        (*env)->DeleteGlobalRef(env, g_ctx.vpn_service);
        return JNI_FALSE;
    }

    // Initialize zdtun callbacks
    zdtun_callbacks_t callbacks = {
        .send_client = send_client_callback,
        .on_socket_open = protect_socket_callback,
        .account_packet = NULL,
        .on_connection_open = NULL,
        .on_connection_close = NULL,
    };

    g_ctx.tun = zdtun_init(&callbacks, &g_ctx);
    if (g_ctx.tun == NULL) {
        LOGE("zdtun_init failed");
        (*env)->DeleteGlobalRef(env, g_ctx.vpn_service);
        return JNI_FALSE;
    }

    // Set MTU
    zdtun_set_mtu(g_ctx.tun, 1500);

    LOGI("zdtun initialized successfully");
    return JNI_TRUE;
}

/*
 * Handle packet from TUN interface
 */
JNIEXPORT void JNICALL
Java_com_example_packet_1analyzer_ZdtunVpn_nativeHandlePacket(JNIEnv *env, jobject thiz,
                                                                jbyteArray packet) {
    if (g_ctx.tun == NULL || !g_ctx.running) {
        return;
    }

    jsize len = (*env)->GetArrayLength(env, packet);
    jbyte *pkt_buf = (*env)->GetByteArrayElements(env, packet, NULL);

    if (pkt_buf == NULL) {
        LOGE("Failed to get packet buffer");
        return;
    }

    // Parse packet
    zdtun_pkt_t pkt;
    if (zdtun_parse_pkt(g_ctx.tun, (const char *)pkt_buf, len, &pkt) != 0) {
        LOGW("zdtun_parse_pkt failed");
        (*env)->ReleaseByteArrayElements(env, packet, pkt_buf, JNI_ABORT);
        return;
    }

    // Skip IP fragments
    if (pkt.flags & ZDTUN_PKT_IS_FRAGMENT) {
        LOGW("Skipping IP fragment");
        (*env)->ReleaseByteArrayElements(env, packet, pkt_buf, JNI_ABORT);
        return;
    }

    // Determine if this is a new connection
    uint8_t is_new = 0;
    if (pkt.tuple.ipproto == IPPROTO_TCP) {
        // New connection if SYN without ACK
        is_new = (pkt.tcp->th_flags & TH_SYN) && !(pkt.tcp->th_flags & TH_ACK);
    } else {
        // UDP: always try to create
        is_new = 1;
    }

    // Lookup or create connection
    zdtun_conn_t *conn = zdtun_lookup(g_ctx.tun, &pkt.tuple, is_new);
    if (!conn) {
        if (is_new) {
            LOGE("zdtun_lookup failed to create connection");
        }
        (*env)->ReleaseByteArrayElements(env, packet, pkt_buf, JNI_ABORT);
        return;
    }

    // Forward packet to remote server
    if (zdtun_forward(g_ctx.tun, &pkt, conn) != 0) {
        LOGE("zdtun_forward failed");
        zdtun_conn_close(g_ctx.tun, conn, CONN_STATUS_ERROR);
    }

    (*env)->ReleaseByteArrayElements(env, packet, pkt_buf, JNI_ABORT);
}

/*
 * Process zdtun events (handles socket I/O)
 */
JNIEXPORT void JNICALL
Java_com_example_packet_1analyzer_ZdtunVpn_nativeHandleEvents(JNIEnv *env, jobject thiz,
                                                                jint timeout_ms) {
    if (g_ctx.tun == NULL || !g_ctx.running) {
        return;
    }

    fd_set rdset, wrset;
    int max_fd = 0;
    struct timeval timeout = {
        .tv_sec = timeout_ms / 1000,
        .tv_usec = (timeout_ms % 1000) * 1000
    };

    // Get zdtun's file descriptors
    zdtun_fds(g_ctx.tun, &max_fd, &rdset, &wrset);

    // Wait for activity
    int ret = select(max_fd + 1, &rdset, &wrset, NULL, &timeout);
    if (ret < 0) {
        if (errno != EINTR) {
            LOGE("select error: %s", strerror(errno));
        }
        return;
    }

    if (ret > 0) {
        // Let zdtun handle its sockets
        zdtun_handle_fd(g_ctx.tun, &rdset, &wrset);
    }

    // Periodic cleanup every 30 seconds
    static time_t last_purge = 0;
    time_t now = time(NULL);
    if (now - last_purge >= 30) {
        zdtun_purge_expired(g_ctx.tun);
        last_purge = now;
    }
}

/*
 * Cleanup zdtun
 */
JNIEXPORT void JNICALL
Java_com_example_packet_1analyzer_ZdtunVpn_nativeCleanup(JNIEnv *env, jobject thiz) {
    LOGI("Cleaning up zdtun");

    g_ctx.running = 0;

    if (g_ctx.tun != NULL) {
        zdtun_finalize(g_ctx.tun);
        g_ctx.tun = NULL;
    }

    if (g_ctx.vpn_service != NULL) {
        (*env)->DeleteGlobalRef(env, g_ctx.vpn_service);
        g_ctx.vpn_service = NULL;
    }

    LOGI("zdtun cleanup complete");
}
