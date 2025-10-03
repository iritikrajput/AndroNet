#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <android/log.h>

#define TAG "PcapWriter"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// PCAP file format structures
#define PCAP_MAGIC 0xa1b2c3d4
#define PCAP_VERSION_MAJOR 2
#define PCAP_VERSION_MINOR 4
#define PCAP_SNAPLEN 65535
#define LINKTYPE_RAW 101  // Raw IP packets
#define LINKTYPE_ETHERNET 1

typedef struct {
    uint32_t magic;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t linktype;
} pcap_file_header_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} pcap_packet_header_t;

// Global context
typedef struct {
    FILE *file;
    char *filepath;
    uint32_t packet_count;
    uint64_t total_bytes;
    int linktype;
} pcap_writer_ctx_t;

static pcap_writer_ctx_t g_writer_ctx = {0};

// JNI: Initialize PCAP writer
JNIEXPORT jboolean JNICALL
Java_com_example_packet_1analyzer_PcapWriter_nativeInit(JNIEnv *env, jobject thiz,
                                                         jstring filepath, jint linktype) {
    LOGI("Initializing PCAP writer");

    // Close any existing file
    if (g_writer_ctx.file) {
        fclose(g_writer_ctx.file);
        g_writer_ctx.file = NULL;
    }

    // Get filepath
    const char *path = (*env)->GetStringUTFChars(env, filepath, NULL);
    if (g_writer_ctx.filepath) {
        free(g_writer_ctx.filepath);
    }
    g_writer_ctx.filepath = strdup(path);
    (*env)->ReleaseStringUTFChars(env, filepath, path);

    // Open file for writing
    g_writer_ctx.file = fopen(g_writer_ctx.filepath, "wb");
    if (!g_writer_ctx.file) {
        LOGE("Failed to open file: %s", g_writer_ctx.filepath);
        return JNI_FALSE;
    }

    // Set linktype
    g_writer_ctx.linktype = (linktype == 0) ? LINKTYPE_RAW : linktype;
    g_writer_ctx.packet_count = 0;
    g_writer_ctx.total_bytes = 0;

    // Write PCAP file header
    pcap_file_header_t file_header = {
        .magic = PCAP_MAGIC,
        .version_major = PCAP_VERSION_MAJOR,
        .version_minor = PCAP_VERSION_MINOR,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = PCAP_SNAPLEN,
        .linktype = g_writer_ctx.linktype
    };

    size_t written = fwrite(&file_header, sizeof(pcap_file_header_t), 1, g_writer_ctx.file);
    if (written != 1) {
        LOGE("Failed to write PCAP file header");
        fclose(g_writer_ctx.file);
        g_writer_ctx.file = NULL;
        return JNI_FALSE;
    }

    fflush(g_writer_ctx.file);

    LOGI("PCAP writer initialized: %s (linktype=%d)", g_writer_ctx.filepath, g_writer_ctx.linktype);
    return JNI_TRUE;
}

// JNI: Write a packet to PCAP file
JNIEXPORT jboolean JNICALL
Java_com_example_packet_1analyzer_PcapWriter_nativeWritePacket(JNIEnv *env, jobject thiz,
                                                                jbyteArray packet_data,
                                                                jlong timestamp_ms) {
    if (!g_writer_ctx.file) {
        LOGE("PCAP writer not initialized");
        return JNI_FALSE;
    }

    // Get packet data
    jsize packet_len = (*env)->GetArrayLength(env, packet_data);
    jbyte *packet_bytes = (*env)->GetByteArrayElements(env, packet_data, NULL);

    if (!packet_bytes) {
        LOGE("Failed to get packet data");
        return JNI_FALSE;
    }

    // Convert timestamp from milliseconds to seconds and microseconds
    uint32_t ts_sec = (uint32_t)(timestamp_ms / 1000);
    uint32_t ts_usec = (uint32_t)((timestamp_ms % 1000) * 1000);

    // Write packet header
    pcap_packet_header_t pkt_header = {
        .ts_sec = ts_sec,
        .ts_usec = ts_usec,
        .incl_len = (uint32_t)packet_len,
        .orig_len = (uint32_t)packet_len
    };

    size_t written = fwrite(&pkt_header, sizeof(pcap_packet_header_t), 1, g_writer_ctx.file);
    if (written != 1) {
        LOGE("Failed to write packet header");
        (*env)->ReleaseByteArrayElements(env, packet_data, packet_bytes, JNI_ABORT);
        return JNI_FALSE;
    }

    // Write packet data
    written = fwrite(packet_bytes, 1, packet_len, g_writer_ctx.file);
    if (written != packet_len) {
        LOGE("Failed to write packet data (expected %d, wrote %zu)", packet_len, written);
        (*env)->ReleaseByteArrayElements(env, packet_data, packet_bytes, JNI_ABORT);
        return JNI_FALSE;
    }

    // Update statistics
    g_writer_ctx.packet_count++;
    g_writer_ctx.total_bytes += packet_len;

    // Flush periodically (every 100 packets)
    if (g_writer_ctx.packet_count % 100 == 0) {
        fflush(g_writer_ctx.file);
    }

    (*env)->ReleaseByteArrayElements(env, packet_data, packet_bytes, JNI_ABORT);
    return JNI_TRUE;
}

// JNI: Get statistics
JNIEXPORT jobject JNICALL
Java_com_example_packet_1analyzer_PcapWriter_nativeGetStats(JNIEnv *env, jobject thiz) {
    // Create HashMap for stats
    jclass hashMapClass = (*env)->FindClass(env, "java/util/HashMap");
    jmethodID hashMapInit = (*env)->GetMethodID(env, hashMapClass, "<init>", "()V");
    jmethodID hashMapPut = (*env)->GetMethodID(env, hashMapClass, "put",
        "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");

    jobject statsMap = (*env)->NewObject(env, hashMapClass, hashMapInit);

    // Helper to add long to map
    #define PUT_LONG(key, value) { \
        jstring jkey = (*env)->NewStringUTF(env, key); \
        jclass longClass = (*env)->FindClass(env, "java/lang/Long"); \
        jmethodID longInit = (*env)->GetMethodID(env, longClass, "<init>", "(J)V"); \
        jobject jvalue = (*env)->NewObject(env, longClass, longInit, (jlong)value); \
        (*env)->CallObjectMethod(env, statsMap, hashMapPut, jkey, jvalue); \
        (*env)->DeleteLocalRef(env, jkey); \
        (*env)->DeleteLocalRef(env, jvalue); \
    }

    // Helper to add string to map
    #define PUT_STRING(key, value) { \
        jstring jkey = (*env)->NewStringUTF(env, key); \
        jstring jvalue = (*env)->NewStringUTF(env, value); \
        (*env)->CallObjectMethod(env, statsMap, hashMapPut, jkey, jvalue); \
        (*env)->DeleteLocalRef(env, jkey); \
        (*env)->DeleteLocalRef(env, jvalue); \
    }

    PUT_LONG("packetCount", g_writer_ctx.packet_count);
    PUT_LONG("totalBytes", g_writer_ctx.total_bytes);
    PUT_STRING("filepath", g_writer_ctx.filepath ? g_writer_ctx.filepath : "");

    #undef PUT_LONG
    #undef PUT_STRING

    return statsMap;
}

// JNI: Close PCAP file
JNIEXPORT void JNICALL
Java_com_example_packet_1analyzer_PcapWriter_nativeClose(JNIEnv *env, jobject thiz) {
    LOGI("Closing PCAP writer");

    if (g_writer_ctx.file) {
        fflush(g_writer_ctx.file);
        fclose(g_writer_ctx.file);
        g_writer_ctx.file = NULL;

        LOGI("PCAP file closed: %d packets, %llu bytes",
             g_writer_ctx.packet_count,
             (unsigned long long)g_writer_ctx.total_bytes);
    }

    if (g_writer_ctx.filepath) {
        free(g_writer_ctx.filepath);
        g_writer_ctx.filepath = NULL;
    }

    g_writer_ctx.packet_count = 0;
    g_writer_ctx.total_bytes = 0;
}
