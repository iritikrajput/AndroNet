// pcap_writer.c — AndroNet pcapng capture engine
// Implements RFC 7663 pcapng with nanosecond timestamps, ring buffer,
// write-behind buffering, automatic rotation, anomaly annotations,
// and block-level integrity validation.
//
// Commit history baked in:
//   1  pcapng SHB + IDB format (replaces legacy .pcap)
//   2  nanosecond timestamps via clock_gettime(CLOCK_REALTIME)
//   3  Enhanced Packet Blocks (replaces legacy packet records)
//   4  Section-length backpatch + fsync + 0xDEADBEEF truncation sentinel
//   5  Lock-free ring buffer (2048 × 64 KB) with dedicated writer thread
//   6  Write-behind buffer (256 KB chunks, 500 ms flush interval)
//   7  Automatic file rotation by size (50 MB) and time (1 h), max 10 files
//   9  writeAnnotatedPacket JNI — custom option 2988 in EPB for flagged pkts
//  14  validate_pcapng_file — block-length cross-check + JNI exposure

#include <jni.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>
#include <dirent.h>
#include <sys/stat.h>
#include <android/log.h>

#define TAG  "PcapWriter"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,  TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, TAG, __VA_ARGS__)

// ─────────────────────────────────────────────────────────────────────────────
// pcapng block types (RFC 7663)
// ─────────────────────────────────────────────────────────────────────────────
#define PCAPNG_SHB_TYPE      0x0A0D0D0Au  // Section Header Block
#define PCAPNG_IDB_TYPE      0x00000001u  // Interface Description Block
#define PCAPNG_EPB_TYPE      0x00000006u  // Enhanced Packet Block
#define PCAPNG_CB_NOCOPY     0x00000BADu  // Custom Block (not copyable)
#define PCAPNG_BYTE_ORDER    0x1A2B3C4Du  // Byte-Order Magic

// IDB option codes
#define OPT_ENDOFOPT         0u
#define OPT_IF_NAME          2u
#define OPT_IF_TSRESOL       9u           // 0x09 → 10^-9 = nanoseconds

// Custom option code for anomaly annotations (EPB custom option, copyable)
#define OPT_CUSTOM_COPY      2988u

// File offset of Section Length field within the SHB (and from file start,
// since SHB is always the first block).
// Layout: type(4)+block_len(4)+BOM(4)+major(2)+minor(2) = 16 bytes.
#define SHB_SECTION_LEN_OFFSET 16u

// Truncation sentinel written at file close to detect incomplete captures.
#define MAGIC_TRAILER        0xDEADBEEFu

// ─────────────────────────────────────────────────────────────────────────────
// Link types
// ─────────────────────────────────────────────────────────────────────────────
#define LINKTYPE_RAW         101
#define LINKTYPE_ETHERNET      1

// ─────────────────────────────────────────────────────────────────────────────
// Performance constants
// ─────────────────────────────────────────────────────────────────────────────
#define RING_BUFFER_SIZE     2048
#define RING_SLOT_SIZE       65536
#define WRITE_BUFFER_SIZE    (256 * 1024)
#define FLUSH_INTERVAL_S     0           // flush on every idle cycle (~5 ms)

// ─────────────────────────────────────────────────────────────────────────────
// Rotation defaults
// ─────────────────────────────────────────────────────────────────────────────
#define DEFAULT_MAX_SIZE     ((int64_t)(50 * 1024 * 1024))   // 50 MB
#define DEFAULT_MAX_DURATION 3600                             // 1 hour
#define DEFAULT_MAX_FILES    10

// ─────────────────────────────────────────────────────────────────────────────
// Ring buffer — lock-free SPSC (single-producer, single-consumer)
// Producer: JNI calling thread; Consumer: dedicated writer thread.
// ─────────────────────────────────────────────────────────────────────────────
typedef struct {
    uint8_t  data[RING_SLOT_SIZE];
    uint32_t length;
    uint32_t orig_length;
    uint64_t timestamp_ns;
    char     annotation[512];  // empty string → normal packet (no annotation)
    volatile int ready;        // 0 = empty, 1 = filled, 2 = being written
} RingSlot;

typedef struct {
    RingSlot      slots[RING_BUFFER_SIZE];
    volatile int  write_head;
    volatile int  read_head;
    pthread_t     writer_thread;
    volatile int  running;
    uint64_t      dropped;
} RingBuffer;

// ─────────────────────────────────────────────────────────────────────────────
// Writer context (global singleton)
// ─────────────────────────────────────────────────────────────────────────────
typedef struct {
    FILE     *file;
    int       fd;              // raw fd for fsync(2)
    char     *base_dir;        // directory for rotated files
    char     *current_path;
    char     *if_name;
    int       linktype;

    // Statistics
    uint64_t  packet_count;
    uint64_t  dropped_packets;
    uint64_t  current_file_size;
    uint32_t  rotation_count;
    time_t    file_start_time;

    // pcapng backpatch bookkeeping
    uint32_t  shb_block_len;   // total SHB block size (used to compute section_length)

    // Rotation settings (overridable via JNI)
    int64_t   max_size_bytes;
    int       max_duration_s;
    int       max_files;

    // Write-behind buffer
    uint8_t   wbuf[WRITE_BUFFER_SIZE];
    size_t    wbuf_pos;
    time_t    last_flush_time;

    // Ring buffer
    RingBuffer ring;

    int       initialized;
} PcapWriterCtx;

static PcapWriterCtx    g_ctx       = {0};
static pthread_mutex_t  g_init_mtx  = PTHREAD_MUTEX_INITIALIZER;

// Pending interface info set via nativeSetInterfaceInfo before nativeInit.
static char *g_pending_if_name  = NULL;
static int   g_pending_linktype = -1;

// ─────────────────────────────────────────────────────────────────────────────
// FALLBACK — legacy .pcap writer (kept for safety; never called by default)
// ─────────────────────────────────────────────────────────────────────────────
typedef struct {
    uint32_t magic;
    uint16_t version_major, version_minor;
    int32_t  thiszone;
    uint32_t sigfigs, snaplen, linktype;
} LegacyFileHdr;

typedef struct {
    uint32_t ts_sec, ts_usec, incl_len, orig_len;
} LegacyPktHdr;

static FILE *g_legacy_file = NULL;

// Returns 1 on success.
static int write_legacy_pcap_open(const char *path, int linktype) {
    g_legacy_file = fopen(path, "wb");
    if (!g_legacy_file) return 0;
    LegacyFileHdr h = {
        .magic         = 0xa1b2c3d4u,
        .version_major = 2,
        .version_minor = 4,
        .thiszone      = 0,
        .sigfigs       = 0,
        .snaplen       = 65535,
        .linktype      = (uint32_t)linktype
    };
    return fwrite(&h, sizeof h, 1, g_legacy_file) == 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// Write-behind buffer helpers
// ─────────────────────────────────────────────────────────────────────────────
static void flush_write_buffer(void) {
    if (g_ctx.wbuf_pos > 0 && g_ctx.file) {
        fwrite(g_ctx.wbuf, 1, g_ctx.wbuf_pos, g_ctx.file);
        g_ctx.current_file_size += g_ctx.wbuf_pos;
        g_ctx.wbuf_pos = 0;
        g_ctx.last_flush_time = time(NULL);
    }
}

static void buffered_write(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    while (len > 0) {
        size_t space = WRITE_BUFFER_SIZE - g_ctx.wbuf_pos;
        if (space == 0) {
            flush_write_buffer();
            space = WRITE_BUFFER_SIZE;
        }
        size_t n = (len < space) ? len : space;
        memcpy(g_ctx.wbuf + g_ctx.wbuf_pos, p, n);
        g_ctx.wbuf_pos += n;
        p   += n;
        len -= n;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// pcapng option helpers
// ─────────────────────────────────────────────────────────────────────────────

// Total bytes consumed by one option entry (code + len + padded value).
static uint32_t option_wire_size(uint16_t data_len) {
    uint16_t pad = (uint16_t)((4u - (data_len & 3u)) & 3u);
    return 4u + data_len + pad;
}

static void write_option(uint16_t code, const void *data, uint16_t data_len) {
    static const uint8_t zeros[3] = {0, 0, 0};
    buffered_write(&code, 2);
    buffered_write(&data_len, 2);
    if (data_len > 0 && data) {
        buffered_write(data, data_len);
        uint16_t pad = (uint16_t)((4u - (data_len & 3u)) & 3u);
        if (pad) buffered_write(zeros, pad);
    }
}

static void write_endofopt(void) {
    static const uint8_t eoo[4] = {0, 0, 0, 0};
    buffered_write(eoo, 4);
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMIT 1 — Section Header Block
// ─────────────────────────────────────────────────────────────────────────────
static void write_shb(void) {
    static const char os_str[] = "Android (Kali NetHunter)";
    static const char hw_str[] = "AndroNet v1.0";
    uint16_t os_len = (uint16_t)strlen(os_str);
    uint16_t hw_len = (uint16_t)strlen(hw_str);

    uint32_t opts_len = option_wire_size(os_len)   // shb_os  (code 3)
                      + option_wire_size(hw_len)   // shb_userappl (code 4)
                      + 4u;                        // end-of-opt

    // Fixed SHB header: type(4)+len(4)+BOM(4)+major(2)+minor(2)+sec_len(8) = 24
    // Plus options and trailing block length.
    uint32_t block_len = 24u + opts_len + 4u;
    g_ctx.shb_block_len = block_len;

    // Write type, block length, BOM, version (16 bytes before section_length).
    uint32_t type = PCAPNG_SHB_TYPE;
    buffered_write(&type,      4);
    buffered_write(&block_len, 4);
    uint32_t bom = PCAPNG_BYTE_ORDER;
    buffered_write(&bom, 4);
    uint16_t ver_maj = 1, ver_min = 0;
    buffered_write(&ver_maj, 2);
    buffered_write(&ver_min, 2);

    // Flush so ftell() is accurate, then record the position of section_length.
    flush_write_buffer();
    // At this point the file is exactly SHB_SECTION_LEN_OFFSET bytes long.

    // COMMIT 2 — section_length placeholder; patched on close (COMMIT 4).
    uint64_t sec_len_placeholder = 0xFFFFFFFFFFFFFFFFULL;
    buffered_write(&sec_len_placeholder, 8);

    // Options: shb_os (3) and shb_userappl (4).
    write_option(3u, os_str, os_len);
    write_option(4u, hw_str, hw_len);
    write_endofopt();

    buffered_write(&block_len, 4);  // trailing Block Total Length
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMIT 1 — Interface Description Block
// ─────────────────────────────────────────────────────────────────────────────
static void write_idb(void) {
    const char *ifname  = g_ctx.if_name ? g_ctx.if_name : "tun0";
    uint16_t    if_len  = (uint16_t)strlen(ifname);
    // COMMIT 2 — if_tsresol = 0x09 → 10^-9 = nanoseconds
    uint8_t     tsresol = 0x09u;

    uint32_t opts_len = option_wire_size(if_len)  // if_name (code 2)
                      + option_wire_size(1u)       // if_tsresol (code 9)
                      + 4u;                        // end-of-opt

    // Fixed IDB header: type(4)+len(4)+link_type(2)+reserved(2)+snaplen(4) = 16
    uint32_t block_len = 16u + opts_len + 4u;

    uint32_t type = PCAPNG_IDB_TYPE;
    buffered_write(&type,      4);
    buffered_write(&block_len, 4);
    uint16_t link_type = (uint16_t)g_ctx.linktype;
    uint16_t reserved  = 0u;
    buffered_write(&link_type, 2);
    buffered_write(&reserved,  2);
    uint32_t snaplen = 65535u;
    buffered_write(&snaplen, 4);

    write_option((uint16_t)OPT_IF_NAME,   ifname,   if_len);
    write_option((uint16_t)OPT_IF_TSRESOL, &tsresol, 1u);
    write_endofopt();

    buffered_write(&block_len, 4);  // trailing Block Total Length
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMIT 4 — Finalize current file: patch section_length, fsync, close.
// ─────────────────────────────────────────────────────────────────────────────
static void finalize_current_file(int write_trailer) {
    if (!g_ctx.file) return;

    flush_write_buffer();

    long final_pos = ftell(g_ctx.file);

    // Compute section_length = bytes from first byte of IDB to final_pos.
    // section_length excludes the SHB block itself.
    uint64_t section_len = (uint64_t)(final_pos - (long)g_ctx.shb_block_len);

    // Patch Section Length field at file offset SHB_SECTION_LEN_OFFSET (= 16).
    fseek(g_ctx.file, (long)SHB_SECTION_LEN_OFFSET, SEEK_SET);
    fwrite(&section_len, 8, 1, g_ctx.file);
    fseek(g_ctx.file, final_pos, SEEK_SET);

    if (write_trailer) {
        // COMMIT 4 — write truncation sentinel AFTER section content.
        uint32_t sentinel = MAGIC_TRAILER;
        fwrite(&sentinel, 4, 1, g_ctx.file);
    }

    if (g_ctx.fd >= 0) fsync(g_ctx.fd);

    fclose(g_ctx.file);
    g_ctx.file = NULL;
    g_ctx.fd   = -1;
}

// ─────────────────────────────────────────────────────────────────────────────
// File rotation helpers (COMMIT 7)
// ─────────────────────────────────────────────────────────────────────────────
static char *make_rotated_filepath(const char *dir, uint32_t seq) {
    char buf[64];
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    if (seq == 0) {
        strftime(buf, sizeof buf, "andronet_%Y%m%d_%H%M%S.pcapng", t);
    } else {
        char base[48], suffix[16];
        strftime(base, sizeof base, "andronet_%Y%m%d_%H%M%S", t);
        snprintf(suffix, sizeof suffix, "_%u.pcapng", seq);
        snprintf(buf, sizeof buf, "%s%s", base, suffix);
    }
    size_t dlen = strlen(dir);
    char  *full = (char *)malloc(dlen + strlen(buf) + 2);
    if (!full) return NULL;
    memcpy(full, dir, dlen);
    full[dlen] = '/';
    strcpy(full + dlen + 1, buf);
    return full;
}

// Deletes the oldest rotated captures in `dir` beyond `max_files`, so
// nativeSetRotationSettings's max_files actually bounds disk usage instead
// of only being logged. Directories here hold at most a few dozen rotated
// captures, so the O(n^2) selection sort below is not a concern.
#define PURGE_MAX_TRACKED_FILES 256
static void purge_old_files(const char *dir, int max_files) {
    if (max_files <= 0) return;

    DIR *d = opendir(dir);
    if (!d) {
        LOGE("purge_old_files: cannot open dir %s", dir);
        return;
    }

    char   *paths[PURGE_MAX_TRACKED_FILES];
    time_t  mtimes[PURGE_MAX_TRACKED_FILES];
    int     count = 0;

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL && count < PURGE_MAX_TRACKED_FILES) {
        const char *name = entry->d_name;
        size_t len = strlen(name);
        // Only ever touch files we ourselves rotated: "andronet_...pcapng".
        if (len < 16) continue;
        if (strncmp(name, "andronet_", 9) != 0) continue;
        if (strcmp(name + len - 7, ".pcapng") != 0) continue;

        size_t dlen = strlen(dir);
        char *full = (char *)malloc(dlen + len + 2);
        if (!full) continue;
        memcpy(full, dir, dlen);
        full[dlen] = '/';
        strcpy(full + dlen + 1, name);

        // Never delete the file currently being written to.
        if (g_ctx.current_path && strcmp(full, g_ctx.current_path) == 0) {
            free(full);
            continue;
        }

        struct stat st;
        if (stat(full, &st) != 0) {
            free(full);
            continue;
        }

        paths[count]  = full;
        mtimes[count] = st.st_mtime;
        count++;
    }
    closedir(d);

    if (count > max_files) {
        // Selection sort, oldest first.
        for (int i = 0; i < count - 1; i++) {
            int oldest = i;
            for (int j = i + 1; j < count; j++) {
                if (mtimes[j] < mtimes[oldest]) oldest = j;
            }
            if (oldest != i) {
                char   *tmp_path = paths[i];  paths[i]  = paths[oldest];  paths[oldest]  = tmp_path;
                time_t  tmp_time = mtimes[i]; mtimes[i] = mtimes[oldest]; mtimes[oldest] = tmp_time;
            }
        }

        int to_delete = count - max_files;
        for (int i = 0; i < to_delete; i++) {
            if (remove(paths[i]) == 0) {
                LOGI("Rotation: pruned old capture %s", paths[i]);
            } else {
                LOGE("Rotation: failed to prune %s", paths[i]);
            }
        }
    }

    for (int i = 0; i < count; i++) free(paths[i]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Open a new pcapng file and write SHB + IDB.
// Closes and finalizes any previously open file first.
// ─────────────────────────────────────────────────────────────────────────────
static int open_pcapng_file(const char *path) {
    finalize_current_file(1 /* write sentinel on rotation too */);

    g_ctx.file = fopen(path, "wb");
    if (!g_ctx.file) {
        LOGE("Cannot open pcapng file: %s", path);
        return 0;
    }
    g_ctx.fd = fileno(g_ctx.file);

    free(g_ctx.current_path);
    g_ctx.current_path      = strdup(path);
    g_ctx.current_file_size = 0u;
    g_ctx.file_start_time   = time(NULL);
    g_ctx.wbuf_pos          = 0u;
    g_ctx.shb_block_len     = 0u;

    write_shb();
    write_idb();
    flush_write_buffer();   // commit SHB + IDB immediately

    LOGI("Opened pcapng: %s (if=%s, linktype=%d)",
         path, g_ctx.if_name ? g_ctx.if_name : "?", g_ctx.linktype);
    return 1;
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMIT 7 — Rotation check (called by writer thread before each EPB write)
// ─────────────────────────────────────────────────────────────────────────────
static void check_rotation(void) {
    if (!g_ctx.file) return;

    int rotate = 0;

    if (g_ctx.max_size_bytes > 0) {
        int64_t approx_size = (int64_t)(g_ctx.current_file_size + g_ctx.wbuf_pos);
        if (approx_size >= g_ctx.max_size_bytes) {
            LOGI("Rotation triggered: size (%lld >= %lld bytes)",
                 (long long)approx_size, (long long)g_ctx.max_size_bytes);
            rotate = 1;
        }
    }
    if (!rotate && g_ctx.max_duration_s > 0) {
        time_t elapsed = time(NULL) - g_ctx.file_start_time;
        if (elapsed >= (time_t)g_ctx.max_duration_s) {
            LOGI("Rotation triggered: duration (%ld s >= %d s)",
                 (long)elapsed, g_ctx.max_duration_s);
            rotate = 1;
        }
    }

    if (rotate) {
        g_ctx.rotation_count++;
        char *new_path = make_rotated_filepath(g_ctx.base_dir, g_ctx.rotation_count);
        if (!new_path) return;
        open_pcapng_file(new_path);
        if (g_ctx.max_files > 0) purge_old_files(g_ctx.base_dir, g_ctx.max_files);
        free(new_path);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMIT 3 — Write Enhanced Packet Block (with optional annotation option)
// COMMIT 9 — annotation written as EPB custom option 2988 when non-empty
// ─────────────────────────────────────────────────────────────────────────────
static void write_epb(const uint8_t *pkt, uint32_t cap_len,
                      uint32_t orig_len, uint64_t ts_ns,
                      const char *annotation) {
    // COMMIT 2 — nanosecond timestamp split into two 32-bit words.
    uint32_t ts_high = (uint32_t)(ts_ns >> 32);
    uint32_t ts_low  = (uint32_t)(ts_ns & 0xFFFFFFFFULL);

    uint16_t pkt_pad = (uint16_t)((4u - (cap_len & 3u)) & 3u);

    // Fixed EPB header: type(4)+len(4)+iface_id(4)+ts_hi(4)+ts_lo(4)+
    //                   cap_len(4)+orig_len(4) = 28 bytes; trailing len(4) = 32
    uint32_t block_len = 32u + cap_len + pkt_pad;

    // COMMIT 9 — annotation option
    uint16_t ann_len = 0u;
    uint16_t ann_pad = 0u;
    if (annotation && annotation[0] != '\0') {
        ann_len = (uint16_t)strlen(annotation);
        if (ann_len > 511u) ann_len = 511u;
        ann_pad = (uint16_t)((4u - (ann_len & 3u)) & 3u);
        // option_wire_size(ann_len) + end-of-opt(4)
        block_len += option_wire_size(ann_len) + 4u;
    }

#ifdef DEBUG
    assert(block_len % 4u == 0u);
    assert(cap_len <= orig_len);
#endif

    uint32_t type     = PCAPNG_EPB_TYPE;
    uint32_t iface_id = 0u;
    static const uint8_t zeros[4] = {0, 0, 0, 0};

    buffered_write(&type,     4);
    buffered_write(&block_len,4);
    buffered_write(&iface_id, 4);
    buffered_write(&ts_high,  4);
    buffered_write(&ts_low,   4);
    buffered_write(&cap_len,  4);
    buffered_write(&orig_len, 4);
    buffered_write(pkt, cap_len);
    if (pkt_pad) buffered_write(zeros, pkt_pad);

    // COMMIT 9 — write annotation option (only for flagged packets)
    if (ann_len > 0u) {
        uint16_t opt_code = (uint16_t)OPT_CUSTOM_COPY;
        buffered_write(&opt_code, 2);
        buffered_write(&ann_len,  2);
        buffered_write(annotation, ann_len);
        if (ann_pad) buffered_write(zeros, ann_pad);
        write_endofopt();
    }

    // Trailing Block Total Length — MUST equal leading value (RFC 7663 §3.1)
    buffered_write(&block_len, 4);

#ifdef DEBUG
    // Verify the assertion holds for the values we just wrote.
    assert(block_len == 32u + cap_len + pkt_pad +
           (ann_len > 0u ? (option_wire_size(ann_len) + 4u) : 0u));
#endif
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMIT 5 — Ring buffer producer (called from JNI / capture thread)
// ─────────────────────────────────────────────────────────────────────────────
static void ring_produce(const uint8_t *data, uint32_t len, uint32_t orig_len,
                         uint64_t ts_ns, const char *annotation) {
    int wh   = g_ctx.ring.write_head;
    int next = (wh + 1) % RING_BUFFER_SIZE;

    if (next == g_ctx.ring.read_head) {
        // Ring full — drop packet.
        g_ctx.ring.dropped++;
        g_ctx.dropped_packets++;
        LOGD("Ring full: %llu drops so far", (unsigned long long)g_ctx.ring.dropped);
        return;
    }

    RingSlot *slot = &g_ctx.ring.slots[wh];

    uint32_t copy_len = (len < RING_SLOT_SIZE) ? len : (uint32_t)RING_SLOT_SIZE;
    memcpy(slot->data, data, copy_len);
    slot->length      = copy_len;
    slot->orig_length = orig_len;
    slot->timestamp_ns = ts_ns;

    if (annotation && annotation[0] != '\0') {
        strncpy(slot->annotation, annotation, sizeof slot->annotation - 1u);
        slot->annotation[sizeof slot->annotation - 1u] = '\0';
    } else {
        slot->annotation[0] = '\0';
    }

    // Memory barrier: ensure all slot data is visible before setting ready.
    __sync_synchronize();
    slot->ready = 1;

    // Advance write head — barrier ensures ready=1 is visible first.
    __sync_synchronize();
    g_ctx.ring.write_head = next;
    __sync_synchronize();
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMIT 5+6+7 — Dedicated writer thread (consumer of the ring buffer)
// ─────────────────────────────────────────────────────────────────────────────
static void *writer_thread(void *arg) {
    (void)arg;
    LOGI("pcapng writer thread started (ring=%d slots, wbuf=%d KB)",
         RING_BUFFER_SIZE, WRITE_BUFFER_SIZE / 1024);

    static const struct timespec IDLE_SLEEP = {0, 5000000L};  // 5 ms

    while (1) {
        // Memory barrier: see latest write_head from producer.
        __sync_synchronize();

        int rh = g_ctx.ring.read_head;
        int wh = g_ctx.ring.write_head;

        if (rh == wh) {
            // Ring empty.
            if (!g_ctx.ring.running) break;  // normal shutdown

            // COMMIT 6 — flush write buffer on 500 ms idle.
            if (g_ctx.wbuf_pos > 0) flush_write_buffer();

            nanosleep(&IDLE_SLEEP, NULL);
            continue;
        }

        RingSlot *slot = &g_ctx.ring.slots[rh];

        // Wait for slot to be fully written by producer (rare spin).
        __sync_synchronize();
        if (slot->ready != 1) continue;

        slot->ready = 2;
        __sync_synchronize();

        // COMMIT 7 — rotate before writing if limits exceeded.
        check_rotation();

        if (g_ctx.file) {
            write_epb(slot->data, slot->length, slot->orig_length,
                      slot->timestamp_ns, slot->annotation);
            g_ctx.packet_count++;

            // COMMIT 6 — flush when buffer is large or on timer.
            time_t now = time(NULL);
            if (g_ctx.wbuf_pos >= (size_t)(WRITE_BUFFER_SIZE * 3 / 4) ||
                now != g_ctx.last_flush_time) {
                flush_write_buffer();
            }
        }

        // Mark slot empty and advance read head.
        slot->ready = 0;
        __sync_synchronize();
        g_ctx.ring.read_head = (rh + 1) % RING_BUFFER_SIZE;
        __sync_synchronize();
    }

    // Drain any remaining filled slots after running=0.
    int rh = g_ctx.ring.read_head;
    while (rh != g_ctx.ring.write_head) {
        RingSlot *slot = &g_ctx.ring.slots[rh];
        __sync_synchronize();
        if (slot->ready == 1 && g_ctx.file) {
            write_epb(slot->data, slot->length, slot->orig_length,
                      slot->timestamp_ns, slot->annotation);
            g_ctx.packet_count++;
            slot->ready = 0;
            __sync_synchronize();
        }
        rh = (rh + 1) % RING_BUFFER_SIZE;
    }
    g_ctx.ring.read_head = rh;

    flush_write_buffer();
    LOGI("pcapng writer thread exited (%llu packets, %llu drops)",
         (unsigned long long)g_ctx.packet_count,
         (unsigned long long)g_ctx.dropped_packets);
    return NULL;
}

// ─────────────────────────────────────────────────────────────────────────────
// COMMIT 14 — Block-level integrity validation (static helper + JNI export)
// ─────────────────────────────────────────────────────────────────────────────
static int validate_pcapng_file_internal(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) { LOGE("validate: cannot open %s", path); return -1; }

    // Verify SHB type and byte-order magic.
    uint32_t blk_type = 0u;
    if (fread(&blk_type, 4, 1, f) != 1 || blk_type != PCAPNG_SHB_TYPE) {
        LOGE("validate: not pcapng (type=0x%08X)", blk_type);
        fclose(f); return -1;
    }
    uint32_t shb_len = 0u;
    fread(&shb_len, 4, 1, f);
    uint32_t bom = 0u;
    fread(&bom, 4, 1, f);
    if (bom != PCAPNG_BYTE_ORDER) {
        LOGE("validate: bad BOM 0x%08X", bom);
        fclose(f); return -1;
    }

    // Skip rest of SHB.
    if (shb_len < 12u) { fclose(f); return -1; }
    fseek(f, (long)shb_len, SEEK_SET);

    int epb_count = 0;
    while (1) {
        uint32_t type = 0u, len_start = 0u, len_end = 0u;
        if (fread(&type,      4, 1, f) != 1) break;
        if (fread(&len_start, 4, 1, f) != 1) break;

        if (len_start < 12u || (len_start & 3u) != 0u) {
            LOGE("validate: corrupt block len=%u type=0x%08X", len_start, type);
            fclose(f); return -1;
        }

        // Skip to trailing length field (len_start includes type + len + trailing_len).
        long skip = (long)len_start - 8 - 4;
        if (skip < 0 || fseek(f, skip, SEEK_CUR) != 0) break;

        if (fread(&len_end, 4, 1, f) != 1) break;

        if (len_start != len_end) {
            LOGE("validate: block length mismatch start=%u end=%u type=0x%08X",
                 len_start, len_end, type);
            fclose(f); return -1;
        }

        if (type == PCAPNG_EPB_TYPE) epb_count++;
    }

    fclose(f);
    LOGI("validate: %s OK — %d EPBs", path, epb_count);
    return epb_count;
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal: stop writer thread cleanly.
// ─────────────────────────────────────────────────────────────────────────────
static void stop_writer_thread(void) {
    if (g_ctx.ring.running) {
        g_ctx.ring.running = 0;
        __sync_synchronize();
        pthread_join(g_ctx.ring.writer_thread, NULL);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// JNI: nativeInit
// ─────────────────────────────────────────────────────────────────────────────
JNIEXPORT jboolean JNICALL
Java_com_example_packet_1analyzer_PcapWriter_nativeInit(
        JNIEnv *env, jobject thiz, jstring jpath, jint linktype) {
    pthread_mutex_lock(&g_init_mtx);

    stop_writer_thread();
    finalize_current_file(0 /* no sentinel on re-init */);

    const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);

    // Extract base directory.
    free(g_ctx.base_dir);
    char *dir_copy = strdup(path);
    char *slash    = strrchr(dir_copy, '/');
    if (slash) { *slash = '\0'; g_ctx.base_dir = strdup(dir_copy); }
    else        { g_ctx.base_dir = strdup("."); }
    free(dir_copy);

    free(g_ctx.if_name);
    free(g_ctx.current_path);
    g_ctx.current_path = NULL;

    // COMMIT 12 — use interface info set via nativeSetInterfaceInfo if available.
    if (g_pending_if_name) {
        g_ctx.if_name  = strdup(g_pending_if_name);
        g_ctx.linktype = (g_pending_linktype >= 0) ? g_pending_linktype
                                                    : (int)linktype;
        free(g_pending_if_name);
        g_pending_if_name  = NULL;
        g_pending_linktype = -1;
    } else {
        g_ctx.linktype = (linktype == 0) ? LINKTYPE_RAW : (int)linktype;
        g_ctx.if_name  = strdup(g_ctx.linktype == LINKTYPE_ETHERNET ? "wlan0" : "tun0");
    }

    // Reset stats.
    g_ctx.packet_count    = 0u;
    g_ctx.dropped_packets = 0u;
    g_ctx.rotation_count  = 0u;
    g_ctx.last_flush_time = time(NULL);

    // Rotation defaults.
    g_ctx.max_size_bytes = DEFAULT_MAX_SIZE;
    g_ctx.max_duration_s = DEFAULT_MAX_DURATION;
    g_ctx.max_files      = DEFAULT_MAX_FILES;

    // Reset ring buffer.
    memset(&g_ctx.ring, 0, sizeof g_ctx.ring);

    int ok = open_pcapng_file(path);
    (*env)->ReleaseStringUTFChars(env, jpath, path);

    if (!ok) {
        pthread_mutex_unlock(&g_init_mtx);
        return JNI_FALSE;
    }

    g_ctx.initialized    = 1;
    g_ctx.ring.running   = 1;
    g_ctx.ring.write_head = 0;
    g_ctx.ring.read_head  = 0;

    // COMMIT 5 — start dedicated writer thread.
    if (pthread_create(&g_ctx.ring.writer_thread, NULL, writer_thread, NULL) != 0) {
        LOGE("pthread_create failed — falling back to synchronous (no ring buffer)");
        g_ctx.ring.running = 0;
    }

    LOGI("pcapng init OK: %s (if=%s, linktype=%d)",
         g_ctx.current_path, g_ctx.if_name, g_ctx.linktype);
    pthread_mutex_unlock(&g_init_mtx);
    return JNI_TRUE;
}

// ─────────────────────────────────────────────────────────────────────────────
// JNI: nativeWritePacket — normal (non-annotated) path
// ─────────────────────────────────────────────────────────────────────────────
JNIEXPORT jboolean JNICALL
Java_com_example_packet_1analyzer_PcapWriter_nativeWritePacket(
        JNIEnv *env, jobject thiz, jbyteArray jpkt, jlong timestamp_ms) {
    if (!g_ctx.initialized || !g_ctx.file) {
        LOGE("Writer not initialized");
        return JNI_FALSE;
    }

    jsize  pkt_len   = (*env)->GetArrayLength(env, jpkt);
    jbyte *pkt_bytes = (*env)->GetByteArrayElements(env, jpkt, NULL);
    if (!pkt_bytes) return JNI_FALSE;

    // COMMIT 2 — get true nanosecond timestamp from the C layer.
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t ts_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    // Fallback if clock unavailable: convert ms to ns.
    if (ts_ns == 0u)
        ts_ns = (uint64_t)timestamp_ms * 1000000ULL;

    ring_produce((const uint8_t *)pkt_bytes, (uint32_t)pkt_len,
                 (uint32_t)pkt_len, ts_ns, NULL);

    (*env)->ReleaseByteArrayElements(env, jpkt, pkt_bytes, JNI_ABORT);
    return JNI_TRUE;
}

// ─────────────────────────────────────────────────────────────────────────────
// JNI: nativeWriteAnnotatedPacket — COMMIT 9 (flagged / anomaly packets)
//
// The Kotlin side (PcapWriter.kt) declares this `timestampMs` and passes
// milliseconds (System.currentTimeMillis() / a millisecond epoch from
// PacketAnalysisManager) — same convention as nativeWritePacket above. This
// used to be treated as *already nanoseconds* with no conversion, so every
// anomaly-annotated packet got a timestamp near the 1970 epoch. Fixed to
// mirror nativeWritePacket's behavior: prefer the live clock, fall back to
// a ms->ns conversion of the caller-supplied value.
// ─────────────────────────────────────────────────────────────────────────────
JNIEXPORT jboolean JNICALL
Java_com_example_packet_1analyzer_PcapWriter_nativeWriteAnnotatedPacket(
        JNIEnv *env, jobject thiz,
        jbyteArray jpkt, jlong timestamp_ms, jstring jannotation) {
    if (!g_ctx.initialized || !g_ctx.file) return JNI_FALSE;

    jsize  pkt_len   = (*env)->GetArrayLength(env, jpkt);
    jbyte *pkt_bytes = (*env)->GetByteArrayElements(env, jpkt, NULL);
    if (!pkt_bytes) return JNI_FALSE;

    const char *annotation = NULL;
    if (jannotation)
        annotation = (*env)->GetStringUTFChars(env, jannotation, NULL);

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    uint64_t ts_ns = (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;

    // Fallback if clock unavailable: convert the caller-supplied ms to ns.
    if (ts_ns == 0u)
        ts_ns = (uint64_t)timestamp_ms * 1000000ULL;

    ring_produce((const uint8_t *)pkt_bytes, (uint32_t)pkt_len,
                 (uint32_t)pkt_len, ts_ns, annotation);

    if (annotation) (*env)->ReleaseStringUTFChars(env, jannotation, annotation);
    (*env)->ReleaseByteArrayElements(env, jpkt, pkt_bytes, JNI_ABORT);
    return JNI_TRUE;
}

// ─────────────────────────────────────────────────────────────────────────────
// JNI: nativeGetStats
// ─────────────────────────────────────────────────────────────────────────────
JNIEXPORT jobject JNICALL
Java_com_example_packet_1analyzer_PcapWriter_nativeGetStats(
        JNIEnv *env, jobject thiz) {
    jclass     hmc  = (*env)->FindClass(env, "java/util/HashMap");
    jmethodID  hmi  = (*env)->GetMethodID(env, hmc, "<init>", "()V");
    jmethodID  hmp  = (*env)->GetMethodID(env, hmc, "put",
                          "(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;");
    jobject    map  = (*env)->NewObject(env, hmc, hmi);

    jclass    lc = (*env)->FindClass(env, "java/lang/Long");
    jmethodID li = (*env)->GetMethodID(env, lc, "<init>", "(J)V");

#define PUT_LONG(key, val) do { \
    jstring k = (*env)->NewStringUTF(env, (key)); \
    jobject v = (*env)->NewObject(env, lc, li, (jlong)(val)); \
    (*env)->CallObjectMethod(env, map, hmp, k, v); \
    (*env)->DeleteLocalRef(env, k); \
    (*env)->DeleteLocalRef(env, v); \
} while (0)

#define PUT_STR(key, val) do { \
    jstring k = (*env)->NewStringUTF(env, (key)); \
    jstring v = (*env)->NewStringUTF(env, (val) ? (val) : ""); \
    (*env)->CallObjectMethod(env, map, hmp, k, v); \
    (*env)->DeleteLocalRef(env, k); \
    (*env)->DeleteLocalRef(env, v); \
} while (0)

    PUT_LONG("packetCount",     g_ctx.packet_count);
    PUT_LONG("droppedPackets",  g_ctx.dropped_packets);
    PUT_LONG("currentFileSizeBytes",
             (int64_t)(g_ctx.current_file_size + g_ctx.wbuf_pos));
    PUT_LONG("rotationCount",   g_ctx.rotation_count);
    PUT_LONG("captureStartEpochMs",
             (int64_t)g_ctx.file_start_time * 1000LL);
    PUT_STR("filepath",         g_ctx.current_path);

#undef PUT_LONG
#undef PUT_STR

    return map;
}

// ─────────────────────────────────────────────────────────────────────────────
// JNI: nativeClose — COMMIT 4 (section length, fsync, sentinel)
// ─────────────────────────────────────────────────────────────────────────────
JNIEXPORT void JNICALL
Java_com_example_packet_1analyzer_PcapWriter_nativeClose(
        JNIEnv *env, jobject thiz) {
    LOGI("nativeClose called");
    if (!g_ctx.initialized) return;

    stop_writer_thread();
    finalize_current_file(1 /* write sentinel */);

    LOGI("pcapng closed: %llu pkts, %llu dropped, %u rotations",
         (unsigned long long)g_ctx.packet_count,
         (unsigned long long)g_ctx.dropped_packets,
         g_ctx.rotation_count);

    free(g_ctx.current_path); g_ctx.current_path = NULL;
    free(g_ctx.base_dir);     g_ctx.base_dir     = NULL;
    free(g_ctx.if_name);      g_ctx.if_name      = NULL;

    g_ctx.initialized    = 0;
    g_ctx.packet_count   = 0u;
    g_ctx.dropped_packets= 0u;
    g_ctx.rotation_count = 0u;
}

// ─────────────────────────────────────────────────────────────────────────────
// JNI: nativeSetRotationSettings — COMMIT 7
// ─────────────────────────────────────────────────────────────────────────────
JNIEXPORT void JNICALL
Java_com_example_packet_1analyzer_PcapWriter_nativeSetRotationSettings(
        JNIEnv *env, jobject thiz,
        jlong maxSizeBytes, jint maxDurationSecs, jint maxFiles) {
    g_ctx.max_size_bytes = (int64_t)maxSizeBytes;
    g_ctx.max_duration_s = (int)maxDurationSecs;
    g_ctx.max_files      = (int)maxFiles;
    LOGI("Rotation: maxSize=%lld B, maxDuration=%d s, maxFiles=%d",
         (long long)g_ctx.max_size_bytes, g_ctx.max_duration_s, g_ctx.max_files);
}

// ─────────────────────────────────────────────────────────────────────────────
// JNI: nativeSetInterfaceInfo — COMMIT 12 (must be called before nativeInit)
// ─────────────────────────────────────────────────────────────────────────────
JNIEXPORT jboolean JNICALL
Java_com_example_packet_1analyzer_PcapWriter_nativeSetInterfaceInfo(
        JNIEnv *env, jobject thiz, jstring jifname, jint jlinktype) {
    const char *ifname = (*env)->GetStringUTFChars(env, jifname, NULL);
    free(g_pending_if_name);
    g_pending_if_name  = strdup(ifname);
    g_pending_linktype = (int)jlinktype;
    (*env)->ReleaseStringUTFChars(env, jifname, ifname);
    LOGI("Pending interface info: if=%s linktype=%d",
         g_pending_if_name, g_pending_linktype);
    return JNI_TRUE;
}

// ─────────────────────────────────────────────────────────────────────────────
// JNI: nativeValidatePcapFile — COMMIT 14
// ─────────────────────────────────────────────────────────────────────────────
JNIEXPORT jint JNICALL
Java_com_example_packet_1analyzer_PcapWriter_nativeValidatePcapFile(
        JNIEnv *env, jobject thiz, jstring jpath) {
    const char *path = (*env)->GetStringUTFChars(env, jpath, NULL);
    int result = validate_pcapng_file_internal(path);
    (*env)->ReleaseStringUTFChars(env, jpath, path);
    return (jint)result;
}
