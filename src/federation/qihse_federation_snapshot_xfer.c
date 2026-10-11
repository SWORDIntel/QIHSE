/*
 * QIHSE federation snapshot transfer — implementation.
 * See include/qihse_federation_snapshot_xfer.h for the protocol contract.
 *
 * Decoder discipline (AGENTS.md): one reusable heap buffer per endpoint,
 * every length bounded before allocation-free decode, overflow-checked
 * offset arithmetic, single `goto done` cleanup.
 */

#include "qihse_federation_snapshot_xfer.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/sha.h>

/* ── little-endian codec ──────────────────────────────────────────────── */

static void put_u16(uint8_t* p, uint16_t v) {
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)(v >> 8);
}
static void put_u32(uint8_t* p, uint32_t v) {
    for (int i = 0; i < 4; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static void put_u64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)(v >> (8 * i));
}
static uint16_t get_u16(const uint8_t* p) {
    return (uint16_t)(p[0] | (p[1] << 8));
}
static uint32_t get_u32(const uint8_t* p) {
    uint32_t v = 0;
    for (int i = 3; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}
static uint64_t get_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

/* ── CRC32 (IEEE reflected) for early per-chunk refusal ───────────────── */

static uint32_t s_crc_table[256];
static int s_crc_ready = 0;

static void crc_init(void) {
    for (uint32_t i = 0; i < 256; i++) {
        uint32_t c = i;
        for (int k = 0; k < 8; k++)
            c = (c & 1u) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1);
        s_crc_table[i] = c;
    }
    s_crc_ready = 1;
}

static uint32_t crc32_buf(const uint8_t* p, size_t len) {
    if (!s_crc_ready) crc_init();
    uint32_t c = 0xFFFFFFFFu;
    for (size_t i = 0; i < len; i++)
        c = s_crc_table[(c ^ p[i]) & 0xFFu] ^ (c >> 8);
    return c ^ 0xFFFFFFFFu;
}

/* ── framing ──────────────────────────────────────────────────────────── */

#define QSX_MAGIC 0x31585351u          /* 'Q','S','X','1' little-endian */
#define QSX_HEAD 12u                   /* magic u32 | kind u16 | len u32 */
#define QSX_PAYLOAD_CAP (QIHSE_SNAPSHOT_XFER_CHUNK + 64u)

enum {
    QSX_FETCH = 1,
    QSX_BEGIN = 2,
    QSX_CHUNK = 3,
    QSX_ACK   = 4,
    QSX_DONE  = 5,
    QSX_ABORT = 6
};

/* Payload sizes (fixed-shape frames; CHUNK is the only variable one). */
#define QSX_FETCH_LEN 16u
#define QSX_BEGIN_LEN 64u              /* 8 + 4 + 48 sha + 4 pad */
#define QSX_ACK_LEN   8u
#define QSX_DONE_LEN  8u
#define QSX_ABORT_LEN 128u
#define QSX_CHUNK_MIN 12u              /* offset u64 + crc u32, data >= 0 */

static void set_err(char* err, size_t cap, const char* msg) {
    if (err && cap) {
        snprintf(err, cap, "%s", msg);
        err[cap - 1u] = '\0';
    }
}

static long tx_raw(qihse_repl_transport_t* t, const uint8_t* buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        long n = t->ops->send(t->ctx, buf + off, len - off);
        if (n <= 0) return -1;
        off += (size_t)n;
    }
    return (long)len;
}

/*
 * Receive exactly `len` bytes.  The loopback transport returns -1 for
 * "nothing yet" (the peer runs in another thread), so -1 is retried; the
 * mTLS transport blocks inside recv and only surfaces -1 as a real error
 * or repeated-error hang, and 0 always means the peer went away.
 */
#define QSX_RX_SPIN_MAX 200000000u

static long rx_exact(qihse_repl_transport_t* t, uint8_t* buf, size_t len) {
    size_t off = 0;
    unsigned long spins = 0;
    while (off < len) {
        long n = t->ops->recv(t->ctx, buf + off, len - off);
        if (n == 0) return -1;               /* peer closed */
        if (n < 0) {
            if (++spins > QSX_RX_SPIN_MAX) return -1;
            continue;                        /* nothing yet (loopback) */
        }
        off += (size_t)n;
    }
    return (long)len;
}

static bool frame_send(qihse_repl_transport_t* t, uint16_t kind,
                       const uint8_t* payload, uint32_t payload_len) {
    if (payload_len > QSX_PAYLOAD_CAP) return false;
    uint8_t head[QSX_HEAD];
    put_u32(head, QSX_MAGIC);
    put_u16(head + 4, kind);
    put_u32(head + 8, payload_len);
    if (tx_raw(t, head, QSX_HEAD) < 0) return false;
    if (payload_len && tx_raw(t, payload, payload_len) < 0) return false;
    return true;
}

/* Decode one frame into `buf` (cap >= QSX_PAYLOAD_CAP).  Returns payload
 * length, or -1 on transport/protocol failure with `kind_out` untouched. */
static long frame_recv(qihse_repl_transport_t* t, uint16_t* kind_out,
                       uint8_t* buf, size_t cap) {
    uint8_t head[QSX_HEAD];
    if (rx_exact(t, head, QSX_HEAD) < 0) return -1;
    if (get_u32(head) != QSX_MAGIC) return -1;
    uint16_t kind = get_u16(head + 4);
    uint32_t len = get_u32(head + 8);
    if (len > QSX_PAYLOAD_CAP || len > cap) return -1;
    if (len && rx_exact(t, buf, len) < 0) return -1;
    *kind_out = kind;
    return (long)len;
}

static bool send_abort(qihse_repl_transport_t** t, const char* reason) {
    uint8_t p[QSX_ABORT_LEN];
    memset(p, 0, sizeof(p));
    snprintf((char*)p, QSX_ABORT_LEN, "%s", reason);
    return frame_send(*t, QSX_ABORT, p, QSX_ABORT_LEN);
}

/* ── result vocabulary ────────────────────────────────────────────────── */

const char* qihse_snapshot_xfer_result_name(qihse_snapshot_xfer_result_t r) {
    switch (r) {
    case QIHSE_SNAPSHOT_XFER_OK: return "ok";
    case QIHSE_SNAPSHOT_XFER_IN_PROGRESS: return "in-progress";
    case QIHSE_SNAPSHOT_XFER_ERR_ARGS: return "args";
    case QIHSE_SNAPSHOT_XFER_ERR_PEER: return "peer-unverified";
    case QIHSE_SNAPSHOT_XFER_ERR_PROTOCOL: return "protocol";
    case QIHSE_SNAPSHOT_XFER_ERR_BOUNDS: return "bounds";
    case QIHSE_SNAPSHOT_XFER_ERR_CRC: return "crc";
    case QIHSE_SNAPSHOT_XFER_ERR_IO: return "io";
    }
    return "unknown";
}

/* ── resume state (atomic tmp+rename, never torn) ─────────────────────── */

void qihse_snapshot_xfer_state_path(const char* dest_path,
                                    char* out, size_t cap) {
    snprintf(out, cap, "%s.xfer", dest_path);
}

#pragma pack(push, 1)
typedef struct {
    uint32_t magic;                 /* QSX_MAGIC */
    uint32_t version;               /* 1 */
    uint64_t total_len;
    uint32_t chunk_size;
    uint8_t  header_sha384[48];
    uint64_t offset;
} qsx_state_t;
#pragma pack(pop)

static bool state_load(const char* dest_path, qsx_state_t* st) {
    char path[512];
    qihse_snapshot_xfer_state_path(dest_path, path, sizeof(path));
    FILE* f = fopen(path, "rb");
    if (!f) return false;
    bool ok = fread(st, sizeof(*st), 1u, f) == 1u &&
              st->magic == QSX_MAGIC && st->version == 1u;
    fclose(f);
    return ok;
}

static bool state_save(const char* dest_path, const qsx_state_t* st) {
    char path[512], tmp[540];
    qihse_snapshot_xfer_state_path(dest_path, path, sizeof(path));
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE* f = fopen(tmp, "wb");
    if (!f) return false;
    if (fwrite(st, sizeof(*st), 1u, f) != 1u) { fclose(f); unlink(tmp); return false; }
    if (fflush(f) != 0) { fclose(f); unlink(tmp); return false; }
    int fd = fileno(f);
    if (fd >= 0) (void)fsync(fd);
    fclose(f);
    if (rename(tmp, path) != 0) { unlink(tmp); return false; }
    return true;
}

/* ── sender ───────────────────────────────────────────────────────────── */

uint64_t qihse_snapshot_xfer_serve(qihse_repl_transport_t* t,
                                   const char* container_path,
                                   char* err, size_t err_cap) {
    uint64_t served = 0;
    FILE* f = NULL;
    uint8_t* buf = NULL;

    if (!t || !container_path) {
        set_err(err, err_cap, "args");
        return 0;
    }
    if (!t->peer_verified) {
        set_err(err, err_cap, "peer not verified: an unverified session may not serve state");
        return 0;
    }

    buf = (uint8_t*)malloc(QSX_PAYLOAD_CAP);
    if (!buf) { set_err(err, err_cap, "oom"); return 0; }

    /* FETCH { resume_offset, max_total } */
    uint16_t kind = 0;
    long n = frame_recv(t, &kind, buf, QSX_PAYLOAD_CAP);
    if (n != (long)QSX_FETCH_LEN || kind != QSX_FETCH) {
        set_err(err, err_cap, "expected FETCH");
        goto done;
    }
    uint64_t resume_offset = get_u64(buf);
    uint64_t max_total = get_u64(buf + 8);

    f = fopen(container_path, "rb");
    if (!f) { set_err(err, err_cap, "container open failed"); goto done; }
    if (fseek(f, 0L, SEEK_END) != 0) { set_err(err, err_cap, "container seek failed"); goto done; }
    long fsize = ftell(f);
    if (fsize < 0) { set_err(err, err_cap, "container size failed"); goto done; }
    uint64_t total_len = (uint64_t)fsize;
    if (max_total != 0 && total_len > max_total) {
        send_abort(&t, "container exceeds receiver cap");
        set_err(err, err_cap, "container exceeds receiver cap");
        goto done;
    }
    if (resume_offset > total_len) {
        send_abort(&t, "resume offset beyond container");
        set_err(err, err_cap, "resume offset beyond container");
        goto done;
    }

    /* Header digest: the receiver's resume point binds to the same
     * container across calls. */
    uint8_t begin[QSX_BEGIN_LEN];
    memset(begin, 0, sizeof(begin));
    {
        uint8_t header[464];
        if (fseek(f, 0L, SEEK_SET) != 0) {   /* we sized from EOF; rewind */
            set_err(err, err_cap, "container rewind failed");
            goto done;
        }
        size_t got = fread(header, 1u, sizeof(header), f);
        if (got == 0 && total_len > 0) {
            set_err(err, err_cap, "container header read failed");
            goto done;
        }
        SHA384(header, got, begin + 12);
        if (fseek(f, 0L, SEEK_SET) != 0) {
            set_err(err, err_cap, "container rewind failed");
            goto done;
        }
    }
    put_u64(begin, total_len);
    put_u32(begin + 8, QIHSE_SNAPSHOT_XFER_CHUNK);
    if (!frame_send(t, QSX_BEGIN, begin, QSX_BEGIN_LEN)) {
        set_err(err, err_cap, "BEGIN send failed");
        goto done;
    }

    if (fseek(f, (long)resume_offset, SEEK_SET) != 0) {
        set_err(err, err_cap, "resume seek failed");
        goto done;
    }

    uint64_t offset = resume_offset;
    while (offset < total_len) {
        uint32_t want = (total_len - offset > QIHSE_SNAPSHOT_XFER_CHUNK)
                            ? QIHSE_SNAPSHOT_XFER_CHUNK
                            : (uint32_t)(total_len - offset);
        size_t got = fread(buf + 8, 1u, want, f);
        if (got == 0) { set_err(err, err_cap, "container read failed"); goto done; }
        put_u64(buf, offset);
        put_u32(buf + 8 + got, crc32_buf(buf + 8, got));
        if (!frame_send(t, QSX_CHUNK, buf, (uint32_t)(8u + got + 4u))) {
            set_err(err, err_cap, "CHUNK send failed");
            goto done;
        }
        /* stop-and-wait: one ACK per chunk */
        n = frame_recv(t, &kind, buf, QSX_PAYLOAD_CAP);
        if (n != (long)QSX_ACK_LEN || kind != QSX_ACK) {
            set_err(err, err_cap, "expected ACK");
            goto done;
        }
        if (get_u64(buf) != offset + (uint64_t)got) {
            set_err(err, err_cap, "ACK offset mismatch");
            goto done;
        }
        offset += (uint64_t)got;
        served += (uint64_t)got;
    }

    uint8_t done_p[QSX_DONE_LEN];
    put_u64(done_p, total_len);
    if (!frame_send(t, QSX_DONE, done_p, QSX_DONE_LEN)) {
        set_err(err, err_cap, "DONE send failed");
        goto done;
    }

done:
    if (f) fclose(f);
    free(buf);
    return served;
}

/* ── receiver ─────────────────────────────────────────────────────────── */

qihse_snapshot_xfer_result_t qihse_snapshot_xfer_fetch(
    qihse_repl_transport_t* t, const char* dest_path,
    uint64_t max_total, uint32_t max_chunks, uint64_t* out_offset,
    char* err, size_t err_cap) {
    qihse_snapshot_xfer_result_t rc = QIHSE_SNAPSHOT_XFER_ERR_IO;
    FILE* f = NULL;
    uint8_t* buf = NULL;
    qsx_state_t st;
    memset(&st, 0, sizeof(st));
    uint64_t received = 0;
    bool resumed = false;
    uint32_t chunks_done = 0;

    if (out_offset) *out_offset = 0;
    if (!t || !dest_path || (max_total != 0 && max_total > QIHSE_SNAPSHOT_XFER_MAX_TOTAL)) {
        set_err(err, err_cap, "args");
        return QIHSE_SNAPSHOT_XFER_ERR_ARGS;
    }
    if (max_total == 0) max_total = QIHSE_SNAPSHOT_XFER_MAX_TOTAL;
    if (!t->peer_verified) {
        set_err(err, err_cap, "peer not verified: an unverified session may not receive state");
        return QIHSE_SNAPSHOT_XFER_ERR_PEER;
    }

    buf = (uint8_t*)malloc(QSX_PAYLOAD_CAP);
    if (!buf) { set_err(err, err_cap, "oom"); return QIHSE_SNAPSHOT_XFER_ERR_IO; }

    resumed = state_load(dest_path, &st);
    if (resumed) {
        if (st.total_len == 0 || st.total_len > max_total ||
            st.offset > st.total_len || st.chunk_size == 0 ||
            st.chunk_size > QIHSE_SNAPSHOT_XFER_CHUNK) {
            set_err(err, err_cap, "resume state out of bounds; remove the sidecar to restart");
            rc = QIHSE_SNAPSHOT_XFER_ERR_BOUNDS;
            goto done;
        }
        f = fopen(dest_path, "r+b");
        if (!f) { set_err(err, err_cap, "resume: dest missing"); goto done; }
    } else {
        f = fopen(dest_path, "wb");
        if (!f) { set_err(err, err_cap, "dest create failed"); goto done; }
    }

    /* FETCH { resume_offset, max_total } */
    uint8_t fetch_p[QSX_FETCH_LEN];
    put_u64(fetch_p, resumed ? st.offset : 0u);
    put_u64(fetch_p + 8, max_total);
    if (!frame_send(t, QSX_FETCH, fetch_p, QSX_FETCH_LEN)) {
        set_err(err, err_cap, "FETCH send failed");
        goto done;
    }

    /* BEGIN must match a persisted resume point exactly. */
    uint16_t kind = 0;
    long n = frame_recv(t, &kind, buf, QSX_PAYLOAD_CAP);
    if (kind == QSX_ABORT && n == (long)QSX_ABORT_LEN) {
        set_err(err, err_cap, (const char*)buf);
        rc = QIHSE_SNAPSHOT_XFER_ERR_PROTOCOL;
        goto done;
    }
    if (n != (long)QSX_BEGIN_LEN || kind != QSX_BEGIN) {
        set_err(err, err_cap, "expected BEGIN");
        rc = QIHSE_SNAPSHOT_XFER_ERR_PROTOCOL;
        goto done;
    }
    uint64_t total_len = get_u64(buf);
    uint32_t chunk_size = get_u32(buf + 8);
    if (total_len == 0 || total_len > max_total || chunk_size == 0 ||
        chunk_size > QIHSE_SNAPSHOT_XFER_CHUNK) {
        send_abort(&t, "BEGIN bounds");
        set_err(err, err_cap, "BEGIN out of bounds");
        rc = QIHSE_SNAPSHOT_XFER_ERR_BOUNDS;
        goto done;
    }
    if (resumed) {
        if (st.total_len != total_len ||
            memcmp(st.header_sha384, buf + 12, 48u) != 0) {
            send_abort(&t, "container changed since resume");
            set_err(err, err_cap, "container changed since resume point");
            rc = QIHSE_SNAPSHOT_XFER_ERR_PROTOCOL;
            goto done;
        }
        if (fseek(f, (long)st.offset, SEEK_SET) != 0) {
            set_err(err, err_cap, "resume seek failed");
            goto done;
        }
    } else {
        st.magic = QSX_MAGIC;
        st.version = 1u;
        st.total_len = total_len;
        st.chunk_size = chunk_size;
        st.offset = 0;
        memcpy(st.header_sha384, buf + 12, 48u);
    }

    uint64_t offset = st.offset;
    received = st.offset;

    for (;;) {
        n = frame_recv(t, &kind, buf, QSX_PAYLOAD_CAP);
        if (n < 0) { set_err(err, err_cap, "transport closed mid-transfer"); goto done; }

        if (kind == QSX_ABORT && n == (long)QSX_ABORT_LEN) {
            set_err(err, err_cap, (const char*)buf);
            rc = QIHSE_SNAPSHOT_XFER_ERR_PROTOCOL;
            goto done;
        }
        if (kind == QSX_DONE) {
            if (n != (long)QSX_DONE_LEN || get_u64(buf) != total_len) {
                set_err(err, err_cap, "malformed DONE");
                rc = QIHSE_SNAPSHOT_XFER_ERR_PROTOCOL;
                goto done;
            }
            if (offset != total_len) {
                set_err(err, err_cap, "DONE before all chunks received");
                rc = QIHSE_SNAPSHOT_XFER_ERR_PROTOCOL;
                goto done;
            }
            break;
        }
        if (kind != QSX_CHUNK || n < (long)QSX_CHUNK_MIN) {
            set_err(err, err_cap, "expected CHUNK");
            rc = QIHSE_SNAPSHOT_XFER_ERR_PROTOCOL;
            goto done;
        }
        uint64_t off = get_u64(buf);
        uint32_t crc = get_u32(buf + (uint32_t)n - 4u);
        size_t data_len = (size_t)n - 12u;
        if (off != offset || data_len == 0 ||
            off + (uint64_t)data_len < off ||              /* overflow */
            off + (uint64_t)data_len > total_len) {
            send_abort(&t, "CHUNK bounds");
            set_err(err, err_cap, "chunk offset/length out of bounds");
            rc = QIHSE_SNAPSHOT_XFER_ERR_BOUNDS;
            goto done;
        }
        if (crc32_buf(buf + 8, data_len) != crc) {
            send_abort(&t, "CHUNK crc");
            set_err(err, err_cap, "chunk CRC mismatch");
            rc = QIHSE_SNAPSHOT_XFER_ERR_CRC;
            goto done;
        }
        if (fwrite(buf + 8, 1u, data_len, f) != data_len) {
            set_err(err, err_cap, "dest write failed");
            goto done;
        }
        offset += (uint64_t)data_len;
        received = offset;
        st.offset = offset;
        if (!state_save(dest_path, &st)) {
            set_err(err, err_cap, "resume state persist failed");
            goto done;
        }
        uint8_t ack_p[QSX_ACK_LEN];
        put_u64(ack_p, offset);
        if (!frame_send(t, QSX_ACK, ack_p, QSX_ACK_LEN)) {
            set_err(err, err_cap, "ACK send failed");
            goto done;
        }
        chunks_done++;
        if (max_chunks && chunks_done >= max_chunks && offset < total_len) {
            /* Tell the sender this round is over — it is blocked in
             * stop-and-wait waiting for our next response and there is
             * none coming. */
            send_abort(&t, "receiver paused (bounded round)");
            if (out_offset) *out_offset = received;
            rc = QIHSE_SNAPSHOT_XFER_IN_PROGRESS;
            goto done_keep_state;
        }
    }

    /* Complete: flush, drop the resume point. */
    if (fflush(f) != 0) { set_err(err, err_cap, "dest flush failed"); goto done; }
    {
        int fd = fileno(f);
        if (fd >= 0) (void)fsync(fd);
    }
    {
        char sidecar[512];
        qihse_snapshot_xfer_state_path(dest_path, sidecar, sizeof(sidecar));
        (void)unlink(sidecar);
    }
    if (out_offset) *out_offset = received;
    rc = QIHSE_SNAPSHOT_XFER_OK;
    goto done;

done_keep_state:
    if (f) { fflush(f); }
    free(buf);
    if (f) fclose(f);
    return rc;

done:
    if (f) fclose(f);
    free(buf);
    return rc;
}
