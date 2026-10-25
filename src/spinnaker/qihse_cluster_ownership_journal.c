#include "qihse_cluster_ownership_journal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define QIHSE_OWNERSHIP_JOURNAL_MAGIC 0x4A534F51u /* "QOSJ" */
#define QIHSE_OWNERSHIP_JOURNAL_NAME  "slot-ownership.journal"
#define QIHSE_OWNERSHIP_JOURNAL_FRAME 65u            /* see wire layout below */

/* Fixed wire layout (little-endian):
 *   [0..3]   magic (uint32)
 *   [4..5]   start (uint16)
 *   [6..7]   end   (uint16)
 *   [8..48]  owner_id (41 bytes, NUL-padded)
 *   [49..56] config_epoch (uint64)
 *   [57..64] FNV-1a checksum of bytes [0..56]
 */

static uint64_t fnv1a64(const uint8_t* p, size_t n) {
    uint64_t h = 14695981039346656037ull;
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 1099511628211ull;
    }
    return h;
}

static void put_u16(uint8_t* p, uint16_t v) { p[0] = (uint8_t)(v & 0xffu); p[1] = (uint8_t)(v >> 8); }
static void put_u32(uint8_t* p, uint32_t v) {
    p[0] = (uint8_t)(v & 0xffu); p[1] = (uint8_t)((v >> 8) & 0xffu);
    p[2] = (uint8_t)((v >> 16) & 0xffu); p[3] = (uint8_t)((v >> 24) & 0xffu);
}
static void put_u64(uint8_t* p, uint64_t v) {
    for (int i = 0; i < 8; i++) p[i] = (uint8_t)((v >> (8 * i)) & 0xffu);
}
static uint16_t get_u16(const uint8_t* p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t get_u32(const uint8_t* p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static uint64_t get_u64(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    return v;
}

static int journal_path(const char* data_dir, char* out, size_t out_cap) {
    int n = snprintf(out, out_cap, "%s/%s", data_dir, QIHSE_OWNERSHIP_JOURNAL_NAME);
    return (n > 0 && (size_t)n < out_cap) ? 0 : -1;
}

int qihse_cluster_ownership_journal_append(const char* data_dir,
                                           uint16_t start, uint16_t end,
                                           const char* owner_id,
                                           uint64_t config_epoch) {
    if (!data_dir || !owner_id || !*owner_id) { errno = EINVAL; return -1; }
    char path[4096];
    if (journal_path(data_dir, path, sizeof(path)) != 0) { errno = ENAMETOOLONG; return -1; }

    uint8_t frame[QIHSE_OWNERSHIP_JOURNAL_FRAME];
    memset(frame, 0, sizeof(frame));
    put_u32(frame, QIHSE_OWNERSHIP_JOURNAL_MAGIC);
    put_u16(frame + 4, start);
    put_u16(frame + 6, end);
    size_t oid = strlen(owner_id);
    if (oid > QIHSE_CLUSTER_NODE_ID_LEN) oid = QIHSE_CLUSTER_NODE_ID_LEN;
    memcpy(frame + 8, owner_id, oid);
    put_u64(frame + 49, config_epoch);
    uint64_t cksum = fnv1a64(frame, 57u);
    put_u64(frame + 57, cksum);

    int fd = open(path, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    ssize_t w = 0;
    while (w < (ssize_t)sizeof(frame)) {
        ssize_t n = write(fd, frame + w, sizeof(frame) - (size_t)w);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        w += n;
    }
    if (fsync(fd) != 0) { int e = errno; close(fd); errno = e; return -1; }
    close(fd);
    return 0;
}

int qihse_cluster_ownership_journal_replay(const char* data_dir,
                                           qihse_cluster_ownership_journal_cb cb,
                                           void* ctx) {
    if (!data_dir || !cb) { errno = EINVAL; return -1; }
    char path[4096];
    if (journal_path(data_dir, path, sizeof(path)) != 0) { errno = ENAMETOOLONG; return -1; }

    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return (errno == ENOENT) ? 0 : -1; /* no journal yet = nothing to replay */

    int replayed = 0;
    uint8_t frame[QIHSE_OWNERSHIP_JOURNAL_FRAME];
    for (;;) {
        ssize_t got = 0;
        while (got < (ssize_t)sizeof(frame)) {
            ssize_t n = read(fd, frame + got, sizeof(frame) - (size_t)got);
            if (n == 0) break;            /* EOF */
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) { close(fd); return replayed; }
            got += n;
        }
        if (got < (ssize_t)sizeof(frame)) break; /* torn tail — stop */
        uint32_t magic = get_u32(frame);
        uint64_t stored = get_u64(frame + 57);
        uint64_t computed = fnv1a64(frame, 57u);
        if (magic != QIHSE_OWNERSHIP_JOURNAL_MAGIC || stored != computed) {
            break; /* corrupt/torn entry — stop, preserve earlier valid entries */
        }
        qihse_cluster_ownership_entry_t e;
        e.start = get_u16(frame + 4);
        e.end = get_u16(frame + 6);
        memcpy(e.owner_id, frame + 8, QIHSE_CLUSTER_NODE_ID_LEN);
        e.owner_id[QIHSE_CLUSTER_NODE_ID_LEN] = '\0';
        e.config_epoch = get_u64(frame + 49);
        cb(&e, ctx);
        replayed++;
    }
    close(fd);
    return replayed;
}
