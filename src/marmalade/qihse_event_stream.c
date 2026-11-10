#include "qihse_event_stream.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/sendfile.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <pthread.h>
#include <limits.h>

typedef struct es_id_entry {
    uint8_t id[QIHSE_ES_EVENT_ID_SIZE];
    uint8_t payload_digest[QIHSE_ES_EVENT_ID_SIZE];
    uint32_t schema_id;
    uint64_t offset;
    bool used;
} es_id_entry_t;

struct es_topic_cache {
    char name[112];
    struct stat stamp;
    bool valid;
    uint64_t end, previous;
    es_id_entry_t* ids;
    size_t capacity, count;
    bool committed_corruption;
    struct es_topic_cache* next;
};

static void scoped_cache_destroy(struct es_topic_cache* cache);
static bool scoped_flush(qihse_event_stream_t* stream);
static bool legacy_append_cached(qihse_event_stream_t*, const char*, uint32_t,
                                 const uint8_t*, const uint8_t*, size_t, uint64_t*);
static bool same_stamp(const struct stat*, const struct stat*);

/* ── Internal structure ───────────────────────────────────────────────────── */

struct qihse_event_stream {
    char* log_directory;
    qihse_es_durability_t durability;
    bool read_only;
    int directory_fd;
    pthread_mutex_t mutex;
    struct es_topic_cache* topics;
};

/* ── Helpers ──────────────────────────────────────────────────────────────── */

static bool topic_is_safe(const char* topic) {
    if (!topic || topic[0] == '\0' || strlen(topic) > QIHSE_ES_TOPIC_MAX) return false;
    for (const char* p = topic; *p; ++p) {
        if (*p == '/' || *p == '\\') return false;
        if (*p == '.' && p[1] == '.') return false;
    }
    return true;
}

static void build_path(char* buf, size_t buf_size, const char* dir, const char* topic) {
    snprintf(buf, buf_size, "%s/%s.log", dir, topic);
}

/* Validate a record header. */
static bool validate_header(const qihse_es_record_header_t* hdr, uint64_t expected_offset) {
    if (hdr->magic != QIHSE_ES_MAGIC) return false;
    if (hdr->format_version != QIHSE_ES_FORMAT_VERSION) return false;
    if (hdr->stream_offset != expected_offset) return false;
    if (hdr->payload_size > QIHSE_ES_MAX_PAYLOAD) return false;
    return true;
}

/* Compute SHA-384 of (topic || payload). */
static void compute_event_id(const char* topic, const uint8_t* payload, size_t payload_size, uint8_t out[QIHSE_ES_EVENT_ID_SIZE]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) { memset(out, 0, QIHSE_ES_EVENT_ID_SIZE); return; }
    EVP_DigestInit_ex(ctx, EVP_sha384(), NULL);
    EVP_DigestUpdate(ctx, topic, strlen(topic));
    EVP_DigestUpdate(ctx, payload, payload_size);
    unsigned int outlen = 0;
    EVP_DigestFinal_ex(ctx, out, &outlen);
    EVP_MD_CTX_free(ctx);
}

/* ── Lifecycle ───────────────────────────────────────────────────────────── */

qihse_event_stream_t* qihse_event_stream_create(const char* log_directory) {
    return qihse_event_stream_open(log_directory, QIHSE_ES_DURABILITY_FDATASYNC, false);
}

qihse_event_stream_t* qihse_event_stream_open(
        const char* log_directory,
        qihse_es_durability_t durability,
        bool read_only) {
    if (!log_directory || durability < QIHSE_ES_DURABILITY_NONE ||
        durability > QIHSE_ES_DURABILITY_FULL) return NULL;

    /* Verify directory exists and is a directory (no symlink following). */
    struct stat st;
    if (stat(log_directory, &st) != 0 || !S_ISDIR(st.st_mode)) {
        if (!read_only) {
            if (mkdir(log_directory, 0700) != 0 && errno != EEXIST) return NULL;
        } else {
            return NULL;
        }
    }

    qihse_event_stream_t* stream = calloc(1, sizeof(*stream));
    if (!stream) return NULL;
    stream->log_directory = strdup(log_directory);
    if (!stream->log_directory) { free(stream); return NULL; }
    stream->directory_fd = open(log_directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (stream->directory_fd < 0 || pthread_mutex_init(&stream->mutex, NULL) != 0) {
        if (stream->directory_fd >= 0) close(stream->directory_fd);
        free(stream->log_directory);
        free(stream);
        return NULL;
    }
    stream->durability = durability;
    stream->read_only = read_only;
    return stream;
}

void qihse_event_stream_destroy(qihse_event_stream_t* stream) {
    if (stream) {
        scoped_cache_destroy(stream->topics);
        pthread_mutex_destroy(&stream->mutex);
        close(stream->directory_fd);
        free(stream->log_directory);
        free(stream);
    }
}

bool qihse_event_stream_flush(qihse_event_stream_t* stream) {
    return stream && scoped_flush(stream);
}

/* ── Open topic file ─────────────────────────────────────────────────────── */

static int open_topic(qihse_event_stream_t* stream, const char* topic, bool for_write) {
    if (!topic_is_safe(topic)) return -1;

    char filepath[1024];
    build_path(filepath, sizeof(filepath), stream->log_directory, topic);

    int flags;
    if (for_write && !stream->read_only) {
        flags = O_RDWR | O_CREAT;
    } else {
        flags = O_RDONLY;
    }
    /* O_NOFOLLOW: reject symlinks */
    flags |= O_NOFOLLOW;

    int fd = open(filepath, flags, 0600);
    if (fd < 0) return -1;

    /* Advisory exclusive lock for writers, shared lock for readers. */
    if (for_write && !stream->read_only) {
        if (flock(fd, LOCK_EX) < 0) { close(fd); return -1; }
    } else {
        if (flock(fd, LOCK_SH) < 0) { close(fd); return -1; }
    }

    return fd;
}

/* ── Append ──────────────────────────────────────────────────────────────── */

uint64_t qihse_event_stream_append_record(
        qihse_event_stream_t* stream,
        const char* topic,
        uint32_t schema_id,
        const uint8_t* event_id,
        const uint8_t* payload,
        size_t payload_size) {
    if (!stream || !topic || !event_id || (!payload && payload_size > 0)) return 0;
    if (stream->read_only) return 0;
    if (payload_size > QIHSE_ES_MAX_PAYLOAD) return 0;

    uint64_t offset = 0;
    if (!legacy_append_cached(stream, topic, schema_id, event_id, payload, payload_size,
                              &offset)) return 0;
    return offset + 1; /* preserve legacy offset+1 ABI */
}

bool qihse_event_stream_append(
        qihse_event_stream_t* stream,
        const char* topic,
        const uint8_t* payload,
        size_t payload_size) {
    if (!stream || !topic) return false;
    uint8_t event_id[QIHSE_ES_EVENT_ID_SIZE];
    compute_event_id(topic, payload, payload_size, event_id);
    return qihse_event_stream_append_record(stream, topic, 0, event_id, payload, payload_size) != 0;
}

/* ── Read ────────────────────────────────────────────────────────────────── */

bool qihse_event_stream_read(
        qihse_event_stream_t* stream,
        const char* topic,
        uint64_t stream_offset,
        qihse_es_record_header_t* out_header,
        uint8_t** out_payload,
        size_t* out_payload_size) {
    if (out_payload) *out_payload = NULL;
    if (out_payload_size) *out_payload_size = 0;
    if (!stream || !topic || !out_header) return false;

    int fd = open_topic(stream, topic, false);
    if (fd < 0) return false;

    if (pread(fd, out_header, sizeof(*out_header), stream_offset) != (ssize_t)sizeof(*out_header)) {
        close(fd); return false;
    }
    if (!validate_header(out_header, stream_offset)) {
        close(fd); return false;
    }
    if (!(out_header->flags & QIHSE_ES_F_COMMITTED)) {
        close(fd); return false;
    }

    if (out_payload && out_payload_size && out_header->payload_size > 0) {
        *out_payload = malloc(out_header->payload_size);
        if (!*out_payload) { close(fd); return false; }
        if (pread(fd, *out_payload, out_header->payload_size, stream_offset + sizeof(*out_header))
                != (ssize_t)out_header->payload_size) {
            free(*out_payload);
            *out_payload = NULL;
            close(fd); return false;
        }
        *out_payload_size = out_header->payload_size;
    }

    close(fd);
    return true;
}

bool qihse_event_stream_iterate(
        qihse_event_stream_t* stream,
        const char* topic,
        uint64_t* cursor,
        qihse_es_record_header_t* out_header,
        uint8_t** out_payload,
        size_t* out_payload_size) {
    if (out_payload) *out_payload = NULL;
    if (out_payload_size) *out_payload_size = 0;
    if (!stream || !topic || !cursor || !out_header) return false;

    int fd = open_topic(stream, topic, false);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return false; }
    uint64_t file_size = (uint64_t)st.st_size;

    while (*cursor < file_size) {
        if (pread(fd, out_header, sizeof(*out_header), *cursor) != (ssize_t)sizeof(*out_header)) {
            break;
        }
        if (!validate_header(out_header, *cursor) || !(out_header->flags & QIHSE_ES_F_COMMITTED)) {
            break;
        }
        if (out_payload && out_payload_size && out_header->payload_size > 0) {
            *out_payload = malloc(out_header->payload_size);
            if (!*out_payload) { close(fd); return false; }
            if (pread(fd, *out_payload, out_header->payload_size, *cursor + sizeof(*out_header))
                    != (ssize_t)out_header->payload_size) {
                free(*out_payload);
                *out_payload = NULL;
                break;
            }
            *out_payload_size = out_header->payload_size;
        }
        *cursor += sizeof(*out_header) + out_header->payload_size;
        close(fd);
        return true;
    }

    close(fd);
    return false;
}

uint64_t qihse_event_stream_length(qihse_event_stream_t* stream, const char* topic) {
    if (!stream || !topic_is_safe(topic)) return 0;
    char filepath[1024];
    build_path(filepath, sizeof(filepath), stream->log_directory, topic);
    struct stat st;
    if (stat(filepath, &st) != 0) return 0;
    return (uint64_t)st.st_size;
}

bool qihse_event_stream_has_event_id(
        qihse_event_stream_t* stream,
        const char* topic,
        const uint8_t* event_id) {
    if (!stream || !topic || !event_id) return false;

    int fd = open_topic(stream, topic, false);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return false; }
    uint64_t file_size = (uint64_t)st.st_size;
    uint64_t offset = 0;

    while (offset < file_size) {
        qihse_es_record_header_t hdr;
        if (pread(fd, &hdr, sizeof(hdr), offset) != (ssize_t)sizeof(hdr)) break;
        if (!validate_header(&hdr, offset)) break;
        if (!(hdr.flags & QIHSE_ES_F_COMMITTED)) break;
        if (memcmp(hdr.event_id, event_id, QIHSE_ES_EVENT_ID_SIZE) == 0) {
            close(fd);
            return true;
        }
        offset += sizeof(hdr) + hdr.payload_size;
    }

    close(fd);
    return false;
}

/* ── Recovery ────────────────────────────────────────────────────────────── */

static bool pread_fully_at(int fd, void* buffer, size_t size, uint64_t offset)
{
    size_t done = 0u;
    while (done < size) {
        ssize_t n = pread(fd, (uint8_t*)buffer + done, size - done,
                          (off_t)(offset + done));
        if (n > 0) { done += (size_t)n; continue; }
        if (n < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

uint64_t qihse_event_stream_replay(
        qihse_event_stream_t* stream,
        const char* topic,
        qihse_es_replay_cb callback,
        void* user_data) {
    uint64_t count = 0;
    (void)qihse_event_stream_replay_checked(stream, topic, callback, user_data, &count);
    return count;
}

bool qihse_event_stream_replay_checked(
        qihse_event_stream_t* stream,
        const char* topic,
        qihse_es_replay_cb callback,
        void* user_data,
        uint64_t* out_count) {
    if (out_count) *out_count = 0;
    if (!stream || !topic || !callback || !topic_is_safe(topic)) return false;

    int fd = open_topic(stream, topic, false);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) != 0 || st.st_size < 0) { close(fd); return false; }
    uint64_t file_size = (uint64_t)st.st_size;
    uint64_t offset = 0;
    uint64_t count = 0;
    bool ok = true;

    while (offset < file_size) {
        qihse_es_record_header_t hdr;
        uint64_t remaining = file_size - offset;
        if (remaining < sizeof(hdr) ||
            !pread_fully_at(fd, &hdr, sizeof(hdr), offset) ||
            !validate_header(&hdr, offset) ||
            hdr.flags != QIHSE_ES_F_COMMITTED ||
            hdr.payload_size > remaining - sizeof(hdr)) {
            ok = false;
            break;
        }

        uint8_t* payload = NULL;
        if (hdr.payload_size > 0) {
            payload = malloc(hdr.payload_size);
            if (!payload) { ok = false; break; }
            if (!pread_fully_at(fd, payload, (size_t)hdr.payload_size,
                                offset + sizeof(hdr))) {
                free(payload);
                ok = false;
                break;
            }
        }

        if (!callback(&hdr, payload, hdr.payload_size, user_data)) {
            free(payload);
            ok = false;
            break;
        }
        free(payload);
        count++;
        offset += sizeof(hdr) + hdr.payload_size;
    }

    if (close(fd) != 0) ok = false;
    if (out_count) *out_count = count;
    return ok && offset == file_size;
}

bool qihse_event_stream_truncate_torn_tail(
        qihse_event_stream_t* stream,
        const char* topic) {
    if (!stream || !topic || stream->read_only) return false;

    int fd = open_topic(stream, topic, true);
    if (fd < 0) return false;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return false; }
    uint64_t file_size = (uint64_t)st.st_size;
    uint64_t offset = 0;
    uint64_t last_valid_end = 0;

    while (offset < file_size) {
        qihse_es_record_header_t hdr;
        uint64_t remaining = file_size - offset;
        if (remaining < sizeof(hdr)) break;
        if (pread(fd, &hdr, sizeof(hdr), offset) != (ssize_t)sizeof(hdr) ||
            !validate_header(&hdr, offset)) {
            close(fd);
            return false;
        }
        if (hdr.flags == 0) break;
        if (hdr.flags != QIHSE_ES_F_COMMITTED ||
            hdr.payload_size > remaining - sizeof(hdr)) {
            close(fd);
            return false;
        }
        last_valid_end = offset + sizeof(hdr) + hdr.payload_size;
        offset = last_valid_end;
    }

    if (last_valid_end < file_size &&
        (ftruncate(fd, (off_t)last_valid_end) != 0 || fdatasync(fd) != 0)) {
        close(fd);
        return false;
    }

    close(fd);
    return true;
}

/* ── Zero-copy consumption ────────────────────────────────────────────────── */

bool qihse_event_stream_consume_zero_copy(
        qihse_event_stream_t* stream,
        const char* topic,
        uint64_t offset,
        int network_socket_fd,
        size_t count) {
    if (!stream || !topic || network_socket_fd < 0) return false;
    if (!topic_is_safe(topic)) return false;

    char filepath[1024];
    build_path(filepath, sizeof(filepath), stream->log_directory, topic);

    int fd = open(filepath, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return false;

    off_t off = (off_t)offset;
    ssize_t sent = sendfile(network_socket_fd, fd, &off, count);
    close(fd);

    return sent >= 0;
}

/* V2 and legacy caches are protected by the handle mutex. File locks
 * additionally serialize distinct handles and cooperating processes. */
static void scoped_cache_destroy(struct es_topic_cache* cache) {
    while (cache) {
        struct es_topic_cache* next = cache->next;
        free(cache->ids);
        free(cache);
        cache = next;
    }
}

static bool es_digest(const char* domain, const void* a, size_t an,
                      const void* b, size_t bn, uint8_t out[48]) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned int n = 0;
    bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha384(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, domain, strlen(domain) + 1) == 1 &&
        (!an || EVP_DigestUpdate(ctx, a, an) == 1) &&
        (!bn || EVP_DigestUpdate(ctx, b, bn) == 1) &&
        EVP_DigestFinal_ex(ctx, out, &n) == 1 && n == 48;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static bool digest_u64(EVP_MD_CTX* ctx, uint64_t value) {
    uint8_t encoded[8];
    for (size_t i = 0; i < sizeof(encoded); ++i) encoded[i] = (uint8_t)(value >> (i * 8));
    return EVP_DigestUpdate(ctx, encoded, sizeof(encoded)) == 1;
}

static bool stable_identity(const char* domain, const char* version, uint32_t schema,
                            const void* a, size_t a_size, const void* b, size_t b_size,
                            uint8_t out[48]) {
    if (!domain || !version || !version[0] || strlen(version) > 255 ||
        (!a && a_size) || (!b && b_size) || !out) return false;
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    unsigned int n = 0;
    uint8_t schema_bytes[4] = {(uint8_t)schema, (uint8_t)(schema >> 8),
                               (uint8_t)(schema >> 16), (uint8_t)(schema >> 24)};
    bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha384(), NULL) == 1 &&
        EVP_DigestUpdate(ctx, domain, strlen(domain) + 1) == 1;
    ok = ok && digest_u64(ctx, strlen(version)) &&
        EVP_DigestUpdate(ctx, version, strlen(version)) == 1 &&
        EVP_DigestUpdate(ctx, schema_bytes, sizeof(schema_bytes)) == 1 &&
        digest_u64(ctx, a_size) && (!a_size || EVP_DigestUpdate(ctx, a, a_size) == 1) &&
        digest_u64(ctx, b_size);
    ok = ok && (!b_size || EVP_DigestUpdate(ctx, b, b_size) == 1) &&
        EVP_DigestFinal_ex(ctx, out, &n) == 1 && n == 48;
    EVP_MD_CTX_free(ctx);
    return ok;
}

bool qihse_event_stream_archive_id(const uint8_t* archive, size_t size,
                                   const char* scan_version, uint32_t schema,
                                   uint8_t out[48]) {
    return stable_identity("QIHSE archive identity v2", scan_version, schema,
                           archive, size, NULL, 0, out);
}

bool qihse_event_stream_member_id(const uint8_t archive[48], const char* name,
                                  const char* scan_version, uint32_t schema,
                                  uint8_t out[48]) {
    return archive && name && stable_identity("QIHSE member identity v2", scan_version,
        schema, archive, 48, name, strlen(name), out);
}

static bool scoped_name(const qihse_user_t* user, const qihse_es_scope_t* scope,
                        char name[112]) {
    if (!user || !scope || !topic_is_safe(scope->topic) ||
        !qihse_auth_user_is_active(user) ||
        !qihse_auth_can_access(user, scope->classification, scope->sci)) return false;
    uint32_t tenant = qihse_user_get_tenant_id(user);
    if (tenant == QIHSE_TENANT_INVALID) return false;
    uint8_t identity[8], hash[48];
    for (unsigned i = 0; i < 4; ++i) identity[i] = (uint8_t)(tenant >> (8*i));
    identity[4] = (uint8_t)scope->classification;
    identity[5] = (uint8_t)(scope->classification >> 8);
    identity[6] = (uint8_t)scope->sci;
    identity[7] = (uint8_t)(scope->sci >> 8);
    if (!es_digest("QIHSE scoped topic v2", identity, sizeof(identity),
                   scope->topic, strlen(scope->topic), hash)) return false;
    memcpy(name, "scoped-v2-", 10);
    for (size_t i = 0; i < 48; ++i) snprintf(name + 10 + 2*i, 3, "%02x", hash[i]);
    memcpy(name + 106, ".log", 5);
    return true;
}

static bool es_io(int fd, void* buffer, size_t size, uint64_t offset, bool write_it) {
    uint8_t* p = buffer;
    while (size) {
        ssize_t n = write_it ? pwrite(fd, p, size, (off_t)offset) :
                               pread(fd, p, size, (off_t)offset);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        p += n;
        size -= (size_t)n;
        offset += (size_t)n;
    }
    return true;
}

static size_t id_bucket(const uint8_t id[48], size_t capacity) {
    uint64_t h = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < 48; ++i) h = (h ^ id[i]) * UINT64_C(1099511628211);
    return (size_t)h & (capacity - 1);
}

static es_id_entry_t* id_find(struct es_topic_cache* t, const uint8_t id[48]) {
    if (!t->capacity) return NULL;
    size_t i = id_bucket(id, t->capacity);
    while (t->ids[i].used) {
        if (memcmp(t->ids[i].id, id, 48) == 0) return &t->ids[i];
        i = (i + 1) & (t->capacity - 1);
    }
    return NULL;
}

static void id_insert(struct es_topic_cache* t, const uint8_t id[48], uint32_t schema,
                      const uint8_t digest[48], uint64_t offset) {
    size_t i = id_bucket(id, t->capacity);
    while (t->ids[i].used) i = (i + 1) & (t->capacity - 1);
    memcpy(t->ids[i].id, id, 48);
    memcpy(t->ids[i].payload_digest, digest, 48);
    t->ids[i].schema_id = schema;
    t->ids[i].offset = offset;
    t->ids[i].used = true;
    ++t->count;
}

static bool id_reserve(struct es_topic_cache* t, size_t extra) {
    if (extra > SIZE_MAX - t->count) return false;
    size_t need = t->count + extra, cap = t->capacity ? t->capacity : 128;
    while (need >= cap / 2) {
        if (cap > SIZE_MAX / 2) return false;
        cap *= 2;
    }
    if (cap == t->capacity) return true;
    es_id_entry_t* entries = calloc(cap, sizeof(*entries));
    if (!entries) return false;
    es_id_entry_t* old = t->ids;
    size_t oldcap = t->capacity;
    t->ids = entries;
    t->capacity = cap;
    t->count = 0;
    for (size_t i = 0; i < oldcap; ++i)
        if (old[i].used) id_insert(t, old[i].id, old[i].schema_id,
                                   old[i].payload_digest, old[i].offset);
    free(old);
    return true;
}

static struct es_topic_cache* legacy_cache_get(qihse_event_stream_t* stream,
                                               const char* topic) {
    char key[112];
    int n = snprintf(key, sizeof(key), "%s.log", topic);
    if (n < 0 || (size_t)n >= sizeof(key)) return NULL;
    struct es_topic_cache* t = stream->topics;
    while (t && strcmp(t->name, key)) t = t->next;
    if (!t) {
        t = calloc(1, sizeof(*t));
        if (!t) return NULL;
        memcpy(t->name, key, (size_t)n + 1);
        t->next = stream->topics;
        stream->topics = t;
    }
    return t;
}

/* Rebuild only after a file identity/size/timestamp change. The caller holds
 * both the handle mutex and the topic's exclusive flock. Committed corruption
 * is a hard error; only explicit tail-recovery API may truncate a V1 log. */
static bool legacy_cache_recover(struct es_topic_cache* t, int fd, struct stat* out_stamp) {
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0) return false;
    if (t->valid && same_stamp(&t->stamp, &st)) {
        *out_stamp = st;
        return !t->committed_corruption;
    }
    t->valid = false;
    t->committed_corruption = false;
    t->end = t->previous = t->count = 0;
    if (t->ids) memset(t->ids, 0, t->capacity * sizeof(*t->ids));
    while (t->end < (uint64_t)st.st_size) {
        qihse_es_record_header_t h;
        uint64_t left = (uint64_t)st.st_size - t->end;
        if (left < sizeof(h) || !es_io(fd, &h, sizeof(h), t->end, false) ||
            !validate_header(&h, t->end) || h.flags != QIHSE_ES_F_COMMITTED ||
            h.payload_size > left - sizeof(h) || h.prev_record_offset != t->previous ||
            id_find(t, h.event_id)) {
            t->committed_corruption = true;
            return false;
        }
        if (!id_reserve(t, 1)) return false;
        uint8_t no_digest[48] = {0};
        id_insert(t, h.event_id, h.schema_id, no_digest, t->end);
        t->previous = t->end;
        t->end += sizeof(h) + h.payload_size;
    }
    t->stamp = st;
    t->valid = true;
    *out_stamp = st;
    return true;
}

static bool legacy_append_cached(qihse_event_stream_t* stream, const char* topic,
                                 uint32_t schema_id, const uint8_t* event_id,
                                 const uint8_t* payload, size_t payload_size,
                                 uint64_t* out_offset) {
    bool ok = false;
    int fd = -1;
    struct es_topic_cache* t = NULL;
    struct stat st;
    pthread_mutex_lock(&stream->mutex);
    fd = open_topic(stream, topic, true);
    if (fd < 0 || !(t = legacy_cache_get(stream, topic)) ||
        !legacy_cache_recover(t, fd, &st) || id_find(t, event_id) ||
        !id_reserve(t, 1) || t->end > (uint64_t)INT64_MAX - sizeof(qihse_es_record_header_t) - payload_size)
        goto done;

    qihse_es_record_header_t h = {0};
    h.magic = QIHSE_ES_MAGIC;
    h.format_version = QIHSE_ES_FORMAT_VERSION;
    h.schema_id = schema_id;
    h.stream_offset = t->end;
    h.payload_size = payload_size;
    h.prev_record_offset = t->previous;
    memcpy(h.event_id, event_id, sizeof(h.event_id));
    uint64_t offset = t->end;
    if (!es_io(fd, &h, sizeof(h), offset, true) ||
        !es_io(fd, (void*)payload, payload_size, offset + sizeof(h), true)) {
        t->valid = false;
        goto done;
    }
    if (stream->durability >= QIHSE_ES_DURABILITY_FDATASYNC && fdatasync(fd) != 0) {
        t->valid = false;
        goto done;
    }
    uint32_t committed = QIHSE_ES_F_COMMITTED;
    if (!es_io(fd, &committed, sizeof(committed),
               offset + offsetof(qihse_es_record_header_t, flags), true) ||
        (stream->durability >= QIHSE_ES_DURABILITY_FDATASYNC && fdatasync(fd) != 0)) {
        t->valid = false;
        goto done;
    }
    uint8_t no_digest[48] = {0};
    id_insert(t, event_id, schema_id, no_digest, offset);
    t->previous = offset;
    t->end = offset + sizeof(h) + payload_size;
    if (fstat(fd, &t->stamp) != 0) {
        t->valid = false;
        goto done;
    }
    t->valid = true;
    *out_offset = offset;
    ok = true;
done:
    if (fd >= 0) close(fd);
    pthread_mutex_unlock(&stream->mutex);
    return ok;
}

/* A trailer hashes the committed header and payload, independently of event_id.
 * Thus caller-assigned stable IDs cannot disable payload integrity checking. */
/* -1 is a transient/resource failure, never a reason to truncate a log. */
static int v2_read(int fd, uint64_t offset, uint64_t end,
                    qihse_es_record_header_t* h, uint8_t** payload) {
    *payload = NULL;
    if (offset > end || end - offset < sizeof(*h) + 48) return 0;
    if (!es_io(fd, h, sizeof(*h), offset, false)) return -1;
    if (h->magic != QIHSE_ES_MAGIC || h->format_version != 2 ||
        h->stream_offset != offset || h->flags != QIHSE_ES_F_COMMITTED ||
        h->payload_size > QIHSE_ES_MAX_PAYLOAD ||
        h->payload_size > end - offset - sizeof(*h) - 48) return 0;
    uint8_t* p = malloc(h->payload_size ? (size_t)h->payload_size : 1);
    uint8_t stored[48], computed[48];
    if (!p) return -1;
    if (!es_io(fd, p, (size_t)h->payload_size, offset + sizeof(*h), false) ||
        !es_io(fd, stored, 48, offset + sizeof(*h) + h->payload_size, false) ||
        !es_digest("QIHSE record v2", h, sizeof(*h), p, (size_t)h->payload_size, computed)) {
        free(p);
        return -1;
    }
    if (CRYPTO_memcmp(stored, computed, 48) != 0) { free(p); return 0; }
    *payload = p;
    return 1;
}

static bool same_stamp(const struct stat* a, const struct stat* b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}

static struct es_topic_cache* scoped_recover(qihse_event_stream_t* s, int fd,
                                             const char* name) {
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0) return NULL;
    struct es_topic_cache* t = s->topics;
    while (t && strcmp(t->name, name)) t = t->next;
    if (!t) {
        t = calloc(1, sizeof(*t));
        if (!t) return NULL;
        strcpy(t->name, name);
        t->next = s->topics;
        s->topics = t;
    }
    if (t->valid && same_stamp(&t->stamp, &st)) return t;
    /* Other handles may append, truncate or replace the file. Never retain
     * stale IDs or trust an unverified prefix after an external modification. */
    t->valid = false;
    t->end = t->previous = 0;
    t->committed_corruption = false;
    t->count = 0;
    if (t->ids) memset(t->ids, 0, t->capacity * sizeof(*t->ids));
    while (t->end < (uint64_t)st.st_size) {
        qihse_es_record_header_t h;
        uint8_t* p;
        int status = v2_read(fd, t->end, (uint64_t)st.st_size, &h, &p);
        if (status < 0) return NULL;
        if (!status) {
            /* Only a well-framed uncommitted header can identify a disposable tail.
             * Every other invalid suffix may be committed corruption. */
            qihse_es_record_header_t tail;
            uint64_t remaining = (uint64_t)st.st_size - t->end;
            if (remaining < sizeof(tail)) break; /* a header cannot yet be committed */
            if (es_io(fd, &tail, sizeof(tail), t->end, false) &&
                tail.magic == QIHSE_ES_MAGIC && tail.format_version == 2 &&
                tail.stream_offset == t->end && tail.flags == 0 &&
                tail.payload_size <= QIHSE_ES_MAX_PAYLOAD)
                break;
            t->committed_corruption = true;
            return NULL;
        }
        if (h.prev_record_offset != t->previous || id_find(t, h.event_id)) {
            t->committed_corruption = true;
            return NULL;
        }
        if (!id_reserve(t, 1)) return NULL;
        uint8_t payload_digest[48];
        if (!es_digest("QIHSE payload v2", p, (size_t)h.payload_size, NULL, 0, payload_digest) ||
            !id_reserve(t, 1)) { free(p); return NULL; }
        id_insert(t, h.event_id, h.schema_id, payload_digest, t->end);
        free(p);
        t->previous = t->end;
        t->end += sizeof(h) + h.payload_size + 48;
    }
    t->stamp = st;
    t->valid = true;
    return t;
}

static int scoped_open(qihse_event_stream_t* s, const char* name, bool writing) {
    int fd = openat(s->directory_fd, name,
        (writing ? O_RDWR | O_CREAT : O_RDONLY) | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    if (fd < 0) return -1;
    if (flock(fd, writing ? LOCK_EX : LOCK_SH) != 0) { close(fd); return -1; }
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_nlink != 1) {
        close(fd);
        return -1;
    }
    return fd;
}

static bool scoped_flush(qihse_event_stream_t* s) {
    bool ok = true;
    pthread_mutex_lock(&s->mutex);
    for (struct es_topic_cache* t = s->topics; t; t = t->next) {
        int fd = scoped_open(s, t->name, true);
        if (fd < 0) { ok = false; continue; }
        if (fdatasync(fd)) ok = false;
        close(fd);
    }
    if (fsync(s->directory_fd)) ok = false;
    pthread_mutex_unlock(&s->mutex);
    return ok;
}

bool qihse_event_stream_append_batch(qihse_event_stream_t* s,
        const qihse_user_t* user, const qihse_es_scope_t* scope,
        const qihse_es_batch_record_t* records, size_t count,
        qihse_es_batch_result_t* results) {
    char name[112];
    if (!s || s->read_only || !records || !results || !count ||
        count > QIHSE_ES_BATCH_MAX_RECORDS || !scoped_name(user, scope, name)) return false;
    size_t bytes = 0;
    for (size_t i = 0; i < count; ++i) {
        if ((!records[i].payload && records[i].payload_size) ||
            records[i].payload_size > QIHSE_ES_MAX_PAYLOAD ||
            records[i].payload_size > QIHSE_ES_BATCH_MAX_BYTES - bytes) return false;
        bytes += records[i].payload_size;
    }
    uint8_t (*ids)[48] = calloc(count, 48);
    qihse_es_batch_result_t* staged = calloc(count, sizeof(*staged));
    if (!ids || !staged) { free(ids); free(staged); return false; }
    bool ok = false;
    int fd = -1;
    struct es_topic_cache* t = NULL;
    uint64_t start = 0, previous = 0;
    bool changed = false;
    for (size_t i = 0; i < count; ++i) {
        if (records[i].event_id) memcpy(ids[i], records[i].event_id, 48);
        else if (!es_digest("QIHSE event v2", name, strlen(name), records[i].payload,
                            records[i].payload_size, ids[i])) goto done_unlocked;
    }
    pthread_mutex_lock(&s->mutex);
    fd = scoped_open(s, name, true);
    if (fd < 0 || !(t = scoped_recover(s, fd, name)) || !id_reserve(t, count)) goto done;
    start = t->end;
    previous = t->previous;
    if (t->committed_corruption) goto done;
    if ((uint64_t)t->stamp.st_size != start) {
        if (ftruncate(fd, (off_t)start)) goto done;
        changed = true;
    }
    for (size_t i = 0; i < count; ++i) {
        es_id_entry_t* existing = id_find(t, ids[i]);
        uint8_t payload_digest[48];
        if (!es_digest("QIHSE payload v2", records[i].payload, records[i].payload_size,
                       NULL, 0, payload_digest)) goto rollback;
        if (existing) {
            if (existing->schema_id != records[i].schema_id ||
                CRYPTO_memcmp(existing->payload_digest, payload_digest, 48) != 0) goto rollback;
            staged[i].stream_offset = existing->offset;
            staged[i].duplicate = true;
            continue;
        }
        for (size_t j = 0; j < i; ++j) {
            if (CRYPTO_memcmp(ids[j], ids[i], 48) == 0) {
                uint8_t prior_digest[48];
                if (records[j].schema_id != records[i].schema_id ||
                    !es_digest("QIHSE payload v2", records[j].payload, records[j].payload_size,
                               NULL, 0, prior_digest) ||
                    CRYPTO_memcmp(prior_digest, payload_digest, 48) != 0) goto rollback;
                staged[i] = staged[j];
                staged[i].duplicate = true;
                existing = (es_id_entry_t*)1;
                break;
            }
        }
        if (existing) continue;
        qihse_es_record_header_t h = {0};
        h.magic = QIHSE_ES_MAGIC;
        h.format_version = 2;
        h.flags = QIHSE_ES_F_COMMITTED;
        h.schema_id = records[i].schema_id;
        h.stream_offset = t->end;
        h.prev_record_offset = t->previous;
        h.payload_size = records[i].payload_size;
        memcpy(h.event_id, ids[i], 48);
        uint8_t trailer[48];
        if (t->end > (uint64_t)INT64_MAX - sizeof(h) - h.payload_size - 48 ||
            !es_digest("QIHSE record v2", &h, sizeof(h), records[i].payload,
                       records[i].payload_size, trailer)) goto rollback;
        h.flags = 0;
        changed = true;
        if (!es_io(fd, &h, sizeof(h), t->end, true) ||
            !es_io(fd, (void*)records[i].payload, records[i].payload_size, t->end + sizeof(h), true) ||
            !es_io(fd, trailer, 48, t->end + sizeof(h) + h.payload_size, true)) goto rollback;
        staged[i].stream_offset = t->end;
        id_insert(t, ids[i], records[i].schema_id, payload_digest, t->end);
        t->previous = t->end;
        t->end += sizeof(h) + h.payload_size + 48;
    }
    if (changed && s->durability != QIHSE_ES_DURABILITY_NONE && fdatasync(fd)) goto rollback;
    for (size_t i = 0; i < count; ++i) {
        uint32_t flags = QIHSE_ES_F_COMMITTED;
        if (!staged[i].duplicate && !es_io(fd, &flags, sizeof(flags),
                staged[i].stream_offset + offsetof(qihse_es_record_header_t, flags), true)) goto rollback;
    }
    if (changed && s->durability != QIHSE_ES_DURABILITY_NONE &&
        (fdatasync(fd) || fsync(s->directory_fd))) goto rollback;
    if (fstat(fd, &t->stamp)) goto rollback;
    memcpy(results, staged, count * sizeof(*results));
    ok = true;
    goto done;
rollback:
    /* Failed batches never leave live cache entries for rolled-back records.
     * If rollback I/O itself fails, recovery validates the remaining prefix. */
    if (changed) {
        int truncated = ftruncate(fd, (off_t)start);
        if (!truncated && s->durability != QIHSE_ES_DURABILITY_NONE) (void)fdatasync(fd);
    }
    t->end = start;
    t->previous = previous;
    t->valid = false;
done:
    if (fd >= 0) close(fd);
    pthread_mutex_unlock(&s->mutex);
done_unlocked:
    free(ids);
    free(staged);
    return ok;
}

void qihse_event_stream_batch_free(qihse_es_read_record_t* records, size_t count) {
    if (!records) return;
    for (size_t i = 0; i < count; ++i) {
        free(records[i].payload);
        memset(&records[i], 0, sizeof(records[i]));
    }
}

bool qihse_event_stream_read_batch(qihse_event_stream_t* s,
        const qihse_user_t* user, const qihse_es_scope_t* scope,
        uint64_t* cursor, qihse_es_read_record_t* records, size_t capacity,
        size_t max_bytes, size_t* out_count) {
    if (out_count) *out_count = 0;
    char name[112];
    if (!s || !cursor || !records || !out_count || !capacity ||
        capacity > QIHSE_ES_BATCH_MAX_RECORDS || max_bytes > QIHSE_ES_BATCH_MAX_BYTES ||
        !scoped_name(user, scope, name)) return false;
    bool ok = false;
    size_t count = 0, bytes = 0;
    uint64_t at = *cursor;
    pthread_mutex_lock(&s->mutex);
    int fd = scoped_open(s, name, false);
    struct es_topic_cache* t = fd >= 0 ? scoped_recover(s, fd, name) : NULL;
    if (!t || at > t->end) goto done;
    /* Check exact boundaries without scanning the whole log on each page. */
    if (at < t->end) {
        qihse_es_record_header_t h;
        if (!es_io(fd, &h, sizeof(h), at, false)) goto done;
        es_id_entry_t* entry = id_find(t, h.event_id);
        if (!entry || entry->offset != at) goto done;
    }
    while (at < t->end && count < capacity) {
        qihse_es_record_header_t h;
        uint8_t* p;
        /* Inspect the size before allocation so the caller's budget bounds
         * this read, including the first record on a page. */
        if (!es_io(fd, &h, sizeof(h), at, false)) goto done;
        if (h.payload_size > max_bytes - bytes) {
            if (!count) goto done;
            break;
        }
        if (v2_read(fd, at, t->end, &h, &p) != 1) { t->valid = false; goto done; }
        records[count].header = h;
        records[count].payload = p;
        records[count].payload_size = (size_t)h.payload_size;
        ++count;
        bytes += (size_t)h.payload_size;
        at += sizeof(h) + h.payload_size + 48;
    }
    *cursor = at;
    *out_count = count;
    ok = true;
done:
    if (!ok) qihse_event_stream_batch_free(records, count);
    if (fd >= 0) close(fd);
    pthread_mutex_unlock(&s->mutex);
    return ok;
}
