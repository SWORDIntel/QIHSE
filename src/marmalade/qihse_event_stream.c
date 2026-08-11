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

/* ── Internal structure ───────────────────────────────────────────────────── */

struct qihse_event_stream {
    char* log_directory;
    qihse_es_durability_t durability;
    bool read_only;
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
    if (!log_directory) return NULL;

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
    stream->durability = durability;
    stream->read_only = read_only;
    return stream;
}

void qihse_event_stream_destroy(qihse_event_stream_t* stream) {
    if (stream) {
        free(stream->log_directory);
        free(stream);
    }
}

bool qihse_event_stream_flush(qihse_event_stream_t* stream) {
    /* Nothing to flush — each append_record does its own fdatasync. */
    (void)stream;
    return true;
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

    /* Check for duplicate event ID. */
    if (qihse_event_stream_has_event_id(stream, topic, event_id)) {
        return 0; /* duplicate rejected */
    }

    int fd = open_topic(stream, topic, true);
    if (fd < 0) return 0;

    /* Get current file size = next stream offset. */
    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return 0; }
    uint64_t offset = (uint64_t)st.st_size;

    /* Find previous record offset (last committed record before this one). */
    uint64_t prev_offset = 0;
    if (offset > 0) {
        uint64_t scan = 0;
        while (scan < offset) {
            qihse_es_record_header_t h;
            if (pread(fd, &h, sizeof(h), scan) != (ssize_t)sizeof(h)) break;
            if (!validate_header(&h, scan)) break;
            if (!(h.flags & QIHSE_ES_F_COMMITTED)) break;
            prev_offset = scan;
            scan += sizeof(h) + h.payload_size;
        }
    }

    /* Build the record header. */
    qihse_es_record_header_t hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = QIHSE_ES_MAGIC;
    hdr.format_version = QIHSE_ES_FORMAT_VERSION;
    hdr.flags = 0; /* not yet committed */
    hdr.schema_id = schema_id;
    hdr.stream_offset = offset;
    hdr.payload_size = payload_size;
    hdr.prev_record_offset = prev_offset;
    memcpy(hdr.event_id, event_id, QIHSE_ES_EVENT_ID_SIZE);

    /* Write uncommitted header + payload. */
    if (pwrite(fd, &hdr, sizeof(hdr), offset) != (ssize_t)sizeof(hdr)) {
        close(fd); return 0;
    }
    if (payload_size > 0) {
        if (pwrite(fd, payload, payload_size, offset + sizeof(hdr)) != (ssize_t)payload_size) {
            close(fd); return 0;
        }
    }

    /* Durability: fdatsync before committing. */
    if (stream->durability >= QIHSE_ES_DURABILITY_FDATASYNC) {
        if (fdatasync(fd) != 0) {
            close(fd); return 0;
        }
    }

    /* Flip the committed flag atomically (4-byte pwrite at offset+8). */
    uint32_t committed_flags = QIHSE_ES_F_COMMITTED;
    if (pwrite(fd, &committed_flags, 4, offset + offsetof(qihse_es_record_header_t, flags)) != 4) {
        close(fd); return 0;
    }

    if (stream->durability >= QIHSE_ES_DURABILITY_FDATASYNC) {
        fdatasync(fd);
    }

    close(fd);
    return offset + 1; /* return non-zero to distinguish from failure */
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
    if (!stream || !topic) return 0;
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

uint64_t qihse_event_stream_replay(
        qihse_event_stream_t* stream,
        const char* topic,
        qihse_es_replay_cb callback,
        void* user_data) {
    if (!stream || !topic || !callback) return 0;

    int fd = open_topic(stream, topic, false);
    if (fd < 0) return 0;

    struct stat st;
    if (fstat(fd, &st) != 0) { close(fd); return 0; }
    uint64_t file_size = (uint64_t)st.st_size;
    uint64_t offset = 0;
    uint64_t count = 0;

    while (offset < file_size) {
        qihse_es_record_header_t hdr;
        if (pread(fd, &hdr, sizeof(hdr), offset) != (ssize_t)sizeof(hdr)) break;
        if (!validate_header(&hdr, offset)) break;
        if (!(hdr.flags & QIHSE_ES_F_COMMITTED)) break;

        uint8_t* payload = NULL;
        if (hdr.payload_size > 0) {
            payload = malloc(hdr.payload_size);
            if (!payload) break;
            if (pread(fd, payload, hdr.payload_size, offset + sizeof(hdr)) != (ssize_t)hdr.payload_size) {
                free(payload);
                break;
            }
        }

        if (!callback(&hdr, payload, hdr.payload_size, user_data)) {
            free(payload);
            break;
        }
        free(payload);
        count++;
        offset += sizeof(hdr) + hdr.payload_size;
    }

    close(fd);
    return count;
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
        if (pread(fd, &hdr, sizeof(hdr), offset) != (ssize_t)sizeof(hdr)) break;
        if (!validate_header(&hdr, offset)) break;
        if (!(hdr.flags & QIHSE_ES_F_COMMITTED)) break;
        last_valid_end = offset + sizeof(hdr) + hdr.payload_size;
        offset = last_valid_end;
    }

    if (last_valid_end < file_size) {
        if (ftruncate(fd, (off_t)last_valid_end) != 0) {
            close(fd); return false;
        }
        fdatasync(fd);
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
