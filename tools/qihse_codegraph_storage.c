#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_codegraph_storage.h"
#include "qihse_auth.h"
#include <zstd.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CG_STORAGE_MAX (UINT64_C(64) << 30)
#define CG_BLOCK 65536u
static const unsigned char magic[8] = {'Q','C','G','Z','0','0','0','1'};
static bool active(qihse_user_t *user) {
    if (user && qihse_auth_user_is_active(user)) return true;
    errno = EACCES;
    return false;
}
static bool temporary(char path[PATH_MAX], int *fd) {
    const char *dir = getenv("QIHSE_DATA_DIR");
    struct stat st;
    if (!dir || lstat(dir, &st) || !S_ISDIR(st.st_mode) ||
        st.st_uid != geteuid() || (st.st_mode & 0077)) return false;
    if (snprintf(path, PATH_MAX, "%s/.codegraph-codec-XXXXXX", dir) >= PATH_MAX) {
        path[0] = '\0';
        return false;
    }
    *fd = mkstemp(path);
    if (*fd < 0) path[0] = '\0';
    return *fd >= 0;
}
static void put64(unsigned char *p, uint64_t n) {
    for (int i = 7; i >= 0; --i) { p[i] = (unsigned char)n; n >>= 8; }
}
static uint64_t get64(const unsigned char *p) {
    uint64_t n = 0;
    for (int i = 0; i < 8; ++i) n = (n << 8) | p[i];
    return n;
}
static bool sync_parent(const char *path) {
    char parent[PATH_MAX];
    if (snprintf(parent, sizeof(parent), "%s", path) >= (int)sizeof(parent)) return false;
    char *slash = strrchr(parent, '/');
    if (slash) { if (slash == parent) slash[1] = '\0'; else *slash = '\0'; }
    else strcpy(parent, ".");
    int fd = open(parent, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    bool ok = fsync(fd) == 0;
    close(fd);
    return ok;
}

bool cg_storage_save(qihse_kv_store_t *store, const char *path, qihse_user_t *user) {
    if (!store || !path || !active(user)) return false;
    char raw[PATH_MAX] = {0}, output[PATH_MAX] = {0};
    int fd = -1;
    FILE *in = NULL, *out = NULL;
    ZSTD_CCtx *ctx = NULL;
    unsigned char *buffers = NULL;
    bool ok = false;
    if (!temporary(raw, &fd)) goto done;
    close(fd); fd = -1;
    /* Authorization and all record metadata belong to the existing KV API. */
    if (qihse_kv_save_user(store, raw, user) != 0) goto done;
    fd = open(raw, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size > CG_STORAGE_MAX) goto done;
    in = fdopen(fd, "rb"); if (!in) goto done; fd = -1;
    if (snprintf(output, sizeof(output), "%s.codec-XXXXXX", path) >= (int)sizeof(output)) {
        output[0] = '\0';
        goto done;
    }
    fd = mkstemp(output); if (fd < 0) { output[0] = '\0'; goto done; }
    out = fdopen(fd, "wb"); if (!out) goto done; fd = -1;
    unsigned char header[16]; memcpy(header, magic, 8); put64(header + 8, (uint64_t)st.st_size);
    if (fwrite(header, 1, sizeof(header), out) != sizeof(header)) goto done;
    ctx = ZSTD_createCCtx(); buffers = malloc(CG_BLOCK * 2);
    if (!ctx || !buffers || ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_compressionLevel, 3)) ||
        ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_windowLog, 23)) ||
        ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_checksumFlag, 1)) ||
        ZSTD_isError(ZSTD_CCtx_setPledgedSrcSize(ctx, (uint64_t)st.st_size))) goto done;
    for (;;) {
        size_t n = fread(buffers, 1, CG_BLOCK, in);
        if (ferror(in) || !active(user)) goto done;
        ZSTD_inBuffer input = {buffers, n, 0};
        ZSTD_EndDirective mode = feof(in) ? ZSTD_e_end : ZSTD_e_continue;
        size_t remaining;
        do {
            ZSTD_outBuffer result = {buffers + CG_BLOCK, CG_BLOCK, 0};
            remaining = ZSTD_compressStream2(ctx, &result, &input, mode);
            if (ZSTD_isError(remaining) ||
                fwrite(result.dst, 1, result.pos, out) != result.pos) goto done;
        } while (input.pos < input.size || (mode == ZSTD_e_end && remaining));
        if (mode == ZSTD_e_end) break;
    }
    if (!active(user) || fflush(out) || fsync(fileno(out))) goto done;
    if (fclose(out)) { out = NULL; goto done; } out = NULL;
    if (rename(output, path)) goto done;
    output[0] = '\0';
    ok = sync_parent(path);
done:
    if (fd >= 0) close(fd);
    if (in) fclose(in);
    if (out) fclose(out);
    ZSTD_freeCCtx(ctx); free(buffers);
    if (raw[0]) unlink(raw);
    if (output[0]) unlink(output);
    return ok;
}

bool cg_storage_load(qihse_kv_store_t *store, const char *path, qihse_user_t *user) {
    if (!store || !path || !active(user)) return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd < 0) return false;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) { close(fd); return false; }
    FILE *in = fdopen(fd, "rb");
    if (!in) { close(fd); return false; }
    unsigned char header[16];
    size_t n = fread(header, 1, sizeof(header), in);
    /* A compact-looking header never falls back to the legacy text parser. */
    if (n < 4 || memcmp(header, "QCGZ", 4)) {
        fclose(in);
        return active(user) && qihse_kv_load_user(store, path, user) == 0;
    }
    if (n != sizeof(header) || memcmp(header, magic, 8) || get64(header + 8) > CG_STORAGE_MAX) {
        fclose(in); return false;
    }
    uint64_t expected = get64(header + 8), total = 0;
    char raw[PATH_MAX] = {0};
    FILE *out = NULL;
    ZSTD_DCtx *ctx = NULL;
    unsigned char *buffers = NULL;
    bool ok = false, ended = false;
    fd = -1;
    if (!temporary(raw, &fd)) goto done;
    out = fdopen(fd, "wb"); if (!out) goto done; fd = -1;
    ctx = ZSTD_createDCtx(); buffers = malloc(CG_BLOCK * 2);
    if (!ctx || !buffers || ZSTD_isError(ZSTD_DCtx_setParameter(ctx, ZSTD_d_windowLogMax, 23)))
        goto done;
    while ((n = fread(buffers, 1, CG_BLOCK, in)) != 0) {
        if (!active(user) || ended) goto done;
        ZSTD_inBuffer input = {buffers, n, 0};
        while (input.pos < input.size) {
            ZSTD_outBuffer result = {buffers + CG_BLOCK, CG_BLOCK, 0};
            size_t remaining = ZSTD_decompressStream(ctx, &result, &input);
            if (ZSTD_isError(remaining) || result.pos > expected - total) goto done;
            total += result.pos;
            if (fwrite(result.dst, 1, result.pos, out) != result.pos) goto done;
            if (!remaining) {
                ended = true;
                if (input.pos != input.size) goto done; /* reject concatenation/trailing data */
                break;
            }
        }
    }
    if (ferror(in) || !ended || total != expected || !active(user)) goto done;
    if (fclose(out)) { out = NULL; goto done; } out = NULL;
    /* The decoded temporary is private. Only the principal-bound KV parser
     * may interpret its records or install them; it denies the entire load
     * on a forbidden classification/SCI label, leaving the store unchanged. */
    ok = qihse_kv_load_user(store, raw, user) == 0;
done:
    if (fd >= 0) close(fd);
    fclose(in);
    if (out) fclose(out);
    ZSTD_freeDCtx(ctx); free(buffers);
    if (raw[0]) unlink(raw);
    return ok;
}

/* FILE adapter lets the canonical authenticated KV decoder check each record's
 * labels before materializing its value. No expanded snapshot is written. */
typedef struct {
    FILE *source;
    ZSTD_DCtx *decoder;
    qihse_user_t *principal;
    unsigned char buffer[CG_BLOCK];
    ZSTD_inBuffer input;
    uint64_t expected, total;
    bool input_eof, ended;
} cg_decode_stream;
static ssize_t decode_read(void *cookie, char *output, size_t capacity) {
    cg_decode_stream *s = cookie;
    if (!active(s->principal)) return -1;
    if (s->ended) return 0;
    ZSTD_outBuffer out = {output, capacity, 0};
    while (out.pos == 0) {
        if (s->input.pos == s->input.size && !s->input_eof) {
            size_t n = fread(s->buffer, 1, sizeof(s->buffer), s->source);
            if (ferror(s->source)) { errno = EIO; return -1; }
            s->input = (ZSTD_inBuffer){s->buffer, n, 0};
            s->input_eof = feof(s->source);
        }
        size_t remaining = ZSTD_decompressStream(s->decoder, &out, &s->input);
        if (ZSTD_isError(remaining) || out.pos > s->expected - s->total) {
            errno = EINVAL; return -1;
        }
        s->total += out.pos;
        if (!remaining) {
            /* Validate the complete frame/trailer before exposing EOF. A
             * second frame or any suffix is forbidden by the container. */
            if (s->total != s->expected || s->input.pos != s->input.size ||
                fgetc(s->source) != EOF || ferror(s->source)) {
                errno = EINVAL; return -1;
            }
            s->ended = true;
            return (ssize_t)out.pos;
        }
        if (!out.pos && s->input_eof && s->input.pos == s->input.size) {
            errno = EINVAL; return -1;
        }
    }
    return (ssize_t)out.pos;
}
qihse_kv_store_t *cg_storage_open(const char *path, qihse_user_t *user,
                                 size_t max_bytes, size_t max_records) {
    if (!active(user)) return NULL;
    if (!path || !max_bytes || !max_records) { errno = EINVAL; return NULL; }
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return NULL;
    struct stat info;
    if (fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size < 0) {
        close(fd); errno = EINVAL; return NULL;
    }
    FILE *source = fdopen(fd, "rb");
    if (!source) { close(fd); return NULL; }
    unsigned char header[16];
    size_t n = fread(header, 1, sizeof(header), source);
    qihse_kv_store_t *store = NULL;
    int error = EINVAL;
    cg_decode_stream *state = NULL;
    FILE *decoded = NULL;
    if (ferror(source)) { error = EIO; goto done; }
    if (n < 4 || memcmp(header, "QCGZ", 4)) {
        if ((uint64_t)info.st_size > max_bytes) { error = EFBIG; goto done; }
        rewind(source);
        store = qihse_kv_open_snapshot_user(source, user, max_bytes, max_records);
        error = errno;
        goto done;
    }
    if (n != sizeof(header) || memcmp(header, magic, 8) || get64(header + 8) > CG_STORAGE_MAX)
        goto done;
    if (get64(header + 8) > max_bytes) { error = EFBIG; goto done; }
    state = calloc(1, sizeof(*state));
    if (!state) { error = ENOMEM; goto done; }
    state->source = source; state->principal = user; state->expected = get64(header + 8);
    state->decoder = ZSTD_createDCtx();
    if (!state->decoder) { error = ENOMEM; goto done; }
    if (ZSTD_isError(ZSTD_DCtx_setParameter(state->decoder, ZSTD_d_windowLogMax, 23))) goto done;
    cookie_io_functions_t io = {.read = decode_read};
    decoded = fopencookie(state, "rb", io);
    if (!decoded) { error = errno; goto done; }
    store = qihse_kv_open_snapshot_user(decoded, user, max_bytes, max_records);
    error = errno;
    if (store && (!state->ended || ferror(decoded))) {
        qihse_kv_store_destroy(store); store = NULL; error = EINVAL;
    }
done:
    if (decoded) fclose(decoded);
    if (state) { ZSTD_freeDCtx(state->decoder); free(state); }
    fclose(source);
    if (!store) errno = error;
    return store;
}
