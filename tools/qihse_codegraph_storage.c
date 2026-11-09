#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_codegraph_storage.h"
#include "qihse_codegraph_packed.h"
#include "qihse_codegraph_dictionary.h"
#include "qihse_codegraph_chunked.h"
#include "qihse_codegraph_progress.h"
#include "qihse_auth.h"
#include <openssl/evp.h>
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
static const unsigned char packed_magic[8] = {'Q','C','G','P','0','0','0','2'};
static const unsigned char chunked_magic[8] = {'Q','C','G','P','0','0','0','4'};
static const unsigned char dictionary_magic[8] = {'Q','C','G','P','0','0','0','3'};
static bool packed_header(const unsigned char *header, size_t n) {
    return n >= 8 && (!memcmp(header, packed_magic, 8) || !memcmp(header, dictionary_magic, 8) || !memcmp(header, chunked_magic, 8));
}
const char *cg_storage_format_name(cg_storage_format format) {
    return format == CG_STORAGE_GENERATIONS ? "qihse-codegraph-generations-v1" :
           format == CG_STORAGE_CHUNKED ? "qihse-codegraph-packed-v4" :
           format == CG_STORAGE_DICTIONARY ? "qihse-codegraph-packed-v3" :
           format == CG_STORAGE_PACKED ? "qihse-codegraph-packed-v2" : "qihse-codegraph-zstd-v1";
}
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
/* Bind packed record labels to the manifest before any packed payload decode.
 * The digest and decoder use the same descriptor; the principal is checked
 * throughout even though a digest never exposes payload bytes. */
static bool source_same(const struct stat *a, const struct stat *b) {
    return a->st_dev==b->st_dev && a->st_ino==b->st_ino && a->st_size==b->st_size &&
        a->st_mtim.tv_sec==b->st_mtim.tv_sec && a->st_mtim.tv_nsec==b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec==b->st_ctim.tv_sec && a->st_ctim.tv_nsec==b->st_ctim.tv_nsec;
}
static bool verify_source_checksum(FILE *source, const struct stat *before,
    const cg_snapshot_checksum *expected, qihse_user_t *user) {
    if (!cg_checksum_valid(expected) || !active(user)) { errno=EACCES; return false; }
    cg_snapshot_checksum actual; struct stat after;
    if (!cg_snapshot_checksum_stream_user(source,user,expected->algorithm,&actual) ||
        fstat(fileno(source),&after) || !source_same(before,&after)) return false;
    if (strcmp(actual.hex,expected->hex)) { errno=EINVAL;return false; }
    return true;
}
static uint32_t section_u32(const unsigned char *p) {
    return (uint32_t)p[0]<<24 | (uint32_t)p[1]<<16 | (uint32_t)p[2]<<8 | p[3];
}
/* Called only after the principal-bound decoder and expected checksum have
 * admitted every record. Read section headers through that same descriptor,
 * then recheck its complete identity before publishing any size metadata. */
static bool section_info(FILE *source,const struct stat *before,qihse_user_t *user,
                         cg_storage_info_t *info) {
    if(!active(user))return false;
    unsigned char h[112];size_t size=(size_t)before->st_size;
    size_t want=size<64?size:64;ssize_t n;
    do n=pread(fileno(source),h,want,0);while(n<0 && errno==EINTR);
    if(n!=(ssize_t)want)return false;
    uint64_t framing=0,metadata=0,body=0,chunks=1,sections=1;
    if(size>=16 && !memcmp(h,magic,8)) {framing=16;body=size-16;}
    else if(size>=48 && (!memcmp(h,packed_magic,8) || !memcmp(h,dictionary_magic,8))) {
        framing=!memcmp(h,dictionary_magic,8)?56:48;
        metadata=section_u32(h+36);body=section_u32(h+40);sections=2;
        if(framing+metadata+body!=size)return false;
    } else if(size>=64 && !memcmp(h,chunked_magic,8)) {
        chunks=section_u32(h+24);sections=chunks*9;framing=64;uint64_t offset=64;
        if(chunks>(size-64)/112)return false;
        for(uint64_t c=0;c<chunks;c++) {
            if(!active(user) || offset>size || size-offset<112)return false;
            do n=pread(fileno(source),h,112,(off_t)offset);while(n<0 && errno==EINTR);
            if(n!=112)return false;
            uint64_t encoded=0;
            for(size_t i=0;i<9;i++) {
                uint64_t bytes=section_u32(h+68+4*i);encoded+=bytes;
                if(i==8)body+=bytes;else metadata+=bytes;
            }
            if(encoded>size-offset-112)return false;
            framing+=112;offset+=112+encoded;
        }
        if(offset!=size || framing+metadata+body!=size)return false;
    } else body=size; /* Legacy text is one unsplit section. */
    struct stat after;
    if(fstat(fileno(source),&after) || !source_same(before,&after) || !active(user))return false;
    info->framing_encoded_bytes=framing;info->metadata_encoded_bytes=metadata;
    info->body_encoded_bytes=body;info->storage_chunks=chunks;info->storage_sections=sections;
    info->section_accounting_valid=true;return true;
}
static void publish_info(cg_storage_info_t *out, FILE *source,
                         const struct stat *before, uint64_t decoded, bool compact,
                         bool packed, qihse_user_t *user,
                         const cg_snapshot_checksum *verified) {
    if (!out || !active(user)) return;
    struct stat after;
    if (fstat(fileno(source),&after) || !S_ISREG(after.st_mode) ||
        after.st_uid!=geteuid() || after.st_nlink!=1 || after.st_size<0 ||
        after.st_blocks<0 || (uint64_t)after.st_blocks>INT64_MAX/512 ||
        !source_same(before,&after)) return;
    cg_snapshot_checksum actual;
    if (verified) {
        if (!cg_checksum_valid(verified)) return;
        actual=*verified;
    } else if (!cg_snapshot_checksum_stream_user(source,user,CG_CHECKSUM_SHA256,&actual)) return;
    if (!active(user)) return;
    *out=(cg_storage_info_t){.encoded_bytes=(uint64_t)after.st_size,
        .allocated_bytes=(uint64_t)after.st_blocks*512,.decoded_bytes=decoded,
        .compact=compact,.packed=packed,.valid=true,.checksum=actual};
    if(!section_info(source,before,user,out)) {memset(out,0,sizeof(*out));return;}
    if (actual.algorithm==CG_CHECKSUM_SHA256) memcpy(out->sha256,actual.hex,65);
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

static bool compress_export(FILE *in, FILE *out, uint64_t raw_bytes,
                            qihse_user_t *user) {
    unsigned char header[16];
    memcpy(header, magic, 8); put64(header + 8, raw_bytes);
    if (fwrite(header, 1, sizeof(header), out) != sizeof(header)) return false;
    ZSTD_CCtx *ctx = ZSTD_createCCtx();
    unsigned char *buffers = malloc(CG_BLOCK * 2);
    bool ok = false;uint64_t consumed=0;
    cg_progress_emit("encode-zstd","bytes",0,raw_bytes);
    if (!ctx || !buffers || ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_compressionLevel, CG_CODEGRAPH_ZSTD_LEVEL)) ||
        ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_windowLog, 23)) ||
        ZSTD_isError(ZSTD_CCtx_setParameter(ctx, ZSTD_c_checksumFlag, 1)) ||
        ZSTD_isError(ZSTD_CCtx_setPledgedSrcSize(ctx, raw_bytes))) goto done;
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
        consumed+=n;cg_progress_emit("encode-zstd","bytes",consumed,raw_bytes);
        if (mode == ZSTD_e_end) break;
    }
    ok = active(user) && !fflush(out);
done:
    ZSTD_freeCCtx(ctx); free(buffers);
    return ok;
}

static FILE *candidate(const char *path, char output[PATH_MAX]) {
    if (snprintf(output, PATH_MAX, "%s.codec-XXXXXX", path) >= PATH_MAX) {
        output[0] = '\0'; errno = ENAMETOOLONG; return NULL;
    }
    int fd = mkstemp(output);
    if (fd < 0) { output[0] = '\0'; return NULL; }
    FILE *out = fdopen(fd, "wb");
    if (!out) close(fd);
    return out;
}

static bool save_snapshot(qihse_kv_store_t *store, const char *path,
                           qihse_user_t *user, int mode, cg_storage_format *selected) {
    if (!store || !path || !active(user)) return false;
    char raw[PATH_MAX] = {0}, paths[4][PATH_MAX] = {{0}};
    FILE *input = NULL, *outputs[4] = {NULL};
    int fd = -1, best = -1;
    off_t best_bytes = 0;
    bool ok = false;
    if (!temporary(raw, &fd)) goto done;
    close(fd); fd = -1;
    if (qihse_kv_save_user(store, raw, user)) goto done;
    fd = open(raw, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd < 0 || fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uint64_t)st.st_size > CG_STORAGE_MAX) goto done;
    input = fdopen(fd, "rb"); if (!input) goto done; fd = -1;
    for (int kind = 0; kind < 4; ++kind) {
        if (mode >= 0 && kind != mode) continue;
        if (mode < 0 && (kind == CG_STORAGE_PACKED || kind == CG_STORAGE_DICTIONARY) && (uint64_t)st.st_size > CG_PACKED_MAX_RAW_BYTES) continue;
        if (fseeko(input, 0, SEEK_SET)) goto done;
        outputs[kind] = candidate(path, paths[kind]);
        if (!outputs[kind]) goto done;
        errno = 0;
        bool encoded = kind == CG_STORAGE_CHUNKED ?
            cg_chunked_encode_snapshot(input, outputs[kind], user, CG_STORAGE_MAX, CG_CHUNKED_MAX_RECORDS) :
            kind == CG_STORAGE_DICTIONARY ?
            cg_dictionary_encode_snapshot(input, outputs[kind], user, CG_STORAGE_MAX, CG_DICTIONARY_MAX_RECORDS) :
            kind == CG_STORAGE_PACKED ?
            cg_packed_encode_snapshot(input, outputs[kind], user, CG_STORAGE_MAX, CG_PACKED_MAX_RECORDS) :
            compress_export(input, outputs[kind], (uint64_t)st.st_size, user);
        int error = errno;
        if (!active(user)) goto done;
        if (!encoded) {
            if (mode >= 0 || (error != EFBIG && error != E2BIG && error != ENOMEM)) goto done;
            continue;
        }
        if (fflush(outputs[kind])) goto done;
        off_t bytes = ftello(outputs[kind]);
        if (bytes < 0) goto done;
        if (best < 0 || bytes < best_bytes) { best = kind; best_bytes = bytes; }
    }
    if (best < 0 || !active(user) || fsync(fileno(outputs[best]))) goto done;
    if (fclose(outputs[best])) { outputs[best] = NULL; goto done; }
    outputs[best] = NULL;
    if (!active(user) || rename(paths[best], path)) goto done;
    paths[best][0] = 0;
    ok = sync_parent(path);
    if (ok && selected) *selected = (cg_storage_format)best;
done:
    if (fd >= 0) close(fd);
    if (input) fclose(input);
    for (int i = 0; i < 4; ++i) {
        if (outputs[i]) fclose(outputs[i]);
        if (paths[i][0]) unlink(paths[i]);
    }
    if (raw[0]) unlink(raw);
    return ok;
}
bool cg_storage_save(qihse_kv_store_t *s, const char *p, qihse_user_t *u) {
    return save_snapshot(s, p, u, CG_STORAGE_ZSTD, NULL);
}
bool cg_storage_save_packed(qihse_kv_store_t *s, const char *p, qihse_user_t *u) {
    return save_snapshot(s, p, u, CG_STORAGE_PACKED, NULL);
}
bool cg_storage_save_dictionary(qihse_kv_store_t *s, const char *p, qihse_user_t *u) {
    return save_snapshot(s, p, u, CG_STORAGE_DICTIONARY, NULL);
}
bool cg_storage_save_chunked(qihse_kv_store_t *s, const char *p, qihse_user_t *u) {
    return save_snapshot(s, p, u, CG_STORAGE_CHUNKED, NULL);
}
bool cg_storage_save_auto_format(qihse_kv_store_t *s, const char *p, qihse_user_t *u,
                                 cg_storage_format *format) {
    return save_snapshot(s, p, u, -1, format);
}
bool cg_storage_save_auto(qihse_kv_store_t *s, const char *p, qihse_user_t *u, bool *packed) {
    cg_storage_format format;
    bool ok = cg_storage_save_auto_format(s, p, u, &format);
    if (ok && packed) *packed = format != CG_STORAGE_ZSTD;
    return ok;
}

static bool load_packed_snapshot(qihse_kv_store_t *store, FILE *source,
                                 const struct stat *source_stat, qihse_user_t *user,
                                 const cg_snapshot_checksum *expected_checksum, bool dictionary, bool chunked,
                                 cg_storage_info_t *out_info) {
    char raw[PATH_MAX] = {0};
    int fd = -1;
    FILE *out = NULL;
    bool ok = false;
    uint64_t decoded = 0;
    if (fseek(source, 0, SEEK_SET) || !temporary(raw, &fd)) goto done;
    out = fdopen(fd, "wb"); if (!out) goto done; fd = -1;
    if (!(chunked ? cg_chunked_decode_checksum_snapshot(source, out, user, expected_checksum, CG_STORAGE_MAX,
                                    CG_CHUNKED_MAX_RECORDS) :
           dictionary ? cg_dictionary_decode_checksum_snapshot(source, out, user, expected_checksum, CG_STORAGE_MAX,
                                    CG_DICTIONARY_MAX_RECORDS) :
                       cg_packed_decode_snapshot(source, out, user, CG_STORAGE_MAX,
                                    CG_PACKED_MAX_RECORDS)) || fflush(out)) goto done;
    off_t length = ftello(out);
    if (length < 0) goto done;
    decoded = (uint64_t)length;
    if (fclose(out)) { out = NULL; goto done; } out = NULL;
    ok = verify_source_checksum(source, source_stat, expected_checksum, user) &&
         qihse_kv_load_user(store, raw, user) == 0;
    if (ok) {
        publish_info(out_info, source, source_stat, decoded, false, true, user, expected_checksum);
        if (out_info && out_info->valid) out_info->dictionary = dictionary;
        if (out_info && out_info->valid) out_info->chunked = chunked;
    }
done:
    if (fd >= 0) close(fd);
    if (out) fclose(out);
    if (raw[0]) unlink(raw);
    return ok;
}

static bool storage_load_checksum_internal(qihse_kv_store_t *store, const char *path,
                                   qihse_user_t *user, const cg_snapshot_checksum *expected_checksum,
                                   cg_storage_info_t *out_info) {
    if (out_info) memset(out_info, 0, sizeof(*out_info));
    if (!store || !path || !active(user)) return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    if (fd < 0) return false;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode)) { close(fd); return false; }
    FILE *in = fdopen(fd, "rb");
    if (!in) { close(fd); return false; }
    unsigned char header[16];
    size_t n = fread(header, 1, sizeof(header), in);
    if (expected_checksum && !verify_source_checksum(in, &st, expected_checksum, user)) {
        fclose(in); return false;
    }
    if (n >= 4 && !memcmp(header, "QCGP", 4)) {
        bool ok = expected_checksum && packed_header(header, n) &&
                  load_packed_snapshot(store, in, &st, user, expected_checksum,
                                       !memcmp(header, dictionary_magic, 8), !memcmp(header, chunked_magic, 8), out_info);
        fclose(in);
        return ok;
    }
    /* A compact-looking header never falls back to the legacy text parser. */
    if (n < 4 || memcmp(header, "QCGZ", 4)) {
        if (expected_checksum) { fclose(in); errno=EINVAL; return false; }
        fclose(in);
        /* This path-based legacy KV loader reopens the file. Its metadata
         * cannot be bound to the descriptor checked above. */
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
    if (expected_checksum && !verify_source_checksum(in, &st, expected_checksum, user)) goto done;
    ok = qihse_kv_load_user(store, raw, user) == 0;
done:
    if (fd >= 0) close(fd);
    if (ok) publish_info(out_info, in, &st, expected, true, false, user, expected_checksum);
    fclose(in);
    if (out) fclose(out);
    ZSTD_freeDCtx(ctx); free(buffers);
    if (raw[0]) unlink(raw);
    return ok;
}
bool cg_storage_load_info(qihse_kv_store_t *store, const char *path,
                          qihse_user_t *user, cg_storage_info_t *out_info) {
    return cg_storage_load_verified_info(store, path, user, NULL, out_info);
}
bool cg_storage_load(qihse_kv_store_t *store, const char *path, qihse_user_t *user) {
    return cg_storage_load_info(store, path, user, NULL);
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
static qihse_kv_store_t *storage_open_checksum_internal(const char *path, qihse_user_t *user,
    size_t max_bytes, size_t max_records, const cg_snapshot_checksum *expected_checksum,
    cg_storage_info_t *out_info) {
    if (out_info) memset(out_info, 0, sizeof(*out_info));
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
    uint64_t decoded_size = (uint64_t)info.st_size;
    bool compact = false, packed = false, dictionary = false, chunked = false;
    if (ferror(source)) { error = EIO; goto done; }
    if (expected_checksum && !verify_source_checksum(source, &info, expected_checksum, user)) {
        error=errno; goto done;
    }
    if (n >= 4 && !memcmp(header, "QCGP", 4)) {
        if (!expected_checksum || !packed_header(header, n)) {
            error = EACCES; goto done;
        }
        packed = true;
        dictionary = !memcmp(header, dictionary_magic, 8);
        chunked = !memcmp(header, chunked_magic, 8);
        rewind(source);
        size_t raw_size = 0;
        if (dictionary || chunked) {
            decoded = tmpfile();
            if (!decoded || !(chunked ?
                cg_chunked_decode_checksum_snapshot(source, decoded, user, expected_checksum, max_bytes, max_records) :
                cg_dictionary_decode_checksum_snapshot(source, decoded, user, expected_checksum, max_bytes, max_records))) {
                error = errno; goto done;
            }
            off_t size = ftello(decoded);
            if (size < 0 || fseeko(decoded, 0, SEEK_SET)) { error = EIO; goto done; }
            raw_size = (size_t)size;
            store = qihse_kv_open_snapshot_user(decoded, user, max_bytes, max_records);
        } else store = cg_packed_open_snapshot_user(source, user, max_bytes, max_records, &raw_size);
        if (!store) { error = errno; goto done; }
        decoded_size = raw_size;
        goto done;
    }
    if (n < 4 || memcmp(header, "QCGZ", 4)) {
        /* The bounded legacy reader consumes this exact descriptor. Common
         * pre/post checksum fences apply; the durable path must not reopen it. */
        if ((uint64_t)info.st_size > max_bytes) { error = EFBIG; goto done; }
        rewind(source);
        store = qihse_kv_open_snapshot_user(source, user, max_bytes, max_records);
        error = errno;
        goto done;
    }
    if (n != sizeof(header) || memcmp(header, magic, 8) || get64(header + 8) > CG_STORAGE_MAX)
        goto done;
    compact = true;
    decoded_size = get64(header + 8);
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
    if (store && expected_checksum && !verify_source_checksum(source,&info,expected_checksum,user)) {
        error=errno; qihse_kv_store_destroy(store); store=NULL;
    }
    if (decoded) fclose(decoded);
    if (state) { ZSTD_freeDCtx(state->decoder); free(state); }
    if (store) publish_info(out_info, source, &info, decoded_size, compact, packed, user,
                             expected_checksum);
    if (store && out_info && out_info->valid) {
        out_info->dictionary = dictionary; out_info->chunked = chunked;
    }
    fclose(source);
    if (!store) errno = error;
    return store;
}
qihse_kv_store_t *cg_storage_open_info(const char *path, qihse_user_t *user,
                                      size_t max_bytes, size_t max_records,
                                      cg_storage_info_t *out_info) {
    return cg_storage_open_verified_info(path, user, max_bytes, max_records,
                                         NULL, out_info);
}
qihse_kv_store_t *cg_storage_open(const char *path, qihse_user_t *user,
                                 size_t max_bytes, size_t max_records) {
    return cg_storage_open_info(path, user, max_bytes, max_records, NULL);
}

bool cg_storage_load_checksum_info(qihse_kv_store_t *store, const char *path,
    qihse_user_t *user, const cg_snapshot_checksum *expected, cg_storage_info_t *out) {
    if (out) memset(out,0,sizeof(*out));
    if (!active(user)) return false;
    if (!cg_checksum_valid(expected)) {errno=EINVAL;return false;}
    return storage_load_checksum_internal(store,path,user,expected,out);
}
qihse_kv_store_t *cg_storage_open_checksum_info(const char *path,qihse_user_t *user,
    size_t max_bytes,size_t max_records,const cg_snapshot_checksum *expected,cg_storage_info_t *out) {
    if (out) memset(out,0,sizeof(*out));
    if (!active(user)) return NULL;
    if (!cg_checksum_valid(expected)) {errno=EINVAL;return NULL;}
    return storage_open_checksum_internal(path,user,max_bytes,max_records,expected,out);
}
bool cg_storage_load_verified_info(qihse_kv_store_t *store,const char *path,
    qihse_user_t *user,const char *sha,cg_storage_info_t *out) {
    if (out) memset(out,0,sizeof(*out));
    if (!sha) return storage_load_checksum_internal(store,path,user,NULL,out);
    if (strlen(sha)!=64) {errno=EINVAL;return false;}
    cg_snapshot_checksum expected={.algorithm=CG_CHECKSUM_SHA256};memcpy(expected.hex,sha,65);
    return cg_storage_load_checksum_info(store,path,user,&expected,out);
}
qihse_kv_store_t *cg_storage_open_verified_info(const char *path,qihse_user_t *user,
    size_t max_bytes,size_t max_records,const char *sha,cg_storage_info_t *out) {
    if (out) memset(out,0,sizeof(*out));
    if (!sha) return storage_open_checksum_internal(path,user,max_bytes,max_records,NULL,out);
    if (strlen(sha)!=64) {errno=EINVAL;return NULL;}
    cg_snapshot_checksum expected={.algorithm=CG_CHECKSUM_SHA256};memcpy(expected.hex,sha,65);
    return cg_storage_open_checksum_info(path,user,max_bytes,max_records,&expected,out);
}
