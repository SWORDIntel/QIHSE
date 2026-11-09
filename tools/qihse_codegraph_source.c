/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_codegraph_source.h"
#include "qihse_codegraph_progress.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <json-c/json.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    char *path;
    uint64_t bytes;
    char digest[65];
    bool deleted;
} source_record;
typedef struct {
    source_record *records;
    size_t count, capacity;
    uint64_t bytes;
    double deadline;
    qihse_user_t *principal;
    uint16_t classification, sci;
    bool overlay;
} scan_state;
static _Thread_local uint64_t progress_files, progress_bytes;
static bool active(scan_state *s) {
    if (!s->principal || !qihse_auth_user_is_active(s->principal) ||
        !qihse_auth_can_access(s->principal, s->classification, s->sci)) {
        errno = EACCES;
        return false;
    }
    return true;
}
static double now_seconds(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}
static bool budget(scan_state *s) {
    if (!active(s))
        return false;
    if (now_seconds() > s->deadline) {
        errno = ETIMEDOUT;
        return false;
    }
    return true;
}
static bool same_stat(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
           a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
           a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static void hex_digest(const unsigned char *digest, char out[65]) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 32; i++) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 15];
    }
    out[64] = 0;
}
static bool buffer_digest(const void *bytes, size_t size, char out[65]) {
    unsigned char digest[32];
    unsigned n = 0;
    if (EVP_Digest(bytes, size, digest, &n, EVP_sha256(), NULL) != 1 || n != 32)
        return false;
    hex_digest(digest, out);
    return true;
}
static bool path_valid(const char *path) {
    if (!path || !*path || *path == '/' || *path == '~' || strchr(path, '\\') ||
        strlen(path) >= PATH_MAX)
        return false;
    for (const char *p = path; *p;) {
        const char *end = strchr(p, '/');
        size_t n = end ? (size_t)(end - p) : strlen(p);
        if (!n || (n == 1 && *p == '.') || (n == 2 && !memcmp(p, "..", 2)) ||
            (n == 4 && !memcmp(p, ".git", 4)) || (n == 18 && !memcmp(p, ".code-review-graph", 18)))
            return false;
        p = end ? end + 1 : p + n;
        if (end && !*p)
            return false;
    }
    return true;
}
static void release_records(scan_state *s) {
    for (size_t i = 0; i < s->count; i++)
        free(s->records[i].path);
    free(s->records);
    s->records = NULL;
    s->count = s->capacity = 0;
}
static bool add_record(scan_state *s, const char *path, uint64_t bytes, const char *digest,
                       bool deleted) {
    uint64_t total_limit =
        CG_SOURCE_MAX_TOTAL_BYTES + (s->overlay ? CG_SOURCE_MAX_OVERLAY_BYTES : 0);
    size_t count_limit = CG_SOURCE_MAX_FILES + (s->overlay ? CG_SOURCE_MAX_OVERLAY_FILES : 0);
    if (s->count >= count_limit || bytes > CG_SOURCE_MAX_FILE_BYTES ||
        bytes > total_limit - s->bytes) {
        errno = EFBIG;
        return false;
    }
    if (s->count == s->capacity) {
        size_t next = s->capacity ? s->capacity * 2 : 256;
        source_record *r = realloc(s->records, next * sizeof(*r));
        if (!r)
            return false;
        s->records = r;
        s->capacity = next;
    }
    char *copy = strdup(path);
    if (!copy)
        return false;
    source_record *r = &s->records[s->count++];
    memset(r, 0, sizeof(*r));
    r->path = copy;
    r->bytes = bytes;
    r->deleted = deleted;
    if (digest)
        memcpy(r->digest, digest, 65);
    s->bytes += bytes;
    return true;
}
static bool read_digest(scan_state *s, int dirfd, const char *name, const struct stat *info,
                        uint64_t *bytes, char digest[65]) {
    int fd = openat(dirfd, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return false;
    struct stat before, after;
    unsigned char chunk[8192], sum[32];
    unsigned n = 0;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    uint64_t size = 0;
    bool ok = ctx && !fstat(fd, &before) && S_ISREG(before.st_mode) && same_stat(info, &before) &&
              info->st_size >= 0 && (uint64_t)info->st_size <= CG_SOURCE_MAX_FILE_BYTES &&
              EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1;
    while (ok) {
        if (!budget(s)) {
            ok = false;
            break;
        }
        ssize_t got = read(fd, chunk, sizeof(chunk));
        if (got < 0 && errno == EINTR)
            continue;
        if (got < 0) {
            ok = false;
            break;
        }
        if (!got)
            break;
        if ((uint64_t)got > CG_SOURCE_MAX_FILE_BYTES - size ||
            (uint64_t)got > CG_SOURCE_MAX_TOTAL_BYTES - s->bytes - size) {
            errno = EFBIG;
            ok = false;
            break;
        }
        size += (uint64_t)got;
        ok = EVP_DigestUpdate(ctx, chunk, (size_t)got) == 1;
        progress_bytes += (uint64_t)got;
        cg_progress_emit("source-hash", "bytes", progress_bytes, UINT64_MAX);
    }
    ok = ok && !fstat(fd, &after) && same_stat(&before, &after) &&
         size == (uint64_t)before.st_size && EVP_DigestFinal_ex(ctx, sum, &n) == 1 && n == 32;
    if (ok) {
        *bytes = size;
        hex_digest(sum, digest);
    }
    EVP_MD_CTX_free(ctx);
    close(fd);
    return ok;
}
static int compare_names(const void *a, const void *b) {
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}
static int compare_records(const void *a, const void *b) {
    return strcmp(((const source_record *)a)->path, ((const source_record *)b)->path);
}
static bool walk(scan_state *s, int fd, const char *prefix, unsigned depth) {
    if (depth > 128) {
        errno = EFBIG;
        return false;
    }
    struct stat before, after;
    if (fstat(fd, &before) || !budget(s))
        return false;
    int duplicate = dup(fd);
    if (duplicate < 0)
        return false;
    DIR *dir = fdopendir(duplicate);
    if (!dir) {
        close(duplicate);
        return false;
    }
    char **names = NULL;
    size_t count = 0, cap = 0;
    bool ok = true;
    for (;;) {
        errno = 0;
        struct dirent *e = readdir(dir);
        if (!e) {
            if (errno)
                ok = false;
            break;
        }
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..") || !strcmp(e->d_name, ".git") ||
            !strcmp(e->d_name, ".code-review-graph"))
            continue;
        if (count >= CG_SOURCE_MAX_FILES || !budget(s)) {
            errno = EFBIG;
            ok = false;
            break;
        }
        if (count == cap) {
            size_t nc = cap ? cap * 2 : 64;
            char **nn = realloc(names, nc * sizeof(*nn));
            if (!nn) {
                ok = false;
                break;
            }
            names = nn;
            cap = nc;
        }
        names[count] = strdup(e->d_name);
        if (!names[count]) {
            ok = false;
            break;
        }
        count++;
    }
    closedir(dir);
    if (ok)
        qsort(names, count, sizeof(*names), compare_names);
    for (size_t i = 0; ok && i < count; i++) {
        char *path = NULL;
        if (asprintf(&path, "%s%s", prefix, names[i]) < 0) {
            ok = false;
            break;
        }
        struct stat info;
        if (!path_valid(path) || !budget(s) || fstatat(fd, names[i], &info, AT_SYMLINK_NOFOLLOW)) {
            free(path);
            ok = false;
            break;
        }
        if (S_ISDIR(info.st_mode)) {
            int child = openat(fd, names[i], O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
            struct stat opened;
            if (child < 0 || fstat(child, &opened) || !same_stat(&info, &opened)) {
                if (child >= 0)
                    close(child);
                free(path);
                ok = false;
                break;
            }
            char *sub = NULL;
            if (asprintf(&sub, "%s/", path) < 0)
                ok = false;
            else
                ok = walk(s, child, sub, depth + 1);
            free(sub);
            close(child);
        } else if (S_ISREG(info.st_mode)) {
            uint64_t bytes = 0;
            char digest[65];
            if (s->count >= CG_SOURCE_MAX_FILES) {
                free(path);
                errno = EFBIG;
                ok = false;
                break;
            }
            ok = read_digest(s, fd, names[i], &info, &bytes, digest) &&
                 add_record(s, path, bytes, digest, false);
            if (ok) {
                progress_files++;
                cg_progress_emit("source-hash", "files", progress_files, UINT64_MAX);
            }
        } else {
            errno = EINVAL;
            ok = false;
        }
        free(path);
    }
    for (size_t i = 0; i < count; i++)
        free(names[i]);
    free(names);
    return ok && !fstat(fd, &after) && same_stat(&before, &after) && budget(s);
}
static bool records_digest(scan_state *s, char out[65]) {
    qsort(s->records, s->count, sizeof(*s->records), compare_records);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    unsigned char sum[32];
    unsigned n = 0;
    static const char domain[] = "qihse-filesystem-content-v1";
    bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
              EVP_DigestUpdate(ctx, domain, sizeof(domain)) == 1;
    for (size_t i = 0; ok && i < s->count; i++) {
        source_record *r = &s->records[i];
        if (r->deleted)
            continue;
        char parent[PATH_MAX];
        snprintf(parent, sizeof(parent), "%s", r->path);
        for (char *p = parent; *p; p++)
            if (*p == '/') {
                *p = 0;
                source_record needle = {.path = parent};
                source_record *ancestor =
                    bsearch(&needle, s->records, s->count, sizeof(*s->records), compare_records);
                *p = '/';
                if (ancestor && !ancestor->deleted) {
                    ok = false;
                    errno = EINVAL;
                    break;
                }
            }
        if (!ok)
            break;
        char length[32];
        int len = snprintf(length, sizeof(length), "%" PRIu64, r->bytes);
        ok = budget(s) && len > 0 && EVP_DigestUpdate(ctx, r->path, strlen(r->path) + 1) == 1 &&
             EVP_DigestUpdate(ctx, length, (size_t)len + 1) == 1 &&
             EVP_DigestUpdate(ctx, r->digest, 65) == 1;
    }
    ok = ok && EVP_DigestFinal_ex(ctx, sum, &n) == 1 && n == 32;
    if (ok)
        hex_digest(sum, out);
    EVP_MD_CTX_free(ctx);
    return ok;
}
/* Validate independently of json-c build-specific UTF-8 flag behavior. */
static bool utf8_valid(const unsigned char *p, size_t size) {
    for (size_t i = 0; i < size;) {
        unsigned c = p[i++];
        if (c < 0x80)
            continue;
        unsigned need = 0, minimum = 0, value = 0;
        if (c >= 0xc2 && c <= 0xdf) {
            need = 1;
            minimum = 0x80;
            value = c & 0x1f;
        } else if (c >= 0xe0 && c <= 0xef) {
            need = 2;
            minimum = 0x800;
            value = c & 0x0f;
        } else if (c >= 0xf0 && c <= 0xf4) {
            need = 3;
            minimum = 0x10000;
            value = c & 7;
        } else
            return false;
        if (need > size - i)
            return false;
        for (unsigned j = 0; j < need; j++) {
            c = p[i++];
            if ((c & 0xc0) != 0x80)
                return false;
            value = (value << 6) | (c & 0x3f);
        }
        if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff))
            return false;
    }
    return true;
}
static bool json_text_exact(struct json_object *obj, const char *key, const char **out) {
    struct json_object *field = NULL;
    if (!json_object_object_get_ex(obj, key, &field) ||
        !json_object_is_type(field, json_type_string))
        return false;
    const char *value = json_object_get_string(field);
    if (strlen(value) != (size_t)json_object_get_string_len(field))
        return false;
    *out = value;
    return true;
}
static bool apply_overlay(scan_state *s, const char *root, const char *path, char digest[65]) {
    char resolved[PATH_MAX];
    size_t rootlen = strlen(root);
    if (!realpath(path, resolved) || (!strncmp(root, resolved, rootlen) &&
                                      (resolved[rootlen] == '/' || resolved[rootlen] == 0))) {
        errno = EINVAL;
        return false;
    }
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return false;
    struct stat before, after;
    unsigned char *raw = NULL, *decoded = NULL, *canonical64 = NULL;
    struct json_tokener *tok = NULL;
    struct json_object *obj = NULL, *canonical = NULL;
    bool ok = false;
    if (fstat(fd, &before) || !S_ISREG(before.st_mode) || before.st_uid != geteuid() ||
        before.st_nlink != 1 || (before.st_mode & 077) || before.st_size < 0 ||
        (uint64_t)before.st_size > CG_SOURCE_MAX_OVERLAY_BYTES)
        goto done;
    size_t size = (size_t)before.st_size;
    raw = malloc(size + 1);
    if (!raw)
        goto done;
    size_t have = 0;
    while (have < size) {
        ssize_t n = read(fd, raw + have, size - have);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            goto done;
        have += (size_t)n;
    }
    raw[size] = 0;
    if (memchr(raw, 0, size) || !utf8_valid(raw, size) || fstat(fd, &after) ||
        !same_stat(&before, &after) || !budget(s) || !buffer_digest(raw, size, digest))
        goto done;
    tok = json_tokener_new();
    if (!tok)
        goto done;
    /* The exact canonical reconstruction below rejects permissive syntax and
     * duplicate fields. UTF-8 is independently checked above. */
    obj = json_tokener_parse_ex(tok, (const char *)raw, (int)size);
    if (!obj || json_tokener_get_error(tok) != json_tokener_success ||
        json_tokener_get_parse_end(tok) != size || !json_object_is_type(obj, json_type_object) ||
        json_object_object_length(obj) != 2)
        goto done;
    struct json_object *version = NULL, *rows = NULL;
    if (!json_object_object_get_ex(obj, "version", &version) ||
        !json_object_is_type(version, json_type_int) || json_object_get_int64(version) != 1 ||
        !json_object_object_get_ex(obj, "files", &rows) ||
        !json_object_is_type(rows, json_type_array) ||
        json_object_array_length(rows) > CG_SOURCE_MAX_OVERLAY_FILES)
        goto done;
    canonical = json_object_new_object();
    struct json_object *canonical_rows = json_object_new_array();
    if (!canonical || !canonical_rows) {
        if (canonical_rows)
            json_object_put(canonical_rows);
        goto done;
    }
    json_object_object_add(canonical, "version", json_object_new_int(1));
    json_object_object_add(canonical, "files", canonical_rows);
    const char *previous = NULL;
    size_t original_count = s->count; /* Sorted disk rows; appended overlay rows are unique. */
    s->overlay = true;
    for (size_t i = 0; i < json_object_array_length(rows); i++) {
        struct json_object *row = json_object_array_get_idx(rows, i), *deletion = NULL;
        const char *name = NULL, *encoded = NULL;
        if (!json_object_is_type(row, json_type_object) || json_object_object_length(row) != 2 ||
            !json_text_exact(row, "path", &name) || !path_valid(name) ||
            (previous && strcmp(previous, name) >= 0) || !budget(s))
            goto done;
        previous = name;
        bool deleted = false;
        uint64_t length = 0;
        char content[65] = {0};
        struct json_object *canon_row = json_object_new_object();
        if (!canon_row)
            goto done;
        json_object_array_add(canonical_rows, canon_row);
        json_object_object_add(canon_row, "path", json_object_new_string(name));
        if (json_object_object_get_ex(row, "deleted", &deletion)) {
            if (!json_object_is_type(deletion, json_type_boolean) ||
                !json_object_get_boolean(deletion))
                goto done;
            deleted = true;
            json_object_object_add(canon_row, "deleted", json_object_new_boolean(true));
        } else {
            if (!json_text_exact(row, "content_b64", &encoded))
                goto done;
            size_t en = strlen(encoded);
            if (en % 4 || en > CG_SOURCE_MAX_OVERLAY_BYTES)
                goto done;
            for (size_t j = 0; j < en; j++)
                if (!((encoded[j] >= 'A' && encoded[j] <= 'Z') ||
                      (encoded[j] >= 'a' && encoded[j] <= 'z') ||
                      (encoded[j] >= '0' && encoded[j] <= '9') || encoded[j] == '+' ||
                      encoded[j] == '/' || encoded[j] == '='))
                    goto done;
            decoded = malloc(en / 4 * 3 + 1);
            canonical64 = malloc(en + 1);
            if (!decoded || !canonical64)
                goto done;
            int amount = en ? EVP_DecodeBlock(decoded, (const unsigned char *)encoded, (int)en) : 0;
            if (amount < 0)
                goto done;
            if (en && encoded[en - 1] == '=')
                amount--;
            if (en > 1 && encoded[en - 2] == '=')
                amount--;
            if (amount < 0 || EVP_EncodeBlock(canonical64, decoded, amount) != (int)en ||
                memcmp(canonical64, encoded, en))
                goto done;
            length = (uint64_t)amount;
            if (!buffer_digest(decoded, (size_t)amount, content))
                goto done;
            free(decoded);
            decoded = NULL;
            free(canonical64);
            canonical64 = NULL;
            json_object_object_add(canon_row, "content_b64", json_object_new_string(encoded));
        }
        source_record needle = {.path = (char *)name};
        source_record *r =
            bsearch(&needle, s->records, original_count, sizeof(*s->records), compare_records);
        if (r) {
            s->bytes -= r->bytes;
            if (length > CG_SOURCE_MAX_TOTAL_BYTES + CG_SOURCE_MAX_OVERLAY_BYTES - s->bytes) {
                errno = EFBIG;
                goto done;
            }
            r->bytes = length;
            r->deleted = deleted;
            memcpy(r->digest, content, 65);
            s->bytes += length;
        } else if (!add_record(s, name, length, content, deleted))
            goto done;
    }
    const char *canon = json_object_to_json_string_ext(
        canonical, JSON_C_TO_STRING_PLAIN | JSON_C_TO_STRING_NOSLASHESCAPE);
    if (!canon || strlen(canon) != size || memcmp(canon, raw, size))
        goto done;
    size_t effective = 0;
    for (size_t i = 0; i < s->count; i++)
        if (!s->records[i].deleted)
            effective++;
    if (effective > CG_SOURCE_MAX_FILES || s->bytes > CG_SOURCE_MAX_TOTAL_BYTES) {
        errno = EFBIG;
        goto done;
    }
    ok = budget(s);
done:
    if (!ok && errno != EACCES && errno != ETIMEDOUT && errno != ENOMEM)
        errno = EINVAL;
    if (obj)
        json_object_put(obj);
    if (canonical)
        json_object_put(canonical);
    if (tok)
        json_tokener_free(tok);
    free(raw);
    free(decoded);
    free(canonical64);
    close(fd);
    return ok;
}
bool cg_source_identity_user(const char *root, const char *overlay_path, qihse_user_t *principal,
                             uint16_t classification, uint16_t sci, cg_source_identity *out) {
    if (!out) {
        errno = EINVAL;
        return false;
    }
    memset(out, 0, sizeof(*out));
    scan_state s = {.deadline = now_seconds() + 30.0,
                    .principal = principal,
                    .classification = classification,
                    .sci = sci};
    if (!active(&s))
        return false;
    if (!root) {
        errno = EINVAL;
        return false;
    }
    char resolved[PATH_MAX];
    if (!realpath(root, resolved))
        return false;
    int fd = open(resolved, O_RDONLY | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0)
        return false;
    cg_source_identity result = {0};
    bool ok = walk(&s, fd, "", 0) && records_digest(&s, result.disk_digest);
    close(fd);
    result.disk_files = s.count;
    result.disk_bytes = s.bytes;
    if (ok && overlay_path)
        ok = apply_overlay(&s, resolved, overlay_path, result.overlay_digest);
    if (ok)
        ok = records_digest(&s, result.effective_digest);
    if (ok) {
        for (size_t i = 0; i < s.count; i++)
            if (!s.records[i].deleted)
                result.effective_files++;
        result.effective_bytes = s.bytes;
        if (!overlay_path)
            memcpy(result.digest, result.disk_digest, 65);
        else {
            static const char domain[] = "qihse-overlay-content-v1";
            EVP_MD_CTX *ctx = EVP_MD_CTX_new();
            unsigned char sum[32];
            unsigned n = 0;
            ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) == 1 &&
                 EVP_DigestUpdate(ctx, domain, sizeof(domain)) == 1 &&
                 EVP_DigestUpdate(ctx, result.disk_digest, 65) == 1 &&
                 EVP_DigestUpdate(ctx, result.overlay_digest, 65) == 1 &&
                 EVP_DigestUpdate(ctx, result.effective_digest, 65) == 1 &&
                 EVP_DigestFinal_ex(ctx, sum, &n) == 1 && n == 32;
            if (ok)
                hex_digest(sum, result.digest);
            EVP_MD_CTX_free(ctx);
        }
    }
    ok = ok && budget(&s);
    release_records(&s);
    if (ok)
        *out = result;
    return ok;
}
