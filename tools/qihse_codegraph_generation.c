/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_codegraph_generation.h"
#include "qihse_codegraph_progress.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <json-c/json.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

enum {
  PARENT_HEAD = 64,
  BLOCK_HEAD = 48,
  HEADER_MAX = 256,
  KEY_MAX = 65535,
  VALUE_MAX = 16 * 1024 * 1024,
  TABLE_MAX = 256 * 1024 * 1024,
  BLOCK_TARGET = 8 * 1024 * 1024
};
typedef struct {
  unsigned char *p;
  size_t n, cap;
} bytes;
typedef struct {
  uint32_t kn;
  uint64_t vn, expiry, sequence;
  uint16_t classification, sci;
  uint8_t flags;
} header;
typedef struct {
  header h;
  char *key, *file, *text;
  uint16_t hn;
  off_t value_offset, staged_offset;
  uint32_t original, block, slot;
} record;
typedef struct {
  char name[37];
  uint64_t raw, encoded;
  uint32_t count;
} block;
typedef struct {
  bytes image, table;
  record *rows;
  block *blocks;
  uint32_t nr, nb;
  uint64_t raw;
  uint16_t classification, sci;
} parent;
static bool active(qihse_user_t *u, uint16_t c, uint16_t s) {
  if (u && qihse_auth_user_is_active(u) && qihse_auth_can_access(u, c, s))
    return true;
  errno = EACCES;
  return false;
}
static bool key_access(qihse_user_t *u, const char *key, size_t length) {
  uint32_t tenant = qihse_user_get_tenant_id(u);
  if (tenant == QIHSE_TENANT_SYSTEM)
    return true;
  char prefix[32];
  int n = snprintf(prefix, sizeof(prefix), "t:%" PRIu32 "/", tenant);
  if (tenant != QIHSE_TENANT_INVALID &&
      ((length >= 8 && !memcmp(key, "commons/", 8)) ||
       (n > 0 && length > (size_t)n && !memcmp(key, prefix, (size_t)n))))
    return true;
  errno = EACCES;
  return false;
}
static bool bounds(uint64_t *b, size_t *r) {
  if (!b || !r || !*b || !*r) {
    errno = EINVAL;
    return false;
  }
  if (*b > CG_GENERATION_MAX_RAW_BYTES)
    *b = CG_GENERATION_MAX_RAW_BYTES;
  if (*r > CG_GENERATION_MAX_RECORDS)
    *r = CG_GENERATION_MAX_RECORDS;
  return true;
}
static void release(bytes *b) {
  if (b->p) {
    OPENSSL_cleanse(b->p, b->cap);
    free(b->p);
  }
  memset(b, 0, sizeof(*b));
}
static bool add(bytes *b, const void *p, size_t n, size_t max) {
  if (n > max || b->n > max - n) {
    errno = EFBIG;
    return false;
  }
  size_t need = b->n + n;
  if (need > b->cap) {
    size_t cap = b->cap ? b->cap : 4096;
    while (cap < need) {
      if (cap > max / 2) {
        cap = max;
        break;
      }
      cap *= 2;
    }
    unsigned char *next = realloc(b->p, cap);
    if (!next)
      return false;
    b->p = next;
    b->cap = cap;
  }
  if (n)
    memcpy(b->p + b->n, p, n);
  b->n += n;
  return true;
}
static uint16_t g16(const unsigned char *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}
static uint32_t g32(const unsigned char *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}
static uint64_t g64(const unsigned char *p) {
  uint64_t n = 0;
  for (size_t i = 0; i < 8; i++)
    n = (n << 8) | p[i];
  return n;
}
static void p16(unsigned char *p, uint16_t n) {
  p[0] = (unsigned char)(n >> 8);
  p[1] = (unsigned char)n;
}
static void p32(unsigned char *p, uint32_t n) {
  for (size_t i = 0; i < 4; i++)
    p[3 - i] = (unsigned char)(n >> (8 * i));
}
static void p64(unsigned char *p, uint64_t n) {
  for (size_t i = 0; i < 8; i++)
    p[7 - i] = (unsigned char)(n >> (8 * i));
}
static bool parse_header(const unsigned char *p, size_t n, header *h) {
  if (!p || n < 2 || n >= HEADER_MAX || p[n - 1] != '\n' || memchr(p, 0, n)) {
    errno = EINVAL;
    return false;
  }
  uint64_t v[7] = {0};
  size_t at = 0;
  for (size_t k = 0; k < 7; k++) {
    size_t begin = at;
    while (at < n && p[at] >= '0' && p[at] <= '9') {
      unsigned d = p[at++] - '0';
      if (v[k] > (UINT64_MAX - d) / 10) {
        errno = EINVAL;
        return false;
      }
      v[k] = v[k] * 10 + d;
    }
    if (begin == at || at >= n) {
      errno = EINVAL;
      return false;
    }
    if (k < 6) {
      if (p[at] != ' ' && p[at] != '\t') {
        errno = EINVAL;
        return false;
      }
      while (at < n && (p[at] == ' ' || p[at] == '\t'))
        at++;
    } else if (p[at] != '\n' && p[at] != ' ' && p[at] != '\t') {
      errno = EINVAL;
      return false;
    }
  }
  if (!v[0] || v[0] > KEY_MAX || v[1] > VALUE_MAX || v[3] > UINT16_MAX ||
      v[4] > UINT16_MAX || v[5] > 1 || (v[5] && v[1])) {
    errno = EINVAL;
    return false;
  }
  *h = (header){.kn = (uint32_t)v[0],
                .vn = v[1],
                .expiry = v[2],
                .classification = (uint16_t)v[3],
                .sci = (uint16_t)v[4],
                .flags = (uint8_t)v[5],
                .sequence = v[6]};
  return true;
}
static bool same_stat(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
         a->st_size == b->st_size && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
         a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
         a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
         a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool regular_private(int fd, struct stat *st) {
  return !fstat(fd, st) && S_ISREG(st->st_mode) && st->st_uid == geteuid() &&
         !(st->st_mode & 077) && st->st_nlink <= 1 && st->st_size >= 0;
}
static bool pread_all(int fd, void *p, size_t n, off_t off) {
  size_t at = 0;
  while (at < n) {
    ssize_t got = pread(fd, (unsigned char *)p + at, n - at, off + (off_t)at);
    if (got < 0 && errno == EINTR)
      continue;
    if (got <= 0) {
      errno = EIO;
      return false;
    }
    at += (size_t)got;
  }
  return true;
}
static bool write_all(int fd, const void *p, size_t n) {
  size_t at = 0;
  while (at < n) {
    ssize_t got = write(fd, (const unsigned char *)p + at, n - at);
    if (got < 0 && errno == EINTR)
      continue;
    if (got <= 0) {
      errno = EIO;
      return false;
    }
    at += (size_t)got;
  }
  return true;
}
static int open_directory(const char *path, bool create) {
  if (!path || !*path || strlen(path) >= 4096) {
    errno = EINVAL;
    return -1;
  }
  char *copy = strdup(path);
  if (!copy)
    return -1;
  int fd = open(path[0] == '/' ? "/" : ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  char *save = NULL;
  char *part = strtok_r(copy, "/", &save);
  while (fd >= 0 && part) {
    if (!strcmp(part, "..")) {
      close(fd);
      fd = -1;
      errno = EINVAL;
      break;
    }
    char *next = strtok_r(NULL, "/", &save);
    if (strcmp(part, ".")) {
      if (!next && create && mkdirat(fd, part, 0700) && errno != EEXIST) {
        close(fd);
        fd = -1;
        break;
      }
      int child =
          openat(fd, part, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
      close(fd);
      fd = child;
    }
    part = next;
  }
  free(copy);
  struct stat st;
  if (fd >= 0 && (fstat(fd, &st) || !S_ISDIR(st.st_mode) ||
                  st.st_uid != geteuid() || (st.st_mode & 077))) {
    close(fd);
    fd = -1;
    errno = EACCES;
  }
  return fd;
}
static bool compress_bytes(const bytes *raw, bytes *zip, size_t limit,
                           const bytes *dictionary) {
  size_t cap = ZSTD_compressBound(raw->n);
  if (cap > limit) {
    errno = EFBIG;
    return false;
  }
  if (!add(zip, NULL, 0, limit))
    return false;
  zip->p = malloc(cap ? cap : 1);
  if (!zip->p)
    return false;
  zip->cap = cap;
  ZSTD_CCtx *c = ZSTD_createCCtx();
  if (!c)
    return false;
  bool ok =
      !ZSTD_isError(ZSTD_CCtx_setParameter(c, ZSTD_c_compressionLevel, 9)) &&
      !ZSTD_isError(ZSTD_CCtx_setParameter(c, ZSTD_c_windowLog, 23)) &&
      !ZSTD_isError(ZSTD_CCtx_setParameter(c, ZSTD_c_checksumFlag, 1));
  if (ok && dictionary)
    ok = !ZSTD_isError(
        ZSTD_CCtx_loadDictionary(c, dictionary->p, dictionary->n));
  if (ok) {
    size_t n = ZSTD_compress2(
        c, zip->p, cap, raw->p ? raw->p : (const unsigned char *)"", raw->n);
    ok = !ZSTD_isError(n);
    if (ok)
      zip->n = n;
  }
  ZSTD_freeCCtx(c);
  if (!ok)
    errno = EINVAL;
  return ok;
}
static bool decompress_bytes(const unsigned char *zip, size_t zn, size_t raw_n,
                             bytes *raw, size_t limit,
                             const bytes *dictionary) {
  ZSTD_frameHeader h;
  if (raw_n > limit || ZSTD_getFrameHeader(&h, zip, zn) || !h.checksumFlag ||
      h.windowSize > (1u << 23) || h.frameContentSize != raw_n ||
      ZSTD_findFrameCompressedSize(zip, zn) != zn) {
    errno = EINVAL;
    return false;
  }
  raw->p = malloc(raw_n ? raw_n : 1);
  if (!raw->p)
    return false;
  raw->cap = raw_n;
  size_t n;
  if (dictionary) {
    ZSTD_DCtx *c = ZSTD_createDCtx();
    if (!c)
      return false;
    n = ZSTD_decompress_usingDict(c, raw->p, raw_n, zip, zn, dictionary->p,
                                  dictionary->n);
    ZSTD_freeDCtx(c);
  } else
    n = ZSTD_decompress(raw->p, raw_n, zip, zn);
  if (ZSTD_isError(n) || n != raw_n) {
    errno = EINVAL;
    return false;
  }
  raw->n = n;
  return true;
}
static void rows_free(record *r, size_t n) {
  if (r)
    for (size_t i = 0; i < n; i++) {
      free(r[i].key);
      free(r[i].file);
      free(r[i].text);
    }
  free(r);
}
static void parent_free(parent *p) {
  rows_free(p->rows, p->nr);
  free(p->blocks);
  release(&p->image);
  release(&p->table);
  memset(p, 0, sizeof(*p));
}
static bool digest(const void *p, size_t n, qihse_user_t *u, char hex[65]) {
  cg_snapshot_checksum h;
  if (!cg_snapshot_checksum_buffer_user(p, n, u, CG_CHECKSUM_XXH3_128, &h))
    return false;
  memcpy(hex, h.hex, 33);
  return true;
}
static bool block_name(const char *s) {
  if (!s || strlen(s) != 36 || strcmp(s + 32, ".qgb"))
    return false;
  for (size_t i = 0; i < 32; i++)
    if (!((s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f')))
      return false;
  return true;
}
static bool pending_name(const char *name) {
  if (strncmp(name, ".pending-", 9))
    return false;
  const char *p = name + 9;
  if (*p < '1' || *p > '9')
    return false;
  uint64_t pid = 0;
  while (*p >= '0' && *p <= '9') {
    pid = pid * 10 + (unsigned)(*p++ - '0');
    if (pid > INT_MAX)
      return false;
  }
  if (*p++ != '-' || strlen(p) != 16)
    return false;
  for (unsigned i = 0; i < 16; i++)
    if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f')))
      return false;
  return true;
}
static bool full_system_operator(qihse_user_t *u) {
  return active(u, UINT16_MAX, UINT16_MAX) &&
         qihse_user_get_tenant_id(u) == QIHSE_TENANT_SYSTEM &&
         qihse_user_get_role(u) == QIHSE_ROLE_OPERATOR;
}
typedef struct {
  char name[37];
  struct stat identity;
  uint16_t classification, sci;
  bool pending;
} gc_candidate;
static int cmp_key(const void *a, const void *b) {
  const record *x = *(const record *const *)a, *y = *(const record *const *)b;
  return strcmp(x->key, y->key);
}
static int cmp_group(const void *a, const void *b) {
  const record *x = *(const record *const *)a, *y = *(const record *const *)b;
  int c = strcmp(x->file, y->file);
  return c ? c : strcmp(x->key, y->key);
}
static int cmp_name(const void *a, const void *b) {
  return strcmp((const char *)a, (const char *)b);
}
static char *group_file(const unsigned char *value, size_t n) {
  char *result = NULL;
  if (n && n <= INT_MAX) {
    struct json_tokener *t = json_tokener_new();
    struct json_object *o =
        t ? json_tokener_parse_ex(t, (const char *)value, (int)n) : NULL;
    struct json_object *f = NULL;
    if (o && json_tokener_get_error(t) == json_tokener_success &&
        json_object_object_get_ex(o, "file", &f) &&
        json_object_is_type(f, json_type_string)) {
      const char *s = json_object_get_string(f);
      int len = json_object_get_string_len(f);
      if (len > 0 && len < 4096 && strlen(s) == (size_t)len)
        result = strdup(s);
    }
    if (o)
      json_object_put(o);
    if (t)
      json_tokener_free(t);
  }
  return result ? result : strdup("");
}
static bool compare_block(int dir, const bytes *encoded, const char *name,
                          qihse_user_t *u, bool *reused) {
  if (!active(u, 0, 0))
    return false;
  int old = openat(dir, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (old >= 0) {
    struct stat a, b;
    bool ok = regular_private(old, &a) && a.st_nlink == 1 &&
              (uint64_t)a.st_size == encoded->n;
    unsigned char scratch[8192];
    for (size_t at = 0; ok && at < encoded->n;) {
      size_t n = encoded->n - at;
      if (n > sizeof(scratch))
        n = sizeof(scratch);
      ok = active(u, 0, 0) && pread_all(old, scratch, n, (off_t)at) &&
           !memcmp(scratch, encoded->p + at, n);
      at += n;
    }
    ok = ok && !fstat(old, &b) && same_stat(&a, &b);
    close(old);
    if (!ok) {
      errno = EEXIST;
      return false;
    }
    *reused = true;
    return true;
  }
  return false;
}
static bool store_block(int dir, const bytes *encoded, const char *name,
                        qihse_user_t *u, bool *reused) {
  if (compare_block(dir, encoded, name, u, reused))
    return true;
  if (errno != ENOENT)
    return false;
  unsigned char rnd[8];
  if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
    errno = EIO;
    return false;
  }
  char temporary[64];
  snprintf(temporary, sizeof(temporary),
           ".pending-%ld-%02x%02x%02x%02x%02x%02x%02x%02x", (long)getpid(),
           rnd[0], rnd[1], rnd[2], rnd[3], rnd[4], rnd[5], rnd[6], rnd[7]);
  int fd = openat(dir, temporary,
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
  if (fd < 0)
    return false;
  bool ok = write_all(fd, encoded->p, encoded->n) && !fsync(fd);
  if (close(fd))
    ok = false;
  if (ok && renameat2(dir, temporary, dir, name, RENAME_NOREPLACE)) {
    if (errno == EEXIST) {
      unlinkat(dir, temporary, 0);
      return compare_block(dir, encoded, name, u, reused);
    }
    ok = false;
  }
#ifdef CG_GENERATION_TEST_FAULTS
  if (ok && getenv("CG_GENERATION_TEST_AFTER_RENAME"))
    _exit(86);
#endif
  if (unlinkat(dir, temporary, 0) && errno != ENOENT)
    ok = false;
  if (ok)
    ok = !fsync(dir) && active(u, 0, 0);
  *reused = false;
  return ok;
}

static bool streams(FILE *input, FILE *output, qihse_user_t *u,
                    uint64_t *max_bytes, size_t *max_records) {
  struct stat a, b;
  if (!active(u, 0, 0))
    return false;
  if (!input || !output || input == output || !bounds(max_bytes, max_records) ||
      ferror(input) || ferror(output) || ftello(output) != 0 ||
      !regular_private(fileno(input), &a) ||
      !regular_private(fileno(output), &b) || b.st_size ||
      ((a.st_dev == b.st_dev) && (a.st_ino == b.st_ino))) {
    errno = EINVAL;
    return false;
  }
  return true;
}
bool cg_generation_encode_snapshot(FILE *input, FILE *output,
                                   const char *directory, qihse_user_t *u,
                                   uint64_t max_bytes, size_t max_records,
                                   cg_generation_info *result) {
  if (!streams(input, output, u, &max_bytes, &max_records))
    return false;
  if (ftello(input) != 0) {
    errno = EINVAL;
    return false;
  }
  int dir = open_directory(directory, true);
  if (dir < 0)
    return false;
  record *rows = NULL;
  record **sorted = NULL;
  block *blocks = NULL;
  size_t nr = 0, cap = 0, nb = 0;
  bytes value = {0}, raw = {0}, zip = {0}, encoded = {0}, table = {0},
        meta_zip = {0}, labels = {0}, label_zip = {0};
  struct stat before, after;
  bool ok = !fstat(fileno(input), &before);
  cg_generation_info info = {0};
  uint16_t classification = 0, sci = 0;
  while (ok) {
    char text[HEADER_MAX];
    if (!fgets(text, sizeof(text), input)) {
      if (ferror(input))
        ok = false;
      break;
    }
    size_t hn = strlen(text);
    header h;
    if (nr >= max_records) {
      errno = E2BIG;
      ok = false;
      break;
    }
    if (!parse_header((unsigned char *)text, hn, &h) ||
        !active(u, h.classification, h.sci)) {
      ok = false;
      break;
    }
    uint64_t amount = (uint64_t)hn + h.kn + h.vn + 1;
    if (amount > max_bytes || info.raw_bytes > max_bytes - amount) {
      errno = EFBIG;
      ok = false;
      break;
    }
    if (nr == cap) {
      size_t next = cap ? cap * 2 : 1024;
      if (next > max_records)
        next = max_records;
      record *r = realloc(rows, next * sizeof(*r));
      if (!r) {
        ok = false;
        break;
      }
      rows = r;
      memset(rows + cap, 0, (next - cap) * sizeof(*rows));
      cap = next;
    }
    record *r = &rows[nr];
    r->h = h;
    r->hn = (uint16_t)hn;
    r->text = strdup(text);
    r->key = malloc((size_t)h.kn + 1);
    r->original = (uint32_t)nr;
    /* Include a partially populated row in cleanup immediately. */
    nr++;
    if (!r->text || !r->key || fread(r->key, 1, h.kn, input) != h.kn ||
        memchr(r->key, 0, h.kn)) {
      errno = EINVAL;
      ok = false;
      break;
    }
    r->key[h.kn] = 0;
    if (!key_access(u, r->key, h.kn)) {
      ok = false;
      break;
    }
    r->value_offset = ftello(input);
    if (r->value_offset < 0) {
      ok = false;
      break;
    }
    value.n = 0;
    if (!add(&value, NULL, 0, VALUE_MAX)) {
      ok = false;
      break;
    }
    if (h.vn > value.cap) {
      unsigned char *p = realloc(value.p, (size_t)h.vn);
      if (!p) {
        ok = false;
        break;
      }
      value.p = p;
      value.cap = (size_t)h.vn;
    }
    if ((h.vn && (fread(value.p, 1, (size_t)h.vn, input) != h.vn ||
                  memchr(value.p, 0, (size_t)h.vn))) ||
        fgetc(input) != '\n') {
      errno = EINVAL;
      ok = false;
      break;
    }
    value.n = (size_t)h.vn;
    r->file = group_file(value.p, value.n);
    if (!r->file) {
      ok = false;
      break;
    }
    if (h.classification > classification)
      classification = h.classification;
    sci |= h.sci;
    info.raw_bytes += amount;
    cg_progress_emit("encode-generations", "records", nr, UINT64_MAX);
  }
  if (ok && (!active(u, classification, sci) || fstat(fileno(input), &after) ||
             !same_stat(&before, &after)))
    ok = false;
  if (ok) {
    sorted = malloc((nr ? nr : 1) * sizeof(*sorted));
    blocks = calloc(CG_GENERATION_MAX_BLOCKS, sizeof(*blocks));
    ok = sorted && blocks;
  }
  if (ok) {
    for (size_t i = 0; i < nr; i++)
      sorted[i] = &rows[i];
    qsort(sorted, nr, sizeof(*sorted), cmp_key);
    for (size_t i = 1; i < nr; i++)
      if (!strcmp(sorted[i - 1]->key, sorted[i]->key)) {
        errno = EINVAL;
        ok = false;
        break;
      }
    qsort(sorted, nr, sizeof(*sorted), cmp_group);
  }
  for (size_t at = 0; ok && at < nr;) {
    if (nb >= CG_GENERATION_MAX_BLOCKS) {
      errno = E2BIG;
      ok = false;
      break;
    }
    size_t end = at, need = 4;
    uint16_t bc = 0, bs = 0;
    while (end < nr && !strcmp(sorted[at]->file, sorted[end]->file)) {
      record *r = sorted[end];
      size_t amount = 25 + (size_t)r->h.kn + (size_t)r->h.vn;
      if (need > 4 && need + amount > BLOCK_TARGET)
        break;
      if (amount > CG_GENERATION_MAX_BLOCK_BYTES - need) {
        errno = EFBIG;
        ok = false;
        break;
      }
      need += amount;
      if (r->h.classification > bc)
        bc = r->h.classification;
      bs |= r->h.sci;
      end++;
    }
    if (!ok)
      break;
    release(&raw);
    release(&zip);
    release(&encoded);
    release(&labels);
    release(&label_zip);
    ok = true;
    for (size_t i = at; ok && i < end; i++) {
      record *r = sorted[i];
      r->block = (uint32_t)nb;
      r->slot = (uint32_t)(i - at);
      unsigned char fields[25];
      p32(fields, r->h.kn);
      p64(fields + 4, r->h.vn);
      p64(fields + 12, r->h.expiry);
      p16(fields + 20, r->h.classification);
      p16(fields + 22, r->h.sci);
      fields[24] = r->h.flags;
      ok =
          active(u, r->h.classification, r->h.sci) &&
          add(&labels, fields, sizeof(fields), CG_GENERATION_MAX_BLOCK_BYTES) &&
          add(&labels, r->key, r->h.kn, CG_GENERATION_MAX_BLOCK_BYTES);
      if (ok) {
        size_t off = raw.n;
        ok = add(&raw, NULL, 0, CG_GENERATION_MAX_BLOCK_BYTES);
        if (ok && r->h.vn) {
          size_t available = CG_GENERATION_MAX_BLOCK_BYTES - raw.n;
          if (r->h.vn > available) {
            errno = EFBIG;
            ok = false;
          } else {
            if (raw.n + r->h.vn > raw.cap) {
              unsigned char *p = realloc(raw.p, raw.n + (size_t)r->h.vn);
              if (!p)
                ok = false;
              else {
                raw.p = p;
                raw.cap = raw.n + (size_t)r->h.vn;
              }
            }
            if (ok) {
              ok = pread_all(fileno(input), raw.p + off, (size_t)r->h.vn,
                             r->value_offset);
              raw.n += (size_t)r->h.vn;
            }
          }
        }
      }
    }
    if (ok)
      ok = compress_bytes(&labels, &label_zip,
                          ZSTD_compressBound(CG_GENERATION_MAX_BLOCK_BYTES),
                          NULL) &&
           compress_bytes(&raw, &zip,
                          ZSTD_compressBound(CG_GENERATION_MAX_BLOCK_BYTES),
                          &labels);
    unsigned char bh[BLOCK_HEAD] = {0};
    memcpy(bh, "QCGB0001", 8);
    p64(bh + 8, raw.n);
    p64(bh + 16, zip.n);
    p32(bh + 24, (uint32_t)(end - at));
    p16(bh + 28, bc);
    p16(bh + 30, bs);
    p64(bh + 32, label_zip.n);
    p32(bh + 40, qihse_user_get_tenant_id(u));
    p32(bh + 44, (uint32_t)labels.n);
    if (ok)
      ok = add(&encoded, bh, sizeof(bh),
               BLOCK_HEAD +
                   2 * ZSTD_compressBound(CG_GENERATION_MAX_BLOCK_BYTES)) &&
           add(&encoded, label_zip.p, label_zip.n,
               BLOCK_HEAD +
                   2 * ZSTD_compressBound(CG_GENERATION_MAX_BLOCK_BYTES)) &&
           add(&encoded, zip.p, zip.n,
               BLOCK_HEAD +
                   2 * ZSTD_compressBound(CG_GENERATION_MAX_BLOCK_BYTES));
    char hash[65];
    bool reused = false;
    if (ok)
      ok = digest(encoded.p, encoded.n, u, hash);
    if (ok) {
      snprintf(blocks[nb].name, sizeof(blocks[nb].name), "%.32s.qgb", hash);
      ok = store_block(dir, &encoded, blocks[nb].name, u, &reused);
    }
    if (ok) {
      blocks[nb].raw = raw.n + labels.n;
      blocks[nb].encoded = encoded.n;
      blocks[nb].count = (uint32_t)(end - at);
      info.block_bytes += encoded.n;
      if (reused) {
        info.reused_blocks++;
        info.reused_block_bytes += encoded.n;
      } else {
        info.new_blocks++;
        info.new_block_bytes += encoded.n;
      }
      nb++;
      at = end;
    }
  }
  for (size_t i = 0; ok && i < nb; i++) {
    unsigned char fields[52] = {0};
    memcpy(fields, blocks[i].name, 32);
    p64(fields + 32, blocks[i].raw);
    p64(fields + 40, blocks[i].encoded);
    p32(fields + 48, blocks[i].count);
    ok = add(&table, fields, sizeof(fields), TABLE_MAX);
  }
  for (size_t i = 0; ok && i < nr; i++) {
    unsigned char fields[10];
    p32(fields, rows[i].block);
    p32(fields + 4, rows[i].slot);
    p16(fields + 8, rows[i].hn);
    ok = add(&table, fields, sizeof(fields), TABLE_MAX) &&
         add(&table, rows[i].text, rows[i].hn, TABLE_MAX);
  }
  if (ok)
    ok = compress_bytes(&table, &meta_zip, ZSTD_compressBound(TABLE_MAX), NULL);
  if (ok && (!active(u, classification, sci) || fstat(fileno(input), &after) ||
             !same_stat(&before, &after)))
    ok = false;
  if (ok) {
    unsigned char head[PARENT_HEAD] = {0};
    memcpy(head, CG_GENERATION_MAGIC, 8);
    p64(head + 8, info.raw_bytes);
    p32(head + 16, (uint32_t)nr);
    p32(head + 20, (uint32_t)nb);
    p64(head + 24, table.n);
    p64(head + 32, meta_zip.n);
    p16(head + 40, classification);
    p16(head + 42, sci);
    p32(head + 44, qihse_user_get_tenant_id(u));
    p64(head + 48, info.block_bytes);
    ok = fwrite(head, 1, sizeof(head), output) == sizeof(head) &&
         fwrite(meta_zip.p, 1, meta_zip.n, output) == meta_zip.n &&
         !fflush(output) && active(u, classification, sci);
    info.parent_bytes = PARENT_HEAD + meta_zip.n;
    info.blocks = (uint32_t)nb;
    info.records = (uint32_t)nr;
  }
  if (ok && result)
    *result = info;
  rows_free(rows, nr);
  free(sorted);
  free(blocks);
  release(&value);
  release(&raw);
  release(&zip);
  release(&encoded);
  release(&table);
  release(&meta_zip);
  release(&labels);
  release(&label_zip);
  close(dir);
  return ok;
}

static bool load_parent(FILE *input, qihse_user_t *u,
                        const cg_snapshot_checksum *expected,
                        uint64_t max_bytes, size_t max_records, parent *out) {
  memset(out, 0, sizeof(*out));
  struct stat before, after;
  if (!active(u, 0, 0))
    return false;
  if (!input || !cg_checksum_valid(expected) ||
      !bounds(&max_bytes, &max_records) ||
      !regular_private(fileno(input), &before) ||
      before.st_size < PARENT_HEAD ||
      (uint64_t)before.st_size > PARENT_HEAD + ZSTD_compressBound(TABLE_MAX)) {
    errno = EINVAL;
    return false;
  }
  unsigned char prefix[PARENT_HEAD];
  if (!pread_all(fileno(input), prefix, sizeof(prefix), 0))
    return false;
  if (!active(u, g16(prefix + 40), g16(prefix + 42)))
    return false;
  if (g64(prefix + 8) > max_bytes) {
    errno = EFBIG;
    return false;
  }
  if (g32(prefix + 16) > max_records) {
    errno = E2BIG;
    return false;
  }
  out->image.p = malloc((size_t)before.st_size);
  if (!out->image.p)
    return false;
  out->image.n = out->image.cap = (size_t)before.st_size;
  bool ok = pread_all(fileno(input), out->image.p, out->image.n, 0) &&
            !fstat(fileno(input), &after) && same_stat(&before, &after);
  cg_snapshot_checksum actual;
  if (ok)
    ok = cg_snapshot_checksum_buffer_user(out->image.p, out->image.n, u,
                                          expected->algorithm, &actual) &&
         !strcmp(actual.hex, expected->hex);
  if (!ok) {
    errno = EINVAL;
    return false;
  }
  const unsigned char *h = out->image.p;
  out->raw = g64(h + 8);
  out->nr = g32(h + 16);
  out->nb = g32(h + 20);
  out->classification = g16(h + 40);
  out->sci = g16(h + 42);
  uint64_t table_size = g64(h + 24), zip_size = g64(h + 32);
  if (!active(u, out->classification, out->sci))
    return false;
  if (out->raw > max_bytes) {
    errno = EFBIG;
    return false;
  }
  if (out->nr > max_records) {
    errno = E2BIG;
    return false;
  }
  if (memcmp(h, CG_GENERATION_MAGIC, 8) || g64(h + 56) ||
      out->nb > CG_GENERATION_MAX_BLOCKS || table_size > TABLE_MAX ||
      zip_size != out->image.n - PARENT_HEAD || (!out->nr && out->nb) ||
      (!out->nb && out->nr) ||
      table_size < (uint64_t)out->nb * 52 + (uint64_t)out->nr * 12) {
    errno = EINVAL;
    return false;
  }
  if (g32(h + 44) != qihse_user_get_tenant_id(u)) {
    errno = EACCES;
    return false;
  }
  if (!active(u, out->classification, out->sci) ||
      !decompress_bytes(h + PARENT_HEAD, (size_t)zip_size, (size_t)table_size,
                        &out->table, TABLE_MAX, NULL))
    return false;
  out->rows = calloc(out->nr ? out->nr : 1, sizeof(*out->rows));
  out->blocks = calloc(out->nb ? out->nb : 1, sizeof(*out->blocks));
  if (!out->rows || !out->blocks)
    return false;
  size_t at = 0;
  uint64_t blockbytes = 0, totalrows = 0;
  for (uint32_t i = 0; i < out->nb; i++) {
    const unsigned char *p = out->table.p + at;
    memcpy(out->blocks[i].name, p, 32);
    memcpy(out->blocks[i].name + 32, ".qgb", 5);
    out->blocks[i].raw = g64(p + 32);
    out->blocks[i].encoded = g64(p + 40);
    out->blocks[i].count = g32(p + 48);
    at += 52;
    block *b = &out->blocks[i];
    if (!block_name(b->name) || !b->count || b->raw < 4 ||
        b->raw > CG_GENERATION_MAX_BLOCK_BYTES || b->encoded < BLOCK_HEAD ||
        b->encoded > BLOCK_HEAD + 2 * ZSTD_compressBound((size_t)b->raw) ||
        b->count > out->nr || totalrows > out->nr - b->count ||
        blockbytes > UINT64_MAX - b->encoded) {
      errno = EINVAL;
      return false;
    }
    totalrows += b->count;
    blockbytes += b->encoded;
  }
  if (totalrows != out->nr || blockbytes != g64(h + 48)) {
    errno = EINVAL;
    return false;
  }
  uint16_t classification = 0, sci = 0;
  uint64_t raw = 0;
  for (uint32_t i = 0; i < out->nr; i++) {
    if (out->table.n - at < 10) {
      errno = EINVAL;
      return false;
    }
    record *r = &out->rows[i];
    r->block = g32(out->table.p + at);
    r->slot = g32(out->table.p + at + 4);
    r->hn = g16(out->table.p + at + 8);
    at += 10;
    if (r->block >= out->nb || r->slot >= out->blocks[r->block].count ||
        r->hn >= HEADER_MAX || out->table.n - at < r->hn ||
        !parse_header(out->table.p + at, r->hn, &r->h) ||
        !active(u, r->h.classification, r->h.sci))
      return false;
    r->text = malloc((size_t)r->hn + 1);
    if (!r->text)
      return false;
    memcpy(r->text, out->table.p + at, r->hn);
    r->text[r->hn] = 0;
    at += r->hn;
    uint64_t amount = (uint64_t)r->hn + r->h.kn + r->h.vn + 1;
    if (amount > max_bytes || raw > max_bytes - amount) {
      errno = EFBIG;
      return false;
    }
    raw += amount;
    if (r->h.classification > classification)
      classification = r->h.classification;
    sci |= r->h.sci;
  }
  if (at != out->table.n || raw != out->raw ||
      classification != out->classification || sci != out->sci) {
    errno = EINVAL;
    return false;
  }
  return true;
}

/* Keys and labels live in a separate metadata frame. After every namespace
 * and label has been authorized, that exact metadata seeds the raw Zstd
 * dictionary for values, avoiding duplicate random ID storage across streams.
 * Unknown value bytes remain exact; no semantic JSON rewriting is performed. */
static bool read_block(int directory, const block *b, qihse_user_t *u,
                       bytes *labels, bytes *body) {
  int fd = openat(directory, b->name,
                  O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
  if (fd < 0)
    return false;
  struct stat a, z;
  bytes encoded = {0};
  bool ok = regular_private(fd, &a) && a.st_nlink == 1 &&
            (uint64_t)a.st_size == b->encoded;
  if (ok) {
    encoded.p = malloc((size_t)b->encoded);
    ok = encoded.p != NULL;
    encoded.n = encoded.cap = (size_t)b->encoded;
  }
  if (ok)
    ok = pread_all(fd, encoded.p, encoded.n, 0) && !fstat(fd, &z) &&
         same_stat(&a, &z);
  close(fd);
  char hash[65];
  if (ok)
    ok = digest(encoded.p, encoded.n, u, hash) && !memcmp(hash, b->name, 32);
  uint64_t raw_n = 0, zip_n = 0, label_n = 0;
  uint32_t label_raw = 0;
  uint16_t classification = 0, sci = 0;
  if (ok) {
    const unsigned char *h = encoded.p;
    raw_n = g64(h + 8);
    zip_n = g64(h + 16);
    label_n = g64(h + 32);
    classification = g16(h + 28);
    sci = g16(h + 30);
    label_raw = g32(h + 44);
    ok = !memcmp(h, "QCGB0001", 8) && g32(h + 24) == b->count &&
         raw_n <= CG_GENERATION_MAX_BLOCK_BYTES &&
         label_raw <= CG_GENERATION_MAX_BLOCK_BYTES &&
         b->raw == raw_n + label_raw && label_n <= b->encoded - BLOCK_HEAD &&
         zip_n == b->encoded - BLOCK_HEAD - label_n &&
         active(u, classification, sci);
    if (ok && g32(h + 40) != qihse_user_get_tenant_id(u)) {
      errno = EACCES;
      ok = false;
    }
  }
  if (ok)
    ok = decompress_bytes(encoded.p + BLOCK_HEAD, (size_t)label_n, label_raw,
                          labels, CG_GENERATION_MAX_BLOCK_BYTES, NULL);
  uint16_t actual_class = 0, actual_sci = 0;
  uint64_t body_n = 0;
  size_t label_at = 0;
  for (uint32_t i = 0; ok && i < b->count; i++) {
    if (labels->n - label_at < 25) {
      errno = EINVAL;
      ok = false;
      break;
    }
    const unsigned char *m = labels->p + label_at;
    uint32_t kn = g32(m);
    uint64_t vn = g64(m + 4);
    uint16_t c = g16(m + 20), sci_mask = g16(m + 22);
    uint8_t flags = m[24];
    label_at += 25;
    ok = kn && kn <= KEY_MAX && kn <= labels->n - label_at && vn <= VALUE_MAX &&
         flags <= 1 && (!flags || !vn) && active(u, c, sci_mask) &&
         !memchr(labels->p + label_at, 0, kn) &&
         key_access(u, (const char *)labels->p + label_at, kn) && vn <= raw_n &&
         body_n <= raw_n - vn;
    if (ok) {
      body_n += vn;
      label_at += kn;
      if (c > actual_class)
        actual_class = c;
      actual_sci |= sci_mask;
    }
  }
  if (ok)
    ok = label_at == labels->n && body_n == raw_n &&
         actual_class == classification && actual_sci == sci;
  if (ok)
    ok = decompress_bytes(encoded.p + BLOCK_HEAD + (size_t)label_n,
                          (size_t)zip_n, (size_t)raw_n, body,
                          CG_GENERATION_MAX_BLOCK_BYTES, labels) &&
         active(u, classification, sci);
  if (!ok && errno != EACCES)
    errno = EINVAL;
  release(&encoded);
  return ok;
}
static bool copy_payload(FILE *from, FILE *to, off_t off, uint64_t n,
                         qihse_user_t *u) {
  unsigned char buffer[8192];
  while (n) {
    if (!active(u, 0, 0))
      return false;
    size_t amount = n > sizeof(buffer) ? sizeof(buffer) : (size_t)n;
    if (!pread_all(fileno(from), buffer, amount, off) ||
        fwrite(buffer, 1, amount, to) != amount)
      return false;
    n -= amount;
    off += (off_t)amount;
  }
  return true;
}
static int cmp_digest(const void *a, const void *b) { return memcmp(a, b, 16); }
static void generation_progress(const char *phase) {
  static _Thread_local uint64_t decoded, collected, accounted;
  uint64_t *counter = !strcmp(phase, "gc-generations")        ? &collected
                      : !strcmp(phase, "account-generations") ? &accounted
                                                              : &decoded;
  if (*counter < INT64_MAX)
    ++*counter;
  cg_progress_emit(phase, "chunks", *counter, UINT64_MAX);
}
static bool decode_parent(parent *p, int directory, FILE *output,
                          qihse_user_t *u, const char *phase) {
  bool materialize = output != NULL;
  FILE *payload = materialize ? tmpfile() : NULL;
  FILE *raw = materialize ? tmpfile() : NULL;
  record **mapping = NULL;
  unsigned char *keys = NULL;
  size_t *offsets = NULL;
  bool ok = !materialize || (payload && raw);
  if (ok) {
    mapping = calloc(p->nr ? p->nr : 1, sizeof(*mapping));
    keys = malloc((p->nr ? p->nr : 1) * 16);
    offsets = calloc((size_t)p->nb + 1, sizeof(*offsets));
    ok = mapping && keys && offsets;
  }
  if (ok) {
    for (uint32_t i = 0; i < p->nb; i++)
      offsets[i + 1] = offsets[i] + p->blocks[i].count;
    for (uint32_t i = 0; i < p->nr; i++) {
      size_t index = offsets[p->rows[i].block] + p->rows[i].slot;
      if (index >= p->nr || mapping[index]) {
        errno = EINVAL;
        ok = false;
        break;
      }
      mapping[index] = &p->rows[i];
    }
  }
  size_t key_index = 0;
  for (uint32_t i = 0; ok && i < p->nb; i++) {
    bytes labels = {0}, body = {0};
    ok = read_block(directory, &p->blocks[i], u, &labels, &body);
    size_t at = 0, label_at = 0;
    for (uint32_t j = 0; ok && j < p->blocks[i].count; j++) {
      record *r = mapping[offsets[i] + j];
      const unsigned char *m = labels.p + label_at;
      uint32_t kn = g32(m);
      uint64_t vn = g64(m + 4);
      label_at += 25;
      const unsigned char *key = labels.p + label_at;
      ok = r && r->h.kn == kn && r->h.vn == vn && r->h.expiry == g64(m + 12) &&
           r->h.classification == g16(m + 20) && r->h.sci == g16(m + 22) &&
           r->h.flags == m[24] && at <= body.n && vn <= body.n - at &&
           (!vn || !memchr(body.p + at, 0, (size_t)vn));
      if (ok) {
        char hex[65];
        ok = digest(key, kn, u, hex);
        if (ok) {
          for (size_t k = 0; k < 16; k++) {
            unsigned a = (unsigned)(hex[2 * k] <= '9' ? hex[2 * k] - '0'
                                                      : hex[2 * k] - 'a' + 10);
            unsigned b =
                (unsigned)(hex[2 * k + 1] <= '9' ? hex[2 * k + 1] - '0'
                                                 : hex[2 * k + 1] - 'a' + 10);
            keys[key_index * 16 + k] = (unsigned char)((a << 4) | b);
          }
          key_index++;
          if (materialize) {
            r->staged_offset = ftello(payload);
            ok = r->staged_offset >= 0 && fwrite(key, 1, kn, payload) == kn &&
                 fwrite(body.p + at, 1, (size_t)vn, payload) == vn;
          }
          at += (size_t)vn;
          label_at += kn;
        }
      }
    }
    if (ok)
      ok = at == body.n && label_at == labels.n;
    release(&labels);
    release(&body);
    if (ok)
      generation_progress(phase);
  }
  if (ok) {
    qsort(keys, key_index, 16, cmp_digest);
    for (size_t i = 1; i < key_index; i++)
      if (!memcmp(keys + (i - 1) * 16, keys + i * 16, 16)) {
        errno = EEXIST;
        ok = false;
        break;
      }
  }
  if (ok && materialize)
    ok = !fflush(payload);
  for (uint32_t i = 0; materialize && ok && i < p->nr; i++) {
    record *r = &p->rows[i];
    ok = active(u, r->h.classification, r->h.sci) &&
         fwrite(r->text, 1, r->hn, raw) == r->hn &&
         copy_payload(payload, raw, r->staged_offset,
                      (uint64_t)r->h.kn + r->h.vn, u) &&
         fputc('\n', raw) != EOF;
  }
  if (ok && materialize)
    ok = !fflush(raw) && active(u, p->classification, p->sci) &&
         copy_payload(raw, output, 0, p->raw, u) && !fflush(output);
  if (ok)
    ok = active(u, p->classification, p->sci);
  if (payload)
    fclose(payload);
  if (raw)
    fclose(raw);
  free(mapping);
  free(keys);
  free(offsets);
  return ok;
}
bool cg_generation_decode_snapshot(FILE *input, FILE *output,
                                   const char *directory, qihse_user_t *u,
                                   const cg_snapshot_checksum *expected,
                                   uint64_t max_bytes, size_t max_records,
                                   cg_generation_info *result) {
  if (!streams(input, output, u, &max_bytes, &max_records))
    return false;
  parent p;
  bool ok = load_parent(input, u, expected, max_bytes, max_records, &p);
  int dir = -1;
  if (ok) {
    dir = open_directory(directory, false);
    ok = dir >= 0;
  }
  if (ok)
    ok = decode_parent(&p, dir, output, u, "decode-generations");
  if (ok && result) {
    cg_generation_info info = {.parent_bytes = p.image.n,
                               .raw_bytes = p.raw,
                               .blocks = p.nb,
                               .records = p.nr};
    for (uint32_t i = 0; i < p.nb; i++)
      info.block_bytes += p.blocks[i].encoded;
    *result = info;
  }
  if (dir >= 0)
    close(dir);
  parent_free(&p);
  return ok;
}

bool cg_generation_gc(const char *directory, qihse_user_t *u,
                      const cg_generation_root *roots, size_t root_count,
                      size_t *removed_blocks, uint64_t *removed_bytes) {
  if (!active(u, 0, 0))
    return false;
  if (root_count > 2 || (!roots && root_count)) {
    errno = EINVAL;
    return false;
  }
  int dir = open_directory(directory, false);
  if (dir < 0)
    return false;
  uint16_t required_class = 0, required_sci = 0;
  bool require_operator = false;
  uint32_t tenant = qihse_user_get_tenant_id(u);
  parent retained[2] = {0};
  char (*live)[37] = NULL;
  size_t live_count = 0;
  bool ok = true;
  for (size_t i = 0; ok && i < root_count; i++) {
    ok = load_parent(roots[i].parent, u, &roots[i].checksum,
                     CG_GENERATION_MAX_RAW_BYTES, CG_GENERATION_MAX_RECORDS,
                     &retained[i]);
    if (ok)
      ok = decode_parent(&retained[i], dir, NULL, u, "gc-generations");
    if (ok) {
      if (retained[i].classification > required_class)
        required_class = retained[i].classification;
      required_sci |= retained[i].sci;
      size_t next = live_count + retained[i].nb;
      char (*names)[37] = realloc(live, (next ? next : 1) * sizeof(*live));
      if (!names) {
        ok = false;
        break;
      }
      live = names;
      for (uint32_t j = 0; j < retained[i].nb; j++)
        memcpy(live[live_count++], retained[i].blocks[j].name, 37);
    }
  }
  if (ok && live_count > 1)
    qsort(live, live_count, sizeof(*live), cmp_name);
  DIR *scan = NULL;
  gc_candidate *dead = NULL;
  size_t dead_count = 0;
  if (ok) {
    int copy = dup(dir);
    if (copy >= 0)
      scan = fdopendir(copy);
    if (!scan) {
      if (copy >= 0)
        close(copy);
      ok = false;
    }
  }
  struct dirent *entry;
  size_t scan_entries = 0;
  while (ok) {
    errno = 0;
    entry = readdir(scan);
    if (!entry) {
      if (errno)
        ok = false;
      break;
    }
    if (++scan_entries > CG_GENERATION_MAX_SCAN_ENTRIES) {
      errno = E2BIG;
      ok = false;
      break;
    }
    bool pending = pending_name(entry->d_name);
    if ((!block_name(entry->d_name) && !pending) ||
        (live_count &&
         bsearch(entry->d_name, live, live_count, sizeof(*live), cmp_name)))
      continue;
    if (pending) {
      int fd = openat(dir, entry->d_name,
                      O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
      struct stat st;
      bool owned = fd >= 0 && regular_private(fd, &st) && st.st_nlink == 1;
      if (fd >= 0)
        close(fd);
      if (!owned)
        continue;
      if (!full_system_operator(u)) {
        errno = EACCES;
        ok = false;
        break;
      }
      require_operator = true;
      required_class = required_sci = UINT16_MAX;
      gc_candidate *next = realloc(dead, (dead_count + 1) * sizeof(*dead));
      if (!next) {
        ok = false;
        break;
      }
      dead = next;
      dead[dead_count] = (gc_candidate){.identity = st,
                                        .classification = UINT16_MAX,
                                        .sci = UINT16_MAX,
                                        .pending = true};
      snprintf(dead[dead_count].name, sizeof(dead[dead_count].name), "%.36s",
               entry->d_name);
      dead_count++;
      continue;
    }
    int fd = openat(dir, entry->d_name,
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0) {
      if (errno == ELOOP || errno == ENOENT)
        continue;
      ok = false;
      break;
    }
    struct stat st;
    unsigned char head[BLOCK_HEAD];
    bool candidate = regular_private(fd, &st) && st.st_nlink == 1 &&
                     (uint64_t)st.st_size >= BLOCK_HEAD &&
                     (uint64_t)st.st_size <=
                         BLOCK_HEAD + 2 * ZSTD_compressBound(
                                              CG_GENERATION_MAX_BLOCK_BYTES) &&
                     pread_all(fd, head, sizeof(head), 0);
    close(fd);
    if (!candidate)
      continue;
    block b = {0};
    memcpy(b.name, entry->d_name, 37);
    b.count = g32(head + 24);
    b.raw = g64(head + 8) + g32(head + 44);
    b.encoded = (uint64_t)st.st_size;
    if (memcmp(head, "QCGB0001", 8) || !b.count ||
        b.count > CG_GENERATION_MAX_RECORDS ||
        b.raw > CG_GENERATION_MAX_BLOCK_BYTES) {
      errno = EINVAL;
      ok = false;
      break;
    }
    bytes labels = {0}, body = {0};
    ok = read_block(dir, &b, u, &labels, &body);
    release(&labels);
    release(&body);
    struct stat verified;
    if (ok)
      ok = !fstatat(dir, entry->d_name, &verified, AT_SYMLINK_NOFOLLOW) &&
           same_stat(&st, &verified);
    if (!ok)
      break;
    if (g16(head + 28) > required_class)
      required_class = g16(head + 28);
    required_sci |= g16(head + 30);
    generation_progress("gc-generations");
    gc_candidate *next = realloc(dead, (dead_count + 1) * sizeof(*dead));
    if (!next) {
      ok = false;
      break;
    }
    dead = next;
    dead[dead_count] = (gc_candidate){.identity = st,
                                      .classification = g16(head + 28),
                                      .sci = g16(head + 30)};
    memcpy(dead[dead_count].name, entry->d_name, 37);
    dead_count++;
  }
  if (scan)
    closedir(scan);
  if (ok)
    ok = active(u, required_class, required_sci) &&
         qihse_user_get_tenant_id(u) == tenant &&
         (!require_operator || full_system_operator(u));
  size_t removed = 0;
  uint64_t removed_size = 0;
  /* No deletion occurs until every retained root and candidate is validated. */
  for (size_t i = 0; ok && i < dead_count; i++) {
    if (!active(u, dead[i].classification, dead[i].sci) ||
        (dead[i].pending && !full_system_operator(u))) {
      ok = false;
      break;
    }
    struct stat st;
    if (fstatat(dir, dead[i].name, &st, AT_SYMLINK_NOFOLLOW) ||
        !S_ISREG(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 077) ||
        st.st_nlink != 1 || !same_stat(&st, &dead[i].identity)) {
      errno = EIO;
      ok = false;
      break;
    }
    if (unlinkat(dir, dead[i].name, 0)) {
      ok = false;
      break;
    }
    removed++;
    removed_size += (uint64_t)dead[i].identity.st_size;
  }
  if (ok)
    ok = !fsync(dir) && active(u, required_class, required_sci) &&
         qihse_user_get_tenant_id(u) == tenant &&
         (!require_operator || full_system_operator(u));
  if (ok) {
    if (removed_blocks)
      *removed_blocks = removed;
    if (removed_bytes)
      *removed_bytes = removed_size;
  }
  for (size_t i = 0; i < 2; i++)
    parent_free(&retained[i]);
  free(live);
  free(dead);
  close(dir);
  return ok;
}

bool cg_generation_account_user(const char *directory, qihse_user_t *u,
                                const cg_generation_root *roots,
                                size_t root_count, cg_generation_account *out) {
  if (!active(u, 0, 0))
    return false;
  if (!out || root_count > 2 || (!roots && root_count)) {
    errno = EINVAL;
    return false;
  }
  int dir = open_directory(directory, false);
  if (dir < 0)
    return false;
  uint16_t required_class = 0, required_sci = 0;
  bool require_operator = false;
  uint32_t tenant = qihse_user_get_tenant_id(u);
  parent retained[2] = {0};
  char (*live)[37] = NULL;
  size_t count = 0;
  bool ok = true;
  cg_generation_account result = {.coverage_complete = true};
  for (size_t i = 0; ok && i < root_count; i++) {
    ok = load_parent(roots[i].parent, u, &roots[i].checksum,
                     CG_GENERATION_MAX_RAW_BYTES, CG_GENERATION_MAX_RECORDS,
                     &retained[i]);
    if (ok)
      ok = decode_parent(&retained[i], dir, NULL, u, "account-generations");
    if (ok) {
      if (retained[i].classification > required_class)
        required_class = retained[i].classification;
      required_sci |= retained[i].sci;
      size_t next = count + retained[i].nb;
      char (*names)[37] = realloc(live, (next ? next : 1) * sizeof(*live));
      if (!names) {
        ok = false;
        break;
      }
      live = names;
      for (uint32_t j = 0; j < retained[i].nb; j++)
        memcpy(live[count++], retained[i].blocks[j].name, 37);
    }
  }
  if (ok && count > 1)
    qsort(live, count, sizeof(*live), cmp_name);
  for (size_t i = 0; ok && i < count; i++) {
    if (i && !strcmp(live[i], live[i - 1]))
      continue;
    struct stat st;
    int fd =
        openat(dir, live[i], O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    ok = fd >= 0 && regular_private(fd, &st) && st.st_nlink == 1;
    if (fd >= 0)
      close(fd);
    if (ok) {
      result.referenced_blocks++;
      result.referenced_bytes += (uint64_t)st.st_size;
      result.referenced_allocated_bytes += (uint64_t)st.st_blocks * 512;
    }
  }
  DIR *scan = NULL;
  if (ok) {
    int copy = dup(dir);
    if (copy >= 0)
      scan = fdopendir(copy);
    if (!scan) {
      if (copy >= 0)
        close(copy);
      ok = false;
    }
  }
  size_t scan_entries = 0;
  while (ok) {
    errno = 0;
    struct dirent *entry = readdir(scan);
    if (!entry) {
      if (errno)
        ok = false;
      break;
    }
    if (++scan_entries > CG_GENERATION_MAX_SCAN_ENTRIES) {
      result.coverage_complete = false;
      break;
    }
    if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
      continue;
    bool pending = pending_name(entry->d_name);
    if (!block_name(entry->d_name) && !pending) {
      result.coverage_complete = false;
      continue;
    }
    if (count && bsearch(entry->d_name, live, count, sizeof(*live), cmp_name))
      continue;
    if (pending) {
      int fd = openat(dir, entry->d_name,
                      O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
      struct stat st;
      bool admitted = fd >= 0 && regular_private(fd, &st) && st.st_nlink == 1 &&
                      full_system_operator(u);
      if (fd >= 0)
        close(fd);
      if (admitted) {
        require_operator = true;
        required_class = required_sci = UINT16_MAX;
        result.orphan_blocks++;
        result.orphan_bytes += (uint64_t)st.st_size;
        result.orphan_allocated_bytes += (uint64_t)st.st_blocks * 512;
      } else
        result.coverage_complete = false;
      continue;
    }
    int fd = openat(dir, entry->d_name,
                    O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    struct stat st;
    unsigned char head[BLOCK_HEAD];
    bool admitted = fd >= 0 && regular_private(fd, &st) && st.st_nlink == 1 &&
                    (uint64_t)st.st_size >= BLOCK_HEAD &&
                    (uint64_t)st.st_size <=
                        BLOCK_HEAD + 2 * ZSTD_compressBound(
                                             CG_GENERATION_MAX_BLOCK_BYTES) &&
                    pread_all(fd, head, sizeof(head), 0);
    if (fd >= 0)
      close(fd);
    if (admitted) {
      block b = {0};
      memcpy(b.name, entry->d_name, 37);
      b.count = g32(head + 24);
      b.raw = g64(head + 8) + g32(head + 44);
      b.encoded = (uint64_t)st.st_size;
      admitted = !memcmp(head, "QCGB0001", 8) && b.count &&
                 b.count <= CG_GENERATION_MAX_RECORDS &&
                 b.raw <= CG_GENERATION_MAX_BLOCK_BYTES;
      bytes labels = {0}, body = {0};
      if (admitted)
        admitted = read_block(dir, &b, u, &labels, &body);
      release(&labels);
      release(&body);
      struct stat after;
      if (admitted)
        admitted = !fstatat(dir, entry->d_name, &after, AT_SYMLINK_NOFOLLOW) &&
                   same_stat(&st, &after);
    }
    if (admitted) {
      if (g16(head + 28) > required_class)
        required_class = g16(head + 28);
      required_sci |= g16(head + 30);
      generation_progress("account-generations");
      result.orphan_blocks++;
      result.orphan_bytes += (uint64_t)st.st_size;
      result.orphan_allocated_bytes += (uint64_t)st.st_blocks * 512;
    } else
      result.coverage_complete = false;
  }
  if (scan)
    closedir(scan);
  if (ok)
    ok = active(u, required_class, required_sci) &&
         qihse_user_get_tenant_id(u) == tenant &&
         (!require_operator || full_system_operator(u));
  if (ok)
    *out = result;
  for (size_t i = 0; i < 2; i++)
    parent_free(&retained[i]);
  free(live);
  close(dir);
  return ok;
}
