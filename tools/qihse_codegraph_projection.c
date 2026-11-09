/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_codegraph_projection.h"
#include <errno.h>
#include <float.h>
#include <math.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#define ZSTD_STATIC_LINKING_ONLY
#include <zstd.h>

_Static_assert(sizeof(double) == 8 && DBL_MANT_DIG == 53 && FLT_RADIX == 2,
               "projection wire confidence requires IEEE-754 binary64");
_Static_assert(sizeof(int) == 4, "projection node lines require 32-bit int");

enum {
  HEADER = 256,
  NODE_WIRE = 64,
  BLOCK = 256,
  MAX_NODES = 2000000,
  MAX_EDGES = 8000000,
  MAX_STRINGS = 128 * 1024 * 1024,
  MAX_FILE = 1024 * 1024 * 1024
};
typedef struct {
  unsigned char *p;
  size_t n, cap;
} buf;
typedef struct {
  uint64_t hash;
  uint32_t offset;
} slot;
typedef struct {
  buf bytes;
  slot *slots;
  size_t cap, used;
} strings;
typedef struct {
  size_t offset, size;
  uint32_t count;
  _Atomic(cg_csr_edge *) ready;
} block;
struct cg_projection {
  qihse_user_t *principal;
  cg_projection_binding binding;
  cg_projection_view view;
  unsigned char *encoded;
  size_t encoded_size, string_size, block_count, base_bytes;
  char *strings;
  uint32_t *sources, *targets;
  block *blocks;
  pthread_mutex_t mutex;
  bool mutex_ready;
  atomic_size_t evidence_bytes;
  atomic_bool failed;
};
static uint32_t r32(const unsigned char *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
         p[3];
}
static uint64_t r64(const unsigned char *p) {
  return (uint64_t)r32(p) << 32 | r32(p + 4);
}
static void w32(unsigned char *p, uint32_t n) {
  p[0] = n >> 24;
  p[1] = n >> 16;
  p[2] = n >> 8;
  p[3] = n;
}
static void w64(unsigned char *p, uint64_t n) {
  w32(p, (uint32_t)(n >> 32));
  w32(p + 4, (uint32_t)n);
}
static bool allowed(qihse_user_t *u, const cg_projection_binding *b) {
  if (u && b && b->source_format <= 5 && cg_checksum_valid(&b->source) &&
      qihse_auth_user_is_active(u) &&
      qihse_auth_can_access(u, b->classification, b->sci) &&
      qihse_user_get_tenant_id(u) == b->tenant &&
      qihse_user_get_id(u) == b->principal_id)
    return true;
  errno = EACCES;
  return false;
}
static bool add(buf *b, const void *p, size_t n, size_t max) {
  if (n > max || b->n > max - n) {
    errno = EFBIG;
    return false;
  }
  if (b->n + n > b->cap) {
    size_t cap = b->cap ? b->cap : 4096;
    while (cap < b->n + n)
      cap = cap > max / 2 ? max : cap * 2;
    void *next = realloc(b->p, cap);
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
static bool zeros(buf *b, size_t n) {
  if (!add(b, NULL, 0, MAX_FILE))
    return false;
  unsigned char zero[256] = {0};
  while (n) {
    size_t take = n > sizeof(zero) ? sizeof(zero) : n;
    if (!add(b, zero, take, MAX_FILE))
      return false;
    n -= take;
  }
  return true;
}
static uint64_t shash(const char *p) {
  uint64_t h = UINT64_C(14695981039346656037);
  for (; *p; ++p) {
    h ^= (unsigned char)*p;
    h *= UINT64_C(1099511628211);
  }
  return h ? h : 1;
}
static bool intern(strings *s, const char *p, uint32_t *off) {
  if (!p) {
    errno = EINVAL;
    return false;
  }
  if (!s->cap || s->used * 4 >= s->cap * 3) {
    size_t next = s->cap ? s->cap * 2 : 256;
    if (next > 8388608u) {
      errno = E2BIG;
      return false;
    }
    slot *table = calloc(next, sizeof(*table));
    if (!table)
      return false;
    for (size_t i = 0; i < s->cap; ++i)
      if (s->slots[i].hash) {
        size_t j = s->slots[i].hash & (next - 1);
        while (table[j].hash)
          j = (j + 1) & (next - 1);
        table[j] = s->slots[i];
      }
    free(s->slots);
    s->slots = table;
    s->cap = next;
  }
  uint64_t h = shash(p);
  size_t i = h & (s->cap - 1);
  while (s->slots[i].hash) {
    if (s->slots[i].hash == h &&
        !strcmp((char *)s->bytes.p + s->slots[i].offset, p)) {
      *off = s->slots[i].offset;
      return true;
    }
    i = (i + 1) & (s->cap - 1);
  }
  size_t length = strnlen(p, MAX_STRINGS);
  if (length == MAX_STRINGS) {
    errno = EFBIG;
    return false;
  }
  *off = (uint32_t)s->bytes.n;
  if (!add(&s->bytes, p, length + 1, MAX_STRINGS))
    return false;
  s->slots[i] = (slot){h, *off};
  ++s->used;
  return true;
}
static bool zip(const void *raw, size_t n, buf *out) {
  size_t cap = ZSTD_compressBound(n);
  if (cap > MAX_FILE) {
    errno = EFBIG;
    return false;
  }
  out->p = malloc(cap ? cap : 1);
  if (!out->p)
    return false;
  out->cap = cap;
  static const unsigned char empty = 0;
  out->n = ZSTD_compress(out->p, cap, n ? raw : &empty, n, 3);
  if (ZSTD_isError(out->n)) {
    errno = EINVAL;
    return false;
  }
  return true;
}
static bool unzip(const unsigned char *z, size_t zn, unsigned char *raw,
                  size_t n) {
  ZSTD_frameHeader frame;
  if (!zn || ZSTD_getFrameHeader(&frame, z, zn) != 0 ||
      frame.windowSize > (1u << 23) || ZSTD_getFrameContentSize(z, zn) != n ||
      ZSTD_findFrameCompressedSize(z, zn) != zn) {
    errno = EINVAL;
    return false;
  }
  size_t got = ZSTD_decompress(raw, n, z, zn);
  if (ZSTD_isError(got) || got != n) {
    errno = EINVAL;
    return false;
  }
  return true;
}
static bool valid_path(const char *p) {
  if (!p || *p == '/' || *p == '~' || strchr(p, '\\'))
    return false;
  for (const char *s = p; *s;) {
    const char *e = strchr(s, '/');
    size_t n = e ? (size_t)(e - s) : strlen(s);
    if (!n || (n == 2 && !memcmp(s, "..", 2)) ||
        (n == 4 && !memcmp(s, ".git", 4)))
      return false;
    s = e ? e + 1 : s + n;
  }
  return true;
}
static const char *str_at(const cg_projection *g, uint32_t off) {
  if (off >= g->string_size || (off && g->strings[off - 1]) ||
      !memchr(g->strings + off, 0, g->string_size - off))
    return NULL;
  return g->strings + off;
}
static bool id_pack(const char *text, unsigned char out[32], uint32_t *width) {
  size_t n = strnlen(text, 65);
  if (n != 32 && n != 64)
    return false;
  memset(out, 0, 32);
  *width = (uint32_t)n / 2;
  for (size_t i = 0; i < n; i += 2) {
    unsigned a = (unsigned char)text[i], b = (unsigned char)text[i + 1];
    a = a >= '0' && a <= '9'   ? a - '0'
        : a >= 'a' && a <= 'f' ? a - 'a' + 10
                               : 16;
    b = b >= '0' && b <= '9'   ? b - '0'
        : b >= 'a' && b <= 'f' ? b - 'a' + 10
                               : 16;
    if (a > 15 || b > 15)
      return false;
    out[i / 2] = (unsigned char)(a * 16 + b);
  }
  return true;
}
static void id_unpack(const unsigned char *raw, size_t n, char out[65]) {
  static const char h[] = "0123456789abcdef";
  for (size_t i = 0; i < n; ++i) {
    out[2 * i] = h[raw[i] >> 4];
    out[2 * i + 1] = h[raw[i] & 15];
  }
  out[2 * n] = 0;
}
static bool index_of(const cg_projection_node *nodes, size_t n,
                     const cg_projection_node *p, uint32_t *out) {
  uintptr_t base = (uintptr_t)nodes, at = (uintptr_t)p;
  if (at < base || at - base >= n * sizeof(*nodes) ||
      (at - base) % sizeof(*nodes))
    return false;
  *out = (uint32_t)((at - base) / sizeof(*nodes));
  return true;
}
static int by_name(const cg_projection_node *a, const cg_projection_node *b) {
  int n = strcasecmp(a->name, b->name);
  return n ? n : strcmp(a->id, b->id);
}
static int by_file(const cg_projection_node *a, const cg_projection_node *b) {
  int n = strcmp(a->file, b->file);
  return n ? n : by_name(a, b);
}
static bool write_bytes(FILE *out, const void *p, size_t n) {
  return !n || fwrite(p, 1, n, out) == n;
}

bool cg_projection_write(FILE *output, qihse_user_t *principal,
                         const cg_projection_binding *binding,
                         const cg_csr *graph, const cg_projection_node *nodes,
                         size_t nn, cg_projection_node *const *names,
                         cg_projection_node *const *files, size_t total,
                         size_t unresolved, const char *meta, const char *end,
                         cg_snapshot_checksum *out_checksum) {
  if (!allowed(principal, binding) || !cg_csr_has_principal(graph, principal))
    return false;
  size_t ne = cg_csr_edge_count(graph);
  struct stat output_stat;
  if (!output || fstat(fileno(output), &output_stat) ||
      !S_ISREG(output_stat.st_mode) || output_stat.st_uid != geteuid() ||
      output_stat.st_nlink != 1 || (output_stat.st_mode & 077) ||
      output_stat.st_size != 0) {
    errno = EINVAL;
    return false;
  }
  if (!output || !out_checksum || !graph || (!nodes && nn) || !names ||
      !files || !meta || !end || nn > MAX_NODES || ne > MAX_EDGES ||
      total > MAX_EDGES || unresolved > total || total - unresolved != ne ||
      ftello(output) != 0) {
    errno = EINVAL;
    return false;
  }
  strings st = {0};
  buf node = {0}, topo = {0}, nz = {0}, tz = {0}, sz = {0};
  buf dir = {0}, evidence = {0};
  bool ok = false;
  unsigned char header[HEADER] = {0};
  uint32_t meta_off, end_off;
  unsigned char *seen_name = calloc(nn ? nn : 1, 1),
                *seen_file = calloc(nn ? nn : 1, 1),
                *seen_vertex = calloc(nn + 1, 1);
  if (!seen_name || !seen_file || !seen_vertex ||
      !intern(&st, meta, &meta_off) || !intern(&st, end, &end_off) ||
      !zeros(&node, nn * NODE_WIRE + nn * 8) ||
      !zeros(&topo, 8 * (nn + 2) + 16 * ne))
    goto done;
  for (size_t i = 0; i < nn; ++i) {
    const cg_projection_node *n = nodes + i;
    unsigned char *p = node.p + NODE_WIRE * i;
    uint32_t width, off, ni, fi;
    if (!n->file || strlen(n->file) > 4096 || !valid_path(n->file) ||
        !n->name || strlen(n->name) > 512 || !n->kind || strlen(n->kind) > 64 ||
        n->line < 0 || n->end_line < 0 ||
        (n->is_test != 0 && n->is_test != 1) || !n->vertex || n->vertex > nn ||
        seen_vertex[n->vertex]++ || !id_pack(n->id, p, &width) ||
        (i && strcmp(nodes[i - 1].id, n->id) >= 0) ||
        !intern(&st, n->file, &off)) {
      errno = EINVAL;
      goto done;
    }
    w32(p + 32, off);
    if (!intern(&st, n->name, &off))
      goto done;
    w32(p + 36, off);
    if (!intern(&st, n->kind, &off))
      goto done;
    w32(p + 40, off);
    w32(p + 44, (uint32_t)n->line);
    w32(p + 48, (uint32_t)n->end_line);
    w32(p + 52, (uint32_t)n->is_test);
    w32(p + 56, (uint32_t)n->vertex);
    w32(p + 60, width);
    if (!index_of(nodes, nn, names[i], &ni) ||
        !index_of(nodes, nn, files[i], &fi) || seen_name[ni]++ ||
        seen_file[fi]++ || (i && by_name(names[i - 1], names[i]) >= 0) ||
        (i && by_file(files[i - 1], files[i]) >= 0)) {
      errno = EINVAL;
      goto done;
    }
    w32(node.p + nn * NODE_WIRE + 4 * i, ni);
    w32(node.p + nn * (NODE_WIRE + 4) + 4 * i, fi);
  }
  size_t off_out = 8 * ne, off_in = off_out + 4 * (nn + 2),
         out_edges = off_in + 4 * (nn + 2), in_edges = out_edges + 4 * ne;
  size_t outgoing = 0, incoming = 0;
  for (uint32_t v = 1; v <= nn; ++v) {
    size_t count;
    const uint32_t *edges = cg_csr_incident(graph, v, false, &count);
    if (!edges || outgoing + count > ne)
      goto done;
    w32(topo.p + off_out + v * 4, (uint32_t)outgoing);
    for (size_t i = 0; i < count; ++i)
      w32(topo.p + out_edges + 4 * outgoing++, edges[i]);
    edges = cg_csr_incident(graph, v, true, &count);
    if (!edges || incoming + count > ne)
      goto done;
    w32(topo.p + off_in + v * 4, (uint32_t)incoming);
    for (size_t i = 0; i < count; ++i)
      w32(topo.p + in_edges + 4 * incoming++, edges[i]);
  }
  w32(topo.p + off_out + (nn + 1) * 4, (uint32_t)outgoing);
  w32(topo.p + off_in + (nn + 1) * 4, (uint32_t)incoming);
  if (outgoing != ne || incoming != ne) {
    errno = EINVAL;
    goto done;
  }
  for (size_t start = 0; start < ne; start += BLOCK) {
    size_t count = ne - start > BLOCK ? BLOCK : ne - start;
    unsigned char raw[BLOCK * 24];
    buf ez = {0};
    for (size_t j = 0; j < count; ++j) {
      const cg_csr_edge *edge = cg_csr_get_edge(graph, (uint32_t)(start + j));
      uint32_t type, file;
      uint64_t bits;
      if (!edge || !edge->source || edge->source > nn || !edge->target ||
          edge->target > nn || !edge->type || strlen(edge->type) >= 32 ||
          !valid_path(edge->file) || !isfinite(edge->confidence) ||
          edge->confidence < 0 || edge->confidence > 1 || edge->line < 0 ||
          !intern(&st, edge->type, &type) || !intern(&st, edge->file, &file))
        goto done;
      w32(topo.p + 4 * (start + j), edge->source);
      w32(topo.p + 4 * ne + 4 * (start + j), edge->target);
      w32(raw + j * 4, type);
      w32(raw + count * 4 + j * 4, file);
      memcpy(&bits, &edge->line, 8);
      w64(raw + count * 8 + j * 8, bits);
      memcpy(&bits, &edge->confidence, 8);
      w64(raw + count * 16 + j * 8, bits);
    }
    if (!zip(raw, count * 24, &ez)) {
      free(ez.p);
      goto done;
    }
    unsigned char d[16] = {0};
    w32(d, (uint32_t)count);
    w64(d + 8, ez.n);
    bool added = add(&dir, d, sizeof(d), MAX_FILE) &&
                 add(&evidence, ez.p, ez.n, MAX_FILE);
    free(ez.p);
    if (!added)
      goto done;
  }
  if (!zip(node.p, node.n, &nz) || !zip(topo.p, topo.n, &tz) ||
      !zip(st.bytes.p, st.bytes.n, &sz))
    goto done;
  memcpy(header, CG_PROJECTION_MAGIC, 8);
  w32(header + 12, (uint32_t)nn);
  w32(header + 16, (uint32_t)total);
  w32(header + 20, (uint32_t)ne);
  w32(header + 24, (uint32_t)unresolved);
  w32(header + 28, (uint32_t)st.bytes.n);
  w32(header + 32, meta_off);
  w32(header + 36, end_off);
  w32(header + 40, (uint32_t)binding->classification << 16 | binding->sci);
  w32(header + 44, binding->tenant);
  w32(header + 48, binding->source.algorithm);
  memcpy(header + 52, binding->source.hex, strlen(binding->source.hex) + 1);
  w64(header + 120, node.n);
  w64(header + 128, nz.n);
  w64(header + 136, topo.n);
  w64(header + 144, tz.n);
  w64(header + 152, sz.n);
  w32(header + 160, (uint32_t)((ne + BLOCK - 1) / BLOCK));
  w32(header + 164, BLOCK);
  w64(header + 168, dir.n);
  w32(header + 176, binding->principal_id);
  w32(header + 180, binding->source_format);
  if (!allowed(principal, binding) || !write_bytes(output, header, HEADER) ||
      !write_bytes(output, nz.p, nz.n) || !write_bytes(output, tz.p, tz.n) ||
      !write_bytes(output, sz.p, sz.n) || !write_bytes(output, dir.p, dir.n) ||
      !write_bytes(output, evidence.p, evidence.n) || fflush(output))
    goto done;
  ok = cg_snapshot_checksum_stream_user(output, principal, CG_CHECKSUM_XXH3_128,
                                        out_checksum) &&
       allowed(principal, binding);
done:
  free(seen_name);
  free(seen_file);
  free(seen_vertex);
  free(st.bytes.p);
  free(st.slots);
  free(node.p);
  free(topo.p);
  free(nz.p);
  free(tz.p);
  free(sz.p);
  free(dir.p);
  free(evidence.p);
  return ok;
}

static const cg_csr_edge *fetch(void *opaque, uint32_t id) {
  cg_projection *g = opaque;
  if (atomic_load_explicit(&g->failed, memory_order_acquire) ||
      !allowed(g->principal, &g->binding) ||
      id >= g->view.edge_count - g->view.unresolved)
    return NULL;
  block *b = &g->blocks[id / BLOCK];
  cg_csr_edge *records = atomic_load_explicit(&b->ready, memory_order_acquire);
  if (!records) {
    pthread_mutex_lock(&g->mutex);
    records = atomic_load_explicit(&b->ready, memory_order_acquire);
    if (!records) {
      unsigned char raw[BLOCK * 24];
      records = calloc(b->count, sizeof(*records));
      if (records &&
          unzip(g->encoded + b->offset, b->size, raw, b->count * 24)) {
        bool valid = true;
        for (size_t j = 0; j < b->count; ++j) {
          uint64_t bits;
          size_t edge = (size_t)(id / BLOCK) * BLOCK + j;
          records[j].type = str_at(g, r32(raw + j * 4));
          records[j].file = str_at(g, r32(raw + b->count * 4 + j * 4));
          bits = r64(raw + b->count * 8 + j * 8);
          memcpy(&records[j].line, &bits, 8);
          bits = r64(raw + b->count * 16 + j * 8);
          memcpy(&records[j].confidence, &bits, 8);
          records[j].source = g->sources[edge];
          records[j].target = g->targets[edge];
          if (!records[j].type || strlen(records[j].type) >= 32 ||
              !valid_path(records[j].file) ||
              !isfinite(records[j].confidence) || records[j].confidence < 0 ||
              records[j].confidence > 1 || records[j].line < 0)
            valid = false;
        }
        if (valid) {
          atomic_fetch_add_explicit(&g->evidence_bytes,
                                    b->count * sizeof(*records),
                                    memory_order_relaxed);
          atomic_store_explicit(&b->ready, records, memory_order_release);
        } else {
          free(records);
          records = NULL;
          errno = EINVAL;
        }
      } else {
        free(records);
        records = NULL;
      }
    }
    if (!records)
      atomic_store_explicit(&g->failed, true, memory_order_release);
    pthread_mutex_unlock(&g->mutex);
  }
  return records ? records + id % BLOCK : NULL;
}
static bool unchanged(const struct stat *a, const struct stat *b) {
  return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
         a->st_size == b->st_size && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
         a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
         a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
         a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
cg_projection *cg_projection_open(FILE *input, qihse_user_t *principal,
                                  const cg_projection_binding *binding,
                                  const cg_snapshot_checksum *expected) {
  if (!allowed(principal, binding))
    return NULL;
  struct stat before, after;
  cg_snapshot_checksum actual;
  if (!input || !cg_checksum_valid(expected) || fstat(fileno(input), &before) ||
      !S_ISREG(before.st_mode) || before.st_uid != geteuid() ||
      before.st_nlink != 1 || (before.st_mode & 077) ||
      before.st_size < HEADER || before.st_size > MAX_FILE) {
    errno = EINVAL;
    return NULL;
  }
  cg_projection *g = calloc(1, sizeof(*g));
  unsigned char *nr = NULL, *tr = NULL;
  uint32_t *out = NULL, *in = NULL, *oe = NULL, *ie = NULL;
  if (!g)
    return NULL;
  g->principal = principal;
  g->binding = *binding;
  g->encoded_size = (size_t)before.st_size;
  atomic_init(&g->evidence_bytes, 0);
  atomic_init(&g->failed, false);
  if (pthread_mutex_init(&g->mutex, NULL))
    goto fail;
  g->mutex_ready = true;
  g->encoded = malloc(g->encoded_size);
  if (!g->encoded)
    goto fail;
  for (size_t off = 0; off < g->encoded_size;) {
    ssize_t n = pread(fileno(input), g->encoded + off, g->encoded_size - off,
                      (off_t)off);
    if (n < 0 && errno == EINTR)
      continue;
    if (n <= 0 || !allowed(principal, binding))
      goto fail;
    off += (size_t)n;
  }
  if (fstat(fileno(input), &after) || !unchanged(&before, &after) ||
      !cg_snapshot_checksum_buffer_user(g->encoded, g->encoded_size, principal,
                                        expected->algorithm, &actual) ||
      strcmp(actual.hex, expected->hex)) {
    errno = EINVAL;
    goto fail;
  }
  const unsigned char *h = g->encoded;
  size_t nn = r32(h + 12), total = r32(h + 16), ne = r32(h + 20),
         unresolved = r32(h + 24), string_size = r32(h + 28), nz = r64(h + 128),
         tz = r64(h + 144), sz = r64(h + 152), chunks = r32(h + 160),
         dirsize = r64(h + 168);
  cg_snapshot_checksum source = {.algorithm =
                                     (cg_checksum_algorithm)r32(h + 48)};
  memcpy(source.hex, h + 52, 65);
  if (memcmp(h, CG_PROJECTION_MAGIC, 8) || r32(h + 8) || nn > MAX_NODES ||
      ne > MAX_EDGES || total > MAX_EDGES || unresolved > total ||
      ne != total - unresolved || !string_size || string_size > MAX_STRINGS ||
      !cg_checksum_valid(&source) ||
      source.algorithm != binding->source.algorithm ||
      strcmp(source.hex, binding->source.hex) ||
      r32(h + 40) != ((uint32_t)binding->classification << 16 | binding->sci) ||
      r32(h + 44) != binding->tenant || r32(h + 176) != binding->principal_id ||
      r32(h + 180) != binding->source_format ||
      r64(h + 120) != nn * (NODE_WIRE + 8) ||
      r64(h + 136) != 8 * (nn + 2) + 16 * ne || r32(h + 164) != BLOCK ||
      chunks != (ne + BLOCK - 1) / BLOCK || dirsize != chunks * 16 || !nz ||
      !tz || !sz || nz > g->encoded_size - HEADER ||
      tz > g->encoded_size - HEADER - nz ||
      sz > g->encoded_size - HEADER - nz - tz ||
      dirsize > g->encoded_size - HEADER - nz - tz - sz) {
    errno = EINVAL;
    goto fail;
  }
  for (size_t i = 117; i < 120; ++i)
    if (h[i]) {
      errno = EINVAL;
      goto fail;
    }
  for (size_t i = 184; i < HEADER; ++i)
    if (h[i]) {
      errno = EINVAL;
      goto fail;
    }
  /* Disallow noncanonical trailing data after a shorter source digest. */
  for (size_t i = strlen(source.hex) + 1; i < sizeof(source.hex); ++i)
    if (source.hex[i]) {
      errno = EINVAL;
      goto fail;
    }
  g->view.node_count = nn;
  g->view.edge_count = total;
  g->view.unresolved = unresolved;
  g->string_size = string_size;
  g->block_count = chunks;
  nr = malloc(nn * (NODE_WIRE + 8) + 1);
  tr = malloc(8 * (nn + 2) + 16 * ne);
  g->strings = malloc(string_size);
  g->blocks = calloc(chunks ? chunks : 1, sizeof(*g->blocks));
  g->view.nodes = calloc(nn ? nn : 1, sizeof(*g->view.nodes));
  g->view.by_vertex = calloc(nn + 2, sizeof(*g->view.by_vertex));
  g->view.by_name = calloc(nn + 1, sizeof(*g->view.by_name));
  g->view.by_file = calloc(nn + 1, sizeof(*g->view.by_file));
  if (g->blocks)
    for (size_t i = 0; i < chunks; ++i)
      atomic_init(&g->blocks[i].ready, NULL);
  g->sources = calloc(ne ? ne : 1, sizeof(uint32_t));
  g->targets = calloc(ne ? ne : 1, sizeof(uint32_t));
  out = calloc(nn + 2, 4);
  in = calloc(nn + 2, 4);
  oe = calloc(ne ? ne : 1, 4);
  ie = calloc(ne ? ne : 1, 4);
  if (!nr || !tr || !g->strings || !g->blocks || !g->view.nodes ||
      !g->view.by_vertex || !g->view.by_name || !g->view.by_file ||
      !g->sources || !g->targets || !out || !in || !oe || !ie ||
      !unzip(h + HEADER, nz, nr, nn * (NODE_WIRE + 8)) ||
      !unzip(h + HEADER + nz, tz, tr, 8 * (nn + 2) + 16 * ne) ||
      !unzip(h + HEADER + nz + tz, sz, (unsigned char *)g->strings,
             string_size) ||
      g->strings[string_size - 1])
    goto fail;
  g->view.meta_json = str_at(g, r32(h + 32));
  g->view.end_json = str_at(g, r32(h + 36));
  if (!g->view.meta_json || !g->view.end_json) {
    errno = EINVAL;
    goto fail;
  }
  for (size_t i = 0; i < nn; ++i) {
    const unsigned char *p = nr + NODE_WIRE * i;
    cg_projection_node *n = g->view.nodes + i;
    size_t width = r32(p + 60);
    if (width != 16 && width != 32) {
      errno = EINVAL;
      goto fail;
    }
    for (size_t j = width; j < 32; ++j)
      if (p[j]) {
        errno = EINVAL;
        goto fail;
      }
    id_unpack(p, width, n->id);
    n->file = str_at(g, r32(p + 32));
    n->name = str_at(g, r32(p + 36));
    n->kind = str_at(g, r32(p + 40));
    n->line = (int32_t)r32(p + 44);
    n->end_line = (int32_t)r32(p + 48);
    n->is_test = (int32_t)r32(p + 52);
    n->vertex = r32(p + 56);
    if (!valid_path(n->file) || strlen(n->file) > 4096 || !n->name ||
        strlen(n->name) > 512 || !n->kind || strlen(n->kind) > 64 ||
        n->line < 0 || n->end_line < 0 ||
        (n->is_test != 0 && n->is_test != 1) || !n->vertex || n->vertex > nn ||
        g->view.by_vertex[n->vertex] ||
        (i && strcmp(g->view.nodes[i - 1].id, n->id) >= 0)) {
      errno = EINVAL;
      goto fail;
    }
    g->view.by_vertex[n->vertex] = n;
    uint32_t ni = r32(nr + nn * NODE_WIRE + i * 4),
             fi = r32(nr + nn * (NODE_WIRE + 4) + i * 4);
    if (ni >= nn || fi >= nn) {
      errno = EINVAL;
      goto fail;
    }
    g->view.by_name[i] = g->view.nodes + ni;
    g->view.by_file[i] = g->view.nodes + fi;
  }
  for (size_t i = 1; i < nn; ++i)
    if (by_name(g->view.by_name[i - 1], g->view.by_name[i]) >= 0 ||
        by_file(g->view.by_file[i - 1], g->view.by_file[i]) >= 0) {
      errno = EINVAL;
      goto fail;
    }
  size_t off_out = 8 * ne, off_in = off_out + 4 * (nn + 2),
         out_edges = off_in + 4 * (nn + 2), in_edges = out_edges + 4 * ne;
  for (size_t i = 0; i < ne; ++i) {
    g->sources[i] = r32(tr + 4 * i);
    g->targets[i] = r32(tr + 4 * ne + 4 * i);
    oe[i] = r32(tr + out_edges + 4 * i);
    ie[i] = r32(tr + in_edges + 4 * i);
  }
  for (size_t i = 0; i < nn + 2; ++i) {
    out[i] = r32(tr + off_out + 4 * i);
    in[i] = r32(tr + off_in + 4 * i);
  }
  const unsigned char *directory = h + HEADER + nz + tz + sz;
  size_t start = HEADER + nz + tz + sz + dirsize;
  for (size_t i = 0; i < chunks; ++i) {
    uint32_t count = r32(directory + 16 * i);
    size_t len = r64(directory + 16 * i + 8);
    size_t want = ne - i * BLOCK > BLOCK ? BLOCK : ne - i * BLOCK;
    if (count != want || r32(directory + 16 * i + 4) || !len ||
        len > g->encoded_size - start ||
        ZSTD_getFrameContentSize(h + start, len) != count * 24 ||
        ZSTD_findFrameCompressedSize(h + start, len) != len) {
      errno = EINVAL;
      goto fail;
    }
    g->blocks[i].offset = start;
    g->blocks[i].size = len;
    g->blocks[i].count = count;
    start += len;
  }
  if (start != g->encoded_size || !allowed(principal, binding)) {
    errno = EINVAL;
    goto fail;
  }
  g->view.graph = cg_csr_create_indexed(
      principal, nn, ne, binding->classification, binding->sci, out, in, oe, ie,
      g->sources, g->targets, fetch, g);
  if (!g->view.graph)
    goto fail;
  out = in = oe = ie = NULL;
  /* Startup sections have already been validated and decoded. Retain only the
   * immutable compressed evidence tail needed by future lazy reads, rather than
   * keeping a redundant encoded copy of every node/index/string section. This
   * happens before publication of the handle, so no reader can observe offsets
   * while their backing allocation changes. */
  size_t evidence_prefix = HEADER + nz + tz + sz + dirsize;
  size_t evidence_size = g->encoded_size - evidence_prefix;
  if (evidence_size) {
    memmove(g->encoded, g->encoded + evidence_prefix, evidence_size);
    /* Shrinking is best effort: do not turn memory pressure into a failed
     * cache load, and keep byte accounting truthful if the allocator declines.
     */
    int saved_errno = errno;
    unsigned char *smaller = realloc(g->encoded, evidence_size);
    if (smaller) {
      g->encoded = smaller;
      g->encoded_size = evidence_size;
    } else
      errno = saved_errno;
  } else {
    free(g->encoded);
    g->encoded = NULL;
    g->encoded_size = 0;
  }
  for (size_t i = 0; i < chunks; ++i)
    g->blocks[i].offset -= evidence_prefix;
  if (!allowed(principal, binding))
    goto fail;
  g->base_bytes =
      sizeof(*g) + g->encoded_size + string_size + chunks * sizeof(block) +
      (nn ? nn : 1) * sizeof(cg_projection_node) +
      (3 * nn + 4) * sizeof(cg_projection_node *) +
      2 * (ne ? ne : 1) * sizeof(uint32_t) + cg_csr_bytes(g->view.graph);
  free(nr);
  free(tr);
  return g;
fail:
  free(nr);
  free(tr);
  free(out);
  free(in);
  free(oe);
  free(ie);
  cg_projection_destroy(g);
  return NULL;
}
const cg_projection_view *cg_projection_get(cg_projection *g) {
  return g && !atomic_load_explicit(&g->failed, memory_order_acquire) &&
                 allowed(g->principal, &g->binding)
             ? &g->view
             : NULL;
}
size_t cg_projection_bytes(cg_projection *g) {
  return g && allowed(g->principal, &g->binding)
             ? g->base_bytes + atomic_load_explicit(&g->evidence_bytes,
                                                    memory_order_relaxed)
             : 0;
}
void cg_projection_destroy(cg_projection *g) {
  if (!g)
    return;
  cg_csr_destroy(g->view.graph);
  if (g->blocks)
    for (size_t i = 0; i < g->block_count; ++i)
      free(atomic_load_explicit(&g->blocks[i].ready, memory_order_relaxed));
  free(g->blocks);
  free(g->encoded);
  free(g->strings);
  free(g->sources);
  free(g->targets);
  free(g->view.nodes);
  free(g->view.by_vertex);
  free(g->view.by_name);
  free(g->view.by_file);
  if (g->mutex_ready)
    pthread_mutex_destroy(&g->mutex);
  free(g);
}
