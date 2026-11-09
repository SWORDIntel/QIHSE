#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_audit.h"
#include "qihse_codegraph_projection.h"
#include <assert.h>
#include <errno.h>
#include <ftw.h>
#include <inttypes.h>
#include <limits.h>
#include <math.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <zstd.h>
#define PASSWORD "PersistedCodeGraphFixture1!"
static char fixture_root[PATH_MAX];
static FILE *private_file(void) {
  char path[PATH_MAX];
  assert(snprintf(path, sizeof path, "%s/index-XXXXXX", fixture_root) <
         (int)sizeof path);
  int fd = mkstemp(path);
  assert(fd >= 0);
  FILE *f = fdopen(fd, "w+b");
  assert(f);
  return f;
}
static uint32_t r32(const unsigned char *p) {
  return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 |
         p[3];
}
static uint64_t r64(const unsigned char *p) {
  return (uint64_t)r32(p) << 32 | r32(p + 4);
}
static void w32(unsigned char *p, uint32_t v) {
  p[0] = v >> 24;
  p[1] = v >> 16;
  p[2] = v >> 8;
  p[3] = v;
}
static void w64(unsigned char *p, uint64_t v) {
  w32(p, v >> 32);
  w32(p + 4, (uint32_t)v);
}
static double now(void) {
  struct timespec t;
  assert(!clock_gettime(CLOCK_MONOTONIC, &t));
  return t.tv_sec + t.tv_nsec / 1e9;
}
static int cleanup(const char *p, const struct stat *s, int t, struct FTW *f) {
  (void)s;
  (void)t;
  (void)f;
  return remove(p);
}
static unsigned char *bytes(FILE *f, size_t *n) {
  struct stat st;
  assert(!fstat(fileno(f), &st));
  *n = (size_t)st.st_size;
  unsigned char *b = malloc(*n);
  assert(b);
  assert(pread(fileno(f), b, *n, 0) == (ssize_t)*n);
  return b;
}
static FILE *from_bytes(const unsigned char *b, size_t n) {
  FILE *f = private_file();
  assert(f);
  assert(fwrite(b, 1, n, f) == n);
  assert(!fflush(f));
  return f;
}
static cg_snapshot_checksum checksum(FILE *f, qihse_user_t *u) {
  cg_snapshot_checksum c;
  assert(cg_snapshot_checksum_stream_user(f, u, CG_CHECKSUM_XXH3_128, &c));
  return c;
}
typedef struct {
  cg_projection *projection;
  size_t edges;
  bool ok;
} task;
static void *concurrent(void *opaque) {
  task *t = opaque;
  t->ok = true;
  const cg_projection_view *v = cg_projection_get(t->projection);
  if (!v) {
    t->ok = false;
    return NULL;
  }
  for (unsigned repeat = 0; repeat < 3; repeat++)
    for (uint32_t i = 0; i < t->edges; i++) {
      const cg_csr_edge *e = cg_csr_get_edge(v->graph, i);
      if (!e || e->line != (int64_t)i * 13 || e->confidence != 0.875 ||
          strcmp(e->type, "CALLS")) {
        t->ok = false;
        return NULL;
      }
    }
  return NULL;
}
static int cmp_name(const void *a, const void *b) {
  const cg_projection_node *x = *(cg_projection_node *const *)a,
                           *y = *(cg_projection_node *const *)b;
  int n = strcasecmp(x->name, y->name);
  return n ? n : strcmp(x->id, y->id);
}
static int cmp_file(const void *a, const void *b) {
  const cg_projection_node *x = *(cg_projection_node *const *)a,
                           *y = *(cg_projection_node *const *)b;
  int n = strcmp(x->file, y->file);
  return n ? n : cmp_name(a, b);
}
int main(int argc, char **argv) {
  size_t nn = argc > 1 ? strtoul(argv[1], NULL, 10) : 600, ne = nn * 3;
  assert(nn && nn <= 100000);
  char root[PATH_MAX];
  const char *tmp = getenv("TMPDIR");
  assert(snprintf(root, sizeof root, "%s/qihse-persisted-XXXXXX",
                  tmp && *tmp ? tmp : ".") < (int)sizeof root);
  assert(mkdtemp(root));
  snprintf(fixture_root, sizeof fixture_root, "%s", root);
  assert(!setenv("QIHSE_DATA_DIR", root, 1));
  assert(!setenv("QIHSE_FIPS_MODE", "disabled", 1));
  assert(qihse_auth_init() && qihse_auth_bootstrap_operator(PASSWORD));
  qihse_user_t *op = qihse_auth_authenticate_id(0, PASSWORD);
  assert(op);
  assert(
      qihse_auth_create_user(op, 713, QIHSE_ROLE_GUEST, 0, 0, PASSWORD, false));
  qihse_user_t *low = qihse_auth_authenticate_id(713, PASSWORD);
  assert(low);
  assert(qihse_auth_create_user(op, 714, QIHSE_ROLE_ANALYST, 4, 0, PASSWORD,
                                false));
  qihse_user_t *wrong_sci = qihse_auth_authenticate_id(714, PASSWORD);
  assert(wrong_sci);
  assert(qihse_auth_create_user(op, 715, QIHSE_ROLE_ANALYST, 4, 2, PASSWORD,
                                false));
  qihse_user_t *high = qihse_auth_authenticate_id(715, PASSWORD);
  assert(high);
  cg_projection_binding binding = {.classification = 4,
                                   .sci = 2,
                                   .tenant = 0,
                                   .principal_id = 715,
                                   .source_format = 3};
  assert(cg_snapshot_checksum_buffer_user(
      "authoritative-fixture", 21, op, CG_CHECKSUM_XXH3_128, &binding.source));
  cg_projection_node *nodes = calloc(nn, sizeof *nodes);
  cg_projection_node **names = calloc(nn, sizeof *names),
                     **files = calloc(nn, sizeof *files);
  assert(nodes && names && files);
  double build_started = now();
  cg_csr *graph = cg_csr_create(high, nn, ne);
  assert(graph);
  for (size_t i = 0; i < nn; i++) {
    char name[128], file[128];
    snprintf(nodes[i].id, sizeof nodes[i].id, "%032zx", i + 1);
    snprintf(name, sizeof name, "fixture_function_%06zu", nn - i);
    snprintf(file, sizeof file, "src/fixture_%03zu.c", i % 53);
    nodes[i].name = cg_csr_intern(graph, name);
    nodes[i].file = cg_csr_intern(graph, file);
    nodes[i].kind = cg_csr_intern(graph, "Function");
    nodes[i].vertex = i + 1;
    nodes[i].line = i;
    nodes[i].end_line = i + 5;
    nodes[i].is_test = i % 7 == 0;
    names[i] = files[i] = nodes + i;
  }
  for (size_t i = 0; i < ne; i++)
    assert(cg_csr_add_edge(graph, (uint32_t)(i % nn + 1),
                           (uint32_t)((i * 7 + 11) % nn + 1), "CALLS",
                           "src/evidence.c", (int64_t)i * 13, 0.875));
  assert(cg_csr_finish(graph));
  qsort(names, nn, sizeof *names, cmp_name);
  qsort(files, nn, sizeof *files, cmp_file);
  double build_seconds = now() - build_started;
  char trailer[128];
  assert(snprintf(trailer, sizeof trailer, "{\"nodes\":%zu,\"edges\":%zu}", nn,
                  ne + 5) < (int)sizeof trailer);
  FILE *output = private_file();
  assert(output);
  cg_snapshot_checksum digest;
  double write_started = now();
  assert(cg_projection_write(
      output, high, &binding, graph, nodes, nn, names, files, ne + 5, 5,
      "{\"format\":\"qihse-codegraph-v1\",\"protected\":\"CLASSIFIED-NODE\"}",
      trailer, &digest));
  double write_seconds = now() - write_started;
  size_t size;
  unsigned char *encoded = bytes(output, &size);
  errno = 0;
  assert(!cg_projection_open(output, NULL, &binding, &digest) &&
         errno == EACCES);
  errno = 0;
  assert(!cg_projection_open(output, low, &binding, &digest) &&
         errno == EACCES);
  errno = 0;
  assert(!cg_projection_open(output, wrong_sci, &binding, &digest) &&
         errno == EACCES);
  assert(qihse_auth_create_user(op, 716, QIHSE_ROLE_ANALYST, 4, 2, PASSWORD,
                                false));
  qihse_user_t *peer = qihse_auth_authenticate_id(716, PASSWORD);
  assert(peer);
  assert(!cg_projection_open(output, peer, &binding, &digest));
  cg_projection_binding downgrade = binding;
  downgrade.classification = downgrade.sci = 0;
  assert(!cg_projection_open(output, low, &downgrade, &digest));
  cg_projection_binding illicit_export = binding;
  illicit_export.principal_id = 713;
  illicit_export.classification = illicit_export.sci = 0;
  FILE *denied_output = private_file();
  cg_snapshot_checksum denied_digest;
  assert(!cg_projection_write(denied_output, low, &illicit_export, graph, nodes,
                              nn, names, files, ne + 5, 5, "{}", "{}",
                              &denied_digest));
  struct stat denied_stat;
  assert(!fstat(fileno(denied_output), &denied_stat) && !denied_stat.st_size);
  fclose(denied_output);
  cg_projection_binding wrong_source = binding;
  wrong_source.source.hex[0] = wrong_source.source.hex[0] == '0' ? '1' : '0';
  assert(!cg_projection_open(output, high, &wrong_source, &digest));
  cg_projection_binding wrong_format = binding;
  wrong_format.source_format = 4;
  assert(!cg_projection_open(output, high, &wrong_format, &digest));
  cg_projection_binding wrong_tenant = binding;
  wrong_tenant.tenant = 5;
  assert(!cg_projection_open(output, high, &wrong_tenant, &digest));
  cg_snapshot_checksum wrong = digest;
  wrong.hex[0] = wrong.hex[0] == '0' ? '1' : '0';
  assert(!cg_projection_open(output, high, &binding, &wrong));
  double load_started = now();
  cg_projection *loaded = cg_projection_open(output, high, &binding, &digest);
  assert(loaded);
  double load_seconds = now() - load_started;
  const cg_projection_view *v = cg_projection_get(loaded);
  assert(v && v->node_count == nn && v->edge_count == ne + 5 &&
         v->unresolved == 5);
  size_t initial_bytes = cg_projection_bytes(loaded);
  rewind(output);
  assert(fgetc(output) != EOF);
  assert(ungetc('X', output) == 'X');
  cg_projection *stdio_cached =
      cg_projection_open(output, high, &binding, &digest);
  assert(stdio_cached);
  cg_projection_destroy(stdio_cached);
  assert(strstr(v->meta_json, "CLASSIFIED-NODE"));
  for (size_t i = 0; i < nn; i++) {
    assert(!strcmp(v->nodes[i].id, nodes[i].id));
    assert(!strcmp(v->nodes[i].name, nodes[i].name));
    assert(!strcmp(v->nodes[i].file, nodes[i].file));
    assert(v->by_name[i] - v->nodes == names[i] - nodes);
    assert(v->by_file[i] - v->nodes == files[i] - nodes);
    assert(v->by_vertex[i + 1] == v->nodes + i);
  }
  // Concurrent first hit materializes each block once and returns stable
  // records.
  pthread_t threads[4];
  task tasks[4];
  double query_started = now();
  for (size_t i = 0; i < 4; i++) {
    tasks[i] = (task){loaded, ne, false};
    assert(!pthread_create(threads + i, NULL, concurrent, tasks + i));
  }
  for (size_t i = 0; i < 4; i++) {
    assert(!pthread_join(threads[i], NULL));
    assert(tasks[i].ok);
  }
  double query_seconds = now() - query_started;
  assert(cg_projection_bytes(loaded) ==
         initial_bytes + ne * sizeof(cg_csr_edge));
  const cg_csr_edge *stable = cg_csr_get_edge(v->graph, 0);
  assert(stable);
  assert(cg_csr_get_edge(v->graph, (uint32_t)(ne - 1)));
  assert(stable == cg_csr_get_edge(v->graph, 0));
  for (uint32_t i = 1; i <= nn; i++) {
    for (unsigned d = 0; d < 2; d++) {
      size_t a, b;
      const uint32_t *x = cg_csr_incident(graph, i, d, &a),
                     *y = cg_csr_incident(v->graph, i, d, &b);
      assert(x && y && a == b && !memcmp(x, y, a * 4));
    }
  }
  // Every header byte mutation is denied with its original trusted digest.
  for (size_t i = 0; i < 256; i++) {
    unsigned char save = encoded[i];
    encoded[i] ^= 0x80;
    FILE *bad = from_bytes(encoded, size);
    assert(!cg_projection_open(bad, high, &binding, &digest));
    fclose(bad);
    encoded[i] = save;
  }
  // Malformed but caller-rehashed headers must still fail structural
  // validation.
  const size_t offsets[] = {8,   12,  16,  20,  24,  28,  32,  36,  40,  44, 48,
                            120, 128, 136, 144, 152, 160, 164, 168, 176, 180};
  for (size_t i = 0; i < sizeof offsets / sizeof offsets[0]; i++) {
    size_t at = offsets[i];
    unsigned char save = encoded[at];
    encoded[at] ^= 0x80;
    FILE *bad = from_bytes(encoded, size);
    cg_snapshot_checksum hash = checksum(bad, op);
    assert(!cg_projection_open(bad, high, &binding, &hash));
    fclose(bad);
    encoded[at] = save;
  }
  for (size_t n = 0; n < size; n = n ? n * 2 : 1) {
    FILE *bad = from_bytes(encoded, n);
    cg_snapshot_checksum hash = checksum(bad, op);
    assert(!cg_projection_open(bad, high, &binding, &hash));
    fclose(bad);
  }
  // Recompressed invalid topology must fail even with a matching cache digest.
  size_t nz = r64(encoded + 128), tz = r64(encoded + 144),
         raw_topo = r64(encoded + 136);
  unsigned char *topo = malloc(raw_topo),
                *zip = malloc(ZSTD_compressBound(raw_topo));
  assert(topo && zip);
  assert(ZSTD_decompress(topo, raw_topo, encoded + 256 + nz, tz) == raw_topo);
  w32(topo + 8 * ne + 4, 1);
  size_t zlen =
      ZSTD_compress(zip, ZSTD_compressBound(raw_topo), topo, raw_topo, 3);
  assert(!ZSTD_isError(zlen));
  FILE *bad = private_file();
  assert(bad);
  unsigned char h[256];
  memcpy(h, encoded, 256);
  w64(h + 144, zlen);
  assert(fwrite(h, 1, 256, bad) == 256);
  assert(fwrite(encoded + 256, 1, nz, bad) == nz);
  assert(fwrite(zip, 1, zlen, bad) == zlen);
  size_t tail = size - 256 - nz - tz;
  assert(fwrite(encoded + 256 + nz + tz, 1, tail, bad) == tail);
  assert(!fflush(bad));
  cg_snapshot_checksum hash = checksum(bad, op);
  assert(!cg_projection_open(bad, high, &binding, &hash));
  fclose(bad);
  free(topo);
  free(zip);
  // Recompressed out-of-domain lazy evidence is denied and latches invalidity.
  size_t string_zip = r64(encoded + 152),
         directory_offset = 256 + nz + tz + string_zip;
  size_t block_count = r32(encoded + 160),
         first_offset = directory_offset + block_count * 16;
  size_t first_zip = r64(encoded + directory_offset + 8),
         first_count = r32(encoded + directory_offset);
  unsigned char *raw_evidence = malloc(first_count * 24),
                *new_zip = malloc(ZSTD_compressBound(first_count * 24));
  assert(raw_evidence && new_zip);
  assert(ZSTD_decompress(raw_evidence, first_count * 24, encoded + first_offset,
                         first_zip) == first_count * 24);
  w64(raw_evidence + first_count * 8, UINT64_MAX); // negative line
  size_t new_size = ZSTD_compress(new_zip, ZSTD_compressBound(first_count * 24),
                                  raw_evidence, first_count * 24, 3);
  assert(!ZSTD_isError(new_size));
  unsigned char *prefix = malloc(first_offset);
  assert(prefix);
  memcpy(prefix, encoded, first_offset);
  w64(prefix + directory_offset + 8, new_size);
  bad = private_file();
  assert(fwrite(prefix, 1, first_offset, bad) == first_offset);
  assert(fwrite(new_zip, 1, new_size, bad) == new_size);
  tail = size - first_offset - first_zip;
  assert(fwrite(encoded + first_offset + first_zip, 1, tail, bad) == tail);
  assert(!fflush(bad));
  hash = checksum(bad, op);
  cg_projection *lazy_bad = cg_projection_open(bad, high, &binding, &hash);
  assert(lazy_bad);
  const cg_projection_view *bad_view = cg_projection_get(lazy_bad);
  assert(bad_view);
  assert(!cg_csr_get_edge(bad_view->graph, 0));
  assert(!cg_projection_get(lazy_bad));
  cg_projection_destroy(lazy_bad);
  fclose(bad);
  free(raw_evidence);
  free(new_zip);
  free(prefix);
  // SCI revocation is independent of principal identity and classification.
  assert(qihse_auth_modify_user(op, 715, NULL, NULL, -1, -1, 4, 0));
  assert(!cg_projection_open(output, high, &binding, &digest));
  assert(!cg_projection_get(loaded));
  size_t denied_count = 99;
  assert(!cg_csr_incident(v->graph, 1, false, &denied_count) && !denied_count);
  assert(qihse_auth_modify_user(op, 715, NULL, NULL, -1, -1, 4, 2));
  assert(cg_projection_get(loaded));
  // Once loaded, later writes/truncation of the source descriptor cannot change
  // evidence.
  assert(!ftruncate(fileno(output), 0));
  assert(stable == cg_csr_get_edge(v->graph, 0));
  assert(stable->line == 0);
  // Empty graphs exercise zero-length node/evidence sections without NULL UB.
  cg_csr *empty_graph = cg_csr_create(high, 0, 0);
  assert(empty_graph && cg_csr_finish(empty_graph));
  FILE *empty_file = private_file();
  cg_projection_node *no_nodes = NULL;
  cg_snapshot_checksum empty_digest;
  assert(cg_projection_write(empty_file, high, &binding, empty_graph, NULL, 0,
                             &no_nodes, &no_nodes, 0, 0, "{}", "{}",
                             &empty_digest));
  cg_projection *empty_projection =
      cg_projection_open(empty_file, high, &binding, &empty_digest);
  assert(empty_projection &&
         cg_projection_get(empty_projection)->node_count == 0);
  cg_projection_destroy(empty_projection);
  cg_csr_destroy(empty_graph);
  fclose(empty_file);
  // Revocation and clearance downgrade close both new and retained read
  // handles.
  assert(qihse_auth_modify_user(op, 715, NULL, NULL, -1, -1, 0, 2));
  assert(!cg_projection_get(loaded));
  assert(!cg_csr_get_edge(v->graph, 0));
  size_t count = 99;
  assert(!cg_csr_incident(v->graph, 1, false, &count) && count == 0);
  assert(cg_projection_bytes(loaded) == 0);
  printf(
      "{\"nodes\":%zu,\"traversable_edges\":%zu,\"sidecar_bytes\":%zu,"
      "\"resident_before_evidence\":%zu,\"resident_after_evidence\":%zu,"
      "\"baseline_csr_bytes\":%zu,\"csr_build_seconds\":%.9f,\"sidecar_write_"
      "seconds\":%.9f,\"sidecar_load_seconds\":%.9f,\"concurrent_reads_"
      "seconds\":%.9f,\"checks\":\"parity,low-clearance,SCI,NULL,source-"
      "binding,tenant,digest,malformed,concurrent-first-hit,downgrade\"}\n",
      nn, ne, size, initial_bytes, initial_bytes + ne * sizeof(cg_csr_edge),
      cg_csr_bytes(graph), build_seconds, write_seconds, load_seconds,
      query_seconds);
  cg_projection_destroy(loaded);
  cg_csr_destroy(graph);
  fclose(output);
  free(encoded);
  free(nodes);
  free(names);
  free(files);
  qihse_audit_shutdown();
  assert(!nftw(root, cleanup, 16, FTW_DEPTH | FTW_PHYS));
  return 0;
}
