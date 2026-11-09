/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_audit.h"
#include "qihse_codegraph_generation.h"
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <zstd.h>

#define PASSWORD "CodegraphGenerationsStream1!"
#define LIMIT (UINT64_C(256) << 20)
static int clean_test(const char *p, const struct stat *s, int type,
                      struct FTW *w) {
  (void)s;
  (void)type;
  (void)w;
  return remove(p);
}
static uint64_t size(FILE *f) {
  assert(!fflush(f));
  struct stat s;
  assert(!fstat(fileno(f), &s));
  return (uint64_t)s.st_size;
}
static void equal(FILE *a, FILE *b) {
  assert(size(a) == size(b));
  rewind(a);
  rewind(b);
  for (;;) {
    unsigned char x[8192], y[8192];
    size_t n = fread(x, 1, sizeof(x), a);
    assert(fread(y, 1, sizeof(y), b) == n);
    assert(!memcmp(x, y, n));
    if (!n)
      break;
  }
  rewind(a);
  rewind(b);
}
static void row(FILE *out, const char *key, const char *value,
                unsigned classification, unsigned sci, uint64_t sequence,
                bool extended) {
  fprintf(out, "%zu\t%zu 0 %u %u 0 %" PRIu64 "%s\n", strlen(key), strlen(value),
          classification, sci, sequence, extended ? " extension-future" : "");
  assert(fwrite(key, 1, strlen(key), out) == strlen(key));
  assert(fwrite(value, 1, strlen(value), out) == strlen(value));
  fputc('\n', out);
}
static FILE *fixture(unsigned files, unsigned per_file, uint64_t sequence,
                     int edit, int omit, int rename, unsigned classification,
                     unsigned sci) {
  FILE *f = tmpfile();
  assert(f);
  row(f, "_meta", "{\"format\":\"future-metadata\",\"unknown\":true}",
      classification, sci, sequence++, true);
  for (unsigned file = 0; file < files; file++) {
    if ((int)file == omit)
      continue;
    for (unsigned node = 0; node < per_file; node++) {
      char key[64], value[512];
      snprintf(key, sizeof(key), "n:%016x%016x", file, node);
      snprintf(
          value, sizeof(value),
          "{\"id\":\"%016x%016x\",\"file\":\"%s%03u.c\",\"name\":\"function_%"
          "03u_%04u\",\"future\":{\"verbatim\":\"%s\"},\"confidence\":0.70000}",
          file, node, (int)file == rename ? "renamed" : "source", file, file,
          node, (int)file == edit ? "changed" : "same");
      row(f, key, value, classification, sci, sequence++, false);
    }
  }
  row(f, "_end", "{\"all-unknown-fields\":\"retained\"}", classification, sci,
      sequence++, false);
  assert(!fflush(f));
  rewind(f);
  return f;
}
static cg_snapshot_checksum checksum(FILE *f, qihse_user_t *u) {
  cg_snapshot_checksum h;
  uint64_t n = size(f);
  unsigned char *bytes = malloc(n ? n : 1);
  assert(bytes);
  assert(pread(fileno(f), bytes, (size_t)n, 0) == (ssize_t)n);
  assert(cg_snapshot_checksum_buffer_user(bytes, (size_t)n, u,
                                          CG_CHECKSUM_XXH3_128, &h));
  free(bytes);
  return h;
}
static FILE *encode(FILE *raw, const char *dir, qihse_user_t *u,
                    cg_generation_info *i) {
  FILE *f = tmpfile();
  assert(f);
  rewind(raw);
  if (!cg_generation_encode_snapshot(raw, f, dir, u, LIMIT, 100000, i)) {
    perror("generation encode");
    abort();
  }
  rewind(f);
  return f;
}
static void decode_equal(FILE *parent, FILE *raw, const char *dir,
                         qihse_user_t *u) {
  FILE *out = tmpfile();
  assert(out);
  cg_snapshot_checksum h = checksum(parent, u);
  cg_generation_info i;
  if (!cg_generation_decode_snapshot(parent, out, dir, u, &h, LIMIT, 100000,
                                     &i)) {
    perror("generation decode");
    abort();
  }
  equal(out, raw);
  fclose(out);
}
static size_t block_count(const char *dir, uint64_t *bytes) {
  DIR *d = opendir(dir);
  assert(d);
  size_t n = 0;
  uint64_t total = 0;
  struct dirent *e;
  while ((e = readdir(d))) {
    if (strlen(e->d_name) == 36 && !strcmp(e->d_name + 32, ".qgb")) {
      struct stat s;
      assert(!fstatat(dirfd(d), e->d_name, &s, AT_SYMLINK_NOFOLLOW));
      if (S_ISREG(s.st_mode)) {
        n++;
        total += (uint64_t)s.st_size;
      }
    }
  }
  closedir(d);
  if (bytes)
    *bytes = total;
  return n;
}
static FILE *copy(FILE *f) {
  FILE *out = tmpfile();
  assert(out);
  rewind(f);
  unsigned char buffer[8192];
  size_t n;
  while ((n = fread(buffer, 1, sizeof(buffer), f)))
    assert(fwrite(buffer, 1, n, out) == n);
  assert(!ferror(f) && !fflush(out));
  rewind(out);
  rewind(f);
  return out;
}
static void deny(FILE *parent, const char *dir, qihse_user_t *u,
                 const cg_snapshot_checksum *h) {
  FILE *out = tmpfile();
  assert(out);
  assert(!cg_generation_decode_snapshot(parent, out, dir, u, h, LIMIT, 100000,
                                        NULL));
  assert(size(out) == 0);
  fclose(out);
}
static void byte(FILE *f, off_t off, unsigned char ch) {
  assert(pwrite(fileno(f), &ch, 1, off) == 1);
  assert(!fflush(f));
  rewind(f);
}
static uint32_t read32(const unsigned char *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}
static uint64_t read64(const unsigned char *p) {
  uint64_t n = 0;
  for (unsigned i = 0; i < 8; i++)
    n = (n << 8) | p[i];
  return n;
}
static void write64(unsigned char *p, uint64_t n) {
  for (unsigned i = 0; i < 8; i++)
    p[7 - i] = (unsigned char)(n >> (8 * i));
}
static FILE *rewrite_parent(FILE *input, int change) {
  unsigned char head[64];
  assert(pread(fileno(input), head, sizeof(head), 0) == sizeof(head));
  size_t rn = (size_t)read64(head + 24), zn = (size_t)read64(head + 32);
  unsigned char *raw = malloc(rn ? rn : 1), *zip = malloc(zn ? zn : 1);
  assert(raw && zip);
  assert(pread(fileno(input), zip, zn, 64) == (ssize_t)zn);
  assert(ZSTD_decompress(raw, rn, zip, zn) == rn);
  free(zip);
  size_t at = (size_t)read32(head + 20) * 52;
  uint32_t nr = read32(head + 16);
  if (change == 1) {
    head[40] = head[41] = head[42] = head[43] = 0;
    for (uint32_t i = 0; i < nr; i++) {
      assert(rn - at >= 10);
      size_t hn = ((size_t)raw[at + 8] << 8) | raw[at + 9];
      at += 10;
      unsigned char *match = memmem(raw + at, hn, " 4 2 ", 5);
      assert(match);
      match[1] = '0';
      match[3] = '0';
      at += hn;
    }
  } else if (change == 2) {
    assert(nr > 1);
    size_t next = at + 10 + (((size_t)raw[at + 8] << 8) | raw[at + 9]);
    assert(rn - next >= 10);
    memcpy(raw + next, raw + at, 8);
  } else if (change == 3) {
    head[16] = 0x7f;
  } else if (change == 4) {
    write64(head + 8, LIMIT + 1);
  } else
    assert(!"unknown mutation");
  size_t cap = ZSTD_compressBound(rn);
  zip = malloc(cap);
  assert(zip);
  ZSTD_CCtx *c = ZSTD_createCCtx();
  assert(c);
  assert(!ZSTD_isError(ZSTD_CCtx_setParameter(c, ZSTD_c_compressionLevel, 9)));
  assert(!ZSTD_isError(ZSTD_CCtx_setParameter(c, ZSTD_c_checksumFlag, 1)));
  assert(!ZSTD_isError(ZSTD_CCtx_setParameter(c, ZSTD_c_windowLog, 23)));
  zn = ZSTD_compress2(c, zip, cap, raw, rn);
  assert(!ZSTD_isError(zn));
  ZSTD_freeCCtx(c);
  write64(head + 32, zn);
  FILE *out = tmpfile();
  assert(out);
  assert(fwrite(head, 1, sizeof(head), out) == sizeof(head) &&
         fwrite(zip, 1, zn, out) == zn && !fflush(out));
  free(raw);
  free(zip);
  rewind(out);
  return out;
}
static void first_block(FILE *parent, char name[37]) {
  unsigned char head[64];
  assert(pread(fileno(parent), head, sizeof(head), 0) == sizeof(head));
  size_t rn = (size_t)read64(head + 24), zn = (size_t)read64(head + 32);
  unsigned char *raw = malloc(rn), *zip = malloc(zn);
  assert(raw && zip);
  assert(pread(fileno(parent), zip, zn, 64) == (ssize_t)zn);
  assert(ZSTD_decompress(raw, rn, zip, zn) == rn);
  memcpy(name, raw, 32);
  memcpy(name + 32, ".qgb", 5);
  free(raw);
  free(zip);
}
static void block_adversarial(FILE *parent, FILE *raw, const char *dir,
                              qihse_user_t *op) {
  char name[37], path[512], saved[512];
  first_block(parent, name);
  snprintf(path, sizeof(path), "%s/%s", dir, name);
  snprintf(saved, sizeof(saved), "%s/saved-block", dir);
  FILE *f = fopen(path, "r+b");
  assert(f);
  size_t n = (size_t)size(f);
  unsigned char *bytes = malloc(n);
  assert(bytes);
  assert(pread(fileno(f), bytes, n, 0) == (ssize_t)n);
  unsigned char changed = bytes[n - 1] ^ 1;
  assert(pwrite(fileno(f), &changed, 1, (off_t)n - 1) == 1);
  cg_snapshot_checksum h = checksum(parent, op);
  deny(parent, dir, op, &h);
  FILE *out = tmpfile();
  assert(out);
  rewind(raw);
  assert(
      !cg_generation_encode_snapshot(raw, out, dir, op, LIMIT, 100000, NULL) &&
      errno == EEXIST && size(out) == 0);
  fclose(out);
  assert(pwrite(fileno(f), bytes, n, 0) == (ssize_t)n);
  free(bytes);
  fclose(f);
  decode_equal(parent, raw, dir, op);
  assert(!rename(path, saved) && !symlink("saved-block", path));
  deny(parent, dir, op, &h);
  assert(!unlink(path) && !rename(saved, path));
  assert(!chmod(path, 0640));
  deny(parent, dir, op, &h);
  assert(!chmod(path, 0600));
  decode_equal(parent, raw, dir, op);
}
#ifdef CG_GENERATION_TEST_FAULTS
static void rename_crash(const char *dir, qihse_user_t *op,
                         const cg_generation_root *roots) {
  size_t before = block_count(dir, NULL);
  pid_t pid = fork();
  assert(pid >= 0);
  if (!pid) {
    alarm(20);
    assert(!setenv("CG_GENERATION_TEST_AFTER_RENAME", "1", 1));
    FILE *raw = fixture(12, 48, 50000, 10, 5, 8, 0, 0);
    FILE *out = tmpfile();
    assert(out);
    cg_generation_encode_snapshot(raw, out, dir, op, LIMIT, 100000, NULL);
    _exit(87);
  }
  int status;
  assert(waitpid(pid, &status, 0) == pid && WIFEXITED(status) &&
         WEXITSTATUS(status) == 86);
  assert(block_count(dir, NULL) == before + 1);
  DIR *d = opendir(dir);
  assert(d);
  struct dirent *e;
  while ((e = readdir(d))) {
    if (strlen(e->d_name) == 36 && !strcmp(e->d_name + 32, ".qgb")) {
      struct stat st;
      assert(!fstatat(dirfd(d), e->d_name, &st, AT_SYMLINK_NOFOLLOW) &&
             st.st_nlink == 1);
    }
  }
  closedir(d);
  FILE *raw = fixture(12, 48, 50000, 10, 5, 8, 0, 0);
  cg_generation_info i;
  FILE *parent = encode(raw, dir, op, &i);
  decode_equal(parent, raw, dir, op);
  size_t removed;
  uint64_t bytes;
  assert(cg_generation_gc(dir, op, roots, 2, &removed, &bytes) && removed >= 1);
  fclose(raw);
  fclose(parent);
}
#endif

static void pending_residue(const char *dir, qihse_user_t *op,
                            qihse_user_t *low,
                            const cg_generation_root *roots) {
  char path[512];
  snprintf(path, sizeof(path), "%s/.pending-%ld-0123456789abcdef", dir,
           (long)getpid());
  FILE *partial = fopen(path, "wb");
  assert(partial && !fchmod(fileno(partial), 0600));
  assert(fwrite("unfinished", 1, 10, partial) == 10 && !fclose(partial));
  cg_generation_account account;
  assert(cg_generation_account_user(dir, op, roots, 2, &account) &&
         account.coverage_complete && account.orphan_blocks == 1 &&
         account.orphan_bytes == 10);
  assert(cg_generation_account_user(dir, low, roots, 2, &account) &&
         !account.coverage_complete && !account.orphan_blocks &&
         !account.orphan_bytes);
  size_t removed = 0;
  uint64_t bytes = 0;
  assert(!cg_generation_gc(dir, low, roots, 2, &removed, &bytes) &&
         !access(path, F_OK));
  assert(cg_generation_gc(dir, op, roots, 2, &removed, &bytes) &&
         removed == 1 && bytes == 10 && access(path, F_OK));
  snprintf(path, sizeof(path), "%s/unmanaged.bin", dir);
  FILE *unknown = fopen(path, "wb");
  assert(unknown && !fchmod(fileno(unknown), 0600));
  assert(fwrite("sentinel", 1, 8, unknown) == 8 && !fclose(unknown));
  assert(cg_generation_account_user(dir, op, roots, 2, &account) &&
         !account.coverage_complete && !account.orphan_blocks);
  assert(cg_generation_gc(dir, op, roots, 2, &removed, &bytes) && !removed &&
         !access(path, F_OK));
  assert(!unlink(path));
}
static void larger_than_64m(const char *base, qihse_user_t *op) {
  char dir[512];
  snprintf(dir, sizeof(dir), "%s/large-blocks", base);
  FILE *raw = tmpfile();
  assert(raw);
  char *value = malloc(65537);
  assert(value);
  const char prefix[] = "{\"file\":\"large.c\",\"opaque\":\"";
  memcpy(value, prefix, sizeof(prefix) - 1);
  memset(value + sizeof(prefix) - 1, 'x', 65534 - (sizeof(prefix) - 1));
  value[65534] = '"';
  value[65535] = '}';
  value[65536] = 0;
  for (unsigned i = 0; i < 1100; i++) {
    char key[64];
    snprintf(key, sizeof(key), "large:%08u", i);
    row(raw, key, value, 0, 0, i + 1, false);
  }
  free(value);
  assert(!fflush(raw));
  rewind(raw);
  cg_generation_info info;
  FILE *parent = encode(raw, dir, op, &info);
  assert(info.raw_bytes > (UINT64_C(64) << 20) && info.blocks > 1);
  decode_equal(parent, raw, dir, op);
  printf("large generation: %" PRIu64 " raw bytes, %u bounded file blocks\n",
         info.raw_bytes, info.blocks);
  fclose(raw);
  fclose(parent);
}

int main(void) {
  char root[] = "./qihse-codegraph-generation-test-XXXXXX";
  assert(mkdtemp(root));
  char state[256], dir[256];
  snprintf(state, sizeof(state), "%s/state", root);
  snprintf(dir, sizeof(dir), "%s/blocks", root);
  assert(!mkdir(state, 0700));
  assert(!setenv("QIHSE_DATA_DIR", state, 1) &&
         !setenv("QIHSE_FIPS_MODE", "disabled", 1));
  assert(qihse_auth_init() && qihse_auth_bootstrap_operator(PASSWORD));
  qihse_user_t *op = qihse_auth_authenticate_id(0, PASSWORD);
  assert(op);
  assert(
      qihse_auth_create_user(op, 631, QIHSE_ROLE_GUEST, 0, 0, PASSWORD, false));
  assert(qihse_auth_create_user(op, 632, QIHSE_ROLE_ANALYST, 4, 0, PASSWORD,
                                false));
  assert(qihse_auth_create_tenant_user(op, 77, 633, QIHSE_ROLE_ANALYST, 4, 2,
                                       PASSWORD, false));
  qihse_user_t *low = qihse_auth_authenticate_id(631, PASSWORD),
               *wrong_sci = qihse_auth_authenticate_id(632, PASSWORD),
               *tenant = qihse_auth_authenticate_id(633, PASSWORD);
  assert(low && wrong_sci && tenant);
  FILE *empty = tmpfile();
  assert(empty);
  cg_generation_info empty_info;
  FILE *empty_parent = encode(empty, dir, op, &empty_info);
  assert(!empty_info.records && !empty_info.blocks);
  decode_equal(empty_parent, empty, dir, op);
  fclose(empty_parent);
  fclose(empty);
  FILE *tombstone = tmpfile();
  assert(tombstone);
  assert(fprintf(tombstone,
                 "4 0 123456 0 0 1 %" PRIu64 " future-extension\ngone\n",
                 UINT64_MAX) > 0 &&
         !fflush(tombstone));
  rewind(tombstone);
  FILE *tombstone_parent = encode(tombstone, dir, op, &empty_info);
  decode_equal(tombstone_parent, tombstone, dir, op);
  fclose(tombstone_parent);
  fclose(tombstone);
  size_t initial_removed;
  uint64_t initial_bytes;
  assert(cg_generation_gc(dir, op, NULL, 0, &initial_removed, &initial_bytes) &&
         initial_removed == 1);
  FILE *offset = fixture(1, 1, 1, -1, -1, -1, 0, 0), *offset_out = tmpfile();
  assert(offset_out && fgetc(offset) != EOF);
  assert(!cg_generation_encode_snapshot(offset, offset_out, dir, op, LIMIT,
                                        100000, NULL) &&
         errno == EINVAL && !size(offset_out));
  fclose(offset);
  fclose(offset_out);
  cg_generation_info first, second, third, removed_info;
  FILE *r1 = fixture(12, 48, 1, -1, -1, -1, 0, 0),
       *p1 = encode(r1, dir, op, &first);
  assert(first.blocks == 13 && first.new_blocks == 13 && !first.reused_blocks);
  decode_equal(p1, r1, dir, op);
  FILE *r2 = fixture(12, 48, 10000, -1, -1, -1, 0, 0),
       *p2 = encode(r2, dir, op, &second);
  assert(second.blocks == first.blocks &&
         second.reused_blocks == first.blocks && !second.new_blocks);
  decode_equal(p2, r2, dir, op);
  FILE *r3 = fixture(12, 48, 20000, 3, -1, -1, 0, 0),
       *p3 = encode(r3, dir, op, &third);
  assert(third.new_blocks == 1 && third.reused_blocks == first.blocks - 1);
  decode_equal(p3, r3, dir, op);
  FILE *r4 = fixture(12, 48, 30000, 3, 5, 8, 0, 0),
       *p4 = encode(r4, dir, op, &removed_info);
  assert(removed_info.blocks == 12 && removed_info.new_blocks == 1);
  decode_equal(p4, r4, dir, op);
  cg_generation_root roots[2] = {{p3, checksum(p3, op)},
                                 {p4, checksum(p4, op)}};
  size_t removed = 999;
  uint64_t removed_bytes = 999;
  assert(cg_generation_gc(dir, op, roots, 2, &removed, &removed_bytes));
  assert(removed == 1 && removed_bytes > 0);
  decode_equal(p3, r3, dir, op);
  decode_equal(p4, r4, dir, op);
  FILE *failed_raw = fixture(12, 48, 40000, 9, 5, 8, 0, 0);
  cg_generation_info failed_info;
  FILE *unpublished = encode(failed_raw, dir, op, &failed_info);
  assert(failed_info.new_blocks >= 1);
  size_t before_gc = block_count(dir, NULL);
  assert(cg_generation_gc(dir, op, roots, 2, &removed, &removed_bytes) &&
         removed >= 1 && block_count(dir, NULL) < before_gc);
  decode_equal(p4, r4, dir, op);
  block_adversarial(p4, r4, dir, op);
#ifdef CG_GENERATION_TEST_FAULTS
  rename_crash(dir, op, roots);
#endif
  FILE *duplicate = rewrite_parent(p4, 2);
  cg_snapshot_checksum duplicate_h = checksum(duplicate, op);
  deny(duplicate, dir, op, &duplicate_h);
  fclose(duplicate);
  FILE *too_many = rewrite_parent(p4, 3);
  cg_snapshot_checksum too_many_h = checksum(too_many, op);
  deny(too_many, dir, op, &too_many_h);
  assert(errno == E2BIG);
  fclose(too_many);
  FILE *too_large = rewrite_parent(p4, 4);
  cg_snapshot_checksum too_large_h = checksum(too_large, op);
  deny(too_large, dir, op, &too_large_h);
  assert(errno == EFBIG);
  fclose(too_large);
  /* A buffered stdio spoof must never replace the verified descriptor image. */
  rewind(p4);
  assert(fgetc(p4) == 'Q' && ungetc('X', p4) != EOF);
  decode_equal(p4, r4, dir, op);
  rewind(p4);
  pending_residue(dir, op, low, roots);
  FILE *bad = copy(p4);
  byte(bad, 0, 'X');
  cg_snapshot_checksum bad_h = checksum(bad, op);
  deny(bad, dir, op, &bad_h);
  cg_generation_root bad_roots[2] = {{p3, checksum(p3, op)}, {bad, bad_h}};
  size_t before_bad = block_count(dir, NULL);
  assert(!cg_generation_gc(dir, op, bad_roots, 2, &removed, &removed_bytes));
  assert(block_count(dir, NULL) == before_bad);
  deny(p4, dir, NULL, &roots[1].checksum);
  deny(p4, dir, tenant, &roots[1].checksum);
  FILE *truncated = copy(p4);
  assert(!ftruncate(fileno(truncated), (off_t)size(truncated) - 1));
  cg_snapshot_checksum truncated_h = checksum(truncated, op);
  deny(truncated, dir, op, &truncated_h);
  cg_snapshot_checksum wrong = roots[1].checksum;
  wrong.hex[0] = wrong.hex[0] == 'a' ? 'b' : 'a';
  deny(p4, dir, op, &wrong);
  FILE *protected_raw = fixture(2, 2, 1, -1, -1, -1, 4, 2);
  cg_generation_info protected_info;
  FILE *protected_parent = encode(protected_raw, dir, op, &protected_info);
  cg_snapshot_checksum protected_h = checksum(protected_parent, op);
  decode_equal(protected_parent, protected_raw, dir, op);
  deny(protected_parent, dir, low, &protected_h);
  deny(protected_parent, dir, wrong_sci, &protected_h);
  FILE *denied_output = tmpfile();
  assert(denied_output);
  rewind(protected_raw);
  assert(!cg_generation_encode_snapshot(protected_raw, denied_output, dir, low,
                                        LIMIT, 100000, NULL) &&
         size(denied_output) == 0);
  fclose(denied_output);
  FILE *forged = rewrite_parent(protected_parent, 1);
  cg_snapshot_checksum forged_h = checksum(forged, op);
  deny(forged, dir, low, &forged_h);
  assert(errno == EACCES);
  fclose(forged);
  cg_generation_account account = {0};
  assert(cg_generation_account_user(dir, op, roots, 2, &account) &&
         account.coverage_complete && account.referenced_blocks > 0 &&
         account.orphan_blocks == protected_info.blocks);
  uint32_t refs = account.referenced_blocks;
  uint64_t refbytes = account.referenced_bytes;
  assert(cg_generation_account_user(dir, low, roots, 2, &account) &&
         !account.coverage_complete && account.referenced_blocks == refs &&
         account.referenced_bytes == refbytes && !account.orphan_blocks &&
         !account.orphan_bytes);
  assert(!cg_generation_account_user(dir, NULL, roots, 2, &account));
  cg_generation_root protected_roots[1] = {{protected_parent, protected_h}};
  assert(!cg_generation_account_user(dir, low, protected_roots, 1, &account));
  before_bad = block_count(dir, NULL);
  assert(!cg_generation_gc(dir, low, NULL, 0, &removed, &removed_bytes));
  assert(block_count(dir, NULL) == before_bad);
  printf("{\"first_parent_bytes\":%" PRIu64 ",\"first_block_bytes\":%" PRIu64
         ",\"unchanged_new_block_bytes\":%" PRIu64
         ",\"unchanged_reused_blocks\":%u,\"changed_new_block_bytes\":%" PRIu64
         ",\"changed_reused_blocks\":%u,\"raw_bytes\":%" PRIu64
         ",\"current_previous_blocks\":%zu}\n",
         first.parent_bytes, first.block_bytes, second.new_block_bytes,
         second.reused_blocks, third.new_block_bytes, third.reused_blocks,
         first.raw_bytes, before_gc);
  larger_than_64m(root, op);
  fclose(r1);
  fclose(p1);
  fclose(r2);
  fclose(p2);
  fclose(r3);
  fclose(p3);
  fclose(r4);
  fclose(p4);
  fclose(failed_raw);
  fclose(unpublished);
  fclose(bad);
  fclose(truncated);
  fclose(protected_raw);
  fclose(protected_parent);
  qihse_audit_shutdown();
  assert(!nftw(root, clean_test, 16, FTW_DEPTH | FTW_PHYS));
  puts("CodeGraph immutable per-file generations: PASS");
  return 0;
}
