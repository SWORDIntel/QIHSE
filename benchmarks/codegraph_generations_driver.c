/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "qihse_audit.h"
#include "qihse_codegraph_dictionary.h"
#include "qihse_codegraph_generation.h"
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <zstd.h>
static double now(void) {
  struct timespec t;
  clock_gettime(CLOCK_MONOTONIC, &t);
  return t.tv_sec + t.tv_nsec / 1e9;
}
static bool zstd_export(FILE *input, FILE *output, qihse_user_t *u) {
  if (!u || !qihse_auth_user_is_active(u) || !qihse_auth_can_access(u, 0, 0))
    return false;
  struct stat st;
  if (fstat(fileno(input), &st) || st.st_size < 0)
    return false;
  unsigned char header[16];
  memcpy(header, "QCGZ0001", 8);
  for (unsigned i = 0; i < 8; i++)
    header[15 - i] = (unsigned char)((uint64_t)st.st_size >> (8 * i));
  if (fwrite(header, 1, sizeof(header), output) != sizeof(header))
    return false;
  unsigned char *buffers = malloc(131072);
  ZSTD_CCtx *c = ZSTD_createCCtx();
  bool ok = buffers && c;
  if (ok)
    ok = !ZSTD_isError(ZSTD_CCtx_setParameter(c, ZSTD_c_compressionLevel, 9)) &&
         !ZSTD_isError(ZSTD_CCtx_setParameter(c, ZSTD_c_windowLog, 23)) &&
         !ZSTD_isError(ZSTD_CCtx_setParameter(c, ZSTD_c_checksumFlag, 1)) &&
         !ZSTD_isError(ZSTD_CCtx_setPledgedSrcSize(c, (uint64_t)st.st_size));
  while (ok) {
    size_t n = fread(buffers, 1, 65536, input);
    if (ferror(input) || !qihse_auth_user_is_active(u)) {
      ok = false;
      break;
    }
    ZSTD_inBuffer in = {buffers, n, 0};
    ZSTD_EndDirective mode = feof(input) ? ZSTD_e_end : ZSTD_e_continue;
    size_t remaining;
    do {
      ZSTD_outBuffer out = {buffers + 65536, 65536, 0};
      remaining = ZSTD_compressStream2(c, &out, &in, mode);
      ok = !ZSTD_isError(remaining) &&
           fwrite(out.dst, 1, out.pos, output) == out.pos;
    } while (ok && (in.pos < in.size || (mode == ZSTD_e_end && remaining)));
    if (mode == ZSTD_e_end)
      break;
  }
  ZSTD_freeCCtx(c);
  free(buffers);
  return ok && !fflush(output) && qihse_auth_user_is_active(u);
}
int main(int argc, char **argv) {
  if (argc != 6) {
    fprintf(stderr, "usage: driver encode|decode|zstd|packed-v3|decode-v3|gc "
                    "INPUT OUTPUT BLOCKS AUTH_DIR\n");
    return 2;
  }
  umask(077);
  assert(!setenv("QIHSE_DATA_DIR", argv[5], 1) &&
         !setenv("QIHSE_FIPS_MODE", "disabled", 1));
  assert(qihse_auth_init() &&
         qihse_auth_bootstrap_operator("GenerationBenchmarkSecret1!"));
  qihse_user_t *u =
      qihse_auth_authenticate_id(0, "GenerationBenchmarkSecret1!");
  assert(u);
  if (!strcmp(argv[1], "gc")) {
    FILE *current = fopen(argv[2], "rb"), *previous = fopen(argv[3], "rb");
    assert(current && previous);
    cg_generation_root roots[2] = {{.parent = current}, {.parent = previous}};
    assert(cg_snapshot_checksum_file_user(argv[2], u, CG_CHECKSUM_XXH3_128,
                                          &roots[0].checksum) &&
           cg_snapshot_checksum_file_user(argv[3], u, CG_CHECKSUM_XXH3_128,
                                          &roots[1].checksum));
    double start = now();
    size_t removed = 0;
    uint64_t bytes = 0;
    assert(cg_generation_gc(argv[4], u, roots, 2, &removed, &bytes));
    cg_generation_account account;
    assert(cg_generation_account_user(argv[4], u, roots, 2, &account) &&
           account.coverage_complete);
    printf("{\"operation\":\"gc\",\"seconds\":%.9f,\"removed_blocks\":%zu,"
           "\"removed_bytes\":%" PRIu64 ",\"referenced_bytes\":%" PRIu64
           ",\"referenced_allocated_bytes\":%" PRIu64
           ",\"referenced_blocks\":%u}\n",
           now() - start, removed, bytes, account.referenced_bytes,
           account.referenced_allocated_bytes, account.referenced_blocks);
    fclose(current);
    fclose(previous);
    qihse_audit_shutdown();
    return 0;
  }
  FILE *input = fopen(argv[2], "rb"), *output = fopen(argv[3], "wb");
  assert(input && output);
  double start = now();
  cg_generation_info info = {0};
  bool ok = false;
  if (!strcmp(argv[1], "encode"))
    ok = cg_generation_encode_snapshot(input, output, argv[4], u,
                                       CG_GENERATION_MAX_RAW_BYTES,
                                       CG_GENERATION_MAX_RECORDS, &info);
  else if (!strcmp(argv[1], "decode")) {
    cg_snapshot_checksum expected;
    assert(cg_snapshot_checksum_file_user(argv[2], u, CG_CHECKSUM_XXH3_128,
                                          &expected));
    ok = cg_generation_decode_snapshot(input, output, argv[4], u, &expected,
                                       CG_GENERATION_MAX_RAW_BYTES,
                                       CG_GENERATION_MAX_RECORDS, &info);
  } else if (!strcmp(argv[1], "zstd"))
    ok = zstd_export(input, output, u);
  else if (!strcmp(argv[1], "packed-v3"))
    ok = cg_dictionary_encode_snapshot(input, output, u,
                                       CG_DICTIONARY_MAX_RAW_BYTES,
                                       CG_DICTIONARY_MAX_RECORDS);
  else if (!strcmp(argv[1], "decode-v3")) {
    cg_snapshot_checksum expected;
    assert(cg_snapshot_checksum_file_user(argv[2], u, CG_CHECKSUM_XXH3_128,
                                          &expected));
    ok = cg_dictionary_decode_checksum_snapshot(input, output, u, &expected,
                                                CG_DICTIONARY_MAX_RAW_BYTES,
                                                CG_DICTIONARY_MAX_RECORDS);
  }
  double elapsed = now() - start;
  assert(!fflush(output));
  struct stat st;
  assert(!fstat(fileno(output), &st));
  struct rusage usage;
  assert(!getrusage(RUSAGE_SELF, &usage));
  if (!ok) {
    perror("codec operation");
    return 1;
  }
  printf("{\"operation\":\"%s\",\"seconds\":%.9f,\"peak_rss_kib\":%ld,\"output_"
         "bytes\":%" PRIu64 ",\"raw_bytes\":%" PRIu64
         ",\"parent_bytes\":%" PRIu64 ",\"block_bytes\":%" PRIu64
         ",\"new_block_bytes\":%" PRIu64 ",\"reused_block_bytes\":%" PRIu64
         ",\"blocks\":%u,\"new_blocks\":%u,\"reused_blocks\":%u}\n",
         argv[1], elapsed, usage.ru_maxrss, (uint64_t)st.st_size,
         info.raw_bytes, info.parent_bytes, info.block_bytes,
         info.new_block_bytes, info.reused_block_bytes, info.blocks,
         info.new_blocks, info.reused_blocks);
  fclose(input);
  fclose(output);
  qihse_audit_shutdown();
  return 0;
}
