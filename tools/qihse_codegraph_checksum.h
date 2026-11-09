#ifndef QIHSE_CODEGRAPH_CHECKSUM_H
#define QIHSE_CODEGRAPH_CHECKSUM_H
#include "qihse_auth.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

typedef enum {
  CG_CHECKSUM_SHA256 = 1,
  CG_CHECKSUM_XXH3_128 = 2
} cg_checksum_algorithm;
typedef struct {
  cg_checksum_algorithm algorithm;
  char hex[65];
} cg_snapshot_checksum;
const char *cg_checksum_algorithm_name(cg_checksum_algorithm algorithm);
bool cg_checksum_valid(const cg_snapshot_checksum *checksum);
/* Hash explicit caller bytes or an owned regular snapshot descriptor. An active
 * principal is always required; checksums do not substitute for record ACLs. */
bool cg_snapshot_checksum_buffer_user(const void *bytes, size_t length,
                                      qihse_user_t *user,
                                      cg_checksum_algorithm algorithm,
                                      cg_snapshot_checksum *out);
bool cg_snapshot_checksum_stream_user(FILE *source, qihse_user_t *user,
                                      cg_checksum_algorithm algorithm,
                                      cg_snapshot_checksum *out);
bool cg_snapshot_checksum_file_user(const char *path, qihse_user_t *user,
                                    cg_checksum_algorithm algorithm,
                                    cg_snapshot_checksum *out);
#endif
