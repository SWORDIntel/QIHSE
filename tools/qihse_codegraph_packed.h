#ifndef QIHSE_CODEGRAPH_PACKED_H
#define QIHSE_CODEGRAPH_PACKED_H

#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Internal, in-memory format experiment restricted to active Operators.
 * Record labels are caller supplied, not attested by this codec: callers must
 * obtain records through authenticated QIHSE KV APIs and verify the trusted
 * manifest/envelope before decode. The checksum detects corruption, not
 * deliberate relabeling. This is not a storage loader or publication API. */
#define CG_PACKED_MAX_RECORDS 2000000u
#define CG_PACKED_MAX_VALUE (8u << 20)
#define CG_PACKED_MAX_BYTES (UINT64_C(1) << 30)

typedef struct {
    char *key;
    size_t key_len;
    unsigned char *value;
    size_t value_len;
    qihse_kv_record_meta_t meta;
} cg_packed_record;

/* Both functions require a non-NULL active principal with clearance for all
 * records. They return no partial output on error. Caller owns successful
 * outputs and releases them with free()/cg_packed_records_free(). */
bool cg_packed_encode(const cg_packed_record *records, size_t count,
                      qihse_user_t *principal, unsigned char **out,
                      size_t *out_len);
bool cg_packed_decode(const unsigned char *data, size_t length,
                      qihse_user_t *principal, cg_packed_record **out,
                      size_t *out_count);
void cg_packed_records_free(cg_packed_record *records, size_t count);

#endif
