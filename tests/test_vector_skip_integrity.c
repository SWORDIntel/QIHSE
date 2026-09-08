#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "qihse_container.h"
#include "qihse_vector_store.h"

static void make_temp_path(char path[128]) {
    snprintf(path, 128, "/tmp/qihse-vector-skip-integrity-%ld.qdb", (long)getpid());
    unlink(path);
}

int main(void) {
    char path[128];
    make_temp_path(path);

    qihse_index_row_t row;
    memset(&row, 0, sizeof(row));
    row.vector_id = 1u;
    row.vector_offset = 0u;
    row.commit_generation = 1u;
    row.row_flags = QIHSE_ROW_F_LIVE;

    float vector[5] = {0.0f, 0.0f, 0.0f, 0.0f, 0.0f};
    /* Five neutral trits (1,1,1,1,1) pack to base-3 value 121. */
    uint8_t valid_trinary[1] = {121u};

    qihse_vector_store_flush_t flush;
    memset(&flush, 0, sizeof(flush));
    flush.vector_dims = 5u;
    flush.commit_generation = 1u;
    flush.rows = &row;
    flush.row_count = 1u;
    flush.vectors = vector;
    flush.vector_bytes = sizeof(vector);
    flush.trinary = valid_trinary;
    flush.trinary_bytes = sizeof(valid_trinary);
    flush.trinary_generation = 1u;
    flush.trinary_row_bytes = 1u;
    flush.trinary_flags = QIHSE_VSTORE_TRI_PRESENT | QIHSE_VSTORE_TRI_VALID;

    assert(qihse_vector_store_flush(path, &flush));

    /* Replace only the trinary section through the container API so the
     * section HMAC is recomputed and remains valid. 0xff is not a legal
     * tryte (valid range is 0..242), while the manifest/CRC remain stale. */
    qihse_container_t writer;
    assert(qihse_ctr_open_write(path, false, &writer));
    uint8_t malformed_trinary[1] = {0xffu};
    qihse_ctr_section_buf_t replacement = {
        QIHSE_CTR_SEC_TRINARY,
        malformed_trinary,
        sizeof(malformed_trinary)
    };
    assert(qihse_ctr_flush(&writer, &replacement, 1u));
    qihse_ctr_close(&writer);

    unsetenv("QIHSE_ENFORCE_INTEGRITY");
    qihse_container_t reader;
    assert(qihse_ctr_open_read(path, &reader));
    /* CI/pre-production has no KEM private key, so this proves the load below
     * exercises the skip-CRC path rather than simply failing a checksum. */
    assert(reader.skip_integrity);
    qihse_ctr_close(&reader);

    qihse_vector_store_snapshot_t snapshot;
    memset(&snapshot, 0, sizeof(snapshot));
    errno = 0;
    assert(!qihse_vector_store_load(path, &snapshot));
    assert(errno == EINVAL);
    qihse_vector_store_snapshot_free(&snapshot);

    unlink(path);
    printf("vector skip-integrity structural validation regression: PASS\n");
    return 0;
}
