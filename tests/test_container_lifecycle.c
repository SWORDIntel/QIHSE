/* Ordinary lifecycle regression: independent reader closure must not release
 * the active writer's lock; key-policy withdrawal must fail every MAC user. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "qihse_container.h"

static void expect_independent_writer_blocked(const char* path) {
    qihse_container_t other;
    assert(!qihse_ctr_open_write(path, false, &other));
    assert(errno == EAGAIN || errno == EACCES);
    qihse_ctr_close(&other);
}

int main(void) {
    char dir[] = "build/container_lifecycle_XXXXXX";
    assert(mkdtemp(dir));
    assert(setenv("QIHSE_KEY_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_ALLOW_INSECURE_CONTAINER", "1", 1) == 0);
    assert(setenv("QIHSE_ENFORCE_INTEGRITY", "1", 1) == 0);
    char path[512];
    assert(snprintf(path, sizeof(path), "%s/test.qdb", dir) > 0);
    qihse_container_t writer, reader;
    assert(qihse_ctr_open_write(path, true, &writer));
    const char payload[] = "container lifecycle";
    qihse_ctr_section_buf_t section = {QIHSE_CTR_SEC_METADATA, payload, sizeof(payload)};
    unsigned char* large = malloc(131073u);
    assert(large);
    for (size_t i = 0; i < 131073u; ++i) large[i] = (unsigned char)(i % 251u);
    qihse_ctr_section_buf_t initial[] = {
        section, {QIHSE_CTR_SEC_INDEX, large, 131073u}
    };
    assert(qihse_ctr_flush(&writer, initial, 2));
    expect_independent_writer_blocked(path);
    assert(qihse_ctr_open_read(path, &reader));
    char slice[4];
    assert(qihse_ctr_read_section_at(&reader, QIHSE_CTR_SEC_INDEX, NULL, 0, 0));
    assert(qihse_ctr_read_section_at(&reader, QIHSE_CTR_SEC_INDEX, slice, sizeof(slice), 65534u));
    assert(memcmp(slice, large + 65534u, sizeof(slice)) == 0);
    assert(qihse_ctr_read_section_at(&reader, QIHSE_CTR_SEC_INDEX, slice, sizeof(slice), 131069u));
    assert(memcmp(slice, large + 131069u, sizeof(slice)) == 0);
    free(large);
    assert(qihse_ctr_read_section_at(&reader, section.section_id, slice, sizeof(slice), 1));
    assert(memcmp(slice, payload + 1, sizeof(slice)) == 0);
    qihse_ctr_close(&reader);
    expect_independent_writer_blocked(path);
    assert(qihse_ctr_wal_append(&writer, "record", 6));
    assert(qihse_ctr_flush(&writer, &section, 1));
    expect_independent_writer_blocked(path);
    assert(qihse_ctr_open_read(path, &reader));
    /* Removing the explicit test-key grant invalidates existing handles too. */
    assert(unsetenv("QIHSE_ALLOW_INSECURE_CONTAINER") == 0);
    unsigned char* data = NULL;
    size_t size = 0;
    assert(!qihse_ctr_read_section_alloc(&reader, section.section_id, &data, &size));
    assert(data == NULL && size == 0);
    memset(slice, 0x5a, sizeof(slice));
    assert(!qihse_ctr_read_section_at(&reader, section.section_id, slice, sizeof(slice), 0));
    for (size_t i = 0; i < sizeof(slice); ++i) assert(slice[i] == 0x5a);
    assert(!qihse_ctr_flush(&writer, &section, 1));
    assert(!qihse_ctr_wal_append(&writer, "next", 4));
    assert(!qihse_ctr_wal_truncate(&writer, 0));
    assert(qihse_ctr_section_length(&writer, QIHSE_CTR_SEC_WAL) == 6);
    qihse_ctr_close(&reader);
    qihse_ctr_close(&writer);
    assert(setenv("QIHSE_ALLOW_INSECURE_CONTAINER", "1", 1) == 0);
    assert(qihse_ctr_open_read(path, &reader));
    assert(qihse_ctr_read_section_alloc(&reader, section.section_id, &data, &size));
    assert(size == sizeof(payload) && memcmp(data, payload, size) == 0);
    free(data);
    qihse_ctr_close(&reader);
    assert(unlink(path) == 0 && rmdir(dir) == 0);
    puts("PASS: container lifecycle locks and fail-closed key policy");
    return 0;
}
