/* V2 makes the WAL its final file extent so partial writes cannot corrupt
 * section metadata. V1 fixtures verify lazy atomic conversion on mutation. */
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "qihse_container.h"

static int fail_partial_pwrite;
static off_t partial_offset;
static int fail_partial_rollback;
static int fail_rename;
static int fail_directory_sync;

ssize_t __real_pwrite(int fd, const void* data, size_t size, off_t offset);
int __real_rename(const char* old_path, const char* new_path);
int __real_ftruncate(int fd, off_t length);
int qihse_test_fsync(int fd);

ssize_t __wrap_pwrite(int fd, const void* data, size_t size, off_t offset) {
    if (fail_partial_pwrite && offset == partial_offset && size > 1u) {
        fail_partial_pwrite = 0;
        size_t prefix = size / 2u;
        assert(__real_pwrite(fd, data, prefix, offset) == (ssize_t)prefix);
        errno = EIO;
        return -1;
    }
    return __real_pwrite(fd, data, size, offset);
}

int __wrap_rename(const char* old_path, const char* new_path) {
    if (fail_rename) {
        fail_rename = 0;
        errno = EIO;
        return -1;
    }
    return __real_rename(old_path, new_path);
}

int __wrap_ftruncate(int fd, off_t length) {
    if (fail_partial_rollback) {
        fail_partial_rollback = 0;
        errno = EIO;
        return -1;
    }
    return __real_ftruncate(fd, length);
}

int qihse_test_fsync(int fd) {
    if (fail_directory_sync) {
        struct stat st;
        if (fstat(fd, &st) == 0 && S_ISDIR(st.st_mode)) {
            fail_directory_sync = 0;
            errno = EIO;
            return -1;
        }
    }
    return (int)syscall(SYS_fsync, fd);
}

static void write_le32(uint8_t* p, uint32_t value) {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static void write_le64(uint8_t* p, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (uint8_t)(value >> (8u * i));
}

/* Create a V1 fixture from a V2 file. The test-only HMAC key is all zeroes. */
static void rewrite_as_v1(const char* path, int include_wal, uint64_t wal_length) {
    int fd = open(path, O_RDWR | O_CLOEXEC);
    assert(fd >= 0);
    uint8_t header[QIHSE_CTR_HEADER_SIZE];
    assert(pread(fd, header, sizeof(header), 0) == (ssize_t)sizeof(header));
    write_le32(header + 8u, QIHSE_CTR_VERSION_V1);
    unsigned int digest_len = 0;
    uint8_t zero_key[48] = {0}, digest[48];
    assert(HMAC(EVP_sha384(), zero_key, sizeof(zero_key), header, 20u,
                digest, &digest_len) != NULL && digest_len == sizeof(digest));
    memcpy(header + 20u, digest, sizeof(digest));
    if (include_wal) {
        uint8_t entry[QIHSE_CTR_SECTION_ENTRY_SIZE];
        int found = 0;
        for (uint32_t i = 0; i < QIHSE_CTR_MAX_SECTIONS; ++i) {
            off_t off = QIHSE_CTR_TABLE_OFFSET +
                        (off_t)i * QIHSE_CTR_SECTION_ENTRY_SIZE;
            assert(pread(fd, entry, sizeof(entry), off) == (ssize_t)sizeof(entry));
            uint16_t section_id = (uint16_t)(entry[0] | ((uint16_t)entry[1] << 8));
            if (section_id == QIHSE_CTR_SEC_WAL) {
                write_le64(entry + 16u, wal_length);
                assert(pwrite(fd, entry, sizeof(entry), off) == (ssize_t)sizeof(entry));
                found = 1;
                break;
            }
        }
        assert(found);
    } else {
        /* Remove only the WAL table entry and retain all ordinary payloads. */
        uint8_t old_table[QIHSE_CTR_TABLE_SIZE], new_table[QIHSE_CTR_TABLE_SIZE] = {0};
        assert(pread(fd, old_table, sizeof(old_table), QIHSE_CTR_TABLE_OFFSET) ==
               (ssize_t)sizeof(old_table));
        uint32_t kept = 0u;
        uint64_t file_end = QIHSE_CTR_PAYLOAD_BASE;
        for (uint32_t i = 0; i < QIHSE_CTR_MAX_SECTIONS; ++i) {
            const uint8_t* entry = old_table + (size_t)i * QIHSE_CTR_SECTION_ENTRY_SIZE;
            uint16_t id = (uint16_t)(entry[0] | ((uint16_t)entry[1] << 8));
            if (!id || id == QIHSE_CTR_SEC_WAL) continue;
            memcpy(new_table + (size_t)kept * QIHSE_CTR_SECTION_ENTRY_SIZE,
                   entry, QIHSE_CTR_SECTION_ENTRY_SIZE);
            uint64_t offset = 0u, length = 0u;
            for (unsigned j = 0; j < 8u; ++j) {
                offset |= (uint64_t)entry[8u + j] << (8u * j);
                length |= (uint64_t)entry[16u + j] << (8u * j);
            }
            if (offset + length > file_end) file_end = offset + length;
            kept++;
        }
        write_le32(header + 16u, kept);
        assert(pwrite(fd, new_table, sizeof(new_table), QIHSE_CTR_TABLE_OFFSET) ==
               (ssize_t)sizeof(new_table));
        assert(ftruncate(fd, (off_t)file_end) == 0);
        assert(HMAC(EVP_sha384(), zero_key, sizeof(zero_key), header, 20u,
                    digest, &digest_len) != NULL && digest_len == sizeof(digest));
        memcpy(header + 20u, digest, sizeof(digest));
    }
    assert(pwrite(fd, header, sizeof(header), 0) == (ssize_t)sizeof(header));
    assert(fsync(fd) == 0);
    close(fd);
}

static void make_path(char* out, size_t cap, const char* dir, const char* name) {
    int n = snprintf(out, cap, "%s/%s", dir, name);
    assert(n > 0 && (size_t)n < cap);
}

static void check_bytes(qihse_container_t* ctr, uint16_t section, const char* expected) {
    size_t n = strlen(expected);
    uint8_t* actual = calloc(n ? n : 1u, 1u);
    assert(actual);
    assert(qihse_ctr_read_section_at(ctr, section, actual, n, 0u));
    assert(memcmp(actual, expected, n) == 0);
    free(actual);
}

static void test_partial_append_and_reopen(const char* dir) {
    char path[512]; make_path(path, sizeof(path), dir, "partial.qdb");
    qihse_container_t ctr;
    assert(qihse_ctr_open_write(path, true, &ctr));
    assert(ctr.format_version == QIHSE_CTR_VERSION);
    assert(qihse_ctr_wal_append(&ctr, "first", 5u));
    partial_offset = (off_t)(QIHSE_CTR_PAYLOAD_BASE + 5u);
    fail_partial_pwrite = 1;
    errno = 0;
    assert(!qihse_ctr_wal_append(&ctr, "second", 6u));
    assert(errno == EIO && !fail_partial_pwrite);
    assert(qihse_ctr_section_length(&ctr, QIHSE_CTR_SEC_WAL) == 5u);
    assert(qihse_ctr_wal_append(&ctr, "second", 6u));
    partial_offset = (off_t)(QIHSE_CTR_PAYLOAD_BASE + 11u);
    fail_partial_pwrite = 1;
    fail_partial_rollback = 1;
    errno = 0;
    assert(!qihse_ctr_wal_append(&ctr, "again", 5u));
    assert(errno == EIO && ctr.write_uncertain);
    assert(!qihse_ctr_wal_append(&ctr, "retry", 5u) && errno == EIO);
    assert(!qihse_ctr_fsync(&ctr) && errno == EIO);
    qihse_ctr_close(&ctr);
    assert(qihse_ctr_open_write(path, false, &ctr));
    assert(qihse_ctr_section_length(&ctr, QIHSE_CTR_SEC_WAL) == 13u);
    assert(qihse_ctr_wal_truncate(&ctr, 11u));
    assert(qihse_ctr_fsync(&ctr));
    qihse_ctr_close(&ctr);

    /* Simulate a process dying after a short raw tail reached EOF. */
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    assert(fd >= 0);
    assert(pwrite(fd, "torn", 4u, QIHSE_CTR_PAYLOAD_BASE + 11u) == 4);
    assert(fsync(fd) == 0); close(fd);
    assert(qihse_ctr_open_write(path, false, &ctr));
    assert(ctr.format_version == QIHSE_CTR_VERSION);
    assert(qihse_ctr_section_length(&ctr, QIHSE_CTR_SEC_WAL) == 15u);
    /* A reader may inspect the malformed frame; the writer's recovery path
     * truncates to the last complete commit before publishing the new length. */
    assert(qihse_ctr_wal_truncate(&ctr, 11u));
    assert(qihse_ctr_fsync(&ctr));
    qihse_ctr_close(&ctr);
    qihse_container_t reader;
    assert(qihse_ctr_open_read(path, &reader));
    assert(qihse_ctr_section_length(&reader, QIHSE_CTR_SEC_WAL) == 11u);
    check_bytes(&reader, QIHSE_CTR_SEC_WAL, "firstsecond");
    qihse_ctr_close(&reader);
    unlink(path);
}

static void test_v1_conversion(const char* dir, const char* name,
                               int absent_wal, int fail_before_rename,
                               int fail_after_rename) {
    char path[512]; make_path(path, sizeof(path), dir, name);
    qihse_container_t ctr;
    assert(qihse_ctr_open_write(path, true, &ctr));
    const char data[] = "preserve-data";
    qihse_ctr_section_buf_t section = {QIHSE_CTR_SEC_METADATA, data, sizeof(data)};
    assert(qihse_ctr_flush(&ctr, &section, 1u));
    if (!absent_wal) assert(qihse_ctr_wal_append(&ctr, "old-wal", 7u));
    assert(qihse_ctr_fsync(&ctr));
    qihse_ctr_close(&ctr);
    rewrite_as_v1(path, !absent_wal, absent_wal ? 0u : 7u);

    assert(qihse_ctr_open_write(path, false, &ctr));
    assert(ctr.format_version == QIHSE_CTR_VERSION_V1);
    if (fail_before_rename) {
        fail_rename = 1;
        errno = 0;
        assert(!qihse_ctr_wal_append(&ctr, "new", 3u));
        assert(errno == EIO && !fail_rename);
        assert(ctr.format_version == QIHSE_CTR_VERSION_V1);
        qihse_ctr_close(&ctr);
        assert(qihse_ctr_open_write(path, false, &ctr));
    } else if (fail_after_rename) {
        fail_directory_sync = 1;
        errno = 0;
        assert(!qihse_ctr_wal_append(&ctr, "new", 3u));
        assert(errno == EIO && !fail_directory_sync);
        assert(ctr.format_version == QIHSE_CTR_VERSION);
        qihse_ctr_close(&ctr);
        assert(qihse_ctr_open_write(path, false, &ctr));
    }
    assert(qihse_ctr_wal_append(&ctr, "new", 3u));
    assert(qihse_ctr_fsync(&ctr));
    assert(ctr.format_version == QIHSE_CTR_VERSION);
    assert(qihse_ctr_section_length(&ctr, QIHSE_CTR_SEC_WAL) ==
           (absent_wal ? 3u : 10u));
    qihse_ctr_close(&ctr);

    qihse_container_t reader;
    assert(qihse_ctr_open_read(path, &reader));
    assert(reader.format_version == QIHSE_CTR_VERSION);
    const char* expected_wal = absent_wal ? "new" : "old-walnew";
    check_bytes(&reader, QIHSE_CTR_SEC_WAL, expected_wal);
    uint8_t* got = NULL; size_t got_size = 0u;
    assert(qihse_ctr_read_section_alloc(&reader, QIHSE_CTR_SEC_METADATA,
                                        &got, &got_size));
    assert(got_size == sizeof(data) && memcmp(got, data, sizeof(data)) == 0);
    free(got);
    qihse_ctr_close(&reader);
    unlink(path);
}

static void test_pending_section_stays_pending(const char* dir) {
    char path[512]; make_path(path, sizeof(path), dir, "pending-section.qdb");
    qihse_container_t ctr;
    assert(qihse_ctr_open_write(path, true, &ctr));
    const char base[] = "base";
    qihse_ctr_section_buf_t initial = {QIHSE_CTR_SEC_METADATA, base, sizeof(base)};
    assert(qihse_ctr_flush(&ctr, &initial, 1u));
    qihse_ctr_close(&ctr);

    rewrite_as_v1(path, 0, 0u);
    assert(qihse_ctr_open_write(path, false, &ctr));
    const char pending_data[] = "pending";
    qihse_ctr_section_buf_t pending = {QIHSE_CTR_SEC_INDEX, pending_data,
                                       sizeof(pending_data)};
    /* WAL conversion must not publish unrelated caller-owned buffers. */
    assert(qihse_ctr_wal_append(&ctr, "wal", 3u));
    assert(qihse_ctr_find_section(&ctr, QIHSE_CTR_SEC_INDEX) == NULL);
    /* The caller can then publish DATA using its normal snapshot flush; that
     * replacement must preserve the V2 WAL as the final extent. */
    assert(qihse_ctr_flush(&ctr, &pending, 1u));
    assert(qihse_ctr_section_length(&ctr, QIHSE_CTR_SEC_WAL) == 3u);
    assert(qihse_ctr_fsync(&ctr));
    qihse_ctr_close(&ctr);

    qihse_container_t reader;
    assert(qihse_ctr_open_read(path, &reader));
    assert(reader.format_version == QIHSE_CTR_VERSION);
    check_bytes(&reader, QIHSE_CTR_SEC_WAL, "wal");
    uint8_t* got = NULL; size_t got_size = 0u;
    assert(qihse_ctr_read_section_alloc(&reader, QIHSE_CTR_SEC_INDEX,
                                        &got, &got_size));
    assert(got_size == sizeof(pending_data) &&
           memcmp(got, pending_data, sizeof(pending_data)) == 0);
    free(got);
    qihse_ctr_close(&reader);
    unlink(path);
}

int main(void) {
    char dir[] = "build/container_wal_recovery_XXXXXX";
    assert(mkdtemp(dir));
    assert(setenv("QIHSE_KEY_DIR", dir, 1) == 0);
    assert(setenv("QIHSE_ALLOW_INSECURE_CONTAINER", "1", 1) == 0);
    assert(setenv("QIHSE_ENFORCE_INTEGRITY", "1", 1) == 0);
    char partial_path[512]; make_path(partial_path, sizeof(partial_path), dir,
                                      "partial-initialization.qdb");
    int partial_fd = open(partial_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    assert(partial_fd >= 0);
    assert(write(partial_fd, "incomplete-header", 17u) == 17);
    close(partial_fd);
    qihse_container_t initialized;
    assert(qihse_ctr_open_write(partial_path, true, &initialized));
    assert(initialized.format_version == QIHSE_CTR_VERSION);
    qihse_ctr_close(&initialized);
    unlink(partial_path);
    test_partial_append_and_reopen(dir);
    test_v1_conversion(dir, "v1-existing-wal.qdb", 0, 0, 0);
    test_v1_conversion(dir, "v1-absent-wal.qdb", 1, 0, 0);
    test_v1_conversion(dir, "v1-rename-failure.qdb", 0, 1, 0);
    test_v1_conversion(dir, "v1-dir-sync-failure.qdb", 0, 0, 1);
    test_pending_section_stays_pending(dir);
    assert(rmdir(dir) == 0);
    puts("container V2 WAL append, truncate and lazy V1 migration passed");
    return 0;
}
