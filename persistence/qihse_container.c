#include "qihse_platform.h"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#include "qihse_container.h"
#include "qihse_file.h"
#include "qihse_persist_format.h"

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#include <sys/mman.h>
#include <pthread.h>
#else
#include <io.h>
#endif
#include <sys/stat.h>

#ifndef _WIN32
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#endif

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* ── HMAC-SHA-384 key management ─────────────────────────────────── */

static uint8_t s_hmac_key[32] = {0};
static bool s_hmac_key_loaded = false;
static bool s_hmac_key_mlocked = false;

static pthread_mutex_t s_hmac_key_mutex = PTHREAD_MUTEX_INITIALIZER;
static bool s_hmac_test_key = false;

/* Caller holds s_hmac_key_mutex. A readable file is not necessarily a secret:
 * reject symlinks, publicly accessible files, empty/short and truncated keys.
 * The derivation remains SHA-384(private key PEM) for on-disk compatibility.
 * New on-disk key identities require an explicit migration, not a silent KDF swap. */
static bool load_hmac_key_locked(void) {
    if (s_hmac_key_loaded) {
        /* Do not allow a test-mode zero key to survive removal of its opt-in. */
        if (s_hmac_test_key) {
            const char* insecure = getenv("QIHSE_ALLOW_INSECURE_CONTAINER");
            if (!insecure || strcmp(insecure, "1") != 0) {
                errno = EACCES;
                return false;
            }
        }
        return true;
    }
#ifndef _WIN32
    const char* key_path = QIHSE_KEM_KEY_PATH();
    int fd = open(key_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1 ||
            (st.st_mode & 077) != 0 || st.st_size < 512 ||
            st.st_size > 1024 * 1024 ||
            (st.st_uid != geteuid() && st.st_uid != 0)) {
            close(fd);
            errno = EACCES;
            return false;
        }
        FILE* kf = fdopen(fd, "rb");
        if (!kf) { close(fd); return false; }

        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        unsigned char digest[SHA384_DIGEST_LENGTH] = {0};
        uint8_t buf[4096] = {0};
        unsigned int md_len = 0;
        size_t total = 0, n;
        bool ok = ctx && EVP_DigestInit_ex(ctx, EVP_sha384(), NULL) == 1;
        while (ok && (n = fread(buf, 1, sizeof(buf), kf)) > 0) {
            total += n;
            ok = EVP_DigestUpdate(ctx, buf, n) == 1;
        }
        if (ferror(kf) || total != (size_t)st.st_size) ok = false;
        if (ok) ok = EVP_DigestFinal_ex(ctx, digest, &md_len) == 1 &&
                     md_len == SHA384_DIGEST_LENGTH;
        if (ok) {
            memcpy(s_hmac_key, digest, sizeof(s_hmac_key));
            s_hmac_key_mlocked = (mlock(s_hmac_key, sizeof(s_hmac_key)) == 0);
            s_hmac_key_loaded = true;
            s_hmac_test_key = false;
        }
        OPENSSL_cleanse(buf, sizeof(buf));
        OPENSSL_cleanse(digest, sizeof(digest));
        EVP_MD_CTX_free(ctx);
        fclose(kf);
        if (!ok) errno = EIO;
        return ok;
    }
    if (errno != ENOENT) {
        /* In particular, a symlink cannot enable the test-mode fallback. */
        return false;
    }
#endif
    const char* insecure = getenv("QIHSE_ALLOW_INSECURE_CONTAINER");
    if (insecure && strcmp(insecure, "1") == 0) {
        fprintf(stderr, "[CONTAINER INSECURE TEST MODE] zero HMAC key enabled explicitly; do not deploy\n");
        s_hmac_key_loaded = true;
        s_hmac_test_key = true;
        return true;
    }
    errno = EACCES;
    return false;
}

static bool load_hmac_key(void) {
    pthread_mutex_lock(&s_hmac_key_mutex);
    bool ok = load_hmac_key_locked();
    pthread_mutex_unlock(&s_hmac_key_mutex);
    return ok;
}

static void qihse_ctr_cleanup_hmac_key(void) {
    pthread_mutex_lock(&s_hmac_key_mutex);
    if (s_hmac_key_loaded) {
        OPENSSL_cleanse(s_hmac_key, sizeof(s_hmac_key));
#ifndef _WIN32
        if (s_hmac_key_mlocked) munlock(s_hmac_key, sizeof(s_hmac_key));
#endif
        s_hmac_key_mlocked = false;
        s_hmac_key_loaded = false;
        s_hmac_test_key = false;
    }
    pthread_mutex_unlock(&s_hmac_key_mutex);
}

static void compute_hmac_sha384(const void* data, size_t len, uint8_t out[48]) {
#ifndef _WIN32
    pthread_mutex_lock(&s_hmac_key_mutex);
    if (load_hmac_key_locked()) {
        unsigned int md_len = 0;
        if (HMAC(EVP_sha384(), s_hmac_key, (int)sizeof(s_hmac_key),
                 (const unsigned char*)data, len, out, &md_len) &&
            md_len == 48u) {
            pthread_mutex_unlock(&s_hmac_key_mutex);
            return;
        }
    }
    pthread_mutex_unlock(&s_hmac_key_mutex);
#endif
    /* Headers/sections with this digest will NOT validate against a real
     * authenticated key. The public open/flush entry points gate missing keys. */
    memset(out, 0, 48);
}

/* ── Serialisation helpers ────────────────────────────────────────── */

static void ctr_write_section_entry(uint8_t* p, const qihse_ctr_section_t* s) {
    /* [u16 id][u16 flags][u32 reserved][u64 offset][u64 length][48-byte hmac][8 pad] */
    memset(p, 0, QIHSE_CTR_SECTION_ENTRY_SIZE);
    p[0] = (uint8_t)(s->section_id & 0xffu);
    p[1] = (uint8_t)((s->section_id >> 8) & 0xffu);
    p[2] = (uint8_t)(s->flags & 0xffu);
    p[3] = (uint8_t)((s->flags >> 8) & 0xffu);
    qihse_le_write_u32(p + 4u, s->reserved);
    qihse_le_write_u64(p + 8u, s->offset);
    qihse_le_write_u64(p + 16u, s->length);
    memcpy(p + 24u, s->hmac_sha384, 48u);
}

static void ctr_read_section_entry(const uint8_t* p, qihse_ctr_section_t* s) {
    s->section_id = (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
    s->flags      = (uint16_t)(p[2] | ((uint16_t)p[3] << 8));
    s->reserved   = qihse_le_read_u32(p + 4u);
    s->offset     = qihse_le_read_u64(p + 8u);
    s->length     = qihse_le_read_u64(p + 16u);
    memcpy(s->hmac_sha384, p + 24u, 48u);
}

/* ── pread / pwrite wrappers ──────────────────────────────────────── */

static bool ctr_pread(int fd, void* buf, size_t size, uint64_t offset) {
    if (offset > INT64_MAX || size > (uint64_t)INT64_MAX - offset) {
        errno = EOVERFLOW;
        return false;
    }
    uint8_t* p = (uint8_t*)buf;
    size_t done = 0u;
    while (done < size) {
        ssize_t n;
        off_t off = (off_t)(offset + done);
#ifdef _WIN32
        n = pread(fd, p + done, size - done, off);
#else
        n = pread(fd, p + done, size - done, off);
#endif
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) { errno = EIO; return false; }
        done += (size_t)n;
    }
    return true;
}

static bool ctr_pwrite(int fd, const void* buf, size_t size, uint64_t offset) {
    if (offset > INT64_MAX || size > (uint64_t)INT64_MAX - offset) {
        errno = EOVERFLOW;
        return false;
    }
    const uint8_t* p = (const uint8_t*)buf;
    size_t done = 0u;
    while (done < size) {
        ssize_t n;
        off_t off = (off_t)(offset + done);
        n = pwrite(fd, p + done, size - done, off);
        if (n < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (n == 0) { errno = EIO; return false; }
        done += (size_t)n;
    }
    return true;
}

/* ── File header encode / decode ──────────────────────────────────── */

/*
 * Header layout (QIHSE_CTR_HEADER_SIZE = 80 bytes):
 *   [0..7]   magic "QIHSEQDB"
 *   [8..11]  version u32
 *   [12..15] flags u32
 *   [16..19] section_count u32
 *   [20..67] header_hmac_sha384 (HMAC-SHA-384 over bytes 0..19)
 *   [68..79] reserved
 */
static void ctr_encode_header(uint8_t hdr[QIHSE_CTR_HEADER_SIZE],
                              uint32_t section_count) {
    memset(hdr, 0, QIHSE_CTR_HEADER_SIZE);
    memcpy(hdr, QIHSE_CTR_MAGIC, 8u);
    qihse_le_write_u32(hdr + 8u,  QIHSE_CTR_VERSION);
    qihse_le_write_u32(hdr + 12u, 0u); /* flags */
    qihse_le_write_u32(hdr + 16u, section_count);
    uint8_t hmac[48];
    compute_hmac_sha384(hdr, 20u, hmac);
    memcpy(hdr + 20u, hmac, 48u);
}

static bool ctr_decode_header(const uint8_t hdr[QIHSE_CTR_HEADER_SIZE],
                               uint32_t* section_count_out) {
    uint8_t expected_hmac[48];

    if (memcmp(hdr, QIHSE_CTR_MAGIC, 8u) != 0) {
        errno = EINVAL;
        return false;
    }
    if (qihse_le_read_u32(hdr + 8u) != QIHSE_CTR_VERSION) {
        errno = EINVAL;
        return false;
    }
    compute_hmac_sha384(hdr, 20u, expected_hmac);
    if (CRYPTO_memcmp(hdr + 20u, expected_hmac, 48u) != 0) {
        errno = EINVAL;
        return false;
    }
    *section_count_out = qihse_le_read_u32(hdr + 16u);
    return true;
}

/* ── POSIX advisory lock helpers ──────────────────────────────────── */

static bool ctr_lock_acquire(int fd) {
#ifndef _WIN32
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type   = F_WRLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;
    return fcntl(fd, F_SETLK, &fl) == 0;
#else
    (void)fd;
    return true;
#endif
}

static bool ctr_lock_release(int fd) {
#ifndef _WIN32
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type   = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fl.l_start  = 0;
    fl.l_len    = 0;
    return fcntl(fd, F_SETLK, &fl) == 0;
#else
    (void)fd;
    return true;
#endif
}

/* ── Internal: read section table from an open fd ─────────────────── */

static bool ctr_read_table(int fd, qihse_ctr_section_t* sections,
                            uint32_t* count_out) {
    uint8_t hdr[QIHSE_CTR_HEADER_SIZE];
    uint32_t count;
    uint32_t i;
    uint8_t entry[QIHSE_CTR_SECTION_ENTRY_SIZE];

    if (!ctr_pread(fd, hdr, sizeof(hdr), 0u)) {
        return false;
    }
    if (!ctr_decode_header(hdr, &count)) {
        return false;
    }
    if (count > QIHSE_CTR_MAX_SECTIONS) {
        errno = EINVAL;
        return false;
    }
    for (i = 0u; i < count; i++) {
        uint64_t entry_offset = QIHSE_CTR_TABLE_OFFSET +
                                (uint64_t)i * QIHSE_CTR_SECTION_ENTRY_SIZE;
        if (!ctr_pread(fd, entry, sizeof(entry), entry_offset)) {
            return false;
        }
        ctr_read_section_entry(entry, &sections[i]);
    }
    /* Header HMAC currently does not bind metadata in the section table.
     * Until an authenticated v2 table exists, at minimum refuse malformed
     * offsets, aliases and overlapping sections before any materialization. */
    struct stat file_stat;
    if (fstat(fd, &file_stat) != 0 || !S_ISREG(file_stat.st_mode) ||
        file_stat.st_size < (off_t)QIHSE_CTR_PAYLOAD_BASE) {
        errno = EINVAL;
        return false;
    }
    const uint64_t file_size = (uint64_t)file_stat.st_size;
    for (i = 0u; i < count; ++i) {
        const qihse_ctr_section_t* s = &sections[i];
        if (s->section_id == 0u ||
            (s->length != 0u &&
             (s->offset < QIHSE_CTR_PAYLOAD_BASE ||
              s->offset > file_size ||
              s->length > file_size - s->offset))) {
            errno = EINVAL;
            return false;
        }
        for (uint32_t j = 0u; j < i; ++j) {
            const qihse_ctr_section_t* prior = &sections[j];
            if (s->section_id == prior->section_id) {
                errno = EINVAL;
                return false;
            }
            if (s->length && prior->length &&
                s->offset < prior->offset + prior->length &&
                prior->offset < s->offset + s->length) {
                errno = EINVAL;
                return false;
            }
        }
    }
    *count_out = count;
    return true;
}

/* ── Internal: write the full header + table to an open fd ─────────── */

static bool ctr_write_table(int fd, const qihse_ctr_section_t* sections,
                             uint32_t count) {
    uint8_t hdr[QIHSE_CTR_HEADER_SIZE];
    uint32_t i;
    uint8_t entry[QIHSE_CTR_SECTION_ENTRY_SIZE];

    ctr_encode_header(hdr, count);
    if (!ctr_pwrite(fd, hdr, sizeof(hdr), 0u)) {
        return false;
    }
    for (i = 0u; i < count; i++) {
        uint64_t entry_offset = QIHSE_CTR_TABLE_OFFSET +
                                (uint64_t)i * QIHSE_CTR_SECTION_ENTRY_SIZE;
        ctr_write_section_entry(entry, &sections[i]);
        if (!ctr_pwrite(fd, entry, sizeof(entry), entry_offset)) {
            return false;
        }
    }
    return true;
}

/* ── Internal: find section index by ID ────────────────────────────── */

static int ctr_find_idx(const qihse_container_t* ctr, uint16_t section_id) {
    uint32_t i;
    for (i = 0u; i < ctr->section_count; i++) {
        if (ctr->sections[i].section_id == section_id) {
            return (int)i;
        }
    }
    return -1;
}

/* ── Public API ─────────────────────────────────────────────────────── */

bool qihse_ctr_open_read(const char* path, qihse_container_t* ctr) {
    int fd;
    uint32_t count = 0u;

    if (!path || !ctr) {
        errno = EINVAL;
        return false;
    }
    memset(ctr, 0, sizeof(*ctr));
    ctr->fd = -1;
    if (!load_hmac_key()) return false;

    fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }

    if (!ctr_read_table(fd, ctr->sections, &count)) {
        close(fd);
        return false;
    }

    ctr->fd = fd;
    ctr->section_count = count;
    ctr->locked = false;
    ctr->read_only = true;
    ctr->path = NULL;

    /* In pre-prod mode (no KEM key file), skip expensive CRC64
     * verification on read. The HMAC key is zero anyway, so the
     * integrity check provides no security. This makes opening a
     * 473MB vector index take <1s instead of 10+ minutes.
     * Set QIHSE_ENFORCE_INTEGRITY=1 to force verification.
     *
     * In production (KEM key present), CRC verification is enabled.
     * Set QIHSE_PARALLEL_CRC=1 to use the unrolled FNV-1a (2x faster)
     * and QIHSE_CRC_THREADS=N to control thread count. */
    {
        bool key_exists = false;
#ifndef _WIN32
        FILE *kf = fopen(QIHSE_KEM_KEY_PATH(), "rb");
        if (kf) { fclose(kf); key_exists = true; }
#endif
        const char* insecure = getenv("QIHSE_ALLOW_INSECURE_CONTAINER");
        bool test_only = insecure && strcmp(insecure, "1") == 0;
        const char* skip = getenv("QIHSE_SKIP_INTEGRITY");
        ctr->skip_integrity = test_only &&
                              getenv("QIHSE_ENFORCE_INTEGRITY") == NULL &&
                              ((!key_exists) || (skip && strcmp(skip, "1") == 0));
        ctr->parallel_crc = (getenv("QIHSE_PARALLEL_CRC") != NULL);
        ctr->use_crc32c = (getenv("QIHSE_CRC32C") != NULL);
        const char* threads_env = getenv("QIHSE_CRC_THREADS");
        ctr->crc_threads = threads_env ? atoi(threads_env) : 0;
    }
    
    {
        int key_idx = ctr_find_idx(ctr, QIHSE_CTR_SEC_KEY);
        if (key_idx >= 0) {
            uint8_t enc_key[QIHSE_MLKEM_CIPHERTEXT_SIZE];
            if (ctr->sections[key_idx].length == QIHSE_MLKEM_CIPHERTEXT_SIZE &&
                ctr_pread(fd, enc_key, QIHSE_MLKEM_CIPHERTEXT_SIZE, ctr->sections[key_idx].offset)) {
                qihse_pqc_init(&ctr->pqc_ctx, enc_key, NULL);
            }
        }
    }
    
    return true;
}

bool qihse_ctr_open_write(const char* path, bool create, qihse_container_t* ctr) {
    int fd;
    uint32_t count = 0u;
    size_t path_len;

    if (!path || !ctr) {
        errno = EINVAL;
        return false;
    }
    memset(ctr, 0, sizeof(*ctr));
    ctr->fd = -1;
    if (!load_hmac_key()) return false;

    if (create) {
        fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    } else {
        fd = open(path, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    }
    if (fd < 0) {
        return false;
    }

    if (!ctr_lock_acquire(fd)) {
        close(fd);
        return false;
    }

    /* TOCTOU mitigation: re-stat after acquiring lock to detect file replacement */
    {
        struct stat st_after_lock;
        if (fstat(fd, &st_after_lock) != 0) {
            ctr_lock_release(fd);
            close(fd);
            return false;
        }
        if (!S_ISREG(st_after_lock.st_mode) || st_after_lock.st_nlink != 1u ||
            (st_after_lock.st_mode & 0002) != 0) {
            ctr_lock_release(fd);
            close(fd);
            errno = EACCES;
            return false;
        }
        /* Verify the file hasn't been replaced between open() and fcntl() */
        struct stat st_path;
        if (stat(path, &st_path) != 0 ||
            st_path.st_dev != st_after_lock.st_dev ||
            st_path.st_ino != st_after_lock.st_ino) {
            ctr_lock_release(fd);
            close(fd);
            errno = ESTALE;
            return false;
        }
    }

    {
        struct stat st;
        if (fstat(fd, &st) != 0) {
            ctr_lock_release(fd);
            close(fd);
            return false;
        }
        if (st.st_size == 0) {
            /* New file: write an empty table */
            uint8_t hdr[QIHSE_CTR_HEADER_SIZE];
            uint8_t table[QIHSE_CTR_TABLE_SIZE];
            ctr_encode_header(hdr, 0u);
            memset(table, 0, sizeof(table));
            if (!ctr_pwrite(fd, hdr, sizeof(hdr), 0u) ||
                !ctr_pwrite(fd, table, sizeof(table), QIHSE_CTR_TABLE_OFFSET)) {
                ctr_lock_release(fd);
                close(fd);
                return false;
            }
            count = 0u;
        } else {
            if (!ctr_read_table(fd, ctr->sections, &count)) {
                ctr_lock_release(fd);
                close(fd);
                return false;
            }
            ctr->section_count = count;
            int key_idx = ctr_find_idx(ctr, QIHSE_CTR_SEC_KEY);
            if (key_idx >= 0) {
                uint8_t enc_key[QIHSE_MLKEM_CIPHERTEXT_SIZE];
                if (ctr->sections[key_idx].length == QIHSE_MLKEM_CIPHERTEXT_SIZE &&
                    ctr_pread(fd, enc_key, QIHSE_MLKEM_CIPHERTEXT_SIZE, ctr->sections[key_idx].offset)) {
                    qihse_pqc_init(&ctr->pqc_ctx, enc_key, NULL);
                }
            }
        }
    }

    if (count == 0u) {
        uint8_t enc_key[QIHSE_MLKEM_CIPHERTEXT_SIZE];
        qihse_pqc_init(&ctr->pqc_ctx, NULL, enc_key);
        /* The flush operation will write this new SEC_KEY into the database automatically */
    }

    path_len = strlen(path);
    ctr->path = (char*)malloc(path_len + 1u);
    if (!ctr->path) {
        ctr_lock_release(fd);
        close(fd);
        return false;
    }
    memcpy(ctr->path, path, path_len + 1u);

    ctr->fd = fd;
    ctr->section_count = count;
    ctr->locked = true;
    return true;
}

void qihse_ctr_close(qihse_container_t* ctr) {
    if (!ctr) return;
    if (ctr->fd >= 0) {
        if (ctr->locked) {
            ctr_lock_release(ctr->fd);
        }
        close(ctr->fd);
        ctr->fd = -1;
    }
    free(ctr->path);
    ctr->path = NULL;
    ctr->locked = false;
    ctr->section_count = 0u;
    qihse_ctr_cleanup_hmac_key();
}

const qihse_ctr_section_t* qihse_ctr_find_section(const qihse_container_t* ctr,
                                                   uint16_t section_id) {
    int idx;
    if (!ctr) return NULL;
    idx = ctr_find_idx(ctr, section_id);
    if (idx < 0 || ctr->sections[idx].length == 0u) return NULL;
    return &ctr->sections[idx];
}

bool qihse_ctr_read_section_alloc(const qihse_container_t* ctr,
                                  uint16_t section_id,
                                  uint8_t** out,
                                  size_t* out_size) {
    const qihse_ctr_section_t* sec;
    uint8_t* buf;

    if (!ctr || !out || !out_size) {
        errno = EINVAL;
        return false;
    }
    *out = NULL;
    *out_size = 0u;

    sec = qihse_ctr_find_section(ctr, section_id);
    if (!sec) {
        printf("[DEBUG] section_id %u not found in container\\n", section_id);
        errno = ENOENT;
        return false;
    }
    if (sec->length > (uint64_t)SIZE_MAX) {
        errno = EOVERFLOW;
        return false;
    }
    buf = (uint8_t*)malloc((size_t)sec->length ? (size_t)sec->length : 1u);
    if (!buf) {
        errno = ENOMEM;
        return false;
    }
    if (!ctr_pread(ctr->fd, buf, (size_t)sec->length, sec->offset)) {
        printf("[DEBUG] ctr_pread failed for section %u\\n", section_id);
        free(buf);
        return false;
    }
    uint8_t computed_hmac[48];
    compute_hmac_sha384(buf, (size_t)sec->length, computed_hmac);
    if (!ctr->skip_integrity &&
        sec->section_id != QIHSE_CTR_SEC_WAL &&
        CRYPTO_memcmp(computed_hmac, sec->hmac_sha384, 48u) != 0) {
        fprintf(stderr, "[CONTAINER] HMAC-SHA-384 mismatch for section %u\n", section_id);
        free(buf);
        errno = EINVAL;
        return false;
    }
    *out = buf;
    *out_size = (size_t)sec->length;
    return true;
}

bool qihse_ctr_read_section_at(const qihse_container_t* ctr,
                                uint16_t section_id,
                                void* buf,
                                size_t size,
                                uint64_t sec_offset) {
    const qihse_ctr_section_t* sec;
    uint64_t end;

    if (!ctr || (!buf && size != 0u)) {
        errno = EINVAL;
        return false;
    }
    if (size == 0u) return true;

    sec = qihse_ctr_find_section(ctr, section_id);
    if (!sec) {
        errno = ENOENT;
        return false;
    }
    if (sec_offset > sec->length ||
        (uint64_t)size > sec->length - sec_offset) {
        errno = EINVAL;
        return false;
    }
    end = sec->offset + sec_offset;
    return ctr_pread(ctr->fd, buf, size, end);
}

uint64_t qihse_ctr_section_length(const qihse_container_t* ctr, uint16_t section_id) {
    int idx;
    if (!ctr) return 0u;
    idx = ctr_find_idx(ctr, section_id);
    if (idx < 0) return 0u;
    return ctr->sections[idx].length;
}

/* ── Atomic flush ──────────────────────────────────────────────────── */
/* Retain a lock on BOTH the old file and replacement inode through rename.
 * POSIX fcntl record locks are inode-specific: keeping a lock on the old fd
 * alone would protect a now-unlinked file, not the published container. */
bool qihse_ctr_flush(qihse_container_t* ctr,
                     const qihse_ctr_section_buf_t* bufs,
                     size_t buf_count) {
    char tmp_path[PATH_MAX] = {0};
    int tmp_fd = -1;
    bool ok = false, renamed = false;
    qihse_ctr_section_t new_sections[QIHSE_CTR_MAX_SECTIONS] = {{0}};
    uint32_t new_count = 0;
    uint64_t write_offset = QIHSE_CTR_PAYLOAD_BASE;

    if (!ctr || !ctr->path || ctr->fd < 0 || !ctr->locked ||
        (!bufs && buf_count != 0u)) {
        errno = EINVAL;
        return false;
    }
    if (!load_hmac_key()) return false;

    /* A writer must never flush an inode already replaced by another writer. */
    struct stat src_stat, path_stat;
    if (fstat(ctr->fd, &src_stat) != 0 ||
        stat(ctr->path, &path_stat) != 0 ||
        !S_ISREG(src_stat.st_mode) ||
        src_stat.st_dev != path_stat.st_dev ||
        src_stat.st_ino != path_stat.st_ino) {
        errno = ESTALE;
        return false;
    }

    /* Duplicate section IDs are ambiguous and could conceal an earlier
     * entry when readers resolve the first matching section. */
    for (size_t i = 0; i < buf_count; ++i) {
        for (size_t j = 0; j < i; ++j) {
            if (bufs[j].section_id == bufs[i].section_id) {
                errno = EINVAL;
                return false;
            }
        }
    }

    size_t path_len = strlen(ctr->path);
    const char* suffix = ".tmp.XXXXXX";
    size_t suffix_len = strlen(suffix);
    if (path_len >= sizeof(tmp_path) ||
        suffix_len >= sizeof(tmp_path) - path_len) {
        errno = ENAMETOOLONG;
        return false;
    }
    memcpy(tmp_path, ctr->path, path_len);
    memcpy(tmp_path + path_len, suffix, suffix_len + 1u);
    tmp_fd = mkstemp(tmp_path);
    if (tmp_fd < 0) return false;
    if (fchmod(tmp_fd, S_IRUSR | S_IWUSR) != 0) goto out;

    uint8_t zeros[QIHSE_CTR_HEADER_SIZE + QIHSE_CTR_TABLE_SIZE] = {0};
    if (!ctr_pwrite(tmp_fd, zeros, sizeof(zeros), 0u)) goto out;

    for (size_t i = 0; i < buf_count; ++i) {
        const qihse_ctr_section_buf_t* section = &bufs[i];
        if (!section->data || section->size == 0u) continue;
        if (new_count >= QIHSE_CTR_MAX_SECTIONS ||
            section->size > INT64_MAX ||
            write_offset > (uint64_t)INT64_MAX - (uint64_t)section->size) {
            errno = EOVERFLOW;
            goto out;
        }
        if (!ctr_pwrite(tmp_fd, section->data, section->size, write_offset))
            goto out;
        qihse_ctr_section_t* entry = &new_sections[new_count++];
        entry->section_id = section->section_id;
        entry->offset = write_offset;
        entry->length = (uint64_t)section->size;
        compute_hmac_sha384(section->data, section->size, entry->hmac_sha384);
        write_offset += (uint64_t)section->size;
    }

    /* Copy unchanged sections with bounded memory rather than malloc'ing
     * an attacker-declared section length in one allocation. */
    uint8_t* copy_buf = malloc(64u * 1024u);
    if (!copy_buf) { errno = ENOMEM; goto out; }
    for (uint32_t i = 0; i < ctr->section_count; ++i) {
        const qihse_ctr_section_t* old = &ctr->sections[i];
        if (old->length == 0u) continue;
        bool replaced = false;
        for (size_t j = 0; j < buf_count; ++j) {
            if (bufs[j].section_id == old->section_id) {
                replaced = true;
                break;
            }
        }
        if (replaced) continue;
        if (new_count >= QIHSE_CTR_MAX_SECTIONS ||
            old->length > (uint64_t)INT64_MAX - write_offset) {
            errno = EOVERFLOW;
            goto copy_failed;
        }
        uint64_t done = 0u;
        while (done < old->length) {
            size_t n = (old->length - done > 65536u)
                     ? 65536u : (size_t)(old->length - done);
            if (!ctr_pread(ctr->fd, copy_buf, n, old->offset + done) ||
                !ctr_pwrite(tmp_fd, copy_buf, n, write_offset + done))
                goto copy_failed;
            done += n;
        }
        new_sections[new_count] = *old;
        new_sections[new_count].offset = write_offset;
        ++new_count;
        write_offset += old->length;
    }
    free(copy_buf);
    copy_buf = NULL;

    if (!ctr_write_table(tmp_fd, new_sections, new_count)) goto out;

    /* Acquire the new inode's lock BEFORE replacing the pathname. */
    if (!ctr_lock_acquire(tmp_fd)) goto out;
#ifndef _WIN32
    if (fsync(tmp_fd) != 0) goto out;
#else
    if (_commit(tmp_fd) != 0) goto out;
#endif
    if (rename(tmp_path, ctr->path) != 0) goto out;
    renamed = true;

    /* New fd already locked: transfer ownership rather than reading an
     * obsolete table from the old, now-unlinked inode. */
    int old_fd = ctr->fd;
    ctr->fd = tmp_fd;
    tmp_fd = -1;
    memcpy(ctr->sections, new_sections, new_count * sizeof(new_sections[0]));
    ctr->section_count = new_count;
    (void)ctr_lock_release(old_fd);
    close(old_fd);
    ok = true;

#ifndef _WIN32
    /* fsync of the parent directory makes the rename durable after crashes.
     * On fsync failure the new fd remains live, but durable publication is
     * NOT claimed. Callers must handle a false return as uncertain commit. */
    char dir[PATH_MAX];
    memcpy(dir, ctr->path, path_len + 1u);
    char* slash = strrchr(dir, '/');
    if (!slash) {
        strcpy(dir, ".");
    } else if (slash == dir) {
        slash[1] = '\0';
    } else {
        *slash = '\0';
    }
    int dir_fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0) {
        ok = false;
    } else {
        if (fsync(dir_fd) != 0) ok = false;
        close(dir_fd);
    }
#endif
    goto out;

copy_failed:
    free(copy_buf);
out:
    if (tmp_fd >= 0) close(tmp_fd);
    if (!renamed && tmp_path[0]) (void)unlink(tmp_path);
    return ok;
}

/* ── WAL helpers ────────────────────────────────────────────────────── */

bool qihse_ctr_wal_append(qihse_container_t* ctr, const void* data, size_t size) {
    int idx;
    uint64_t wal_end;
    uint64_t new_length;
    bool is_new_section = false;

    if (!ctr || ctr->fd < 0 || (!data && size != 0u)) {
        errno = EINVAL;
        return false;
    }
    if (size == 0u) return true;

    idx = ctr_find_idx(ctr, QIHSE_CTR_SEC_WAL);
    if (idx < 0) {
        /* First WAL write — add a new section entry */
        if (ctr->section_count >= QIHSE_CTR_MAX_SECTIONS) {
            errno = ENOMEM;
            return false;
        }
        idx = (int)ctr->section_count;
        memset(&ctr->sections[idx], 0, sizeof(ctr->sections[idx]));
        ctr->sections[idx].section_id = QIHSE_CTR_SEC_WAL;
        /* Place WAL after all existing payloads */
        wal_end = QIHSE_CTR_PAYLOAD_BASE;
        {
            uint32_t i;
            for (i = 0u; i < ctr->section_count; i++) {
                uint64_t end = ctr->sections[i].offset + ctr->sections[i].length;
                if (end > wal_end) wal_end = end;
            }
        }
        ctr->sections[idx].offset = wal_end;
        ctr->sections[idx].length = 0u;
        ctr->section_count++;
        is_new_section = true;
    }

    wal_end = ctr->sections[idx].offset + ctr->sections[idx].length;
    if (!ctr_pwrite(ctr->fd, data, size, wal_end)) {
        return false;
    }

    new_length = ctr->sections[idx].length + (uint64_t)size;
    ctr->sections[idx].length = new_length;

    /* Update the section table entry on disk (length field at entry+16) */
    {
        uint8_t len_bytes[8];
        uint32_t entry_idx = (uint32_t)idx;
        uint64_t field_off = QIHSE_CTR_TABLE_OFFSET +
                             (uint64_t)entry_idx * QIHSE_CTR_SECTION_ENTRY_SIZE + 16u;
        qihse_le_write_u64(len_bytes, new_length);
        if (!ctr_pwrite(ctr->fd, len_bytes, 8u, field_off)) {
            return false;
        }
        /* Also update section_count in header if new entry was added */
        if (is_new_section) {
            uint8_t hdr[QIHSE_CTR_HEADER_SIZE];
            ctr_encode_header(hdr, ctr->section_count);
            if (!ctr_pwrite(ctr->fd, hdr, sizeof(hdr), 0u)) {
                return false;
            }
            /* Write the full new entry */
            {
                uint8_t entry_buf[QIHSE_CTR_SECTION_ENTRY_SIZE];
                uint64_t entry_off = QIHSE_CTR_TABLE_OFFSET +
                                     (uint64_t)idx * QIHSE_CTR_SECTION_ENTRY_SIZE;
                ctr_write_section_entry(entry_buf, &ctr->sections[idx]);
                if (!ctr_pwrite(ctr->fd, entry_buf, sizeof(entry_buf), entry_off)) {
                    return false;
                }
            }
        }
    }
    return true;
}

bool qihse_ctr_wal_truncate(qihse_container_t* ctr, uint64_t new_length) {
    int idx;
    uint8_t len_bytes[8];
    uint64_t field_off;

    if (!ctr || ctr->fd < 0) {
        errno = EINVAL;
        return false;
    }

    idx = ctr_find_idx(ctr, QIHSE_CTR_SEC_WAL);
    if (idx < 0) return true; /* Nothing to truncate */

    if (new_length > ctr->sections[idx].length) {
        errno = EINVAL;
        return false;
    }

    ctr->sections[idx].length = new_length;

    /* Update length on disk */
    field_off = QIHSE_CTR_TABLE_OFFSET +
                (uint64_t)idx * QIHSE_CTR_SECTION_ENTRY_SIZE + 16u;
    qihse_le_write_u64(len_bytes, new_length);
    if (!ctr_pwrite(ctr->fd, len_bytes, 8u, field_off)) {
        return false;
    }

    /* Physically truncate the file if WAL is the last section */
    {
        uint64_t file_end = ctr->sections[idx].offset + new_length;
        /* Check no other section follows the WAL */
        bool is_last = true;
        uint32_t i;
        for (i = 0u; i < ctr->section_count; i++) {
            if ((uint32_t)i == (uint32_t)idx) continue;
            if (ctr->sections[i].offset >= ctr->sections[idx].offset) {
                is_last = false;
                break;
            }
        }
        if (is_last) {
#ifndef _WIN32
            (void)ftruncate(ctr->fd, (off_t)file_end);
#else
            (void)_chsize(ctr->fd, (long)file_end);
#endif
        }
    }
    return true;
}

bool qihse_ctr_fsync(qihse_container_t* ctr) {
    if (!ctr || ctr->fd < 0) { errno = EINVAL; return false; }
#ifndef _WIN32
    int rc;
    do { rc = fsync(ctr->fd); } while (rc != 0 && errno == EINTR);
    return rc == 0;
#else
    return _commit(ctr->fd) == 0;
#endif
}
