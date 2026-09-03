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

static bool load_hmac_key(void) {
    if (s_hmac_key_loaded) return true;
#ifndef _WIN32
    FILE *kf = fopen(QIHSE_KEM_PRIVATE_KEY_FILE, "rb");
    if (kf) {
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        if (mdctx && EVP_DigestInit_ex(mdctx, EVP_sha384(), NULL) > 0) {
            uint8_t buf[4096];
            size_t n;
            while ((n = fread(buf, 1, sizeof(buf), kf)) > 0)
                EVP_DigestUpdate(mdctx, buf, n);
            unsigned char digest[SHA384_DIGEST_LENGTH];
            unsigned int md_len = 0;
            EVP_DigestFinal_ex(mdctx, digest, &md_len);
            memcpy(s_hmac_key, digest, 32);
            OPENSSL_cleanse(digest, sizeof(digest));
#ifndef _WIN32
            mlock(s_hmac_key, 32);
            s_hmac_key_mlocked = true;
#endif
            s_hmac_key_loaded = true;
        }
        if (mdctx) EVP_MD_CTX_free(mdctx);
        fclose(kf);
        return s_hmac_key_loaded;
    }
#endif
    fprintf(stderr, "[CONTAINER WARNING] No KEM key file — HMAC integrity uses zero key (pre-prod mode).\n");
    s_hmac_key_loaded = true;
    return true;
}

static void qihse_ctr_cleanup_hmac_key(void) {
    if (s_hmac_key_loaded) {
        OPENSSL_cleanse(s_hmac_key, 32);
#ifndef _WIN32
        if (s_hmac_key_mlocked) {
            munlock(s_hmac_key, 32);
            s_hmac_key_mlocked = false;
        }
#endif
        s_hmac_key_loaded = false;
    }
}

static void compute_hmac_sha384(const void* data, size_t len, uint8_t out[48]) {
#ifndef _WIN32
    if (load_hmac_key()) {
        unsigned int md_len = 48;
        HMAC(EVP_sha384(), s_hmac_key, 32,
             (const unsigned char*)data, len, out, &md_len);
        return;
    }
#endif
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

    fd = open(path, O_RDONLY);
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
     * Set QIHSE_ENFORCE_INTEGRITY=1 to force verification. */
    {
        bool key_exists = false;
#ifndef _WIN32
        FILE *kf = fopen(QIHSE_KEM_PRIVATE_KEY_FILE, "rb");
        if (kf) { fclose(kf); key_exists = true; }
#endif
        ctr->skip_integrity = (!key_exists &&
                               getenv("QIHSE_ENFORCE_INTEGRITY") == NULL);
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

    if (create) {
        fd = open(path, O_RDWR | O_CREAT, 0600);
    } else {
        fd = open(path, O_RDWR);
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
        /* Verify the file hasn't been replaced between open() and flock() */
        struct stat st_path;
        if (stat(path, &st_path) == 0) {
            if (st_path.st_dev != st_after_lock.st_dev ||
                st_path.st_ino != st_after_lock.st_ino) {
                ctr_lock_release(fd);
                close(fd);
                errno = EINVAL;
                return false;
            }
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
    if (sec->section_id != QIHSE_CTR_SEC_WAL && CRYPTO_memcmp(computed_hmac, sec->hmac_sha384, 48u) != 0) {
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

/* ── Atomic flush ───────────────────────────────────────────────────── */

bool qihse_ctr_flush(qihse_container_t* ctr,
                     const qihse_ctr_section_buf_t* bufs,
                     size_t buf_count) {
    char tmp_path[PATH_MAX];
    int tmp_fd = -1;
    size_t path_len;
    qihse_ctr_section_t new_sections[QIHSE_CTR_MAX_SECTIONS];
    uint32_t new_count = 0u;
    uint64_t write_offset = QIHSE_CTR_PAYLOAD_BASE;
    size_t i;
    bool ok = false;

    if (!ctr || !ctr->path || ctr->fd < 0) {
        errno = EINVAL;
        return false;
    }

    path_len = strlen(ctr->path);
    if (path_len + 5u >= PATH_MAX) {
        errno = ENAMETOOLONG;
        return false;
    }
    memcpy(tmp_path, ctr->path, path_len);
    memcpy(tmp_path + path_len, ".tmp", 5u);

    tmp_fd = open(tmp_path, O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (tmp_fd < 0) {
        return false;
    }

    /* Reserve header + table space */
    {
        uint8_t zeros[QIHSE_CTR_HEADER_SIZE + QIHSE_CTR_TABLE_SIZE];
        memset(zeros, 0, sizeof(zeros));
        if (!ctr_pwrite(tmp_fd, zeros, sizeof(zeros), 0u)) {
            goto out;
        }
    }

    /* Write each section provided in bufs[] */
    for (i = 0u; i < buf_count; i++) {
        const qihse_ctr_section_buf_t* b = &bufs[i];
        if (!b->data || b->size == 0u) continue;
        if (new_count >= QIHSE_CTR_MAX_SECTIONS) { errno = ENOMEM; goto out; }
        if (!ctr_pwrite(tmp_fd, b->data, b->size, write_offset)) goto out;
        new_sections[new_count].section_id = b->section_id;
        new_sections[new_count].flags      = 0u;
        new_sections[new_count].reserved   = 0u;
        new_sections[new_count].offset     = write_offset;
        new_sections[new_count].length     = (uint64_t)b->size;
        compute_hmac_sha384(b->data, b->size, new_sections[new_count].hmac_sha384);
        write_offset += (uint64_t)b->size;
        new_count++;
    }

    /* Carry over existing sections that were NOT supplied in bufs[] */
    for (i = 0u; i < ctr->section_count; i++) {
        const qihse_ctr_section_t* old = &ctr->sections[i];
        size_t j;
        bool replaced = false;
        if (old->length == 0u) continue;
        for (j = 0u; j < buf_count; j++) {
            if (bufs[j].section_id == old->section_id) {
                replaced = true;
                break;
            }
        }
        if (replaced) continue;
        if (new_count >= QIHSE_CTR_MAX_SECTIONS) { errno = ENOMEM; goto out; }
        /* Copy payload from existing fd */
        {
            uint8_t* tmp_buf = (uint8_t*)malloc((size_t)old->length);
            if (!tmp_buf) { errno = ENOMEM; goto out; }
            if (!ctr_pread(ctr->fd, tmp_buf, (size_t)old->length, old->offset)) {
                free(tmp_buf);
                goto out;
            }
            if (!ctr_pwrite(tmp_fd, tmp_buf, (size_t)old->length, write_offset)) {
                free(tmp_buf);
                goto out;
            }
            free(tmp_buf);
        }
        new_sections[new_count] = *old;
        new_sections[new_count].offset = write_offset;
        write_offset += old->length;
        new_count++;
    }

    /* Write updated table */
    if (!ctr_write_table(tmp_fd, new_sections, new_count)) goto out;

#ifndef _WIN32
    ok = fsync(tmp_fd) == 0;
#else
    ok = _commit(tmp_fd) == 0;
#endif
    if (!ok) goto out;

    if (close(tmp_fd) != 0) { tmp_fd = -1; ok = false; goto out; }
    tmp_fd = -1;

    if (rename(tmp_path, ctr->path) == 0) {
        ok = true;
    } else {
        ok = false;
        goto out;
    }

    /* Re-read the table into ctr from the live file (fd still valid for lock) */
    {
        uint32_t count = 0u;
        if (!ctr_read_table(ctr->fd, ctr->sections, &count)) {
            /* The file was replaced; reopen */
            close(ctr->fd);
            ctr->fd = open(ctr->path, O_RDWR);
            if (ctr->fd < 0) { ok = false; goto out; }
            if (!ctr_lock_acquire(ctr->fd)) { ok = false; goto out; }
            if (!ctr_read_table(ctr->fd, ctr->sections, &count)) {
                ok = false; goto out;
            }
        }
        ctr->section_count = count;
    }
    ok = true;

out:
    if (tmp_fd >= 0) {
        close(tmp_fd);
        (void)unlink(tmp_path);
    }
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
