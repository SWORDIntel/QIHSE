/* QIHSE per-lane, per-generation QKV6 retention log.
 *
 * The global WAL remains the KV recovery source until SST publication. This
 * sidecar is the independently bounded retransmission source for one lane.
 * Appenders write and sync the frame before publishing the alternate checked
 * header slot. A replay can therefore repeat an append after a lost header
 * update. ACK compaction publishes a new file atomically after the caller has
 * persisted the ACK and made the rows durable in the SST.
 */
#define CTLL_SLOT_BYTES 320u
#define CTLL_FILE_HEADER_BYTES (2u * CTLL_SLOT_BYTES)
#define CTLL_FOOTER_BYTES 16u
#define CTLL_HEADER_MAGIC "QCLG0001"
#define CTLL_FOOTER_MAGIC "QCLF"

typedef struct {
    uint64_t sequence;
    uint64_t acknowledged;
    uint64_t last_position;
    uint64_t retained_bytes;
    char lane_id[QIHSE_KV_CT_LANE_ID_MAX + 1u];
    char source_id[QIHSE_KV_CT_ID_MAX + 1u];
    char generation[QIHSE_KV_CT_ID_MAX + 1u];
} ct_lane_log_header_t;

static void ctll_put16(unsigned char *p, uint16_t value) {
    p[0] = (unsigned char)(value >> 8u);
    p[1] = (unsigned char)value;
}

static uint16_t ctll_get16(const unsigned char *p) {
    return (uint16_t)(((uint16_t)p[0] << 8u) | p[1]);
}

static void ctll_put32(unsigned char *p, uint32_t value) {
    p[0] = (unsigned char)(value >> 24u);
    p[1] = (unsigned char)(value >> 16u);
    p[2] = (unsigned char)(value >> 8u);
    p[3] = (unsigned char)value;
}

static uint32_t ctll_get32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24u) | ((uint32_t)p[1] << 16u) |
           ((uint32_t)p[2] << 8u) | (uint32_t)p[3];
}

static void ctll_put64(unsigned char *p, uint64_t value) {
    for (size_t i = 0; i < 8u; ++i)
        p[i] = (unsigned char)(value >> (56u - i * 8u));
}

static uint64_t ctll_get64(const unsigned char *p) {
    uint64_t value = 0u;
    for (size_t i = 0; i < 8u; ++i)
        value = (value << 8u) | p[i];
    return value;
}

static bool ctll_digest(unsigned char bytes[CTLL_SLOT_BYTES]) {
    unsigned char digest[32];
    unsigned int digest_len = 0u;
    memset(bytes + CTLL_SLOT_BYTES - 32u, 0, 32u);
    if (!EVP_Digest(bytes, CTLL_SLOT_BYTES, digest, &digest_len,
                    EVP_sha256(), NULL) || digest_len != 32u)
        return false;
    memcpy(bytes + CTLL_SLOT_BYTES - 32u, digest, sizeof(digest));
    return true;
}

static bool ctll_encode_header(const ct_lane_log_header_t *header,
                               unsigned char bytes[CTLL_SLOT_BYTES]) {
    if (!header || !ct_lane_id_valid(header->lane_id) ||
        !ct_id_valid(header->source_id) || !ct_id_valid(header->generation) ||
        header->acknowledged > header->last_position)
        return false;
    memset(bytes, 0, CTLL_SLOT_BYTES);
    memcpy(bytes, CTLL_HEADER_MAGIC, 8u);
    ctll_put64(bytes + 8u, header->sequence);
    ctll_put64(bytes + 16u, header->acknowledged);
    ctll_put64(bytes + 24u, header->last_position);
    ctll_put64(bytes + 32u, header->retained_bytes);
    size_t lane_len = strlen(header->lane_id);
    size_t source_len = strlen(header->source_id);
    size_t generation_len = strlen(header->generation);
    ctll_put16(bytes + 40u, (uint16_t)lane_len);
    ctll_put16(bytes + 42u, (uint16_t)source_len);
    ctll_put16(bytes + 44u, (uint16_t)generation_len);
    memcpy(bytes + 48u, header->lane_id, lane_len);
    memcpy(bytes + 113u, header->source_id, source_len);
    memcpy(bytes + 178u, header->generation, generation_len);
    return ctll_digest(bytes);
}

static bool ctll_decode_header(const unsigned char bytes[CTLL_SLOT_BYTES],
                               ct_lane_log_header_t *out) {
    if (!bytes || !out || memcmp(bytes, CTLL_HEADER_MAGIC, 8u) != 0)
        return false;
    unsigned char checked[CTLL_SLOT_BYTES];
    memcpy(checked, bytes, sizeof(checked));
    unsigned char saved[32];
    memcpy(saved, checked + sizeof(checked) - sizeof(saved), sizeof(saved));
    memset(checked + sizeof(checked) - sizeof(saved), 0, sizeof(saved));
    unsigned char calculated[32];
    unsigned int calculated_len = 0u;
    if (!EVP_Digest(checked, sizeof(checked), calculated, &calculated_len,
                    EVP_sha256(), NULL) || calculated_len != sizeof(saved) ||
        CRYPTO_memcmp(saved, calculated, sizeof(saved)) != 0)
        return false;
    uint16_t lane_len = ctll_get16(bytes + 40u);
    uint16_t source_len = ctll_get16(bytes + 42u);
    uint16_t generation_len = ctll_get16(bytes + 44u);
    if (!lane_len || lane_len > QIHSE_KV_CT_LANE_ID_MAX ||
        !source_len || source_len > QIHSE_KV_CT_ID_MAX ||
        !generation_len || generation_len > QIHSE_KV_CT_ID_MAX)
        return false;
    for (size_t i = 46u; i < 48u; ++i)
        if (bytes[i]) return false;
    for (size_t i = 48u + lane_len; i < 113u; ++i)
        if (bytes[i]) return false;
    for (size_t i = 113u + source_len; i < 178u; ++i)
        if (bytes[i]) return false;
    for (size_t i = 178u + generation_len; i < sizeof(checked) - 32u; ++i)
        if (bytes[i]) return false;
    memset(out, 0, sizeof(*out));
    out->sequence = ctll_get64(bytes + 8u);
    out->acknowledged = ctll_get64(bytes + 16u);
    out->last_position = ctll_get64(bytes + 24u);
    out->retained_bytes = ctll_get64(bytes + 32u);
    memcpy(out->lane_id, bytes + 48u, lane_len);
    memcpy(out->source_id, bytes + 113u, source_len);
    memcpy(out->generation, bytes + 178u, generation_len);
    return out->sequence && out->acknowledged <= out->last_position &&
           ct_lane_id_valid(out->lane_id) && ct_id_valid(out->source_id) &&
           ct_id_valid(out->generation);
}

static bool ctll_path(qihse_kv_store_t *store, const char *lane_id,
                      const char *generation, char *out, size_t out_size) {
    char suffix[192];
    if (!store || store->memory_snapshot || !ct_lane_id_valid(lane_id) ||
        !ct_id_valid(generation))
        return false;
    int n = snprintf(suffix, sizeof(suffix), "ct-lane-log-%s-%s.qcl",
                     lane_id, generation);
    return n > 0 && (size_t)n < sizeof(suffix) &&
           build_data_path(out, out_size, suffix);
}

static bool ctll_pread(int fd, void *buffer, size_t bytes, off_t offset) {
    unsigned char *p = buffer;
    size_t done = 0u;
    while (done < bytes) {
        ssize_t n = pread(fd, p + done, bytes - done, offset + (off_t)done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}

static bool ctll_pwrite(int fd, const void *buffer, size_t bytes, off_t offset) {
    const unsigned char *p = buffer;
    size_t done = 0u;
    while (done < bytes) {
        ssize_t n = pwrite(fd, p + done, bytes - done, offset + (off_t)done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}

static bool ctll_read_header(int fd, const struct stat *st,
                             const char *lane_id, const char *source_id,
                             const char *generation,
                             ct_lane_log_header_t *out,
                             unsigned *out_slot) {
    if (!st || !S_ISREG(st->st_mode) ||
        st->st_size < (off_t)CTLL_FILE_HEADER_BYTES ||
        st->st_uid != geteuid() || st->st_nlink != 1 || (st->st_mode & 077u))
        return false;
    unsigned char slots[2][CTLL_SLOT_BYTES];
    ct_lane_log_header_t headers[2];
    bool valid[2] = {
        ctll_pread(fd, slots[0], CTLL_SLOT_BYTES, 0) &&
            ctll_decode_header(slots[0], &headers[0]),
        ctll_pread(fd, slots[1], CTLL_SLOT_BYTES, CTLL_SLOT_BYTES) &&
            ctll_decode_header(slots[1], &headers[1])
    };
    unsigned selected;
    if (!valid[0] && !valid[1]) return false;
    if (!valid[1] || (valid[0] && headers[0].sequence > headers[1].sequence))
        selected = 0u;
    else
        selected = 1u;
    ct_lane_log_header_t *h = &headers[selected];
    if (strcmp(h->lane_id, lane_id) || strcmp(h->source_id, source_id) ||
        strcmp(h->generation, generation) ||
        h->retained_bytes > (uint64_t)INT64_MAX - CTLL_FILE_HEADER_BYTES ||
        st->st_size < (off_t)(CTLL_FILE_HEADER_BYTES + h->retained_bytes))
        return false;
    *out = *h;
    if (out_slot) *out_slot = selected;
    return true;
}

static bool ctll_write_header(int fd, ct_lane_log_header_t *header,
                              unsigned current_slot) {
    if (header->sequence == UINT64_MAX) { errno = EOVERFLOW; return false; }
    header->sequence++;
    unsigned target = current_slot ^ 1u;
    unsigned char bytes[CTLL_SLOT_BYTES];
    bool ok = ctll_encode_header(header, bytes) &&
              ctll_pwrite(fd, bytes, sizeof(bytes),
                          (off_t)target * CTLL_SLOT_BYTES) && fsync(fd) == 0;
    OPENSSL_cleanse(bytes, sizeof(bytes));
    return ok;
}

static bool ctll_write_new_file(const char *path, const char *lane_id,
                                const char *source_id, const char *generation,
                                uint64_t acknowledged_position,
                                int *out_fd, ct_lane_log_header_t *out_header,
                                unsigned *out_slot) {
    int fd = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    ct_lane_log_header_t h = {0};
    h.sequence = 1u;
    h.acknowledged = acknowledged_position;
    h.last_position = acknowledged_position;
    snprintf(h.lane_id, sizeof(h.lane_id), "%s", lane_id);
    snprintf(h.source_id, sizeof(h.source_id), "%s", source_id);
    snprintf(h.generation, sizeof(h.generation), "%s", generation);
    unsigned char slot[CTLL_SLOT_BYTES];
    bool ok = ctll_encode_header(&h, slot) &&
        ctll_pwrite(fd, slot, sizeof(slot), 0) &&
        ctll_pwrite(fd, slot, sizeof(slot), CTLL_SLOT_BYTES) &&
        fsync(fd) == 0 && fsync_dir_path(get_qihse_data_dir());
    OPENSSL_cleanse(slot, sizeof(slot));
    if (!ok) { int saved = errno; close(fd); unlink(path); fsync_dir_path(get_qihse_data_dir()); errno = saved; return false; }
    *out_fd = fd;
    *out_header = h;
    *out_slot = 1u;
    return true;
}

static bool ctll_validate_frame(const unsigned char *bytes, size_t length,
                                qihse_user_t *principal,
                                qihse_kv_ct_tenant_policy_t policy,
                                uint32_t tenant, const char *source_id,
                                const char *generation, uint64_t position) {
    if (!bytes || !length || length > QIHSE_CT_CODEC_MAX_FRAME ||
        length > INT_MAX)
        return false;
    FILE *input = fmemopen((void *)bytes, length, "rb");
    if (!input) return false;
    qihse_kv_ct_group_t group = {0};
    uint8_t mode = 0u;
    size_t consumed = 0u;
    int rc = qihse_ct_codec_read(input, principal, policy, tenant, length,
                                 &group, &mode, &consumed);
    fclose(input);
    bool ok = rc == 1 && consumed == length &&
        mode == QIHSE_KV_CT_LANE_SOURCE &&
        group.stream_position == position &&
        !strcmp(group.source_id, source_id) &&
        !strcmp(group.generation, generation);
    qihse_ct_codec_clear(&group);
    return ok;
}

static bool ctll_read_frame(int fd, off_t offset, off_t end,
                            qihse_user_t *principal,
                            qihse_kv_ct_tenant_policy_t policy,
                            uint32_t tenant, const char *source_id,
                            const char *generation, uint64_t expected_position,
                            unsigned char **out_frame, size_t *out_frame_len,
                            off_t *out_next) {
    *out_frame = NULL;
    *out_frame_len = 0u;
    *out_next = offset;
    if (end - offset < 64) return false;
    unsigned char prefix[64];
    if (!ctll_pread(fd, prefix, sizeof(prefix), offset) ||
        memcmp(prefix, "QKV6CT01", 8u) != 0)
        return false;
    uint32_t frame_len = ctll_get32(prefix + 12u);
    if (frame_len < sizeof(prefix) || frame_len > QIHSE_CT_CODEC_MAX_FRAME ||
        (uint64_t)frame_len + CTLL_FOOTER_BYTES > (uint64_t)(end - offset))
        return false;
    unsigned char *frame = malloc(frame_len);
    if (!frame) return false;
    if (!ctll_pread(fd, frame, frame_len, offset) ||
        !ctll_validate_frame(frame, frame_len, principal, policy, tenant,
                            source_id, generation, expected_position)) {
        free(frame);
        return false;
    }
    unsigned char footer[CTLL_FOOTER_BYTES];
    if (!ctll_pread(fd, footer, sizeof(footer), offset + frame_len) ||
        memcmp(footer, CTLL_FOOTER_MAGIC, 4u) != 0 ||
        ctll_get32(footer + 4u) != frame_len ||
        ctll_get64(footer + 8u) != expected_position) {
        free(frame);
        return false;
    }
    *out_frame = frame;
    *out_frame_len = frame_len;
    *out_next = offset + (off_t)frame_len + CTLL_FOOTER_BYTES;
    return true;
}

static bool ctll_scan(int fd, qihse_user_t *principal,
                      qihse_kv_ct_tenant_policy_t policy, uint32_t tenant,
                      const char *source_id, const char *generation,
                      const ct_lane_log_header_t *header,
                      bool repair_unpublished_tail,
                      ct_lane_log_header_t *out_header, unsigned *out_slot,
                      off_t *out_end) {
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_uid != geteuid() || st.st_nlink != 1 || (st.st_mode & 077u))
        return false;
    ct_lane_log_header_t h;
    unsigned active_slot = 0u;
    if (!ctll_read_header(fd, &st, header->lane_id, source_id, generation,
                          &h, &active_slot))
        return false;
    off_t end = (off_t)st.st_size;
    off_t offset = (off_t)CTLL_FILE_HEADER_BYTES;
    uint64_t position = h.acknowledged;
    uint64_t retained = 0u;
    while (offset < end) {
        uint64_t next_position = position + 1u;
        unsigned char *frame = NULL;
        size_t frame_len = 0u;
        off_t next = offset;
        if (position == UINT64_MAX ||
            !ctll_read_frame(fd, offset, end, principal, policy, tenant,
                             source_id, generation, next_position, &frame,
                             &frame_len, &next)) {
            /* Only a prefix that ends before the complete declared QKV6 frame
             * may be repaired. A complete but invalid frame is corruption. */
            unsigned char prefix[64];
            uint32_t declared = 0u;
            bool partial = end - offset < (off_t)sizeof(prefix) ||
                (ctll_pread(fd, prefix, sizeof(prefix), offset) &&
                 !memcmp(prefix, "QKV6CT01", 8u) &&
                 (declared = ctll_get32(prefix + 12u)) <=
                     QIHSE_CT_CODEC_MAX_FRAME &&
                 (uint64_t)declared + CTLL_FOOTER_BYTES >
                     (uint64_t)(end - offset));
            if (!repair_unpublished_tail || !partial) return false;
            if (ftruncate(fd, offset) != 0 || fsync(fd) != 0) return false;
            end = offset;
            break;
        }
        free(frame);
        uint64_t added = (uint64_t)frame_len + CTLL_FOOTER_BYTES;
        if (added > UINT64_MAX - retained) return false;
        retained += added;
        position = next_position;
        offset = next;
    }
    if (retained != h.retained_bytes || position != h.last_position) {
        if (!repair_unpublished_tail || retained < h.retained_bytes ||
            position < h.last_position)
            return false;
        h.retained_bytes = retained;
        h.last_position = position;
        if (!ctll_write_header(fd, &h, active_slot)) return false;
        active_slot ^= 1u;
    }
    if (out_header) *out_header = h;
    if (out_slot) *out_slot = active_slot;
    if (out_end) *out_end = end;
    return true;
}

static bool ctll_duplicate_matches(int fd, const ct_lane_log_header_t *header,
                                   qihse_kv_store_t *store,
                                   qihse_kv_ct_tenant_policy_t policy,
                                   uint32_t tenant, uint64_t position,
                                   const unsigned char *expected,
                                   size_t expected_len) {
    if (!header || !store || !store->ct_system_principal ||
        position <= header->acknowledged || position > header->last_position)
        return false;
    struct stat st;
    ct_lane_log_header_t checked;
    unsigned slot = 0u;
    off_t end = 0;
    if (fstat(fd, &st) != 0 ||
        !ctll_scan(fd, store->ct_system_principal, policy, tenant,
                   header->source_id, header->generation, header, false,
                   &checked, &slot, &end))
        return false;
    off_t offset = (off_t)CTLL_FILE_HEADER_BYTES;
    uint64_t current = checked.acknowledged;
    while (offset < end) {
        unsigned char *frame = NULL;
        size_t frame_len = 0u;
        off_t next = offset;
        if (current == UINT64_MAX ||
            !ctll_read_frame(fd, offset, end, store->ct_system_principal,
                policy, tenant, checked.source_id, checked.generation,
                current + 1u, &frame, &frame_len, &next))
            return false;
        current++;
        if (current == position) {
            bool same = frame_len == expected_len &&
                        CRYPTO_memcmp(frame, expected, frame_len) == 0;
            free(frame);
            return same;
        }
        free(frame);
        offset = next;
    }
    return false;
}

static bool ct_lane_log_status(qihse_kv_store_t *store, const char *lane_id,
                               const char *source_id, const char *generation,
                               uint64_t *out_ack, uint64_t *out_last,
                               uint64_t *out_retained_bytes) {
    if (out_ack) *out_ack = 0u;
    if (out_last) *out_last = 0u;
    if (out_retained_bytes) *out_retained_bytes = 0u;
    if (!store || !out_ack || !out_last || !out_retained_bytes ||
        !ct_id_valid(source_id)) return false;
    char path[4096];
    if (!ctll_path(store, lane_id, generation, path, sizeof(path))) return false;
    int fd = open_secure_read(path);
    if (fd < 0) return errno == ENOENT;
    struct stat st;
    unsigned char raw[CTLL_SLOT_BYTES];
    ct_lane_log_header_t h[2];
    bool valid[2] = {false, false};
    if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == geteuid() && st.st_nlink == 1 && !(st.st_mode & 077u)) {
        valid[0] = ctll_pread(fd, raw, sizeof(raw), 0) &&
                   ctll_decode_header(raw, &h[0]);
        valid[1] = ctll_pread(fd, raw, sizeof(raw), CTLL_SLOT_BYTES) &&
                   ctll_decode_header(raw, &h[1]);
    }
    unsigned index = !valid[1] || (valid[0] && h[0].sequence > h[1].sequence)
        ? 0u : 1u;
    bool ok = (valid[0] || valid[1]) &&
        !strcmp(h[index].lane_id, lane_id) &&
        !strcmp(h[index].source_id, source_id) &&
        !strcmp(h[index].generation, generation);
    if (ok)
        ok = (uint64_t)st.st_size ==
             (uint64_t)CTLL_FILE_HEADER_BYTES + h[index].retained_bytes;
    if (ok) {
        *out_ack = h[index].acknowledged;
        *out_last = h[index].last_position;
        *out_retained_bytes = h[index].retained_bytes;
    }
    OPENSSL_cleanse(raw, sizeof(raw));
    close(fd);
    return ok;
}

static bool ct_lane_log_checkpoint(qihse_kv_store_t *store,
                                   const char *lane_id, const char *source_id,
                                   const char *generation,
                                   uint64_t acknowledged_position) {
    if (!store || !ct_id_valid(source_id)) return false;
    char path[4096];
    if (!ctll_path(store, lane_id, generation, path, sizeof(path))) return false;
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0 && errno == ENOENT) {
        ct_lane_log_header_t created;
        unsigned created_slot = 0u;
        bool ok = ctll_write_new_file(path, lane_id, source_id, generation,
            acknowledged_position, &fd, &created, &created_slot);
        if (ok) ok = close(fd) == 0;
        return ok;
    }
    if (fd < 0) return false;
    struct stat st;
    ct_lane_log_header_t header;
    unsigned slot = 0u;
    bool ok = fstat(fd, &st) == 0 &&
        ctll_read_header(fd, &st, lane_id, source_id, generation, &header,
                         &slot) &&
        header.acknowledged == acknowledged_position &&
        header.last_position == acknowledged_position &&
        header.retained_bytes == 0u &&
        st.st_size == (off_t)CTLL_FILE_HEADER_BYTES;
    close(fd);
    return ok;
}

static bool ct_lane_log_append_fd(
    qihse_kv_store_t *store, const char *lane_id, const char *source_id,
    const char *generation, uint64_t acknowledged_position,
    uint64_t position, qihse_user_t *principal,
    qihse_kv_ct_tenant_policy_t policy, uint32_t tenant, int wal_fd,
    off_t frame_offset, size_t frame_len, uint64_t retained_limit,
    uint64_t *out_retained_bytes) {
    if (out_retained_bytes) *out_retained_bytes = 0u;
    if (!store || !principal || !position || wal_fd < 0 || frame_offset < 0 ||
        !out_retained_bytes || !ct_id_valid(source_id) ||
        frame_len < 64u || frame_len > QIHSE_CT_CODEC_MAX_FRAME ||
        frame_len > INT_MAX || !retained_limit) {
        errno = EINVAL; return false;
    }
    unsigned char *frame = malloc(frame_len);
    if (!frame) return false;
    bool ok = ctll_pread(wal_fd, frame, frame_len, frame_offset) &&
        ctll_validate_frame(frame, frame_len, principal, policy, tenant,
                            source_id, generation, position);
    if (!ok) { free(frame); errno = EINVAL; return false; }
    char path[4096];
    if (!ctll_path(store, lane_id, generation, path, sizeof(path))) {
        free(frame); errno = EINVAL; return false;
    }
    int fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    ct_lane_log_header_t h = {0};
    unsigned active_slot = 0u;
    if (fd < 0 && errno == ENOENT) {
        if (position <= acknowledged_position && position != 0u) {
            /* A replayed frame already covered by the durable ACK may be
             * absent after prefix collection. Seed the exact checkpoint. */
        } else if (position != acknowledged_position + 1u ||
            !ctll_write_new_file(path, lane_id, source_id, generation,
                                 acknowledged_position,
                                 &fd, &h, &active_slot)) {
            free(frame); return false;
        }
        if (fd < 0) {
            bool checkpoint_ok = ct_lane_log_checkpoint(store, lane_id,
                source_id, generation, acknowledged_position);
            if (!checkpoint_ok) { free(frame); return false; }
            fd = open(path, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
            if (fd < 0) { free(frame); return false; }
            struct stat st;
            if (fstat(fd, &st) != 0 || !ctll_read_header(fd, &st, lane_id,
                source_id, generation, &h, &active_slot)) {
                int saved = errno ? errno : EINVAL;
                close(fd); free(frame); errno = saved; return false;
            }
        }
    } else if (fd < 0) {
        free(frame); return false;
    } else {
        struct stat st;
        if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
            st.st_uid != geteuid() || st.st_nlink != 1 || (st.st_mode & 077u) ||
            !ctll_read_header(fd, &st, lane_id, source_id, generation,
                              &h, &active_slot)) {
            int saved = errno ? errno : EINVAL;
            close(fd); free(frame); errno = saved; return false;
        }
        if (h.acknowledged != acknowledged_position) {
            close(fd); free(frame); errno = EINVAL; return false;
        }
        if ((uint64_t)st.st_size != CTLL_FILE_HEADER_BYTES + h.retained_bytes) {
            qihse_user_t *system_user = store->ct_system_principal;
            if (!system_user ||
                !ctll_scan(fd, system_user, policy, tenant, source_id, generation,
                           &h, true, &h, &active_slot, NULL)) {
                close(fd); free(frame); errno = EIO; return false;
            }
        }
    }
    if (position <= h.acknowledged) {
        *out_retained_bytes = h.retained_bytes;
        close(fd); free(frame); return true;
    }
    if (position <= h.last_position) {
        bool same = ctll_duplicate_matches(fd, &h, store, policy, tenant,
                                           position, frame, frame_len);
        if (same) *out_retained_bytes = h.retained_bytes;
        close(fd); free(frame);
        if (!same) errno = EILSEQ;
        return same;
    }
    uint64_t stored_bytes = (uint64_t)frame_len + CTLL_FOOTER_BYTES;
    if (position != h.last_position + 1u || stored_bytes > retained_limit ||
        h.retained_bytes > retained_limit - stored_bytes ||
        h.retained_bytes > UINT64_MAX - stored_bytes ||
        h.retained_bytes > (uint64_t)INT64_MAX -
            CTLL_FILE_HEADER_BYTES - stored_bytes) {
        close(fd); free(frame); errno = position > h.last_position + 1u ? EPROTO : ENOSPC; return false;
    }
    off_t end = (off_t)CTLL_FILE_HEADER_BYTES + (off_t)h.retained_bytes;
    unsigned char footer[CTLL_FOOTER_BYTES];
    memcpy(footer, CTLL_FOOTER_MAGIC, 4u);
    ctll_put32(footer + 4u, (uint32_t)frame_len);
    ctll_put64(footer + 8u, position);
    ok = ctll_pwrite(fd, frame, frame_len, end) &&
         ctll_pwrite(fd, footer, sizeof(footer), end + (off_t)frame_len) &&
         fdatasync(fd) == 0;
    if (ok && aimem_durability_test_fail_once(
            "ct-lane-log-after-frame-fsync"))
        ok = false;
    if (ok) {
        h.last_position = position;
        h.retained_bytes += stored_bytes;
        ok = ctll_write_header(fd, &h, active_slot);
    }
    if (ok) *out_retained_bytes = h.retained_bytes;
    int saved = errno;
    close(fd); free(frame); OPENSSL_cleanse(footer, sizeof(footer));
    errno = saved;
    return ok;
}

static bool ct_lane_log_read(
    qihse_kv_store_t *store, const char *lane_id, const char *source_id,
    const char *generation, qihse_user_t *principal,
    qihse_kv_ct_tenant_policy_t policy, uint32_t tenant,
    uint64_t after_position, size_t max_groups, size_t max_bytes,
    qihse_kv_ct_group_t **out_groups, size_t *out_count,
    uint64_t *out_resume_position) {
    if (out_groups) *out_groups = NULL;
    if (out_count) *out_count = 0u;
    if (out_resume_position) *out_resume_position = after_position;
    if (!store || !principal || !out_groups || !out_count ||
        !out_resume_position || !ct_id_valid(source_id) || !max_groups ||
        max_groups > 4096u || !max_bytes || max_bytes > QIHSE_CT_CODEC_MAX_FRAME) {
        errno = EINVAL; return false;
    }
    char path[4096];
    if (!ctll_path(store, lane_id, generation, path, sizeof(path))) return false;
    int fd = open_secure_read(path);
    if (fd < 0 && errno == ENOENT) return true;
    if (fd < 0) return false;
    struct stat st;
    ct_lane_log_header_t h = {0};
    unsigned active_slot = 0u;
    if (fstat(fd, &st) != 0 || !ctll_read_header(fd, &st, lane_id, source_id,
        generation, &h, &active_slot) || after_position < h.acknowledged ||
        after_position > h.last_position ||
        (uint64_t)st.st_size !=
            (uint64_t)CTLL_FILE_HEADER_BYTES + h.retained_bytes) {
        close(fd); errno = EINVAL; return false;
    }
    qihse_kv_ct_group_t *groups = calloc(max_groups, sizeof(*groups));
    if (!groups) { close(fd); return false; }
    off_t offset = (off_t)CTLL_FILE_HEADER_BYTES;
    off_t end = (off_t)CTLL_FILE_HEADER_BYTES + (off_t)h.retained_bytes;
    uint64_t position = h.acknowledged;
    size_t count = 0u, used = 0u;
    bool ok = true;
    while (offset < end) {
        unsigned char *frame = NULL;
        size_t frame_len = 0u;
        off_t next = offset;
        if (position == UINT64_MAX ||
            !ctll_read_frame(fd, offset, end, principal, policy, tenant,
                             source_id, generation, position + 1u, &frame,
                             &frame_len, &next)) {
            ok = false; break;
        }
        position++;
        if (position > after_position) {
            uint8_t mode = 0u;
            size_t consumed = 0u;
            FILE *input = fmemopen(frame, frame_len, "rb");
            if (!input || count == max_groups || used > max_bytes ||
                frame_len > max_bytes - used) {
                if (input) fclose(input);
                free(frame); ok = false; break;
            }
            int rc = qihse_ct_codec_read(input, principal, policy, tenant,
                max_bytes - used, &groups[count], &mode, &consumed);
            fclose(input);
            if (rc != 1 || consumed != frame_len ||
                mode != QIHSE_KV_CT_LANE_SOURCE) {
                qihse_ct_codec_clear(&groups[count]);
                free(frame); ok = false; break;
            }
            used += frame_len + CTLL_FOOTER_BYTES;
            count++;
        }
        free(frame);
        offset = next;
        if (count == max_groups || used >= max_bytes) break;
    }
    if (ok && offset >= end && position != h.last_position) ok = false;
    close(fd);
    if (!ok) {
        qihse_kv_ct_groups_free(groups, count);
        errno = EIO;
        return false;
    }
    *out_groups = groups;
    *out_count = count;
    *out_resume_position = count ? groups[count - 1u].stream_position : after_position;
    return true;
}

static bool ct_lane_log_ack(
    qihse_kv_store_t *store, const char *lane_id, const char *source_id,
    const char *generation, uint64_t ack_position,
    qihse_kv_ct_tenant_policy_t policy, uint32_t tenant,
    uint64_t *out_retained_bytes) {
    if (out_retained_bytes) *out_retained_bytes = 0u;
    if (!store || !out_retained_bytes || !ct_id_valid(source_id)) return false;
    char path[4096], tmp[8192];
    if (!ctll_path(store, lane_id, generation, path, sizeof(path))) return false;
    int fd = open_secure_read(path);
    if (fd < 0 && errno == ENOENT) return ack_position == 0u;
    if (fd < 0) return false;
    struct stat st;
    ct_lane_log_header_t h = {0};
    unsigned active_slot = 0u;
    qihse_user_t *system_user = store->ct_system_principal;
    bool ok = system_user && fstat(fd, &st) == 0 &&
        ctll_read_header(fd, &st, lane_id, source_id, generation, &h,
                         &active_slot) &&
        ctll_scan(fd, system_user, policy, tenant, source_id, generation, &h,
                  false, &h, &active_slot, NULL) &&
        ack_position >= h.acknowledged && ack_position <= h.last_position;
    if (!ok) { close(fd); errno = EINVAL; return false; }
    if (ack_position == h.acknowledged) {
        *out_retained_bytes = h.retained_bytes;
        close(fd);
        return true;
    }
    int n = snprintf(tmp, sizeof(tmp), "%s.tmp.%ld.%llu", path, (long)getpid(),
                     (unsigned long long)current_time_ms());
    if (n < 0 || (size_t)n >= sizeof(tmp)) {
        close(fd); errno = ENAMETOOLONG; return false;
    }
    int out_fd = open_secure_write_exclusive(tmp);
    if (out_fd < 0) { close(fd); return false; }
    FILE *out = fdopen(out_fd, "wb");
    if (!out) { close(out_fd); unlink(tmp); close(fd); return false; }
    ct_lane_log_header_t new_header = h;
    new_header.acknowledged = ack_position;
    new_header.retained_bytes = 0u;
    unsigned char slot[CTLL_SLOT_BYTES];
    ok = new_header.sequence < UINT64_MAX;
    new_header.sequence++;
    ok = ok && ctll_encode_header(&new_header, slot) &&
         fwrite_exact(slot, 1u, sizeof(slot), out) &&
         fwrite_exact(slot, 1u, sizeof(slot), out);
    OPENSSL_cleanse(slot, sizeof(slot));
    off_t offset = (off_t)CTLL_FILE_HEADER_BYTES;
    off_t end = (off_t)CTLL_FILE_HEADER_BYTES + (off_t)h.retained_bytes;
    uint64_t position = h.acknowledged;
    while (ok && offset < end) {
        unsigned char *frame = NULL;
        size_t frame_len = 0u;
        off_t next = offset;
        if (position == UINT64_MAX ||
            !ctll_read_frame(fd, offset, end, system_user, policy, tenant,
                source_id, generation, position + 1u, &frame, &frame_len, &next)) {
            ok = false; break;
        }
        unsigned char footer[CTLL_FOOTER_BYTES];
        bool copy = position + 1u > ack_position;
        memcpy(footer, CTLL_FOOTER_MAGIC, 4u);
        ctll_put32(footer + 4u, (uint32_t)frame_len);
        ctll_put64(footer + 8u, position + 1u);
        if (copy) {
            ok = fwrite_exact(frame, 1u, frame_len, out) &&
                 fwrite_exact(footer, 1u, sizeof(footer), out);
            if (ok) new_header.retained_bytes += frame_len + CTLL_FOOTER_BYTES;
        }
        free(frame);
        position++;
        offset = next;
    }
    if (position != h.last_position) ok = false;
    if (ok) {
        /* Rewrite both header slots with the final retained-byte count. */
        if (fseeko(out, 0, SEEK_SET) != 0) ok = false;
        if (ok) {
            new_header.sequence = h.sequence + 1u;
            ok = ctll_encode_header(&new_header, slot) &&
                 fwrite_exact(slot, 1u, sizeof(slot), out) &&
                 fwrite_exact(slot, 1u, sizeof(slot), out);
        }
        OPENSSL_cleanse(slot, sizeof(slot));
    }
    if (ok) ok = finish_file(out);
    else { fclose(out); unlink(tmp); }
    if (ok && rename(tmp, path) != 0) { unlink(tmp); ok = false; }
    if (ok && !fsync_dir_path(get_qihse_data_dir())) ok = false;
    if (ok) *out_retained_bytes = new_header.retained_bytes;
    close(fd);
    return ok;
}

#undef CTLL_SLOT_BYTES
#undef CTLL_FILE_HEADER_BYTES
#undef CTLL_FOOTER_BYTES
#undef CTLL_HEADER_MAGIC
#undef CTLL_FOOTER_MAGIC
