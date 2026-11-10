/* Durable QKV7 receiver-lane baseline installation. Included after
 * qihse_ct_range_export.inc so the authenticated SSTable range helpers are
 * available without exposing a context-free store read. */

#define CT_LANE_BASELINE_FRAME_BYTES 2256u
#define CT_LANE_BASELINE_CRC_OFFSET 2252u
#define CT_LANE_BASELINE_VERSION 1u

static uint16_t ct_lane_baseline_get16(const uint8_t* p) {
    return (uint16_t)(((uint16_t)p[0] << 8u) | p[1]);
}

static uint32_t ct_lane_baseline_get32(const uint8_t* p) {
    return ((uint32_t)p[0] << 24u) | ((uint32_t)p[1] << 16u) |
           ((uint32_t)p[2] << 8u) | (uint32_t)p[3];
}

static uint64_t ct_lane_baseline_get64(const uint8_t* p) {
    uint64_t value = 0u;
    for (size_t i = 0u; i < 8u; ++i) value = (value << 8u) | p[i];
    return value;
}

static void ct_lane_baseline_put16(uint8_t* p, uint16_t value) {
    p[0] = (uint8_t)(value >> 8u);
    p[1] = (uint8_t)value;
}

static void ct_lane_baseline_put32(uint8_t* p, uint32_t value) {
    p[0] = (uint8_t)(value >> 24u);
    p[1] = (uint8_t)(value >> 16u);
    p[2] = (uint8_t)(value >> 8u);
    p[3] = (uint8_t)value;
}

static void ct_lane_baseline_put64(uint8_t* p, uint64_t value) {
    for (size_t i = 0u; i < 8u; ++i)
        p[i] = (uint8_t)(value >> (56u - 8u * i));
}

static uint32_t ct_lane_baseline_crc32c(const uint8_t* data, size_t length) {
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0u; i < length; ++i) {
        crc ^= data[i];
        for (unsigned bit = 0u; bit < 8u; ++bit)
            crc = (crc >> 1u) ^ (0x82f63b78u & (uint32_t)-(int32_t)(crc & 1u));
    }
    return ~crc;
}

static bool ct_lane_baseline_text_field(const uint8_t* field, size_t width,
                                        size_t length, bool lane_id) {
    if (!field || length == 0u || length > width ||
        (lane_id && length != QIHSE_KV_CT_LANE_ID_MAX)) return false;
    for (size_t i = 0u; i < length; ++i) {
        uint8_t c = field[i];
        bool valid = lane_id ? ((c >= '0' && c <= '9') ||
                                (c >= 'a' && c <= 'f'))
                             : ((c >= '0' && c <= '9') ||
                                (c >= 'a' && c <= 'z') ||
                                (c >= 'A' && c <= 'Z') || c == '-' ||
                                c == '_' || c == '.' || c == ':');
        if (!valid) return false;
    }
    for (size_t i = length; i < width; ++i)
        if (field[i] != 0u) return false;
    return true;
}

static bool ct_lane_baseline_frame_validate(
    const uint8_t frame[CT_LANE_BASELINE_FRAME_BYTES]) {
    if (!frame || memcmp(frame, "QKV7", 4u) != 0 ||
        frame[4] != CT_LANE_BASELINE_VERSION || frame[7] != 0u ||
        ct_lane_baseline_get32(frame + CT_LANE_BASELINE_CRC_OFFSET) !=
            ct_lane_baseline_crc32c(frame, CT_LANE_BASELINE_CRC_OFFSET))
        return false;
    const size_t lane_len = frame[5];
    const size_t generation_len = frame[6];
    const uint8_t* bitmap = frame + 76u;
    const uint8_t* lane = frame + 2124u;
    const uint8_t* generation = frame + 2188u;
    uint64_t seq_base = ct_lane_baseline_get64(frame + 24u);
    uint64_t record_count = ct_lane_baseline_get64(frame + 32u);
    if (!ct_lane_baseline_text_field(lane, QIHSE_KV_CT_LANE_ID_MAX,
                                     lane_len, true) ||
        !ct_lane_baseline_text_field(generation, QIHSE_KV_CT_ID_MAX,
                                     generation_len, false) ||
        record_count > UINT64_MAX - seq_base)
        return false;
    return true;
}

typedef struct {
    const qihse_kv_ct_lane_t* lane;
    const uint8_t* bitmap;
    qihse_user_t* principal;
    ct_range_export_collect_t* collect;
    bool ok;
    bool authorized;
} ct_lane_baseline_collect_t;

static bool ct_lane_baseline_bitmap_has_key(
    const uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES], const char* key) {
    if (!bitmap || !key || qihse_cluster_key_is_node_local(key)) return false;
    uint16_t slot = qihse_cluster_key_slot(key, strlen(key));
    return slot < QIHSE_CLUSTER_SLOT_COUNT &&
        (bitmap[slot / 8u] & (uint8_t)(1u << (slot % 8u))) != 0u;
}

static bool ct_lane_baseline_bitmap_nonempty(
    const uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES]) {
    if (!bitmap) return false;
    uint8_t any = 0u;
    for (size_t i = 0u; i < QIHSE_KV_CT_SLOT_BITMAP_BYTES; ++i)
        any |= bitmap[i];
    return any != 0u;
}

static bool ct_lane_baseline_bitmap_subset(
    const uint8_t subset[QIHSE_KV_CT_SLOT_BITMAP_BYTES],
    const uint8_t superset[QIHSE_KV_CT_SLOT_BITMAP_BYTES]) {
    if (!subset || !superset) return false;
    for (size_t i = 0u; i < QIHSE_KV_CT_SLOT_BITMAP_BYTES; ++i)
        if ((subset[i] & (uint8_t)~superset[i]) != 0u) return false;
    return true;
}

static bool ct_lane_baseline_mem_cb(const char* key, void* value,
                                    size_t value_size, void* user_data) {
    (void)value_size;
    ct_lane_baseline_collect_t* context = user_data;
    kv_payload_t* payload = value;
    if (!context || !context->ok || !context->authorized || !key || !payload)
        return false;
    if (!ct_lane_baseline_bitmap_has_key(context->bitmap, key)) return true;
    if (!qihse_auth_can_access(context->principal, payload->classification,
                               payload->sci_compartment)) {
        context->authorized = false;
        errno = EACCES;
        return false;
    }
    return ct_range_export_add(context->collect, key, payload, NULL);
}

static bool ct_lane_baseline_collect_existing_locked(
    qihse_kv_store_t* store, qihse_user_t* principal,
    const qihse_kv_ct_lane_t* lane,
    const uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES],
    ct_range_image_t* out) {
    if (!store || !principal || !lane || !bitmap || !out || !store->sst_meta ||
        store->sst_meta->degraded) return false;
    memset(out, 0, sizeof(*out));
    ct_range_export_collect_t collected = {
        .principal = principal,
        .first_slot = 0u,
        .last_slot = QIHSE_CLUSTER_SLOT_COUNT - 1u,
        .authorized = true,
        .ok = true
    };
    ct_lane_baseline_collect_t context = {
        .lane = lane,
        .bitmap = bitmap,
        .principal = principal,
        .collect = &collected,
        .ok = true,
        .authorized = true
    };
    qihse_trinary_trie_foreach(store->trie, ct_lane_baseline_mem_cb, &context);
    if (!context.ok || !context.authorized || !collected.ok ||
        !collected.authorized) goto failed;
    for (size_t i = 0u; i < store->sst_meta->cap; ++i) {
        const sst_meta_entry_t* meta = &store->sst_meta->slots[i];
        if (!meta->key || qihse_cluster_key_is_node_local(meta->key) ||
            !ct_lane_baseline_bitmap_has_key(bitmap, meta->key) ||
            qihse_trinary_trie_search(store->trie, meta->key, NULL))
            continue;
        if (!qihse_auth_can_access(principal, meta->classification,
                                   meta->sci_compartment) ||
            !ct_range_export_add(&collected, meta->key, NULL, meta))
            goto failed;
    }
    out->rows = calloc(collected.count ? collected.count : 1u,
                       sizeof(*out->rows));
    if (!out->rows) goto failed;
    out->capacity = collected.count;
    const char* data_dir = get_qihse_data_dir();
    if (!data_dir) goto failed;
    for (size_t i = 0u; i < collected.count; ++i) {
        const ct_range_export_entry_t* entry = &collected.rows[i];
        kv_disk_record_t row = {0};
        if (!qihse_auth_user_is_active(principal) ||
            !qihse_auth_can_access(principal, entry->classification,
                                   entry->sci)) goto failed;
        if (entry->memory) {
            row.key = strdup(entry->key);
            row.val = strdup(entry->memory->val);
            row.classification = entry->classification;
            row.sci_compartment = entry->sci;
            row.expire_time_ms = entry->expiry;
            row.flags = entry->flags;
            row.change_seq = entry->memory->change_seq;
            if (!row.key || !row.val) {
                disk_record_free(&row);
                goto failed;
            }
        } else {
            pthread_mutex_lock(&store->sst_fd_lock);
            int fd = sst_fd_get(store, data_dir, entry->sstable_id);
            pthread_mutex_unlock(&store->sst_fd_lock);
            if (fd < 0 || !ct_range_export_sst_header_allowed(
                    fd, entry->sst_offset, entry, principal) ||
                disk_record_read_at(fd, entry->sst_offset, &row) != 1) {
                disk_record_free(&row);
                goto failed;
            }
            if (strcmp(row.key, entry->key) != 0 ||
                row.classification != entry->classification ||
                row.sci_compartment != entry->sci ||
                row.expire_time_ms != entry->expiry ||
                row.flags != entry->flags) {
                disk_record_free(&row);
                goto failed;
            }
        }
        size_t key_len = strlen(row.key), value_len = strlen(row.val);
        if (key_len > SIZE_MAX - value_len - 64u ||
            key_len + value_len + 64u > SIZE_MAX - out->bytes) {
            disk_record_free(&row);
            errno = EOVERFLOW;
            goto failed;
        }
        out->bytes += key_len + value_len + 64u;
        out->rows[out->count++] = row;
    }
    qsort(out->rows, out->count, sizeof(*out->rows), ct_image_row_cmp);
    for (size_t i = 0u; i < collected.count; ++i)
        free(collected.rows[i].key);
    free(collected.rows);
    return qihse_auth_user_is_active(principal);
failed:
    for (size_t i = 0u; i < collected.count; ++i)
        free(collected.rows[i].key);
    free(collected.rows);
    ct_range_image_free(out);
    return false;
}

static bool ct_lane_baseline_image_read(const char* path,
    qihse_user_t* principal,
    const uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES],
    uint64_t baseline_row_seq,
    ct_range_image_t* out, uint16_t* out_max_class, uint16_t* out_required_sci) {
    if (!path || !principal || !bitmap || !out || !out_max_class ||
        !out_required_sci) return false;
    memset(out, 0, sizeof(*out));
    *out_max_class = 0u;
    *out_required_sci = 0u;
    int fd = open_secure_read(path);
    if (fd < 0) return false;
    FILE* input = fdopen(fd, "rb");
    if (!input) {
        close(fd);
        return false;
    }
    const kv_read_context_t read_context = {.user = principal};
    bool ok = true;
    for (;;) {
        kv_disk_record_t row;
        int rc = disk_record_read_context(input, &row, &read_context);
        if (rc == 0) break;
        if (rc != 1) {
            ok = false;
            break;
        }
        uint16_t slot = qihse_cluster_key_slot(row.key, strlen(row.key));
        bool selected = slot < QIHSE_CLUSTER_SLOT_COUNT &&
            (bitmap[slot / 8u] & (uint8_t)(1u << (slot % 8u))) != 0u;
        if (qihse_cluster_key_is_node_local(row.key) || !selected ||
            (row.flags & ~KV_FLAG_TOMBSTONE) != 0u ||
            row.change_seq > baseline_row_seq ||
            ((row.flags & KV_FLAG_TOMBSTONE) != 0u &&
             (row.val[0] != '\0' || row.expire_time_ms != 0u))) {
            disk_record_free(&row);
            errno = EINVAL;
            ok = false;
            break;
        }
        size_t key_len = strlen(row.key), value_len = strlen(row.val);
        if (key_len > SIZE_MAX - value_len - 64u ||
            key_len + value_len + 64u > SIZE_MAX - out->bytes ||
            out->count == SIZE_MAX) {
            disk_record_free(&row);
            errno = EOVERFLOW;
            ok = false;
            break;
        }
        if (out->count == out->capacity) {
            size_t next = out->capacity ? out->capacity * 2u : 128u;
            if (next <= out->capacity || next > SIZE_MAX / sizeof(*out->rows)) {
                disk_record_free(&row);
                errno = EOVERFLOW;
                ok = false;
                break;
            }
            kv_disk_record_t* grown = realloc(out->rows, next * sizeof(*grown));
            if (!grown) {
                disk_record_free(&row);
                ok = false;
                break;
            }
            out->rows = grown;
            out->capacity = next;
        }
        if (row.classification > *out_max_class)
            *out_max_class = row.classification;
        *out_required_sci |= row.sci_compartment;
        out->bytes += key_len + value_len + 64u;
        out->rows[out->count++] = row;
    }
    if (fclose(input) != 0) ok = false;
    if (ok) {
        qsort(out->rows, out->count, sizeof(*out->rows), ct_image_row_cmp);
        for (size_t i = 1u; i < out->count; ++i)
            if (strcmp(out->rows[i - 1u].key, out->rows[i].key) == 0)
                ok = false;
    }
    if (!ok || !qihse_auth_user_is_active(principal)) {
        ct_range_image_free(out);
        if (ok) errno = EACCES;
        return false;
    }
    return true;
}

static bool ct_lane_baseline_semantic_digest(
    const uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES],
    const ct_range_image_t* image, uint8_t out[32]) {
    if (!bitmap || !image || !out) return false;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    unsigned int digest_len = 0u;
    size_t live_count = 0u;
    for (size_t i = 0u; i < image->count; ++i)
        if (!(image->rows[i].flags & KV_FLAG_TOMBSTONE)) ++live_count;
    bool ok = md && EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(md, "QCT-LANE-RANGE-V1",
                         sizeof("QCT-LANE-RANGE-V1") - 1u) == 1 &&
        EVP_DigestUpdate(md, bitmap, QIHSE_KV_CT_SLOT_BITMAP_BYTES) == 1 &&
        ct_hash_u64(md, (uint64_t)live_count);
    for (size_t i = 0u; ok && i < image->count; ++i) {
        const kv_disk_record_t* row = &image->rows[i];
        if (row->flags & KV_FLAG_TOMBSTONE) continue;
        size_t key_len = strlen(row->key), value_len = strlen(row->val);
        EVP_MD_CTX* row_md = EVP_MD_CTX_new();
        unsigned char row_digest[32];
        unsigned int row_len = 0u;
        bool hashed = row_md && EVP_DigestInit_ex(row_md, EVP_sha256(), NULL) == 1 &&
            ct_hash_u64(row_md, (uint64_t)key_len) &&
            EVP_DigestUpdate(row_md, row->key, key_len) == 1 &&
            ct_hash_u64(row_md, (uint64_t)value_len) &&
            EVP_DigestUpdate(row_md, row->val, value_len) == 1 &&
            ct_hash_u64(row_md, row->expire_time_ms) &&
            ct_hash_u64(row_md, row->classification) &&
            ct_hash_u64(row_md, row->sci_compartment) &&
            EVP_DigestFinal_ex(row_md, row_digest, &row_len) == 1 &&
            row_len == 32u;
        EVP_MD_CTX_free(row_md);
        ok = hashed && ct_hash_u64(md, (uint64_t)key_len) &&
            EVP_DigestUpdate(md, row->key, key_len) == 1 &&
            EVP_DigestUpdate(md, row_digest, 32u) == 1;
        OPENSSL_cleanse(row_digest, sizeof(row_digest));
    }
    if (ok) ok = EVP_DigestFinal_ex(md, out, &digest_len) == 1 && digest_len == 32u;
    EVP_MD_CTX_free(md);
    return ok;
}

static bool ct_lane_baseline_apply_rows_locked(qihse_kv_store_t* store,
    qihse_user_t* principal, const uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES],
    const qihse_kv_ct_lane_t* lane,
    const ct_range_image_t* incoming, uint64_t sequence_base,
    uint64_t baseline_row_seq, uint64_t expected_count,
    uint8_t semantic_digest[32]) {
    ct_range_image_t existing = {0};
    bool ok = lane && ct_lane_baseline_collect_existing_locked(
        store, principal, lane, bitmap, &existing);
    if (ok) ok = expected_count == incoming->count &&
        expected_count <= UINT64_MAX - sequence_base;
    /* Preserve source row versions in the image. The receiver's global local
     * allocator advances separately; source stream position, not a numeric
     * comparison with target-local versions, orders later CT deltas. */
    size_t i = 0u, j = 0u;
    while (ok && j < existing.count) {
        while (i < incoming->count &&
               strcmp(incoming->rows[i].key, existing.rows[j].key) < 0) ++i;
        if (i == incoming->count ||
            strcmp(incoming->rows[i].key, existing.rows[j].key) != 0) {
            const kv_disk_record_t* stale = &existing.rows[j];
            ok = insert_internal(store, stale->key, "", 0u,
                stale->classification, stale->sci_compartment,
                KV_FLAG_TOMBSTONE, baseline_row_seq);
        }
        ++j;
    }
    for (size_t n = 0u; ok && n < incoming->count; ++n) {
        const kv_disk_record_t* row = &incoming->rows[n];
        bool tombstone = (row->flags & KV_FLAG_TOMBSTONE) != 0u;
        uint64_t sequence = row->change_seq;
        ok = insert_internal(store, row->key, tombstone ? "" : row->val,
            tombstone ? 0u : row->expire_time_ms, row->classification,
            row->sci_compartment, tombstone ? KV_FLAG_TOMBSTONE : 0u,
            sequence);
        if (ok) kv_change_seq_floor(store, sequence);
    }
    if (ok) kv_change_seq_floor(store, sequence_base + expected_count);
    if (ok) {
        ct_range_image_t actual = {0};
        ok = ct_lane_baseline_collect_existing_locked(store, principal,
                                                       lane, bitmap, &actual) &&
             ct_lane_baseline_semantic_digest(bitmap, &actual,
                                               semantic_digest);
        ct_range_image_free(&actual);
    }
    ct_range_image_free(&existing);
    return ok;
}

static bool ct_lane_baseline_image_path(const char* lane_id,
    const unsigned char digest[32], char* out, size_t out_size) {
    if (!ct_lane_id_valid(lane_id) || !digest || !out || out_size == 0u)
        return false;
    static const char hex[] = "0123456789abcdef";
    char sha[65];
    for (size_t i = 0u; i < 32u; ++i) {
        sha[2u * i] = hex[digest[i] >> 4u];
        sha[2u * i + 1u] = hex[digest[i] & 0x0fu];
    }
    sha[64] = '\0';
    char suffix[192];
    int n = snprintf(suffix, sizeof(suffix), "ct-lane-baseline-%s-%s.qfs",
                     lane_id, sha);
    return n > 0 && (size_t)n < sizeof(suffix) &&
        build_data_path(out, out_size, suffix);
}

static bool ct_lane_baseline_stage_image(const char* source_path,
    const char* destination_path, const unsigned char expected_digest[32]) {
    int existing_fd = open_secure_read(destination_path);
    if (existing_fd >= 0) {
        unsigned char digest[32];
        bool ok = ct_fd_sha256(existing_fd, digest) &&
                  memcmp(digest, expected_digest, 32u) == 0;
        close(existing_fd);
        return ok;
    }
    if (errno != ENOENT) {
        return false;
    }
    int source_fd = open_secure_read(source_path);
    if (source_fd < 0) return false;
    struct stat source_stat;
    bool ok = fstat(source_fd, &source_stat) == 0 &&
              S_ISREG(source_stat.st_mode) && source_stat.st_size >= 0;
    char temporary[8192];
    FILE* output = NULL;
    if (ok) ok = atomic_file_begin(destination_path, temporary,
                                    sizeof(temporary), &output);
    uint8_t bytes[65536];
    while (ok) {
        ssize_t n = read(source_fd, bytes, sizeof(bytes));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { ok = false; break; }
        if (n == 0) break;
        if (fwrite(bytes, 1u, (size_t)n, output) != (size_t)n) ok = false;
    }
    close(source_fd);
    if (output) {
        if (ok) ok = atomic_file_commit(output, temporary, destination_path) &&
                     fsync_dir_path(get_qihse_data_dir());
        else {
            fclose(output);
            unlink(temporary);
        }
    }
    if (!ok) return false;
    int staged_fd = open_secure_read(destination_path);
    unsigned char staged_digest[32];
    ok = staged_fd >= 0 && ct_fd_sha256(staged_fd, staged_digest) &&
         memcmp(staged_digest, expected_digest, 32u) == 0;
    if (staged_fd >= 0) close(staged_fd);
    if (!ok) (void)unlink(destination_path);
    return ok;
}

static bool ct_lane_baseline_frame_build(uint8_t frame[CT_LANE_BASELINE_FRAME_BYTES],
    const char* lane_id, const char* generation,
    const uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES],
    uint64_t baseline_row_seq, uint64_t source_cut, uint64_t target_seq_base,
    uint64_t target_record_count, const unsigned char image_digest[32],
    uint16_t max_classification, uint16_t required_sci) {
    if (!frame || !ct_lane_id_valid(lane_id) || !ct_id_valid(generation) ||
        !bitmap || !image_digest || target_record_count > UINT64_MAX - target_seq_base)
        return false;
    memset(frame, 0, CT_LANE_BASELINE_FRAME_BYTES);
    memcpy(frame, "QKV7", 4u);
    frame[4] = CT_LANE_BASELINE_VERSION;
    frame[5] = QIHSE_KV_CT_LANE_ID_MAX;
    frame[6] = (uint8_t)strlen(generation);
    ct_lane_baseline_put64(frame + 8u, baseline_row_seq);
    ct_lane_baseline_put64(frame + 16u, source_cut);
    ct_lane_baseline_put64(frame + 24u, target_seq_base);
    ct_lane_baseline_put64(frame + 32u, target_record_count);
    memcpy(frame + 40u, image_digest, 32u);
    ct_lane_baseline_put16(frame + 72u, max_classification);
    ct_lane_baseline_put16(frame + 74u, required_sci);
    memcpy(frame + 76u, bitmap, QIHSE_KV_CT_SLOT_BITMAP_BYTES);
    memcpy(frame + 2124u, lane_id, QIHSE_KV_CT_LANE_ID_MAX);
    memcpy(frame + 2188u, generation, strlen(generation));
    ct_lane_baseline_put32(frame + CT_LANE_BASELINE_CRC_OFFSET,
        ct_lane_baseline_crc32c(frame, CT_LANE_BASELINE_CRC_OFFSET));
    return ct_lane_baseline_frame_validate(frame);
}

static bool ct_lane_baseline_apply_frame(
    qihse_kv_store_t* store,
    const uint8_t frame[CT_LANE_BASELINE_FRAME_BYTES],
    const kv_read_context_t* read_context) {
    if (!store || !ct_lane_baseline_frame_validate(frame)) {
        errno = EINVAL;
        return false;
    }
    if (!read_context || !qihse_auth_user_is_active(read_context->user)) {
        errno = EACCES;
        return false;
    }
    const size_t lane_id_len = frame[5];
    const size_t generation_len = frame[6];
    const uint8_t* lane_id_wire = frame + 2124u;
    const uint8_t* generation_wire = frame + 2188u;
    char* lane_id = malloc(QIHSE_KV_CT_LANE_ID_MAX + 1u);
    if (!lane_id) {
        errno = ENOMEM;
        return false;
    }
    memcpy(lane_id, lane_id_wire, lane_id_len);
    lane_id[lane_id_len] = '\0';
    const uint8_t* bitmap = frame + 76u;
    uint64_t baseline_row_seq = ct_lane_baseline_get64(frame + 8u);
    uint64_t source_cut = ct_lane_baseline_get64(frame + 16u);
    uint64_t target_seq_base = ct_lane_baseline_get64(frame + 24u);
    uint64_t target_record_count = ct_lane_baseline_get64(frame + 32u);
    const uint8_t* image_digest = frame + 40u;
    uint16_t max_classification = ct_lane_baseline_get16(frame + 72u);
    uint16_t required_sci = ct_lane_baseline_get16(frame + 74u);
    char image_path[4096];
    bool ok = false;
    bool locked = false;
    ct_range_image_t incoming = {0};
    uint8_t expected_semantic_digest[32] = {0};
    uint8_t semantic_digest[32] = {0};
    if (!ct_lane_baseline_image_path(lane_id, image_digest, image_path,
                                     sizeof(image_path))) {
        errno = EINVAL;
        goto done;
    }
    int image_fd = open_secure_read(image_path);
    unsigned char actual_image_digest[32];
    ok = image_fd >= 0 && ct_fd_sha256(image_fd, actual_image_digest) &&
        memcmp(actual_image_digest, image_digest, 32u) == 0;
    if (image_fd >= 0) close(image_fd);
    if (!ok) goto done;

    kv_store_wrlock(store);
    locked = true;
    qihse_kv_ct_lane_t* lane = ct_lane_find(store, lane_id);
    unsigned token_nonzero = 0u;
    if (lane) for (size_t i = 0u; i < QIHSE_KV_CT_TOKEN_BYTES; ++i)
        token_nonzero |= lane->owner_token[i];
    bool bitmap_nonempty = ct_lane_baseline_bitmap_nonempty(bitmap);
    bool selected_subset = lane && bitmap_nonempty &&
        ct_lane_baseline_bitmap_subset(bitmap, lane->status.slot_bitmap);
    bool empty_lane_baseline = lane && !bitmap_nonempty &&
        !ct_lane_baseline_bitmap_nonempty(lane->status.slot_bitmap) &&
        source_cut == 0u;
    ok = lane && token_nonzero != 0u && store->ct_enabled &&
        (selected_subset || empty_lane_baseline) &&
        !store->recovery_pending &&
        __atomic_load_n(&store->change_seq, __ATOMIC_ACQUIRE) >= target_seq_base;
    kv_store_unlock(store);
    locked = false;
    if (!ok) goto done;

    uint16_t actual_max_classification = 0u, actual_required_sci = 0u;
    ok = ct_lane_baseline_image_read(image_path, read_context->user, bitmap,
            baseline_row_seq,
            &incoming, &actual_max_classification, &actual_required_sci) &&
        actual_max_classification == max_classification &&
        actual_required_sci == required_sci;
    if (!ok) goto done;
    if (!ct_lane_baseline_bitmap_nonempty(bitmap) &&
        (incoming.count != 0u || source_cut != 0u)) {
        errno = EINVAL;
        ok = false;
        goto done;
    }

    ok = ct_lane_baseline_semantic_digest(bitmap, &incoming,
                                           expected_semantic_digest);
    if (!ok) goto done;
    kv_store_wrlock(store);
    locked = true;
    lane = ct_lane_find(store, lane_id);
    bitmap_nonempty = ct_lane_baseline_bitmap_nonempty(bitmap);
    selected_subset = lane && bitmap_nonempty &&
        ct_lane_baseline_bitmap_subset(bitmap, lane->status.slot_bitmap);
    empty_lane_baseline = lane && !bitmap_nonempty &&
        !ct_lane_baseline_bitmap_nonempty(lane->status.slot_bitmap) &&
        source_cut == 0u && incoming.count == 0u;
    ok = lane && (selected_subset || empty_lane_baseline) &&
        !store->recovery_pending &&
        __atomic_load_n(&store->change_seq, __ATOMIC_ACQUIRE) >= target_seq_base;
    if (ok) ok = ct_lane_baseline_apply_rows_locked(store, read_context->user,
        bitmap, lane, &incoming, target_seq_base, baseline_row_seq,
        target_record_count,
        semantic_digest) &&
        memcmp(semantic_digest, expected_semantic_digest, 32u) == 0;
    bool current_generation = lane &&
        strnlen(lane->status.generation, QIHSE_KV_CT_ID_MAX + 1u) ==
            generation_len &&
        memcmp(lane->status.generation, generation_wire, generation_len) == 0;
    bool selected_is_current = current_generation &&
        (selected_subset || empty_lane_baseline);
    bool selected_is_full_current = selected_is_current &&
        memcmp(bitmap, lane->status.slot_bitmap,
               QIHSE_KV_CT_SLOT_BITMAP_BYTES) == 0;
    if (ok && selected_is_full_current &&
        lane->status.mode == QIHSE_KV_CT_LANE_RECEIVER) {
        lane->status.baseline_row_seq = baseline_row_seq;
        lane->status.baseline_stream_cut = source_cut;
        lane->status.durable_position = source_cut;
        lane->status.acknowledged_position = source_cut;
        lane->status.baseline_sealed = true;
        lane->status.admitted = false;
        memcpy(lane->status.baseline_digest, image_digest, 32u);
        ok = ct_lane_digest_bitmap(lane->status.slot_bitmap,
                                   lane->status.slot_bitmap_digest) &&
             ct_lanes_state_write(store) && ct_lane_marker_write(store);
    }
    if (!ok) store->recovery_pending = true;
    OPENSSL_cleanse(semantic_digest, sizeof(semantic_digest));
    OPENSSL_cleanse(expected_semantic_digest, sizeof(expected_semantic_digest));
    kv_store_unlock(store);
    locked = false;
    ok = ok && qihse_auth_user_is_active(read_context->user);
done:
    if (locked) kv_store_unlock(store);
    ct_range_image_free(&incoming);
    OPENSSL_cleanse(semantic_digest, sizeof(semantic_digest));
    OPENSSL_cleanse(expected_semantic_digest, sizeof(expected_semantic_digest));
    free(lane_id);
    return ok;
}

bool qihse_kv_ct_lane_receiver_baseline_install(qihse_kv_store_t* store,
    qihse_user_t* operator_principal, qihse_user_t* data_principal,
    const char* lane_id,
    const uint8_t selected_bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES],
    const char* snapshot_filepath,
    uint64_t baseline_row_seq, uint64_t source_cut,
    const unsigned char expected_digest[32],
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]) {
    if (!store || !ct_admin(operator_principal) ||
        !qihse_auth_user_is_active(data_principal)) {
        errno = EACCES;
        return false;
    }
    if (!ct_lane_id_valid(lane_id) || !selected_bitmap || !snapshot_filepath ||
        !expected_digest || !owner_token) {
        errno = EINVAL;
        return false;
    }
    uint8_t frame[CT_LANE_BASELINE_FRAME_BYTES];
    char lane_generation[QIHSE_KV_CT_ID_MAX + 1u];
    uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES];
    uint64_t target_seq_base = 0u;
    kv_store_rdlock(store);
    qihse_kv_ct_lane_t* lane = ct_lane_find(store, lane_id);
    unsigned mismatch = 0u;
    if (lane) for (size_t i = 0u; i < QIHSE_KV_CT_TOKEN_BYTES; ++i)
        mismatch |= owner_token[i] ^ lane->owner_token[i];
    bool selected_nonempty = ct_lane_baseline_bitmap_nonempty(selected_bitmap);
    bool allowed = lane && lane->status.mode == QIHSE_KV_CT_LANE_RECEIVER &&
        ((selected_nonempty && ct_lane_baseline_bitmap_subset(
            selected_bitmap, lane->status.slot_bitmap)) ||
         (!selected_nonempty && source_cut == 0u &&
          !ct_lane_baseline_bitmap_nonempty(lane->status.slot_bitmap))) &&
        mismatch == 0u && !store->recovery_pending && store->wal_fd;
    if (allowed) {
        snprintf(lane_generation, sizeof(lane_generation), "%s",
                 lane->status.generation);
        memcpy(bitmap, selected_bitmap, sizeof(bitmap));
        target_seq_base = __atomic_load_n(&store->change_seq, __ATOMIC_ACQUIRE);
    }
    kv_store_unlock(store);
    if (!allowed) { errno = EACCES; return false; }

    char image_path[4096];
    if (!ct_lane_baseline_image_path(lane_id, expected_digest, image_path,
                               sizeof(image_path)) ||
        !ct_lane_baseline_stage_image(snapshot_filepath, image_path,
                                      expected_digest)) return false;
    ct_range_image_t incoming = {0};
    uint16_t max_classification = 0u, required_sci = 0u;
    bool ok = ct_lane_baseline_image_read(image_path, data_principal, bitmap,
        baseline_row_seq,
        &incoming, &max_classification, &required_sci);
    ct_range_image_t existing = {0};
    if (ok) {
        kv_store_rdlock(store);
        lane = ct_lane_find(store, lane_id);
        ok = lane && !store->recovery_pending &&
            lane->status.mode == QIHSE_KV_CT_LANE_RECEIVER &&
            ((ct_lane_baseline_bitmap_nonempty(bitmap) &&
              ct_lane_baseline_bitmap_subset(bitmap, lane->status.slot_bitmap)) ||
             (!ct_lane_baseline_bitmap_nonempty(bitmap) && source_cut == 0u &&
              !ct_lane_baseline_bitmap_nonempty(lane->status.slot_bitmap))) &&
            strcmp(lane->status.generation, lane_generation) == 0 &&
            __atomic_load_n(&store->change_seq, __ATOMIC_ACQUIRE) == target_seq_base;
        if (ok) ok = ct_lane_baseline_collect_existing_locked(
            store, data_principal, lane, bitmap, &existing);
        kv_store_unlock(store);
    }
    uint64_t record_count = (uint64_t)incoming.count;
    if (ok && record_count > UINT64_MAX - target_seq_base) ok = false;
    ct_range_image_free(&existing);
    ct_range_image_free(&incoming);
    if (!ok || !ct_lane_baseline_frame_build(frame, lane_id, lane_generation,
            bitmap, baseline_row_seq, source_cut, target_seq_base,
            record_count, expected_digest, max_classification, required_sci)) {
        if (ok && errno == 0) errno = EINVAL;
        OPENSSL_cleanse(frame, sizeof(frame));
        return false;
    }

    kv_store_wrlock(store);
    lane = ct_lane_find(store, lane_id);
    mismatch = 0u;
    if (lane) for (size_t i = 0u; i < QIHSE_KV_CT_TOKEN_BYTES; ++i)
        mismatch |= owner_token[i] ^ lane->owner_token[i];
    ok = lane && mismatch == 0u && !store->recovery_pending &&
        lane->status.mode == QIHSE_KV_CT_LANE_RECEIVER &&
        ((ct_lane_baseline_bitmap_nonempty(bitmap) &&
          ct_lane_baseline_bitmap_subset(bitmap, lane->status.slot_bitmap)) ||
         (!ct_lane_baseline_bitmap_nonempty(bitmap) && source_cut == 0u &&
          !ct_lane_baseline_bitmap_nonempty(lane->status.slot_bitmap))) &&
        strcmp(lane->status.generation, lane_generation) == 0 &&
        __atomic_load_n(&store->change_seq, __ATOMIC_ACQUIRE) == target_seq_base;
    if (ok) {
        size_t written = fwrite(frame, 1u, sizeof(frame), store->wal_fd);
        ok = written == sizeof(frame) && fflush(store->wal_fd) == 0 &&
             fdatasync(fileno(store->wal_fd)) == 0;
        if (!ok) store->recovery_pending = true;
        else store->wal_unflushed_bytes = 0u;
    }
    kv_store_unlock(store);
    if (ok) {
        const kv_read_context_t read_context = {.user = data_principal};
        ok = ct_lane_baseline_apply_frame(store, frame, &read_context);
    }
    if (!ok) {
        kv_store_wrlock(store);
        store->recovery_pending = true;
        kv_store_unlock(store);
    }
    OPENSSL_cleanse(frame, sizeof(frame));
    return ok;
}
