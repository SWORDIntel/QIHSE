/* SPDX-License-Identifier: LicenseRef-SRSL-1.1 */
/* Exact-bitmap CT2 transfer helpers. Included after qihse_ct_range_export.inc
 * so the authenticated QFS snapshot types and row codec are available. */

typedef struct {
    ct_range_export_collect_t collect;
    const uint8_t* bitmap;
} ct_lane_transfer_collect_t;

static bool ct_lane_transfer_slot_selected(const uint8_t* bitmap,
                                            const char* key) {
    if (!bitmap || !key || qihse_cluster_key_is_node_local(key)) return false;
    size_t n = strlen(key);
    uint16_t slot = qihse_cluster_key_slot(key, n);
    return slot < QIHSE_CLUSTER_SLOT_COUNT &&
        (bitmap[slot / 8u] & (uint8_t)(1u << (slot % 8u))) != 0u;
}

/* SYSTEM_ALL lane snapshots require the existing system tenant principal;
 * classification/SCI clearance alone does not grant cross-tenant access. */
static bool ct_lane_transfer_system_principal(qihse_user_t* principal) {
    return principal && qihse_auth_user_is_active(principal) &&
        qihse_user_get_tenant_id(principal) == 0u;
}

static bool ct_lane_transfer_mem_cb(const char* key, void* value,
    size_t value_size, void* context) {
    (void)value_size;
    ct_lane_transfer_collect_t* x = context;
    if (!x || !x->collect.ok || !x->collect.authorized || !key || !value)
        return false;
    if (!ct_lane_transfer_slot_selected(x->bitmap, key)) return true;
    kv_payload_t* payload = value;
    if (!qihse_auth_user_is_active(x->collect.principal) ||
        !qihse_auth_can_access(x->collect.principal, payload->classification,
                               payload->sci_compartment)) {
        x->collect.authorized = false;
        errno = EACCES;
        return false;
    }
    return ct_range_export_add(&x->collect, key, payload, NULL);
}

static bool ct_lane_transfer_claim_same_reservation(
    const qihse_kv_ct_lane_authority_claim_t* a,
    const qihse_kv_ct_lane_authority_claim_t* b) {
    return a && b && a->operation == QIHSE_KV_CT_LANE_AUTH_TRANSFER &&
        b->operation == QIHSE_KV_CT_LANE_AUTH_TRANSFER &&
        memcmp(a->transfer_id, b->transfer_id, sizeof(a->transfer_id)) == 0 &&
        memcmp(a->source_group_id, b->source_group_id, sizeof(a->source_group_id)) == 0 &&
        memcmp(a->target_group_id, b->target_group_id, sizeof(a->target_group_id)) == 0 &&
        memcmp(a->source_qkp_id, b->source_qkp_id, sizeof(a->source_qkp_id)) == 0 &&
        memcmp(a->target_qkp_id, b->target_qkp_id, sizeof(a->target_qkp_id)) == 0 &&
        memcmp(a->source_generation, b->source_generation, sizeof(a->source_generation)) == 0 &&
        memcmp(a->target_generation, b->target_generation, sizeof(a->target_generation)) == 0 &&
        memcmp(a->successor_qkp_id, b->successor_qkp_id, sizeof(a->successor_qkp_id)) == 0 &&
        memcmp(a->slots, b->slots, sizeof(a->slots)) == 0 &&
        a->grant_epoch == b->grant_epoch && a->reserve_index == b->reserve_index &&
        memcmp(a->reserve_digest, b->reserve_digest, 32u) == 0;
}

static bool ct_lane_transfer_state_matches(
    const qihse_kv_ct_lane_transfer_state_t* state,
    const qihse_kv_ct_lane_authority_claim_t* claim) {
    return state && state->active && claim &&
        ct_lane_transfer_claim_same_reservation(&state->claim, claim) &&
        memcmp(state->pending_slot_bitmap, claim->slots, sizeof(claim->slots)) == 0;
}

static bool ct_lane_transfer_hash_image(const ct_range_image_t* image,
    const uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES], unsigned char out[32]) {
    if (!image || !bitmap || !out) return false;
    size_t live_count = 0u;
    for (size_t i = 0; i < image->count; ++i)
        if (!(image->rows[i].flags & KV_FLAG_TOMBSTONE)) live_count++;
    EVP_MD_CTX* md = EVP_MD_CTX_new();
    bool ok = md && EVP_DigestInit_ex(md, EVP_sha256(), NULL) == 1 &&
        EVP_DigestUpdate(md, "QCT-LANE-RANGE-V1", 17u) == 1 &&
        EVP_DigestUpdate(md, bitmap, QIHSE_KV_CT_SLOT_BITMAP_BYTES) == 1 &&
        ct_hash_u64(md, (uint64_t)live_count);
    for (size_t i = 0; ok && i < image->count; ++i) {
        const kv_disk_record_t* row = &image->rows[i];
        if (row->flags & KV_FLAG_TOMBSTONE) continue;
        size_t key_len = strlen(row->key), value_len = strlen(row->val);
        EVP_MD_CTX* one = EVP_MD_CTX_new();
        unsigned char row_digest[32];
        unsigned int row_len = 0u;
        bool row_ok = one && EVP_DigestInit_ex(one, EVP_sha256(), NULL) == 1 &&
            ct_hash_u64(one, key_len) && EVP_DigestUpdate(one, row->key, key_len) == 1 &&
            ct_hash_u64(one, value_len) && EVP_DigestUpdate(one, row->val, value_len) == 1 &&
            ct_hash_u64(one, row->expire_time_ms) &&
            ct_hash_u64(one, row->classification) &&
            ct_hash_u64(one, row->sci_compartment) &&
            ct_hash_u64(one, row->flags) &&
            EVP_DigestFinal_ex(one, row_digest, &row_len) == 1 && row_len == 32u;
        EVP_MD_CTX_free(one);
        ok = row_ok && (i == 0u || strcmp(image->rows[i - 1u].key, row->key) != 0) &&
            ct_hash_u64(md, key_len) && EVP_DigestUpdate(md, row->key, key_len) == 1 &&
            EVP_DigestUpdate(md, row_digest, sizeof(row_digest)) == 1;
    }
    unsigned int n = 0u;
    if (ok) ok = EVP_DigestFinal_ex(md, out, &n) == 1 && n == 32u;
    EVP_MD_CTX_free(md);
    return ok;
}

static bool ct_lane_transfer_qfs_digest(const ct_range_image_t* image,
                                         unsigned char out[32]) {
    if (!image || !out) return false;
    const char* dir = get_qihse_data_dir();
    char path[4096];
    int n = dir ? snprintf(path, sizeof(path), "%sct-lane-seal-XXXXXX", dir) : -1;
    if (n < 0 || (size_t)n >= sizeof(path)) return false;
    int fd = mkstemp(path);
    if (fd < 0) return false;
    (void)fchmod(fd, 0600);
    if (unlink(path) != 0) { int saved = errno; close(fd); errno = saved; return false; }
    FILE* f = fdopen(fd, "w+b");
    if (!f) { int saved = errno; close(fd); errno = saved; return false; }
    bool ok = true;
    for (size_t i = 0; ok && i < image->count; ++i) {
        const kv_disk_record_t* row = &image->rows[i];
        ok = disk_record_write_fields(f, row->key, row->val, row->expire_time_ms,
            row->classification, row->sci_compartment, row->flags, row->change_seq);
    }
    if (ok) ok = fflush(f) == 0 && fdatasync(fileno(f)) == 0 &&
                 ct_fd_sha256(fileno(f), out);
    int saved = errno;
    fclose(f);
    if (!ok) errno = saved;
    return ok;
}

static bool ct_lane_transfer_snapshot_image(qihse_kv_replica_snapshot_t* snapshot,
    qihse_user_t* principal, const uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES],
    ct_range_image_t* out, char staged_path[4096]) {
    if (!snapshot || !principal || !bitmap || !out || snapshot->fd < 0) return false;
    memset(out, 0, sizeof(*out));
    uint64_t source_size = 0u;
    if (!qihse_kv_replica_snapshot_size(snapshot, principal, &source_size) ||
        source_size > (uint64_t)INT64_MAX) return false;
    const char* dir = get_qihse_data_dir();
    char path[4096];
    int name_len = dir ? snprintf(path, sizeof(path), "%sct-lane-parse-XXXXXX", dir) : -1;
    if (name_len < 0 || (size_t)name_len >= sizeof(path)) return false;
    int stage_fd = mkstemp(path);
    if (stage_fd < 0) return false;
    (void)fchmod(stage_fd, 0600);
    bool copied = true;
    unsigned char bytes[65536];
    uint64_t offset = 0u;
    while (copied && offset < source_size) {
        size_t want = source_size - offset < sizeof(bytes)
            ? (size_t)(source_size - offset) : sizeof(bytes);
        size_t got = 0u;
        copied = qihse_kv_replica_snapshot_read(snapshot, principal,
            offset, bytes, want, &got) && got == want;
        size_t written = 0u;
        while (copied && written < got) {
            ssize_t n = write(stage_fd, bytes + written, got - written);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { copied = false; break; }
            written += (size_t)n;
        }
        offset += got;
    }
    if (copied) copied = fsync(stage_fd) == 0;
    if (close(stage_fd) != 0) copied = false;
    int fd = copied ? open_secure_read(path) : -1;
    int saved = errno;
    if (copied && staged_path)
        snprintf(staged_path, 4096u, "%s", path);
    else
        (void)unlink(path);
    errno = saved;
    FILE* f = fd >= 0 ? fdopen(fd, "rb") : NULL;
    if (!f) { if (fd >= 0) close(fd); return false; }
    const kv_read_context_t context = {.user = principal};
    bool ok = true;
    for (;;) {
        kv_disk_record_t row;
        int rc = disk_record_read_context(f, &row, &context);
        if (rc == 0) break;
        if (rc != 1) { ok = false; break; }
        if (!ct_lane_transfer_slot_selected(bitmap, row.key) ||
            (row.flags & ~KV_FLAG_TOMBSTONE) != 0u ||
            ((row.flags & KV_FLAG_TOMBSTONE) && (row.val[0] || row.expire_time_ms))) {
            disk_record_free(&row); ok = false; break;
        }
        size_t key_len = strlen(row.key), value_len = strlen(row.val);
        if (key_len > SIZE_MAX - value_len - 64u ||
            key_len + value_len + 64u > SIZE_MAX - out->bytes ||
            out->count == SIZE_MAX) {
            disk_record_free(&row); errno = EOVERFLOW; ok = false; break;
        }
        if (out->count == out->capacity) {
            if (out->capacity > SIZE_MAX / 2u) {
                disk_record_free(&row); errno = EOVERFLOW; ok = false; break;
            }
            size_t next = out->capacity ? out->capacity * 2u : 128u;
            if (next > SIZE_MAX / sizeof(*out->rows)) {
                disk_record_free(&row); errno = EOVERFLOW; ok = false; break;
            }
            kv_disk_record_t* grown = realloc(out->rows, next * sizeof(*grown));
            if (!grown) { disk_record_free(&row); ok = false; break; }
            out->rows = grown; out->capacity = next;
        }
        out->bytes += key_len + value_len + 64u;
        out->rows[out->count++] = row;
    }
    if (fclose(f) != 0) ok = false;
    if (ok) {
        if (out->count > 1u)
        qsort(out->rows, out->count, sizeof(*out->rows), ct_image_row_cmp);
        for (size_t i = 1u; i < out->count; ++i)
            if (strcmp(out->rows[i-1u].key, out->rows[i].key) == 0) ok = false;
    }
    if (!ok || !qihse_auth_user_is_active(principal)) {
        ct_range_image_free(out);
        return false;
    }
    return true;
}

/* The target node already has the candidate records in its source-A receiver
 * lane. Read only the exact selected slots so unrelated classifications in
 * intervening slots cannot affect this transfer. */
static bool ct_lane_transfer_local_image_locked(qihse_kv_store_t* store,
    qihse_user_t* principal, const uint8_t bitmap[QIHSE_KV_CT_SLOT_BITMAP_BYTES],
    ct_range_image_t* out) {
    if (!store || !principal || !bitmap || !out || !store->sst_meta ||
        store->sst_meta->degraded) return false;
    ct_lane_transfer_collect_t x = {0};
    x.bitmap = bitmap;
    x.collect.principal = principal;
    x.collect.first_slot = 0u;
    x.collect.last_slot = (uint16_t)(QIHSE_CLUSTER_SLOT_COUNT - 1u);
    x.collect.authorized = true;
    x.collect.ok = true;
    qihse_trinary_trie_foreach(store->trie, ct_lane_transfer_mem_cb, &x);
    if (!x.collect.ok || !x.collect.authorized) goto failed;
    for (size_t i = 0; i < store->sst_meta->cap; ++i) {
        const sst_meta_entry_t* m = &store->sst_meta->slots[i];
        if (!m->key || !ct_lane_transfer_slot_selected(bitmap, m->key) ||
            qihse_trinary_trie_search(store->trie, m->key, NULL)) continue;
        if (!qihse_auth_can_access(principal, m->classification, m->sci_compartment) ||
            !ct_range_export_add(&x.collect, m->key, NULL, m)) goto failed;
    }
    if (x.collect.count > 1u) qsort(x.collect.rows, x.collect.count, sizeof(*x.collect.rows),
              ct_range_export_entry_cmp);
    out->rows = calloc(x.collect.count ? x.collect.count : 1u, sizeof(*out->rows));
    if (!out->rows) goto failed;
    out->capacity = x.collect.count;
    const char* dir = get_qihse_data_dir();
    if (!dir) goto failed;
    for (size_t i = 0; i < x.collect.count; ++i) {
        ct_range_export_entry_t* e = &x.collect.rows[i];
        kv_disk_record_t row = {0};
        if (!qihse_auth_can_access(principal, e->classification, e->sci)) goto failed;
        if (e->memory) {
            row.key = strdup(e->key); row.val = strdup(e->memory->val);
            row.expire_time_ms = e->expiry; row.classification = e->classification;
            row.sci_compartment = e->sci; row.flags = e->flags;
            row.change_seq = e->memory->change_seq;
            if (!row.key || !row.val) { disk_record_free(&row); goto failed; }
        } else {
            pthread_mutex_lock(&store->sst_fd_lock);
            int fd = sst_fd_get(store, dir, e->sstable_id);
            pthread_mutex_unlock(&store->sst_fd_lock);
            if (fd < 0 || !ct_range_export_sst_header_allowed(fd, e->sst_offset, e, principal) ||
                disk_record_read_at(fd, e->sst_offset, &row) != 1) goto failed;
            if (strcmp(row.key, e->key) || row.classification != e->classification ||
                row.sci_compartment != e->sci || row.expire_time_ms != e->expiry ||
                row.flags != e->flags) { disk_record_free(&row); goto failed; }
        }
        size_t kl = strlen(row.key), vl = strlen(row.val);
        if (kl > SIZE_MAX - vl - 64u || kl + vl + 64u > SIZE_MAX - out->bytes) {
            disk_record_free(&row); errno = EOVERFLOW; goto failed;
        }
        out->bytes += kl + vl + 64u;
        out->rows[out->count++] = row;
    }
    for (size_t i = 1; i < out->count; ++i)
        if (!strcmp(out->rows[i-1u].key, out->rows[i].key)) goto failed;
    for (size_t i = 0; i < x.collect.count; ++i) free(x.collect.rows[i].key);
    free(x.collect.rows);
    return true;
failed:
    for (size_t i = 0; i < x.collect.count; ++i) free(x.collect.rows[i].key);
    free(x.collect.rows);
    ct_range_image_free(out);
    return false;
}

/* Snapshot only keys in the quorum-reserved bitmap. Unlike the old range
 * export, disjoint slots inside the bitmap's bounding interval are excluded. */
int qihse_kv_ct_lane_transfer_source_export(qihse_kv_store_t* store,
    qihse_user_t* control_principal, qihse_user_t* data_principal,
    const qihse_kv_ct_lane_authority_claim_t* claim,
    const qihse_kv_ct_proof_t* reserved_proof,
    qihse_kv_ct_lane_authority_verify_fn verify, void* verify_context,
    qihse_kv_replica_snapshot_t** out_snapshot,
    unsigned char out_range_digest[32], unsigned char out_image_digest[32]) {
    if (out_snapshot) *out_snapshot = NULL;
    if (out_range_digest) memset(out_range_digest, 0, 32u);
    if (out_image_digest) memset(out_image_digest, 0, 32u);
    if (!store || !ct_admin(control_principal) ||
        !ct_lane_transfer_system_principal(data_principal) ||
        !out_snapshot || !out_range_digest || !out_image_digest || !claim || !verify ||
        !qihse_kv_ct_lane_authority_proof_validate(store, control_principal,
            data_principal, reserved_proof, verify, verify_context, false)) {
        errno = EACCES;
        return -1;
    }
    qihse_kv_ct_lane_authority_claim_t proof_claim;
    if (!qihse_kv_ct_lane_authority_proof_fields(store, control_principal,
            data_principal, reserved_proof, &proof_claim) ||
        !ct_lane_transfer_claim_same_reservation(claim, &proof_claim) ||
        proof_claim.source_cut != claim->source_cut ||
        proof_claim.target_cursor != claim->target_cursor ||
        (!ct_digest_zero(claim->range_digest) && memcmp(claim->range_digest,
            proof_claim.range_digest, 32u) != 0) ||
        (!ct_digest_zero(claim->image_digest) && memcmp(claim->image_digest,
            proof_claim.image_digest, 32u) != 0)) {
        errno = EACCES;
        return -1;
    }

    ct_lane_transfer_collect_t x = {0};
    x.bitmap = claim->slots;
    x.collect.principal = data_principal;
    x.collect.first_slot = 0u;
    x.collect.last_slot = (uint16_t)(QIHSE_CLUSTER_SLOT_COUNT - 1u);
    x.collect.authorized = true;
    x.collect.ok = true;
    FILE* image = NULL;
    int image_fd = -1;
    kv_store_wrlock(store);
    qihse_kv_ct_lane_t* lane = ct_lane_find(store, claim->source_group_id);
    qihse_kv_ct_lane_transfer_state_t* state = store->lane_transfer;
    bool ok = !store->recovery_pending && store->sst_meta &&
        !store->sst_meta->degraded &&
        ct_lane_transfer_state_matches(state, claim) && state->source_fenced &&
        state->phase == 1u && lane && lane->status.mode == QIHSE_KV_CT_LANE_SOURCE &&
        lane->status.admitted && lane->status.baseline_sealed &&
        strcmp(lane->status.generation, claim->source_generation) == 0 &&
        state->source_cut <= lane->status.durable_position &&
        state->source_cut <= lane->status.acknowledged_position &&
        claim->source_cut == state->source_cut &&
        (ct_digest_zero(state->image_digest) ||
         state->claim.target_cursor == claim->target_cursor);
    if (ok) qihse_trinary_trie_foreach(store->trie, ct_lane_transfer_mem_cb, &x);
    if (!ok || !x.collect.ok || !x.collect.authorized) goto export_done;
    for (size_t i = 0; i < store->sst_meta->cap; ++i) {
        const sst_meta_entry_t* meta = &store->sst_meta->slots[i];
        if (!meta->key || !ct_lane_transfer_slot_selected(claim->slots, meta->key) ||
            qihse_trinary_trie_search(store->trie, meta->key, NULL)) continue;
        if (!qihse_auth_can_access(data_principal, meta->classification,
                                   meta->sci_compartment)) {
            x.collect.authorized = false; errno = EACCES; goto export_done;
        }
        if (!ct_range_export_add(&x.collect, meta->key, NULL, meta)) goto export_done;
    }
    if (x.collect.count > 1u) qsort(x.collect.rows, x.collect.count, sizeof(*x.collect.rows),
              ct_range_export_entry_cmp);
    for (size_t i = 1; i < x.collect.count; ++i)
        if (strcmp(x.collect.rows[i-1].key, x.collect.rows[i].key) == 0) {
            errno = EINVAL; goto export_done;
        }
    ct_range_image_t range = {0};
    uint64_t snapshot_change_seq = 0u;
    range.rows = calloc(x.collect.count ? x.collect.count : 1u, sizeof(*range.rows));
    if (!range.rows) goto export_done;
    range.capacity = x.collect.count;
    const char* dir = get_qihse_data_dir();
    char path[4096];
    int path_len = dir ? snprintf(path, sizeof(path), "%sct-lane-range-XXXXXX", dir) : -1;
    if (path_len < 0 || (size_t)path_len >= sizeof(path)) {
        ct_range_image_free(&range); goto export_done;
    }
    image_fd = mkstemp(path);
    if (image_fd < 0) { ct_range_image_free(&range); goto export_done; }
    (void)fchmod(image_fd, 0600);
    if (unlink(path) != 0) { ct_range_image_free(&range); goto export_done; }
    image = fdopen(image_fd, "w+b");
    if (!image) { ct_range_image_free(&range); goto export_done; }
    image_fd = -1;
    for (size_t i = 0; i < x.collect.count; ++i) {
        ct_range_export_entry_t* e = &x.collect.rows[i];
        kv_disk_record_t row = {0};
        if (!ct_lane_transfer_system_principal(data_principal) ||
            !qihse_auth_can_access(data_principal, e->classification, e->sci)) {
            x.collect.authorized = false; errno = EACCES; ct_range_image_free(&range); goto export_done;
        }
        if (e->memory) {
            row.key = strdup(e->key); row.val = strdup(e->memory->val);
            row.classification = e->classification; row.sci_compartment = e->sci;
            row.expire_time_ms = e->expiry; row.flags = e->flags;
            row.change_seq = e->memory->change_seq;
            if (!row.key || !row.val || !disk_record_write(image, e->key, e->memory)) {
                disk_record_free(&row); ct_range_image_free(&range); goto export_done;
            }
        } else {
            pthread_mutex_lock(&store->sst_fd_lock);
            int fd = sst_fd_get(store, dir, e->sstable_id);
            pthread_mutex_unlock(&store->sst_fd_lock);
            if (fd < 0 || !ct_range_export_sst_header_allowed(fd, e->sst_offset, e,
                                                               data_principal) ||
                disk_record_read_at(fd, e->sst_offset, &row) != 1) {
                ct_range_image_free(&range); goto export_done;
            }
            bool valid = strcmp(row.key, e->key) == 0 &&
                row.classification == e->classification && row.sci_compartment == e->sci &&
                row.expire_time_ms == e->expiry && row.flags == e->flags &&
                disk_record_write_fields(image, row.key, row.val, row.expire_time_ms,
                    row.classification, row.sci_compartment, row.flags, row.change_seq);
            if (!valid) { disk_record_free(&row); ct_range_image_free(&range); goto export_done; }
        }
        size_t key_len = strlen(row.key), value_len = strlen(row.val);
        if (key_len > SIZE_MAX - value_len - 64u ||
            key_len + value_len + 64u > SIZE_MAX - range.bytes) {
            disk_record_free(&row); ct_range_image_free(&range); errno = EOVERFLOW; goto export_done;
        }
        range.bytes += key_len + value_len + 64u;
        if (row.change_seq > snapshot_change_seq)
            snapshot_change_seq = row.change_seq;
        range.rows[range.count++] = row;
    }
    if (fflush(image) != 0 || fdatasync(fileno(image)) != 0 ||
        !ct_lane_transfer_hash_image(&range, claim->slots, out_range_digest) ||
        !ct_fd_sha256(fileno(image), out_image_digest)) {
        ct_range_image_free(&range); goto export_done;
    }
    ct_range_image_free(&range);
    if ((!ct_digest_zero(claim->range_digest) &&
         memcmp(claim->range_digest, out_range_digest, 32u) != 0) ||
        (!ct_digest_zero(claim->image_digest) &&
         memcmp(claim->image_digest, out_image_digest, 32u) != 0) ||
        !ct_lane_transfer_state_matches(state, claim) ||
        !ct_lane_transfer_system_principal(data_principal)) {
        errno = EACCES; goto export_done;
    }
    /* The first successful export pins the selected target group's ACK cut
     * alongside the exported image. Retries must reproduce both the image
     * and that exact cut, including the valid zero-cut case. */
    state->claim = *claim;
    state->target_cursor = claim->target_cursor;
    memcpy(state->image_digest, out_image_digest, 32u);
    memcpy(state->range_digest, out_range_digest, 32u);
    memcpy(state->claim.image_digest, out_image_digest, 32u);
    memcpy(state->claim.range_digest, out_range_digest, 32u);
    if (!ct_lane_transfer_state_write(store)) { store->recovery_pending = true; goto export_done; }
    off_t end = ftello(image);
    if (end < 0) goto export_done;
    qihse_kv_replica_snapshot_t* snapshot = calloc(1u, sizeof(*snapshot));
    if (!snapshot) goto export_done;
    snapshot->fd = dup(fileno(image));
    snapshot->size = (uint64_t)end;
    /* Replica snapshot watermark is the row change-sequence domain. CT lane
     * source_cut is a distinct stream-position domain and remains in state. */
    snapshot->source_change_seq = snapshot_change_seq;
    snapshot->principal = data_principal;
    snapshot->principal_id = qihse_user_get_id(data_principal);
    snapshot->tenant_id = qihse_user_get_tenant_id(data_principal);
    snapshot->classification = x.collect.max_classification;
    snapshot->sci = x.collect.required_sci;
    if (snapshot->fd < 0) { free(snapshot); goto export_done; }
    *out_snapshot = snapshot;
    ok = true;
export_done:
    kv_store_unlock(store);
    if (image) fclose(image);
    if (image_fd >= 0) close(image_fd);
    for (size_t i = 0; i < x.collect.count; ++i) free(x.collect.rows[i].key);
    free(x.collect.rows);
    if (!ok) { memset(out_range_digest, 0, 32u); memset(out_image_digest, 0, 32u); return x.collect.authorized ? -1 : -2; }
    return 0;
}

static bool ct_lane_transfer_token_matches(const qihse_kv_ct_lane_t* lane,
    const unsigned char token[QIHSE_KV_CT_TOKEN_BYTES]) {
    if (!lane || !token) return false;
    unsigned diff = 0u;
    for (size_t i = 0; i < QIHSE_KV_CT_TOKEN_BYTES; ++i)
        diff |= lane->owner_token[i] ^ token[i];
    return diff == 0u;
}

bool qihse_kv_ct_lane_transfer_target_import_begin(qihse_kv_store_t* store,
    qihse_user_t* control_principal, qihse_user_t* data_principal,
    const qihse_kv_ct_lane_authority_claim_t* claim,
    const qihse_kv_ct_proof_t* reserved_proof,
    qihse_kv_ct_lane_authority_verify_fn verify, void* verify_context,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]) {
    qihse_kv_ct_lane_authority_claim_t proof_claim;
    if (!store || !ct_admin(control_principal) ||
        !ct_lane_transfer_system_principal(data_principal) ||
        !owner_token || !verify ||
        !qihse_kv_ct_lane_authority_proof_validate(store, control_principal,
            data_principal, reserved_proof, verify, verify_context, false) ||
        !qihse_kv_ct_lane_authority_proof_fields(store, control_principal,
            data_principal, reserved_proof, &proof_claim) ||
        !ct_lane_transfer_claim_same_reservation(claim, &proof_claim) ||
        proof_claim.source_cut != claim->source_cut ||
        proof_claim.target_cursor != claim->target_cursor) {
        errno = EACCES; return false;
    }
    kv_store_wrlock(store);
    qihse_kv_ct_lane_t* receiver = ct_lane_find(store, claim->source_group_id);
    qihse_kv_ct_lane_t* target = ct_lane_find(store, claim->target_group_id);
    bool receiver_slots = receiver != NULL;
    if (receiver) for (size_t i = 0; i < sizeof(claim->slots); ++i)
        if (claim->slots[i] & (uint8_t)~receiver->status.slot_bitmap[i]) {
            receiver_slots = false; break;
        }
    bool target_role_ok = target &&
        ((target->status.mode == QIHSE_KV_CT_LANE_SOURCE &&
          target->status.admitted && target->status.baseline_sealed &&
          target->status.durable_position >= claim->target_cursor &&
          target->status.acknowledged_position >= claim->target_cursor &&
          strcmp(target->status.source_id, claim->target_qkp_id) == 0 &&
          strcmp(target->status.peer_id, claim->successor_qkp_id) == 0) ||
         (target->status.mode == QIHSE_KV_CT_LANE_RECEIVER &&
          target->status.durable_position >= claim->target_cursor &&
          strcmp(target->status.source_id, claim->target_qkp_id) == 0 &&
          strcmp(target->status.peer_id, claim->successor_qkp_id) == 0)) &&
        strcmp(target->status.generation, claim->target_generation) == 0;
    bool receiver_is_staging = receiver &&
        receiver->status.mode == QIHSE_KV_CT_LANE_RECEIVER &&
        !receiver->status.admitted &&
        strcmp(receiver->status.source_id, claim->source_qkp_id) == 0 &&
        (!strcmp(receiver->status.peer_id, claim->target_qkp_id) ||
         (target && target->status.mode == QIHSE_KV_CT_LANE_RECEIVER &&
          !strcmp(receiver->status.peer_id, claim->successor_qkp_id))) &&
        strcmp(receiver->status.generation, claim->source_generation) == 0;
    bool source_is_fenced_successor = receiver &&
        receiver->status.mode == QIHSE_KV_CT_LANE_SOURCE &&
        strcmp(receiver->status.source_id, claim->source_qkp_id) == 0 &&
        strcmp(receiver->status.generation, claim->source_generation) == 0 &&
        store->lane_transfer && store->lane_transfer->active &&
        store->lane_transfer->source_fenced &&
        store->lane_transfer->source_cut == claim->source_cut &&
        store->lane_transfer->source_cut <= receiver->status.durable_position &&
        store->lane_transfer->source_cut <= receiver->status.acknowledged_position;
    bool ok = !store->recovery_pending && !store->memory_snapshot &&
        target_role_ok &&
        (receiver_is_staging || source_is_fenced_successor) &&
        receiver_slots && ct_lane_transfer_token_matches(target, owner_token);
    if (ok && store->lane_transfer && store->lane_transfer->active &&
        store->lane_transfer->phase == 4u) {
        qihse_kv_ct_lane_transfer_state_t* prior = store->lane_transfer;
        if (ct_lane_transfer_claim_same_reservation(&prior->claim, claim)) {
            ok = prior->target_imported &&
                prior->source_cut == claim->source_cut &&
                prior->target_cursor == claim->target_cursor &&
                (ct_digest_zero(claim->image_digest) ||
                 memcmp(prior->image_digest, claim->image_digest, 32u) == 0) &&
                (ct_digest_zero(claim->range_digest) ||
                 memcmp(prior->range_digest, claim->range_digest, 32u) == 0);
        } else {
            qihse_kv_ct_lane_transfer_state_t* next = calloc(1u, sizeof(*next));
            if (!next) ok = false;
            else {
                next->active = true;
                next->phase = 1u;
                next->claim = *claim;
                next->source_cut = claim->source_cut;
                next->target_cursor = claim->target_cursor;
                next->source_fenced = true;
                memcpy(next->pending_slot_bitmap, claim->slots,
                       sizeof(claim->slots));
                store->lane_transfer = next;
                if (!ct_lane_transfer_state_write(store)) {
                    store->lane_transfer = prior;
                    free(next);
                    store->recovery_pending = true;
                    ok = false;
                } else {
                    free(prior);
                }
            }
        }
    } else if (ok && store->lane_transfer && store->lane_transfer->active) {
        ok = ct_lane_transfer_state_matches(store->lane_transfer, claim) &&
            store->lane_transfer->source_cut == claim->source_cut &&
            ((store->lane_transfer->phase == 1u) ||
             (store->lane_transfer->phase == 2u &&
              store->lane_transfer->target_imported &&
              store->lane_transfer->target_cursor == claim->target_cursor &&
              (ct_digest_zero(claim->image_digest) ||
               memcmp(store->lane_transfer->image_digest,
                      claim->image_digest, 32u) == 0) &&
              (ct_digest_zero(claim->range_digest) ||
               memcmp(store->lane_transfer->range_digest,
                      claim->range_digest, 32u) == 0)));
        if (ok && store->lane_transfer->phase == 1u) {
            store->lane_transfer->target_cursor = claim->target_cursor;
            if (!ct_lane_transfer_state_write(store)) {
                store->recovery_pending = true;
                ok = false;
            }
        }
    } else if (ok) {
        qihse_kv_ct_lane_transfer_state_t* state = calloc(1u, sizeof(*state));
        if (!state) ok = false;
        else {
            state->active = true;
            state->phase = 1u;
            state->claim = *claim;
            state->source_cut = claim->source_cut;
            state->target_cursor = claim->target_cursor;
            state->source_fenced = true; /* authority reservation gates this import */
            memcpy(state->pending_slot_bitmap, claim->slots, sizeof(claim->slots));
            store->lane_transfer = state;
            if (!ct_lane_transfer_state_write(store)) {
                store->lane_transfer = NULL; free(state); store->recovery_pending = true;
                ok = false;
            }
        }
    }
    kv_store_unlock(store);
    if (!ok) errno = EBUSY;
    return ok;
}

bool qihse_kv_ct_lane_transfer_target_import_apply(qihse_kv_store_t* store,
    qihse_user_t* control_principal, qihse_user_t* replication_principal,
    qihse_user_t* data_principal,
    const qihse_kv_ct_lane_authority_claim_t* claim,
    const qihse_kv_ct_proof_t* reserved_proof,
    qihse_kv_ct_lane_authority_verify_fn verify, void* verify_context,
    qihse_kv_replica_snapshot_t* snapshot,
    const unsigned char expected_image_digest[32],
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]) {
    qihse_kv_ct_lane_authority_claim_t proof_claim;
    unsigned char image_digest[32], range_digest[32];
    uint64_t snapshot_size = 0u;
    uint64_t snapshot_change_seq = 0u;
    char staged_path[4096] = {0};
    unsigned char receiver_token[QIHSE_KV_CT_TOKEN_BYTES] = {0};
    ct_range_image_t incoming = {0};
    if (!store || !ct_admin(control_principal) || !snapshot || !expected_image_digest ||
        !replication_principal || !data_principal || !owner_token || !verify ||
        !ct_lane_transfer_system_principal(data_principal) ||
        !qihse_kv_ct_lane_authority_proof_validate(store, control_principal,
            data_principal, reserved_proof, verify, verify_context, false) ||
        !qihse_kv_ct_lane_authority_proof_fields(store, control_principal,
            data_principal, reserved_proof, &proof_claim) ||
        !ct_lane_transfer_claim_same_reservation(claim, &proof_claim) ||
        proof_claim.source_cut != claim->source_cut ||
        proof_claim.target_cursor != claim->target_cursor ||
        (!ct_digest_zero(claim->range_digest) && memcmp(claim->range_digest,
            proof_claim.range_digest, 32u) != 0) ||
        (!ct_digest_zero(claim->image_digest) && memcmp(claim->image_digest,
            proof_claim.image_digest, 32u) != 0) ||
        !qihse_kv_replica_snapshot_size(snapshot, data_principal, &snapshot_size) ||
        !ct_fd_sha256(snapshot->fd, image_digest) ||
        memcmp(image_digest, expected_image_digest, 32u) != 0 ||
        (!ct_digest_zero(claim->image_digest) &&
         memcmp(image_digest, claim->image_digest, 32u) != 0) ||
        !ct_lane_transfer_snapshot_image(snapshot, data_principal, claim->slots,
                                        &incoming, staged_path) ||
        !ct_lane_transfer_hash_image(&incoming, claim->slots, range_digest)) {
        if (staged_path[0]) (void)unlink(staged_path);
        ct_range_image_free(&incoming); errno = EACCES; return false;
    }
    if (!ct_digest_zero(claim->range_digest) &&
        memcmp(range_digest, claim->range_digest, 32u) != 0) {
        (void)unlink(staged_path);
        ct_range_image_free(&incoming); errno = EINVAL; return false;
    }
    int staged_fd = open_secure_read(staged_path);
    struct stat staged_stat;
    unsigned char staged_digest[32];
    bool staged_ok = staged_fd >= 0 && fstat(staged_fd, &staged_stat) == 0 &&
        S_ISREG(staged_stat.st_mode) && staged_stat.st_size >= 0 &&
        (uint64_t)staged_stat.st_size == snapshot_size &&
        ct_fd_sha256(staged_fd, staged_digest) &&
        memcmp(staged_digest, image_digest, sizeof(image_digest)) == 0;
    if (staged_fd >= 0) close(staged_fd);
    if (!staged_ok) {
        (void)unlink(staged_path);
        ct_range_image_free(&incoming); errno = EINVAL; return false;
    }
    for (size_t i = 0; i < incoming.count; ++i)
        if (incoming.rows[i].change_seq > snapshot_change_seq)
            snapshot_change_seq = incoming.rows[i].change_seq;
    if (snapshot->source_change_seq != UINT64_MAX &&
        snapshot->source_change_seq != snapshot_change_seq) {
        (void)unlink(staged_path);
        ct_range_image_free(&incoming); errno = EINVAL; return false;
    }
    kv_store_wrlock(store);
    qihse_kv_ct_lane_t* receiver = ct_lane_find(store, claim->source_group_id);
    qihse_kv_ct_lane_t* target = ct_lane_find(store, claim->target_group_id);
    qihse_kv_ct_lane_transfer_state_t* state = store->lane_transfer;
    bool source_is_receiver = receiver &&
        receiver->status.mode == QIHSE_KV_CT_LANE_RECEIVER;
    bool target_is_receiver = target &&
        target->status.mode == QIHSE_KV_CT_LANE_RECEIVER;
    bool source_is_fenced_owner = receiver &&
        receiver->status.mode == QIHSE_KV_CT_LANE_SOURCE;
    bool source_slots_owned = source_is_fenced_owner;
    if (source_slots_owned) for (size_t i = 0; i < sizeof(claim->slots); ++i)
        if (claim->slots[i] & (uint8_t)~receiver->status.slot_bitmap[i]) {
            source_slots_owned = false; break;
        }
    bool target_role_ok = target &&
        ((target->status.mode == QIHSE_KV_CT_LANE_SOURCE &&
          target->status.durable_position >= claim->target_cursor &&
          target->status.acknowledged_position >= claim->target_cursor &&
          strcmp(target->status.source_id, claim->target_qkp_id) == 0 &&
          strcmp(target->status.peer_id, claim->successor_qkp_id) == 0) ||
         (target->status.mode == QIHSE_KV_CT_LANE_RECEIVER &&
          target->status.durable_position >= claim->target_cursor &&
          strcmp(target->status.source_id, claim->target_qkp_id) == 0 &&
          strcmp(target->status.peer_id, claim->successor_qkp_id) == 0)) &&
        strcmp(target->status.generation, claim->target_generation) == 0;
    bool source_role_ok = source_is_receiver
        ? (!receiver->status.admitted &&
           strcmp(receiver->status.source_id, claim->source_qkp_id) == 0 &&
           (!strcmp(receiver->status.peer_id, claim->target_qkp_id) ||
            (target && target->status.mode == QIHSE_KV_CT_LANE_RECEIVER &&
             !strcmp(receiver->status.peer_id, claim->successor_qkp_id))) &&
           strcmp(receiver->status.generation, claim->source_generation) == 0)
        : (source_is_fenced_owner && state && receiver->status.admitted &&
           state->source_cut <= receiver->status.durable_position &&
           state->source_cut <= receiver->status.acknowledged_position &&
           source_slots_owned &&
           strcmp(receiver->status.source_id, claim->source_qkp_id) == 0 &&
           strcmp(receiver->status.generation, claim->source_generation) == 0);
    bool common_ok = !store->recovery_pending && !store->memory_snapshot &&
        ct_lane_transfer_state_matches(state, claim) && source_role_ok && target_role_ok &&
        state->source_cut == claim->source_cut &&
        state->target_cursor == claim->target_cursor &&
        ct_lane_transfer_token_matches(target, owner_token) &&
        ct_lane_peer_principal(store, replication_principal);
    if (common_ok && state->phase == 2u && state->target_imported &&
        memcmp(state->image_digest, image_digest, 32u) == 0 &&
        memcmp(state->range_digest, range_digest, 32u) == 0) {
        ct_range_image_t current = {0};
        unsigned char current_range[32];
        bool replay_ok = ct_lane_transfer_local_image_locked(store, data_principal,
                claim->slots, &current) &&
            ct_lane_transfer_hash_image(&current, claim->slots, current_range) &&
            memcmp(current_range, range_digest, 32u) == 0;
        ct_range_image_free(&current);
        kv_store_unlock(store);
        (void)unlink(staged_path);
        ct_range_image_free(&incoming);
        if (!replay_ok) errno = EINVAL;
        return replay_ok;
    }
    bool ok = common_ok && state->phase == 1u;
    uint64_t source_cut = ok ? state->source_cut : 0u;
    if (ok && source_is_receiver)
        memcpy(receiver_token, receiver->owner_token, sizeof(receiver_token));
    kv_store_unlock(store);
    if (!ok) {
        (void)unlink(staged_path);
        ct_range_image_free(&incoming); errno = EBUSY; return false;
    }

    int saved_errno = 0;
    if (source_is_receiver) {
        /* Install a complete exact-bitmap receiver baseline. The destination's
         * unrelated keys remain untouched, while stale keys in these slots
         * are removed. The operation is idempotent for crash recovery. */
        ok = qihse_kv_ct_lane_receiver_baseline_install(store, control_principal,
            data_principal, claim->source_group_id, claim->slots, staged_path,
            snapshot_change_seq, source_cut, image_digest, receiver_token);
        saved_errno = errno;
        qihse_kv_ct_lane_status_t installed = {0};
        if (ok) {
            ok = qihse_kv_ct_lane_status(store, control_principal,
                claim->source_group_id, &installed) &&
                installed.mode == QIHSE_KV_CT_LANE_RECEIVER && !installed.admitted &&
                strcmp(installed.source_id, claim->source_qkp_id) == 0 &&
                (!strcmp(installed.peer_id, claim->target_qkp_id) ||
                 (target_is_receiver && !strcmp(installed.peer_id, claim->successor_qkp_id))) &&
                strcmp(installed.generation, claim->source_generation) == 0;
            for (size_t i = 0; ok && i < sizeof(claim->slots); ++i)
                if (claim->slots[i] & (uint8_t)~installed.slot_bitmap[i]) ok = false;
        }
    } else {
        /* The original source may also be the target's successor. It already
         * owns this range, so verify its fenced image instead of overwriting
         * its SOURCE lane or resetting its stream cursor. */
        ct_range_image_t current = {0};
        unsigned char current_image[32] = {0}, current_range[32] = {0};
        kv_store_rdlock(store);
        ok = ct_lane_transfer_local_image_locked(store, data_principal,
            claim->slots, &current);
        kv_store_unlock(store);
        if (ok) ok = ct_lane_transfer_hash_image(&current, claim->slots, current_range) &&
            memcmp(current_range, range_digest, 32u) == 0;
        if (ok) ok = ct_lane_transfer_qfs_digest(&current, current_image) &&
            memcmp(current_image, image_digest, 32u) == 0;
        saved_errno = errno;
        ct_range_image_free(&current);
    }
    if (unlink(staged_path) != 0 && errno != ENOENT) ok = false;
    if (ok) {
        kv_store_wrlock(store);
        state = store->lane_transfer;
        receiver = ct_lane_find(store, claim->source_group_id);
        target = ct_lane_find(store, claim->target_group_id);
        ok = !store->recovery_pending && ct_lane_transfer_state_matches(state, claim) &&
            state->phase == 1u && state->source_cut == source_cut && receiver && target &&
            ((source_is_receiver && receiver->status.mode == QIHSE_KV_CT_LANE_RECEIVER) ||
             (source_is_fenced_owner && receiver->status.mode == QIHSE_KV_CT_LANE_SOURCE &&
              state->source_cut <= receiver->status.durable_position &&
              state->source_cut <= receiver->status.acknowledged_position)) &&
            ct_lane_transfer_token_matches(target, owner_token);
        if (ok) {
            state->target_cursor = claim->target_cursor;
            state->import_base_change_seq = store->change_seq;
            state->applied_records = incoming.count;
            memcpy(state->import_prefix_digest, range_digest, 32u);
            memcpy(state->range_digest, range_digest, 32u);
            memcpy(state->image_digest, image_digest, 32u);
            state->target_imported = true;
            state->phase = 2u;
            ok = ct_lane_transfer_state_write(store);
            if (!ok) {
                state->phase = 1u;
                state->target_imported = false;
                store->recovery_pending = true;
            }
        }
        kv_store_unlock(store);
    }
    ct_range_image_free(&incoming);
    if (!ok) errno = saved_errno ? saved_errno : EBUSY;
    return ok;
}

bool qihse_kv_ct_lane_transfer_target_import_apply_file(qihse_kv_store_t* store,
    qihse_user_t* control_principal, qihse_user_t* replication_principal,
    qihse_user_t* data_principal,
    const qihse_kv_ct_lane_authority_claim_t* claim,
    const qihse_kv_ct_proof_t* reserved_proof,
    qihse_kv_ct_lane_authority_verify_fn verify, void* verify_context,
    const char* snapshot_filepath,
    const unsigned char expected_image_digest[32],
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]) {
    if (!store || !ct_admin(control_principal) ||
        !ct_lane_transfer_system_principal(data_principal) || !snapshot_filepath ||
        !expected_image_digest) { errno = EACCES; return false; }
    const char* data_dir = get_qihse_data_dir();
    size_t dir_len = data_dir ? strlen(data_dir) : 0u;
    if (!dir_len || strncmp(snapshot_filepath, data_dir, dir_len) != 0 ||
        snapshot_filepath[dir_len] == '\0' || strstr(snapshot_filepath + dir_len, "../") ||
        strstr(snapshot_filepath + dir_len, "/..")) {
        errno = EACCES; return false;
    }
    int fd = open_secure_read(snapshot_filepath);
    if (fd < 0) return false;
    struct stat before;
    if (fstat(fd, &before) != 0 || !S_ISREG(before.st_mode) ||
        before.st_uid != geteuid() || (before.st_mode & 077) != 0 ||
        before.st_nlink != 1 || before.st_size < 0 ||
        (uint64_t)before.st_size > (uint64_t)INT64_MAX) {
        close(fd); errno = EINVAL; return false;
    }
    qihse_kv_replica_snapshot_t* snapshot = calloc(1u, sizeof(*snapshot));
    if (!snapshot) { close(fd); return false; }
    snapshot->fd = fd;
    snapshot->size = (uint64_t)before.st_size;
    /* The row watermark is derived from the authenticated QFS stream below.
     * UINT64_MAX is a private sentinel meaning “not supplied by caller”. */
    snapshot->source_change_seq = UINT64_MAX;
    snapshot->principal = data_principal;
    snapshot->principal_id = qihse_user_get_id(data_principal);
    snapshot->tenant_id = qihse_user_get_tenant_id(data_principal);
    snapshot->classification = 0u;
    snapshot->sci = 0u;
    bool ok = qihse_kv_ct_lane_transfer_target_import_apply(store,
        control_principal, replication_principal, data_principal, claim,
        reserved_proof, verify, verify_context, snapshot,
        expected_image_digest, owner_token);
    int saved_errno = errno;
    struct stat after;
    bool stable = fstat(fd, &after) == 0 && after.st_dev == before.st_dev &&
        after.st_ino == before.st_ino && after.st_size == before.st_size &&
        after.st_mtime == before.st_mtime && after.st_ctime == before.st_ctime;
#if defined(__linux__)
    stable = stable && after.st_mtim.tv_nsec == before.st_mtim.tv_nsec &&
        after.st_ctim.tv_nsec == before.st_ctim.tv_nsec;
#endif
    qihse_kv_replica_snapshot_destroy(snapshot);
    if (!stable) { errno = EIO; return false; }
    if (!ok) errno = saved_errno;
    return ok;
}

bool qihse_kv_ct_lane_transfer_target_seal(qihse_kv_store_t* store,
    qihse_user_t* control_principal, qihse_user_t* data_principal,
    const qihse_kv_ct_lane_authority_claim_t* claim,
    const qihse_kv_ct_proof_t* reserved_proof,
    qihse_kv_ct_lane_authority_verify_fn verify, void* verify_context,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES],
    unsigned char out_seal_digest[32]) {
    if (out_seal_digest) memset(out_seal_digest, 0, 32u);
    qihse_kv_ct_lane_authority_claim_t proof_claim;
    if (!store || !ct_admin(control_principal) ||
        !ct_lane_transfer_system_principal(data_principal) ||
        !owner_token || !out_seal_digest || !verify ||
        !qihse_kv_ct_lane_authority_proof_validate(store, control_principal,
            data_principal, reserved_proof, verify, verify_context, false) ||
        !qihse_kv_ct_lane_authority_proof_fields(store, control_principal,
            data_principal, reserved_proof, &proof_claim) ||
        !ct_lane_transfer_claim_same_reservation(claim, &proof_claim) ||
        proof_claim.source_cut != claim->source_cut ||
        proof_claim.target_cursor != claim->target_cursor ||
        (!ct_digest_zero(claim->range_digest) && memcmp(claim->range_digest,
            proof_claim.range_digest, 32u) != 0) ||
        (!ct_digest_zero(claim->image_digest) && memcmp(claim->image_digest,
            proof_claim.image_digest, 32u) != 0)) {
        errno = EACCES; return false;
    }
    ct_range_image_t current = {0};
    kv_store_wrlock(store);
    qihse_kv_ct_lane_transfer_state_t* state = store->lane_transfer;
    qihse_kv_ct_lane_t* receiver = ct_lane_find(store, claim->source_group_id);
    qihse_kv_ct_lane_t* target = ct_lane_find(store, claim->target_group_id);
    bool incoming_receiver = receiver &&
        receiver->status.mode == QIHSE_KV_CT_LANE_RECEIVER;
    bool source_owner = receiver &&
        receiver->status.mode == QIHSE_KV_CT_LANE_SOURCE;
    bool target_ready = target &&
        ((target->status.mode == QIHSE_KV_CT_LANE_SOURCE &&
          target->status.durable_position >= claim->target_cursor &&
          target->status.acknowledged_position >= claim->target_cursor) ||
         (target->status.mode == QIHSE_KV_CT_LANE_RECEIVER &&
          target->status.durable_position >= claim->target_cursor)) &&
        strcmp(target->status.source_id, claim->target_qkp_id) == 0 &&
        strcmp(target->status.peer_id, claim->successor_qkp_id) == 0 &&
        strcmp(target->status.generation, claim->target_generation) == 0;
    bool ok = !store->recovery_pending && state && state->phase == 2u &&
        state->target_imported && ct_lane_transfer_state_matches(state, claim) &&
        (incoming_receiver || source_owner) && target_ready &&
        ct_lane_transfer_token_matches(target, owner_token) &&
        ((incoming_receiver && !receiver->status.admitted) ||
         (source_owner &&
          state->source_cut <= receiver->status.durable_position &&
          state->source_cut <= receiver->status.acknowledged_position));
    if (ok && (claim->source_cut != state->source_cut ||
               claim->target_cursor != state->target_cursor))
        ok = false;
    if (ok) ok = ct_lane_transfer_local_image_locked(store, data_principal,
        claim->slots, &current);
    unsigned char range_digest[32] = {0};
    if (ok) ok = ct_lane_transfer_hash_image(&current, claim->slots, range_digest) &&
        !ct_digest_zero(state->image_digest) &&
        !ct_digest_zero(state->range_digest) &&
        memcmp(range_digest, state->range_digest, 32u) == 0 &&
        (!ct_digest_zero(claim->range_digest) &&
         memcmp(claim->range_digest, range_digest, 32u) == 0) &&
        (!ct_digest_zero(claim->image_digest) &&
         memcmp(claim->image_digest, state->image_digest, 32u) == 0);
    if (ok) {
        qihse_kv_ct_lane_authority_claim_t sealed = *claim;
        memcpy(sealed.range_digest, range_digest, 32u);
        memcpy(sealed.image_digest, state->image_digest, 32u);
        sealed.source_cut = state->source_cut;
        sealed.target_cursor = state->target_cursor;
        /* image_digest authenticates the source QFS bytes installed by the
         * baseline helper. The local store may assign its own row sequence
         * while replacing an older image; the independently recomputed range
         * digest above verifies all user-visible row contents and labels. */
        ok = qihse_kv_ct_lane_transfer_checksum(&sealed, out_seal_digest);
    }
    kv_store_unlock(store);
    ct_range_image_free(&current);
    if (!ok) { memset(out_seal_digest, 0, 32u); errno = EBUSY; }
    return ok;
}

static void ct_lane_transfer_bitmap_remove(uint8_t* destination,
    const uint8_t* remove) {
    for (size_t i = 0; i < QIHSE_KV_CT_SLOT_BITMAP_BYTES; ++i)
        destination[i] &= (uint8_t)~remove[i];
}

static void ct_lane_transfer_bitmap_add(uint8_t* destination,
    const uint8_t* add) {
    for (size_t i = 0; i < QIHSE_KV_CT_SLOT_BITMAP_BYTES; ++i)
        destination[i] |= add[i];
}

static bool ct_lane_transfer_baseline_invalidate(qihse_kv_store_t* store,
                                                 qihse_kv_ct_lane_t* lane) {
    if (!store || !lane) return false;
    lane->status.baseline_sealed = false;
    lane->status.baseline_refresh_needed = false;
    lane->status.baseline_row_seq = 0u;
    lane->status.baseline_stream_cut = lane->status.durable_position;
    memset(lane->status.baseline_digest, 0, sizeof(lane->status.baseline_digest));
    if (lane->status.mode == QIHSE_KV_CT_LANE_SOURCE)
        lane->status.admitted = false;
    char path[4096];
    if (!ct_lane_baseline_path(lane->status.lane_id, path, sizeof(path))) return false;
    if (unlink(path) != 0 && errno != ENOENT) return false;
    return fsync_dir_path(get_qihse_data_dir());
}

bool qihse_kv_ct_lane_transfer_membership_finalize(qihse_kv_store_t* store,
    qihse_user_t* control_principal, qihse_user_t* data_principal,
    const qihse_kv_ct_lane_authority_claim_t* claim,
    const qihse_kv_ct_proof_t* final_proof,
    qihse_kv_ct_lane_authority_verify_fn verify, void* verify_context,
    const unsigned char source_owner_token[QIHSE_KV_CT_TOKEN_BYTES],
    const unsigned char target_owner_token[QIHSE_KV_CT_TOKEN_BYTES]) {
    qihse_kv_ct_lane_authority_claim_t final_claim;
    if (!store || !ct_admin(control_principal) ||
        !ct_lane_transfer_system_principal(data_principal) ||
        !source_owner_token || !verify ||
        !qihse_kv_ct_lane_authority_proof_validate(store, control_principal,
            data_principal, final_proof, verify, verify_context, true) ||
        !qihse_kv_ct_lane_authority_proof_fields(store, control_principal,
            data_principal, final_proof, &final_claim) ||
        !ct_lane_claim_equal(claim, &final_claim) ||
        !qihse_kv_ct_lane_transfer_checksum(claim, (unsigned char[32]){0})) {
        errno = EACCES; return false;
    }
    kv_store_wrlock(store);
    qihse_kv_ct_lane_transfer_state_t* state = store->lane_transfer;
    if (!store->recovery_pending && state && state->active &&
        state->phase == 4u && ct_lane_claim_equal(&state->claim, claim) &&
        state->source_cut == claim->source_cut &&
        state->target_cursor == claim->target_cursor &&
        memcmp(state->image_digest, claim->image_digest, 32u) == 0 &&
        memcmp(state->range_digest, claim->range_digest, 32u) == 0) {
        /* The completed operation is already durable. Reopening disarms
         * SOURCE admission, and later promotions can change live roles;
         * neither condition turns an exact completed retry into new work. */
        kv_store_unlock(store);
        return true;
    }
    qihse_kv_ct_lane_t* source = ct_lane_find(store, claim->source_group_id);
    qihse_kv_ct_lane_t* target = ct_lane_find(store, claim->target_group_id);
    bool source_is_owner = source && source->status.mode == QIHSE_KV_CT_LANE_SOURCE;
    bool source_is_receiver = source && source->status.mode == QIHSE_KV_CT_LANE_RECEIVER;
    bool target_is_owner = target && target->status.mode == QIHSE_KV_CT_LANE_SOURCE;
    bool target_is_receiver = target && target->status.mode == QIHSE_KV_CT_LANE_RECEIVER;
    bool source_role_ok = (source_is_owner || source_is_receiver) &&
        strcmp(source->status.generation, claim->source_generation) == 0 &&
        strcmp(source->status.source_id, claim->source_qkp_id) == 0 &&
        (source_is_owner || !strcmp(source->status.peer_id, claim->target_qkp_id) ||
         (target_is_receiver && !strcmp(source->status.peer_id, claim->successor_qkp_id)));
    bool target_role_ok = !target || ((target_is_owner || target_is_receiver) &&
        (target_is_owner ? (target->status.durable_position >= claim->target_cursor &&
                            target->status.acknowledged_position >= claim->target_cursor) :
                           (target->status.durable_position >= claim->target_cursor)) &&
        strcmp(target->status.generation, claim->target_generation) == 0 &&
        strcmp(target->status.source_id, claim->target_qkp_id) == 0 &&
        strcmp(target->status.peer_id, claim->successor_qkp_id) == 0);
    bool token_ok = source_role_ok &&
        ct_lane_transfer_token_matches(source, source_owner_token) &&
        (!target || (target_owner_token &&
                     ct_lane_transfer_token_matches(target, target_owner_token)));
    bool exported_source = source_is_owner && state && state->source_fenced &&
        state->source_cut <= source->status.durable_position &&
        state->source_cut <= source->status.acknowledged_position;
    bool ok = !store->recovery_pending && state && state->active &&
        state->phase >= 1u && state->phase <= 3u &&
        (state->target_imported || exported_source) &&
        ct_lane_transfer_state_matches(state, claim) && target_role_ok && token_ok &&
        state->source_fenced && state->source_cut == claim->source_cut &&
        state->target_cursor == claim->target_cursor &&
        !ct_digest_zero(state->image_digest) && !ct_digest_zero(state->range_digest) &&
        memcmp(state->image_digest, claim->image_digest, 32u) == 0 &&
        memcmp(state->range_digest, claim->range_digest, 32u) == 0 &&
        (state->phase < 3u || ct_lane_claim_equal(&state->claim, claim));
    if (!ok) { kv_store_unlock(store); errno = EBUSY; return false; }

    bool source_has_all = true, source_has_none = true;
    bool target_has_all = target != NULL, target_has_none = target != NULL;
    for (size_t i = 0; i < sizeof(claim->slots); ++i) {
        if (claim->slots[i] & (uint8_t)~source->status.slot_bitmap[i]) source_has_all = false;
        if (claim->slots[i] & source->status.slot_bitmap[i]) source_has_none = false;
        if (target) {
            if (claim->slots[i] & (uint8_t)~target->status.slot_bitmap[i]) target_has_all = false;
            if (claim->slots[i] & target->status.slot_bitmap[i]) target_has_none = false;
        }
    }
    if (source_has_all == source_has_none ||
        (target && target_has_all == target_has_none)) {
        /* Both false means a partial overlap; both true means an invalid empty
         * selection. Complete old or new state is the only valid transition. */
        kv_store_unlock(store); errno = EINVAL; return false;
    }
    if (target && source == target) { kv_store_unlock(store); errno = EINVAL; return false; }

    /* Persist the final quorum decision before publishing ownership changes.
     * Phase 3 is a replayable intent: after restart, the same final proof can
     * finish an interrupted idempotent bitmap update. */
    if (state->phase < 3u) {
        qihse_kv_ct_lane_authority_claim_t old_claim = state->claim;
        state->claim = *claim;
        state->phase = 3u;
        if (!ct_lane_transfer_state_write(store)) {
            state->claim = old_claim; state->phase = 2u;
            kv_store_unlock(store); return false;
        }
    }

    /* Same-generation membership changes invalidate the bitmap against
     * which old QKV6 frames were admitted. Checkpoint those rows first;
     * independent per-source logs retain outstanding replication frames. */
    if (!kv_sync_store_locked(store)) {
        kv_store_unlock(store);
        return false;
    }

    qihse_kv_ct_lane_t source_old = *source;
    qihse_kv_ct_lane_t target_old;
    if (target) target_old = *target;
    if (source_has_all) ct_lane_transfer_bitmap_remove(source->status.slot_bitmap, claim->slots);
    if (target && target_has_none) ct_lane_transfer_bitmap_add(target->status.slot_bitmap, claim->slots);
    if (ct_lane_bitmap_conflicts(store, source->status.slot_bitmap, source) ||
        (target && ct_lane_bitmap_conflicts(store, target->status.slot_bitmap, target))) {
        *source = source_old; if (target) *target = target_old;
        kv_store_unlock(store); errno = EEXIST; return false;
    }
    if (!ct_lane_digest_bitmap(source->status.slot_bitmap,
                               source->status.slot_bitmap_digest) ||
        (target && !ct_lane_digest_bitmap(target->status.slot_bitmap,
                               target->status.slot_bitmap_digest))) {
        *source = source_old; if (target) *target = target_old;
        kv_store_unlock(store); errno = EIO; return false;
    }
    if (source_is_owner) {
        /* Set this on phase-3 replay too: membership can be durable before
         * the cache marker is. Keep the established source stream live. */
        source->status.baseline_refresh_needed = true;
    } else if (source_has_all) {
        source->status.baseline_sealed = false;
        source->status.baseline_refresh_needed = false;
        source->status.baseline_row_seq = 0u;
        source->status.baseline_stream_cut = source->status.durable_position;
        memset(source->status.baseline_digest, 0,
               sizeof(source->status.baseline_digest));
    }
    if (target && target_is_owner) {
        /* Set this on phase-3 replay too, for the same crash window. */
        target->status.baseline_refresh_needed = true;
    } else if (target && target_has_none) {
        target->status.baseline_sealed = false;
        target->status.baseline_refresh_needed = false;
        target->status.baseline_row_seq = 0u;
        target->status.baseline_stream_cut = target->status.durable_position;
        memset(target->status.baseline_digest, 0,
               sizeof(target->status.baseline_digest));
    }
    if (!ct_lanes_state_write(store) || !ct_lane_marker_write(store)) {
        store->recovery_pending = true; kv_store_unlock(store); return false;
    }
    if (((source_has_all && source_is_receiver) ||
         (source_is_receiver && !source->status.baseline_sealed)) &&
        !ct_lane_transfer_baseline_invalidate(store, source)) {
        store->recovery_pending = true; kv_store_unlock(store); return false;
    }
    if (target && ((target_has_none && target_is_receiver) ||
                   (target_is_receiver && !target->status.baseline_sealed)) &&
        !ct_lane_transfer_baseline_invalidate(store, target)) {
        store->recovery_pending = true; kv_store_unlock(store); return false;
    }
    state->phase = 4u;
    if (!ct_lane_transfer_state_write(store)) {
        state->phase = 3u;
        store->recovery_pending = true; kv_store_unlock(store); return false;
    }
    kv_store_unlock(store);
    return true;
}

bool qihse_kv_ct_lane_transfer_abort(qihse_kv_store_t* store,
    qihse_user_t* control_principal, qihse_user_t* data_principal,
    const qihse_kv_ct_lane_authority_claim_t* claim,
    const qihse_kv_ct_proof_t* aborted_proof,
    qihse_kv_ct_lane_authority_verify_fn verify_aborted, void* verify_context,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]) {
    qihse_kv_ct_lane_authority_claim_t proof_claim;
    if (!store || !ct_admin(control_principal) ||
        !ct_lane_transfer_system_principal(data_principal) ||
        !claim || claim->operation != QIHSE_KV_CT_LANE_AUTH_TRANSFER ||
        !owner_token || !verify_aborted ||
        !qihse_kv_ct_lane_authority_proof_validate(store, control_principal,
            data_principal, aborted_proof, verify_aborted, verify_context, true) ||
        !qihse_kv_ct_lane_authority_proof_fields(store, control_principal,
            data_principal, aborted_proof, &proof_claim) ||
        !ct_lane_claim_equal(claim, &proof_claim)) {
        errno = EACCES;
        return false;
    }
    kv_store_wrlock(store);
    if (store->recovery_pending || store->memory_snapshot) {
        kv_store_unlock(store); errno = EIO; return false;
    }
    qihse_kv_ct_lane_transfer_state_t* state = store->lane_transfer;
    if (!state || !state->active) {
        /* A prior abort may have unlinked the intent before its reply was
         * delivered. The immutable common ABORT is still required above. */
        bool ok = ct_lane_transfer_state_write(store);
        kv_store_unlock(store);
        return ok;
    }
    qihse_kv_ct_lane_t* source = ct_lane_find(store, claim->source_group_id);
    qihse_kv_ct_lane_t* target = ct_lane_find(store, claim->target_group_id);
    bool source_token = source &&
        strcmp(source->status.source_id, claim->source_qkp_id) == 0 &&
        strcmp(source->status.generation, claim->source_generation) == 0 &&
        ct_lane_transfer_token_matches(source, owner_token);
    bool target_token = target &&
        strcmp(target->status.source_id, claim->target_qkp_id) == 0 &&
        strcmp(target->status.peer_id, claim->successor_qkp_id) == 0 &&
        strcmp(target->status.generation, claim->target_generation) == 0 &&
        ct_lane_transfer_token_matches(target, owner_token);
    bool ok = state->phase >= 1u && state->phase <= 2u &&
        ct_lane_transfer_state_matches(state, claim) &&
        state->source_cut == claim->source_cut &&
        (source_token || target_token);
    if (!ok) { kv_store_unlock(store); errno = EBUSY; return false; }
    /* Detaching makes state_write remove the private intent and sync its
     * parent directory. Do not release the in-memory fence until both finish;
     * a failed publication remains retryable with the same common ABORT. */
    store->lane_transfer = NULL;
    ok = ct_lane_transfer_state_write(store);
    if (!ok) store->lane_transfer = state;
    else {
        OPENSSL_cleanse(state, sizeof(*state));
        free(state);
    }
    kv_store_unlock(store);
    return ok;
}

bool qihse_kv_ct_lane_transfer_write_allowed(qihse_kv_store_t* store,
    qihse_user_t* principal, const char* key) {
    if (!store || !key || !qihse_auth_user_is_active(principal)) {
        errno = EACCES; return false;
    }
    /* Call before acquiring the store write lock; the helper takes a read lock
     * so it cannot race phase/state publication or free/replaced state. */
    kv_store_rdlock(store);
    qihse_kv_ct_lane_transfer_state_t* state = store->lane_transfer;
    bool selected = state && state->active &&
        ct_lane_transfer_slot_selected(state->pending_slot_bitmap, key);
    bool allowed = !selected || !state->source_fenced;
    if (selected && state->source_fenced && state->phase >= 3u) {
        qihse_kv_ct_lane_t* target = ct_lane_find(store, state->claim.target_group_id);
        bool owns = target && target->status.mode == QIHSE_KV_CT_LANE_SOURCE &&
            target->status.admitted && target->status.baseline_sealed &&
            target->status.durable_position == target->status.acknowledged_position;
        for (size_t i = 0; owns && i < sizeof(state->pending_slot_bitmap); ++i)
            if (state->pending_slot_bitmap[i] &
                (uint8_t)~target->status.slot_bitmap[i]) owns = false;
        allowed = owns;
    }
    kv_store_unlock(store);
    if (!allowed) errno = EBUSY;
    return allowed;
}
