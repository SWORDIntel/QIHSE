/* CT2 bounded source-range QFS export. Included after qihse_kv_store.c's
 * private helpers so the authenticated metadata index can be used before
 * materializing SSTable values. */

typedef struct {
    char* key;
    kv_payload_t* memory;
    int32_t sstable_id;
    uint64_t sst_offset;
    uint16_t classification;
    uint16_t sci;
    uint64_t expiry;
    uint8_t flags;
} ct_range_export_entry_t;

typedef struct {
    qihse_user_t* principal;
    ct_range_export_entry_t* rows;
    size_t count;
    size_t capacity;
    size_t key_bytes;
    uint16_t first_slot;
    uint16_t last_slot;
    bool authorized;
    bool ok;
    uint16_t max_classification;
    uint16_t required_sci;
} ct_range_export_collect_t;

typedef struct qihse_kv_ct_range_snapshot qihse_kv_ct_range_snapshot_t;
struct qihse_kv_ct_range_snapshot {
    qihse_kv_replica_snapshot_t* image;
    qihse_user_t* principal;
    uint16_t max_classification;
    uint16_t required_sci;
};

static bool ct_range_export_add(ct_range_export_collect_t* c, const char* key,
    kv_payload_t* memory, const sst_meta_entry_t* disk) {
    size_t key_len = strlen(key);
    if (c->count >= QIHSE_KV_CT_MAX_GROUP_RECORDS ||
        key_len > QIHSE_KV_DURABLE_BATCH_MAX_BYTES - c->key_bytes) {
        errno = E2BIG; c->ok = false; return false;
    }
    if (c->count == c->capacity) {
        size_t capacity = c->capacity ? c->capacity * 2u : 128u;
        ct_range_export_entry_t* rows = realloc(c->rows, capacity * sizeof(*rows));
        if (!rows) { c->ok = false; return false; }
        c->rows = rows; c->capacity = capacity;
    }
    char* copy = strdup(key);
    if (!copy) { c->ok = false; return false; }
    ct_range_export_entry_t* row = &c->rows[c->count++];
    memset(row, 0, sizeof(*row));
    row->key = copy;
    row->memory = memory;
    if (disk) {
        row->sstable_id = disk->sstable_id;
        row->sst_offset = disk->sst_offset;
        row->classification = disk->classification;
        row->sci = disk->sci_compartment;
        row->expiry = disk->expire_time_ms;
        row->flags = disk->flags;
    } else {
        row->classification = memory->classification;
        row->sci = memory->sci_compartment;
        row->expiry = memory->expire_time_ms;
        row->flags = memory->flags;
    }
    c->key_bytes += key_len;
    if (row->classification > c->max_classification)
        c->max_classification = row->classification;
    c->required_sci |= row->sci;
    return true;
}

static bool ct_range_export_mem_cb(const char* key, void* value,
    size_t value_size, void* context) {
    (void)value_size;
    ct_range_export_collect_t* c = context;
    kv_payload_t* payload = value;
    if (!c || !c->ok || !c->authorized || !key || !payload) return false;
    if (qihse_cluster_key_is_node_local(key)) return true;
    uint16_t slot = qihse_cluster_key_slot(key, strlen(key));
    if (slot < c->first_slot || slot > c->last_slot) return true;
    if (!qihse_auth_can_access(c->principal, payload->classification,
                               payload->sci_compartment)) {
        c->authorized = false; errno = EACCES; return false;
    }
    return ct_range_export_add(c, key, payload, NULL);
}

static int ct_range_export_entry_cmp(const void* left, const void* right) {
    const ct_range_export_entry_t* a = left;
    const ct_range_export_entry_t* b = right;
    return strcmp(a->key, b->key);
}

/* Inspect the SST header through pread before requesting its value bytes.
 * The metadata index is an optimization, never the final authorization
 * source if the file was externally changed after index construction. */
static bool ct_range_export_sst_header_allowed(int fd, uint64_t offset,
    const ct_range_export_entry_t* entry, qihse_user_t* principal) {
    char header[KV_HEADER_LINE_MAX + 1u];
    ssize_t got = pread(fd, header, KV_HEADER_LINE_MAX, (off_t)offset);
    if (got <= 0) return false;
    char* newline = memchr(header, '\n', (size_t)got);
    if (!newline) return false;
    *newline = '\0';
    size_t key_len = 0u, value_len = 0u;
    unsigned long long expiry = 0u, seq = 0u;
    unsigned classif = 0u, sci = 0u, flags = 0u;
    int fields = sscanf(header, "%zu %zu %llu %u %u %u %llu",
        &key_len, &value_len, &expiry, &classif, &sci, &flags, &seq);
    if (fields < KV_SEQ_FIELDS_MIN || fields > KV_SEQ_FIELDS_V4 ||
        classif > UINT16_MAX || sci > UINT16_MAX ||
        key_len != strlen(entry->key) || value_len > KV_MAX_VALUE_LEN ||
        classif != entry->classification || sci != entry->sci ||
        (uint64_t)expiry != entry->expiry || flags != entry->flags)
        return false;
    return qihse_auth_user_is_active(principal) &&
           qihse_auth_can_access(principal, (uint16_t)classif, (uint16_t)sci);
}

/* Build only the frozen target range. A whole-store replica snapshot would
 * materialize unrelated classified rows and can be arbitrarily large. */
static bool ct_range_import_existing_locked(qihse_kv_store_t* store,
    qihse_user_t* principal, uint16_t first_slot, uint16_t last_slot,
    ct_range_image_t* out) {
    if (!store->sst_meta || store->sst_meta->degraded) return false;
    ct_range_export_collect_t c = {
        .principal = principal, .first_slot = first_slot,
        .last_slot = last_slot,
        .authorized = true, .ok = true
    };
    qihse_trinary_trie_foreach(store->trie, ct_range_export_mem_cb, &c);
    if (!c.ok || !c.authorized) goto failed;
    for (size_t i = 0u; i < store->sst_meta->cap; i++) {
        const sst_meta_entry_t* meta = &store->sst_meta->slots[i];
        if (!meta->key) continue;
        if (qihse_cluster_key_is_node_local(meta->key)) continue;
        uint16_t slot = qihse_cluster_key_slot(meta->key, strlen(meta->key));
        if (slot < first_slot || slot > last_slot) continue;
        if (qihse_trinary_trie_search(store->trie, meta->key, NULL)) continue;
        if (!qihse_auth_can_access(principal, meta->classification,
                                   meta->sci_compartment)) goto failed;
        if (!ct_range_export_add(&c, meta->key, NULL, meta)) goto failed;
    }
    out->rows = calloc(c.count ? c.count : 1u, sizeof(*out->rows));
    if (!out->rows) goto failed;
    out->capacity = c.count;
    const char* dir = get_qihse_data_dir();
    if (!dir) goto failed;
    for (size_t i = 0u; i < c.count; i++) {
        ct_range_export_entry_t* e = &c.rows[i];
        kv_disk_record_t row = {0};
        if (!qihse_auth_user_is_active(principal) ||
            !qihse_auth_can_access(principal, e->classification, e->sci))
            goto failed;
        if (e->memory) {
            row.key = strdup(e->key);
            row.val = strdup(e->memory->val);
            row.classification = e->classification;
            row.sci_compartment = e->sci;
            row.expire_time_ms = e->expiry;
            row.flags = e->flags;
            row.change_seq = e->memory->change_seq;
            if (!row.key || !row.val) { disk_record_free(&row); goto failed; }
        } else {
            pthread_mutex_lock(&store->sst_fd_lock);
            int fd = sst_fd_get(store, dir, e->sstable_id);
            pthread_mutex_unlock(&store->sst_fd_lock);
            if (fd < 0 || !ct_range_export_sst_header_allowed(fd,
                    e->sst_offset, e, principal) ||
                disk_record_read_at(fd, e->sst_offset, &row) != 1)
                goto failed;
            if (strcmp(row.key, e->key) != 0 ||
                row.classification != e->classification ||
                row.sci_compartment != e->sci ||
                row.expire_time_ms != e->expiry || row.flags != e->flags) {
                disk_record_free(&row); goto failed;
            }
        }
        size_t bytes = strlen(row.key) + strlen(row.val) + 64u;
        if (bytes > QIHSE_KV_DURABLE_BATCH_MAX_BYTES - out->bytes) {
            disk_record_free(&row); errno = EFBIG; goto failed;
        }
        out->rows[out->count++] = row;
        out->bytes += bytes;
    }
    qsort(out->rows, out->count, sizeof(*out->rows), ct_image_row_cmp);
    for (size_t i = 0u; i < c.count; i++) free(c.rows[i].key);
    free(c.rows);
    return qihse_auth_user_is_active(principal);
failed:
    for (size_t i = 0u; i < c.count; i++) free(c.rows[i].key);
    free(c.rows);
    ct_range_image_free(out);
    return false;
}

static bool ct_range_export_fence_matches(qihse_kv_store_t* store,
    const char* transfer_id, const char* target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]) {
    return store->ct_enabled && store->ct_mode == 1u &&
        !store->recovery_pending && store->ct_baseline_sealed &&
        store->ct_fence_state == 1u &&
        strcmp(store->ct_transfer_id, transfer_id) == 0 &&
        strcmp(store->ct_target_id, target_id) == 0 &&
        strcmp(store->ct_generation, generation) == 0 &&
        store->ct_fence_first == first_slot &&
        store->ct_fence_last == last_slot &&
        store->ct_ack_lsn >= store->ct_fence_cut_position &&
        ct_token_matches(store, owner_token);
}

int qihse_kv_ct_range_export(qihse_kv_store_t* store,
    qihse_user_t* control_principal, qihse_user_t* data_principal,
    const char* transfer_id, const char* target_id, const char* generation,
    uint16_t first_slot, uint16_t last_slot,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES],
    qihse_kv_ct_range_snapshot_t** out_snapshot, uint64_t* out_source_cut,
    unsigned char out_sha256[32]) {
    if (out_snapshot) *out_snapshot = NULL;
    if (out_source_cut) *out_source_cut = 0u;
    if (out_sha256) memset(out_sha256, 0, 32u);
    if (!store || !ct_admin(control_principal) || !data_principal ||
        !qihse_auth_user_is_active(data_principal) ||
        !ct_id_valid(transfer_id) ||
        !ct_id_valid(target_id) || !ct_id_valid(generation) ||
        first_slot > last_slot || last_slot >= QIHSE_CLUSTER_SLOT_COUNT ||
        !owner_token || !out_snapshot || !out_source_cut || !out_sha256)
        return -1;

    int result = -1;
    ct_range_export_collect_t c = {
        .principal = data_principal, .first_slot = first_slot,
        .last_slot = last_slot, .authorized = true, .ok = true
    };
    FILE* image = NULL;
    int image_fd = -1;
    uint64_t cut = 0u;
    kv_store_wrlock(store);
    /* CT1's successor ACK peer is independent of the CT2 destination.
     * Persist the destination under the frozen source range before exposing
     * its first snapshot; subsequent exports must use that exact identity. */
    if (store->ct_target_id[0] == '\0' && store->ct_enabled &&
        store->ct_mode == 1u && !store->recovery_pending &&
        store->ct_baseline_sealed && store->ct_fence_state == 1u &&
        strcmp(store->ct_transfer_id, transfer_id) == 0 &&
        strcmp(store->ct_generation, generation) == 0 &&
        store->ct_fence_first == first_slot &&
        store->ct_fence_last == last_slot &&
        store->ct_ack_lsn >= store->ct_fence_cut_position &&
        ct_token_matches(store, owner_token)) {
        snprintf(store->ct_target_id, sizeof(store->ct_target_id), "%s",
                 target_id);
        if (!ct_state_write(store)) {
            /* A failed atomic publication may still have reached disk.
             * Reopen under an authenticated principal before retrying. */
            store->recovery_pending = true;
            goto unlock;
        }
    }
    if (!ct_range_export_fence_matches(store, transfer_id, target_id,
            generation, first_slot, last_slot, owner_token) ||
        !store->sst_meta || store->sst_meta->degraded) goto unlock;
    cut = store->ct_fence_cut_position;
    qihse_trinary_trie_foreach(store->trie, ct_range_export_mem_cb, &c);
    if (!c.ok || !c.authorized) goto unlock;
    const sst_meta_index_t* index = store->sst_meta;
    for (size_t i = 0u; i < index->cap; i++) {
        const sst_meta_entry_t* e = &index->slots[i];
        if (!e->key) continue;
        if (qihse_cluster_key_is_node_local(e->key)) continue;
        uint16_t slot = qihse_cluster_key_slot(e->key, strlen(e->key));
        if (slot < first_slot || slot > last_slot) continue;
        size_t ignored = 0u;
        if (qihse_trinary_trie_search(store->trie, e->key, &ignored)) continue;
        if (!qihse_auth_can_access(data_principal, e->classification,
                                   e->sci_compartment)) {
            c.authorized = false; errno = EACCES; goto unlock;
        }
        if (!ct_range_export_add(&c, e->key, NULL, e)) goto unlock;
    }
    qsort(c.rows, c.count, sizeof(*c.rows), ct_range_export_entry_cmp);
    for (size_t i = 1u; i < c.count; i++)
        if (strcmp(c.rows[i - 1u].key, c.rows[i].key) == 0) goto unlock;

    const char* dir = get_qihse_data_dir();
    char path[4096];
    if (!dir) goto unlock;
    int path_len = snprintf(path, sizeof(path), "%sct-range-XXXXXX", dir);
    if (path_len < 0 || (size_t)path_len >= sizeof(path)) goto unlock;
    image_fd = mkstemp(path);
    if (image_fd < 0) goto unlock;
    (void)fchmod(image_fd, 0600);
    if (unlink(path) != 0) {
        int saved = errno;
        (void)unlink(path);
        errno = saved;
        goto unlock;
    }
    image = fdopen(image_fd, "w+b");
    if (!image) goto unlock;
    image_fd = -1;
    for (size_t i = 0u; i < c.count; i++) {
        ct_range_export_entry_t* e = &c.rows[i];
        if (!qihse_auth_user_is_active(data_principal) ||
            !qihse_auth_can_access(data_principal, e->classification, e->sci)) {
            c.authorized = false; errno = EACCES; goto unlock;
        }
        if (e->memory) {
            if (!disk_record_write(image, e->key, e->memory)) goto unlock;
        } else {
            pthread_mutex_lock(&store->sst_fd_lock);
            int fd = sst_fd_get(store, dir, e->sstable_id);
            pthread_mutex_unlock(&store->sst_fd_lock);
            if (fd < 0) goto unlock;
            if (!ct_range_export_sst_header_allowed(fd, e->sst_offset,
                                                      e, data_principal)) goto unlock;
            kv_disk_record_t r;
            if (disk_record_read_at(fd, e->sst_offset, &r) != 1) goto unlock;
            bool valid = strcmp(r.key, e->key) == 0 &&
                r.classification == e->classification &&
                r.sci_compartment == e->sci &&
                r.expire_time_ms == e->expiry && r.flags == e->flags;
            if (valid) valid = disk_record_write_fields(image, r.key, r.val,
                    r.expire_time_ms, r.classification, r.sci_compartment,
                    r.flags, r.change_seq);
            disk_record_free(&r);
            if (!valid) goto unlock;
        }
        off_t size = ftello(image);
        if (size < 0 || (uint64_t)size > QIHSE_KV_DURABLE_BATCH_MAX_BYTES) {
            errno = EFBIG; goto unlock;
        }
    }
    if (fflush(image) != 0 || fdatasync(fileno(image)) != 0) goto unlock;
    if (!ct_range_export_fence_matches(store, transfer_id, target_id,
            generation, first_slot, last_slot, owner_token) ||
        store->ct_fence_cut_position != cut ||
        !ct_admin(control_principal) ||
        !qihse_auth_user_is_active(data_principal) ||
        !qihse_auth_can_access(data_principal, c.max_classification,
                               c.required_sci)) {
        c.authorized = false; errno = EACCES; goto unlock;
    }
    off_t end = ftello(image);
    if (end < 0 || (uint64_t)end > QIHSE_KV_DURABLE_BATCH_MAX_BYTES) goto unlock;
    qihse_kv_ct_range_snapshot_t* snapshot = calloc(1u, sizeof(*snapshot));
    qihse_kv_replica_snapshot_t* raw = calloc(1u, sizeof(*raw));
    if (!snapshot || !raw) { free(snapshot); free(raw); goto unlock; }
    raw->fd = dup(fileno(image));
    raw->size = (uint64_t)end;
    raw->principal = data_principal;
    raw->principal_id = qihse_user_get_id(data_principal);
    raw->tenant_id = qihse_user_get_tenant_id(data_principal);
    raw->classification = c.max_classification;
    raw->sci = c.required_sci;
    if (raw->fd < 0 || !ct_fd_sha256(raw->fd, out_sha256)) {
        if (raw->fd >= 0) close(raw->fd);
        free(raw); free(snapshot); goto unlock;
    }
    snapshot->image = raw;
    snapshot->principal = data_principal;
    snapshot->max_classification = c.max_classification;
    snapshot->required_sci = c.required_sci;
    *out_snapshot = snapshot;
    *out_source_cut = cut;
    result = 0;
unlock:
    kv_store_unlock(store);
    if (image) fclose(image);
    if (image_fd >= 0) close(image_fd);
    for (size_t i = 0u; i < c.count; i++) free(c.rows[i].key);
    free(c.rows);
    if (result != 0) {
        if (*out_snapshot) {
            qihse_kv_replica_snapshot_destroy((*out_snapshot)->image);
            free(*out_snapshot);
            *out_snapshot = NULL;
        }
        *out_source_cut = 0u;
        memset(out_sha256, 0, 32u);
        if (!c.authorized) return -2;
    }
    return result;
}

static bool ct_range_snapshot_authorized(const qihse_kv_ct_range_snapshot_t* snapshot,
    qihse_user_t* principal) {
    return snapshot && principal && principal == snapshot->principal &&
        qihse_auth_user_is_active(principal) &&
        qihse_auth_can_access(principal, snapshot->max_classification,
                              snapshot->required_sci);
}

bool qihse_kv_ct_range_snapshot_size(qihse_kv_ct_range_snapshot_t* snapshot,
    qihse_user_t* principal, uint64_t* out_size) {
    if (out_size) *out_size = 0u;
    if (!out_size || !ct_range_snapshot_authorized(snapshot, principal)) {
        errno = EACCES; return false;
    }
    *out_size = snapshot->image->size;
    return true;
}

bool qihse_kv_ct_range_snapshot_read(qihse_kv_ct_range_snapshot_t* snapshot,
    qihse_user_t* principal, uint64_t offset, void* out, size_t capacity,
    size_t* out_read) {
    if (out_read) *out_read = 0u;
    if (!out_read || !ct_range_snapshot_authorized(snapshot, principal)) {
        errno = EACCES; return false;
    }
    size_t amount = 0u;
    if (!qihse_kv_replica_snapshot_read(snapshot->image, principal, offset, out, capacity,
                                        &amount)) return false;
    if (!ct_range_snapshot_authorized(snapshot, principal)) {
        if (out && amount) memset(out, 0, amount);
        errno = EACCES; return false;
    }
    *out_read = amount;
    return true;
}

void qihse_kv_ct_range_snapshot_destroy(qihse_kv_ct_range_snapshot_t* snapshot) {
    if (!snapshot) return;
    qihse_kv_replica_snapshot_destroy(snapshot->image);
    memset(snapshot, 0, sizeof(*snapshot));
    free(snapshot);
}

/* A frozen range can be imported into an existing primary without replacing
 * its other slots or changing its CT1 generation. Phase 1 and the intended
 * QKV6 digest are durable before the merge; replay then distinguishes a
 * completed group from one that was never appended. */
static bool ct_range_import_fence_matches(qihse_kv_store_t* store,
    const char* transfer_id, uint16_t first_slot, uint16_t last_slot,
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES]) {
    return store->ct_enabled && store->ct_mode == 1u &&
        store->ct_baseline_sealed && !store->recovery_pending &&
        store->ct_fence_state == 1u &&
        strcmp(store->ct_transfer_id, transfer_id) == 0 &&
        store->ct_fence_first == first_slot &&
        store->ct_fence_last == last_slot &&
        ct_token_matches(store, owner_token);
}

static bool ct_range_import_identity_matches(qihse_kv_store_t* store,
    const char* source_id, const char* source_generation,
    uint64_t source_cut, const unsigned char image_sha256[32]) {
    return strcmp(store->ct_transfer_source_id, source_id) == 0 &&
        strcmp(store->ct_transfer_source_generation, source_generation) == 0 &&
        store->ct_transfer_source_cut == source_cut &&
        memcmp(store->ct_transfer_image_digest, image_sha256, 32u) == 0;
}

static bool ct_range_import_publish_applied(qihse_kv_store_t* store) {
    store->ct_transfer_phase = 2u;
    if (ct_state_write(store)) return true;
    /* The state replacement may have reached disk despite the error. Force
     * authenticated reopen instead of serving an ambiguous generation. */
    store->recovery_pending = true;
    return false;
}

bool qihse_kv_ct_range_import(qihse_kv_store_t* store, qihse_user_t* principal,
    qihse_user_t* data_principal, const char* transfer_id,
    const char* source_id, const char* source_generation,
    uint16_t first_slot, uint16_t last_slot, uint64_t source_cut,
    const char* snapshot_filepath, const unsigned char expected_sha256[32],
    const unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES],
    uint64_t* out_target_position) {
    if (out_target_position) *out_target_position = 0u;
    if (!store || !ct_admin(principal) ||
        !ct_replication_principal(store, data_principal) ||
        !ct_id_valid(transfer_id) || !ct_id_valid(source_id) ||
        !ct_id_valid(source_generation) ||
        first_slot > last_slot || last_slot >= QIHSE_CLUSTER_SLOT_COUNT ||
        !snapshot_filepath || !expected_sha256 || !owner_token ||
        !out_target_position) return false;

    /* Check the pinned fence before any classified file materialization.
     * In particular, a caller cannot use the importer as a generic QFS read. */
    kv_store_rdlock(store);
    bool allowed = ct_range_import_fence_matches(store, transfer_id,
        first_slot, last_slot, owner_token) &&
        store->ct_admitted &&
        ct_id_valid(store->ct_transfer_source_id) &&
        strcmp(store->ct_transfer_source_id, source_id) == 0 &&
        strcmp(store->ct_transfer_source_generation,
               source_generation) == 0 &&
        store->ct_transfer_source_cut == source_cut &&
        (store->ct_transfer_phase != 0u ||
         store->ct_ack_lsn == store->ct_durable_lsn) &&
        (store->ct_transfer_phase == 0u ||
         ct_range_import_identity_matches(store, source_id,
             source_generation, source_cut, expected_sha256));
    if (allowed && store->ct_transfer_phase == 2u)
        *out_target_position = store->ct_transfer_target_position;
    kv_store_unlock(store);
    if (!allowed) return false;
    if (*out_target_position != 0u) return true;

    ct_range_image_t preliminary = {0}, incoming = {0}, existing = {0};
    qihse_kv_ct_group_t group = {0};
    bool ok = false;
    char stage_path[4096];
    /* The authenticated decoder checks row labels before obtaining values.
     * Only then may the bounded QFS input be copied to the durable stage. */
    if (!ct_range_image_from_path(snapshot_filepath, data_principal,
            first_slot, last_slot, true, &preliminary)) goto done;
    ct_range_image_free(&preliminary);
    if (!build_data_path(stage_path, sizeof(stage_path),
            "ct-transfer-stage.qfs")) goto done;

    kv_store_wrlock(store);
    if (!ct_range_import_fence_matches(store, transfer_id,
            first_slot, last_slot, owner_token) || !store->ct_admitted ||
        !ct_id_valid(store->ct_transfer_source_id) ||
        strcmp(store->ct_transfer_source_id, source_id) != 0 ||
        strcmp(store->ct_transfer_source_generation,
               source_generation) != 0 ||
        store->ct_transfer_source_cut != source_cut ||
        !qihse_auth_user_is_active(data_principal)) goto unlock;
    if (store->ct_transfer_phase == 2u) {
        ok = ct_range_import_identity_matches(store, source_id,
            source_generation, source_cut, expected_sha256);
        if (ok) *out_target_position = store->ct_transfer_target_position;
        goto unlock;
    }
    if (store->ct_transfer_phase == 0u) {
        if (store->ct_ack_lsn != store->ct_durable_lsn ||
            !ct_range_stage_copy(snapshot_filepath, expected_sha256,
                                 stage_path)) goto unlock;
    } else if (store->ct_transfer_phase != 1u ||
        !ct_range_import_identity_matches(store, source_id,
            source_generation, source_cut, expected_sha256)) goto unlock;
    int staged_fd = open_secure_read(stage_path);
    unsigned char actual_sha256[32];
    bool stage_ok = staged_fd >= 0 &&
        ct_fd_sha256(staged_fd, actual_sha256) &&
        memcmp(actual_sha256, expected_sha256, 32u) == 0;
    if (staged_fd >= 0) close(staged_fd);
    if (!stage_ok || !ct_range_image_from_path(stage_path, data_principal,
            first_slot, last_slot, true, &incoming)) goto unlock;

    /* The complete QKV6 frame may have replayed after a crash while the
     * separate phase-2 state publication did not. The phase-1 digest pins
     * that exact frame; do not rebuild it from already changed target rows. */
    if (store->ct_transfer_phase == 1u &&
        store->ct_durable_lsn == store->ct_transfer_target_position) {
        unsigned char zero[32] = {0};
        ok = memcmp(store->ct_transfer_group_digest, zero, 32u) == 0 ||
             memcmp(store->ct_last_group_digest,
                    store->ct_transfer_group_digest, 32u) == 0;
        if (ok) ok = ct_range_import_publish_applied(store);
        if (ok) *out_target_position = store->ct_transfer_target_position;
        goto unlock;
    }
    if (!ct_range_import_existing_locked(store, data_principal,
            first_slot, last_slot, &existing)) goto unlock;

    /* The range was frozen throughout the target snapshot, so these exact
     * rows remain the merge preimage. Unrelated CT1 writes may have advanced
     * the global sequence before this lock; assign target-local IDs now. */
    if (!ct_range_merge_group(store, data_principal,
                              &incoming, &existing, &group)) goto unlock;
    uint64_t next_seq = __atomic_load_n(&store->change_seq, __ATOMIC_ACQUIRE);
    if (group.count > UINT64_MAX - next_seq) goto unlock;
    for (size_t i = 0u; i < group.count; i++)
        group.records[i].change_seq = next_seq + i + 1u;
    group.first_seq = group.count ? next_seq + 1u : 0u;
    group.last_seq = next_seq + group.count;

    unsigned char group_digest[32] = {0};
    if (group.count && !qihse_ct_codec_group_digest(store->ct_system_principal,
            QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0u,
            &group, group_digest)) goto unlock;
    if (store->ct_transfer_phase == 0u) {
        snprintf(store->ct_transfer_source_id,
                 sizeof(store->ct_transfer_source_id), "%s", source_id);
        snprintf(store->ct_transfer_source_generation,
                 sizeof(store->ct_transfer_source_generation), "%s",
                 source_generation);
        store->ct_transfer_source_cut = source_cut;
        store->ct_transfer_target_position = store->ct_durable_lsn +
            (group.count != 0u);
        memcpy(store->ct_transfer_image_digest, expected_sha256, 32u);
        memcpy(store->ct_transfer_group_digest, group_digest, 32u);
        store->ct_transfer_phase = 1u;
        if (!ct_state_write(store)) {
            store->recovery_pending = true;
            goto unlock;
        }
    } else {
        if (store->ct_transfer_target_position != group.stream_position ||
            memcmp(store->ct_transfer_group_digest,
                   group_digest, 32u) != 0) goto unlock;
    }
    if (group.count == 0u) {
        ok = ct_range_import_publish_applied(store);
        if (ok) *out_target_position = store->ct_transfer_target_position;
        goto unlock;
    }
    if (store->ct_durable_lsn + 1u != store->ct_transfer_target_position ||
        !ct_append_group_locked(store, data_principal, &group)) goto unlock;
    for (size_t i = 0u; i < group.count; i++) {
        qihse_kv_ct_record_t* row = &group.records[i];
        if (!insert_internal(store, row->key, row->tombstone ? "" : row->value,
                row->expire_time_ms, row->classification,
                row->sci_compartment,
                row->tombstone ? KV_FLAG_TOMBSTONE : 0u,
                row->change_seq)) {
            store->recovery_pending = true;
            goto unlock;
        }
        kv_change_seq_floor(store, row->change_seq);
    }
    ok = ct_range_import_publish_applied(store);
    if (ok) *out_target_position = store->ct_transfer_target_position;
unlock:
    kv_store_unlock(store);
done:
    free(group.records); /* strings are borrowed from the two QFS images */
    ct_range_image_free(&incoming);
    ct_range_image_free(&existing);
    ct_range_image_free(&preliminary);
    return ok;
}
