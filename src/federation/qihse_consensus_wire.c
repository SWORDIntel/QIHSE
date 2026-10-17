#include "qihse_consensus_wire.h"
#include "qihse_endian.h"

#include <string.h>

#define QCS_HEADER_SIZE (4u + 2u + 1u + 1u + 16u + 16u + 8u + 8u)
#define QCS_BOUND_SIZE (32u + 8u)
typedef struct {
    uint8_t* p;
    size_t cap;
    size_t n;
    bool ok;
} writer_t;

typedef struct {
    const uint8_t* p;
    size_t len;
    size_t n;
    bool ok;
} reader_t;

static void w_bytes(writer_t* w, const void* data, size_t n) {
    if (!w->ok || n > w->cap - w->n) { w->ok = false; return; }
    if (n) memcpy(w->p + w->n, data, n);
    w->n += n;
}

static void w_u8(writer_t* w, uint8_t v) { w_bytes(w, &v, 1u); }
static void w_u16(writer_t* w, uint16_t v) {
    uint8_t b[2];
    qihse_store_be16(b, v);
    w_bytes(w, b, sizeof(b));
}
static void w_u32(writer_t* w, uint32_t v) {
    uint8_t b[4];
    qihse_store_be32(b, v);
    w_bytes(w, b, sizeof(b));
}
static void w_u64(writer_t* w, uint64_t v) {
    uint8_t b[8];
    qihse_store_be64(b, v);
    w_bytes(w, b, sizeof(b));
}

static void r_bytes(reader_t* r, void* out, size_t n) {
    if (!r->ok || n > r->len - r->n) { r->ok = false; return; }
    if (n) memcpy(out, r->p + r->n, n);
    r->n += n;
}
static uint8_t r_u8(reader_t* r) { uint8_t v = 0; r_bytes(r, &v, 1u); return v; }
static uint16_t r_u16(reader_t* r) {
    uint8_t b[2] = {0}; r_bytes(r, b, sizeof(b));
    return qihse_load_be16(b);
}
static uint32_t r_u32(reader_t* r) {
    uint8_t b[4] = {0}; r_bytes(r, b, sizeof(b));
    return qihse_load_be32(b);
}
static uint64_t r_u64(reader_t* r) {
    uint8_t b[8] = {0}; r_bytes(r, b, sizeof(b));
    return qihse_load_be64(b);
}

static bool group_valid(const char* group, size_t* out_len) {
    if (!group || !out_len) return false;
    size_t n = 0;
    while (n <= QIHSE_CONSENSUS_GROUP_ID_MAX && group[n]) n++;
    if (!n || n > QIHSE_CONSENSUS_GROUP_ID_MAX) return false;
    for (size_t i = 0; i < n; i++) {
        const char c = group[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' ||
              c == '/' || c == ':' || c == '+')) return false;
    }
    *out_len = n;
    return true;
}

static bool history_valid(const uint8_t history_id[32], uint64_t writer_epoch) {
    if (!history_id || writer_epoch == 0u) return false;
    uint8_t value = 0u;
    for (size_t i = 0; i < 32u; i++) value |= history_id[i];
    return value != 0u;
}

static bool entry_valid(const qihse_user_t* principal,
                        const qihse_consensus_entry_t* e) {
    return principal && e && e->payload_len <= QIHSE_CONSENSUS_PAYLOAD_MAX &&
           e->type >= QIHSE_CONSENSUS_ENTRY_DATA &&
           e->type <= QIHSE_CONSENSUS_ENTRY_CONFIG_JOINT_END &&
           qihse_auth_can_access(principal, e->classif, e->sci);
}

static void encode_entry(writer_t* w, const qihse_consensus_entry_t* e) {
    w_u64(w, e->index); w_u64(w, e->term); w_u64(w, e->journal_generation);
    w_u64(w, e->hlc.physical_ms); w_u32(w, e->hlc.logical);
    w_u16(w, e->classif); w_u16(w, e->sci); w_u8(w, (uint8_t)e->type);
    w_u16(w, (uint16_t)e->payload_len); w_bytes(w, e->payload, e->payload_len);
}

static void decode_entry(reader_t* r, qihse_consensus_entry_t* e) {
    memset(e, 0, sizeof(*e));
    e->index = r_u64(r); e->term = r_u64(r); e->journal_generation = r_u64(r);
    e->hlc.physical_ms = r_u64(r); e->hlc.logical = r_u32(r);
    e->classif = r_u16(r); e->sci = r_u16(r);
    e->type = (qihse_consensus_entry_type_t)r_u8(r);
    e->payload_len = r_u16(r);
    if (e->payload_len > QIHSE_CONSENSUS_PAYLOAD_MAX) { r->ok = false; return; }
    r_bytes(r, e->payload, e->payload_len);
}

static uint64_t digest_fold_u64(uint64_t h, uint64_t v) {
    /* Canonical little-endian fold, matching consensus entry digests. */
    for (unsigned i = 0; i < 8u; i++) {
        h ^= (uint8_t)(v & 0xFFu);
        h *= 0x100000001B3ULL;
        v >>= 8;
    }
    return h;
}

uint64_t qihse_consensus_snapshot_chunk_digest(
    const qihse_consensus_snapshot_chunk_t* c) {
    if (!c || c->entry_count == 0u ||
        c->entry_count > QIHSE_CONSENSUS_SNAPSHOT_CHUNK_MAX_ENTRIES) return 0u;
    uint64_t entries_digest = qihse_consensus_snapshot_entries_digest(
        c->entries, c->entry_count);
    uint64_t h = 0xCBF2CE48D222D25BULL;
    h = digest_fold_u64(h, c->transfer_id);
    h = digest_fold_u64(h, c->total_entries);
    h = digest_fold_u64(h, c->first_entry_index);
    h = digest_fold_u64(h, c->last_included_term);
    h = digest_fold_u64(h, c->snapshot_fencing_epoch);
    h = digest_fold_u64(h, c->journal_generation);
    h = digest_fold_u64(h, c->digest);
    h = digest_fold_u64(h, (uint64_t)c->entry_count);
    h = digest_fold_u64(h, c->final_chunk ? 1u : 0u);
    return digest_fold_u64(h, entries_digest);
}

static bool prevalidate(const qihse_user_t* principal,
                        const qihse_consensus_msg_t* m,
                        size_t* group_len) {
    if (!principal || !qihse_auth_user_is_active(principal) || !m ||
        !group_valid(m->group_id, group_len) ||
        qihse_uuid_is_nil(&m->from) || qihse_uuid_is_nil(&m->to) ||
        m->fencing_epoch < m->term) return false;
    switch (m->type) {
        case QIHSE_CONSENSUS_MSG_REQUEST_VOTE:
        case QIHSE_CONSENSUS_MSG_VOTE_REPLY:
        case QIHSE_CONSENSUS_MSG_APPEND_REPLY:
        case QIHSE_CONSENSUS_MSG_SNAPSHOT_REPLY:
            return true;
        case QIHSE_CONSENSUS_MSG_APPEND:
            if (m->u.append.entry_count > QIHSE_CONSENSUS_MAX_ENTRIES_PER_MSG) return false;
            for (size_t i = 0; i < m->u.append.entry_count; i++)
                if (!entry_valid(principal, &m->u.append.entries[i])) return false;
            return true;
        case QIHSE_CONSENSUS_MSG_SNAPSHOT:
            if (m->u.snapshot.entry_count > QIHSE_CONSENSUS_SNAPSHOT_MAX_ENTRIES) return false;
            for (size_t i = 0; i < m->u.snapshot.entry_count; i++)
                if (!entry_valid(principal, &m->u.snapshot.entries[i])) return false;
            return true;
        case QIHSE_CONSENSUS_MSG_SNAPSHOT_CHUNK: {
            const qihse_consensus_snapshot_chunk_t* c = &m->u.snapshot_chunk;
            if (c->transfer_id == 0u || c->total_entries == 0u ||
                c->first_entry_index == 0u || c->first_entry_index > c->total_entries ||
                c->entry_count == 0u ||
                c->entry_count > QIHSE_CONSENSUS_SNAPSHOT_CHUNK_MAX_ENTRIES ||
                c->snapshot_fencing_epoch < c->last_included_term ||
                c->snapshot_fencing_epoch > m->fencing_epoch ||
                c->last_included_term > m->term ||
                c->first_entry_index > UINT64_MAX - (uint64_t)c->entry_count + 1u) return false;
            uint64_t last = c->first_entry_index + (uint64_t)c->entry_count - 1u;
            if (last > c->total_entries || c->final_chunk != (last == c->total_entries))
                return false;
            uint64_t previous_term = 0u, previous_generation = 0u;
            for (size_t i = 0; i < c->entry_count; i++) {
                const qihse_consensus_entry_t* e = &c->entries[i];
                if (!entry_valid(principal, e) ||
                    e->index != c->first_entry_index + (uint64_t)i ||
                    e->term > c->last_included_term ||
                    e->journal_generation > c->journal_generation ||
                    (i > 0u && (e->term < previous_term ||
                                e->journal_generation <= previous_generation))) return false;
                previous_term = e->term;
                previous_generation = e->journal_generation;
            }
            if (c->final_chunk &&
                (c->entries[c->entry_count - 1u].term != c->last_included_term ||
                 c->entries[c->entry_count - 1u].journal_generation != c->journal_generation))
                return false;
            return qihse_consensus_snapshot_chunk_digest(c) == c->chunk_digest;
        }
        default: return false;
    }
}

static bool wire_encode(const qihse_user_t* principal,
                        const qihse_consensus_msg_t* m,
                        const uint8_t history_id[32], uint64_t writer_epoch,
                        uint8_t* out, size_t out_cap, size_t* out_len) {
    size_t group_len = 0;
    if (!out || !out_len || !prevalidate(principal, m, &group_len) ||
        (history_id && !history_valid(history_id, writer_epoch)))
        return false;
    writer_t w = {out, out_cap, 0u, true};
    static const uint8_t magic_legacy[4] = {'Q', 'C', 'S', '1'};
    static const uint8_t magic_bound[4] = {'Q', 'C', 'S', '2'};
    w_bytes(&w, history_id ? magic_bound : magic_legacy, 4u);
    w_u16(&w, history_id ? 2u : 1u);
    w_u8(&w, (uint8_t)m->type); w_u8(&w, (uint8_t)group_len);
    w_bytes(&w, m->from.bytes, sizeof(m->from.bytes));
    w_bytes(&w, m->to.bytes, sizeof(m->to.bytes));
    w_u64(&w, m->term); w_u64(&w, m->fencing_epoch);
    if (history_id) {
        w_bytes(&w, history_id, 32u);
        w_u64(&w, writer_epoch);
    }
    w_bytes(&w, m->group_id, group_len);
    switch (m->type) {
        case QIHSE_CONSENSUS_MSG_REQUEST_VOTE:
            w_u64(&w, m->u.vote.last_log_index); w_u64(&w, m->u.vote.last_log_term); break;
        case QIHSE_CONSENSUS_MSG_VOTE_REPLY:
            w_u8(&w, m->u.vote_reply.granted ? 1u : 0u); break;
        case QIHSE_CONSENSUS_MSG_APPEND:
            w_u64(&w, m->u.append.prev_log_index); w_u64(&w, m->u.append.prev_log_term);
            w_u64(&w, m->u.append.leader_commit); w_u8(&w, (uint8_t)m->u.append.entry_count);
            for (size_t i = 0; i < m->u.append.entry_count; i++) encode_entry(&w, &m->u.append.entries[i]);
            break;
        case QIHSE_CONSENSUS_MSG_APPEND_REPLY:
            w_u8(&w, m->u.append_reply.success ? 1u : 0u); w_u64(&w, m->u.append_reply.match_index); break;
        case QIHSE_CONSENSUS_MSG_SNAPSHOT:
            w_u64(&w, m->u.snapshot.last_included_index); w_u64(&w, m->u.snapshot.last_included_term);
            w_u64(&w, m->u.snapshot.fencing_epoch); w_u64(&w, m->u.snapshot.journal_generation);
            w_u64(&w, m->u.snapshot.digest); w_u8(&w, (uint8_t)m->u.snapshot.entry_count);
            for (size_t i = 0; i < m->u.snapshot.entry_count; i++) encode_entry(&w, &m->u.snapshot.entries[i]);
            break;
        case QIHSE_CONSENSUS_MSG_SNAPSHOT_REPLY:
            w_u8(&w, m->u.snapshot_reply.success ? 1u : 0u); w_u64(&w, m->u.snapshot_reply.match_index); break;
        case QIHSE_CONSENSUS_MSG_SNAPSHOT_CHUNK: {
            const qihse_consensus_snapshot_chunk_t* c = &m->u.snapshot_chunk;
            w_u64(&w, c->transfer_id); w_u64(&w, c->total_entries);
            w_u64(&w, c->first_entry_index); w_u64(&w, c->last_included_term);
            w_u64(&w, c->snapshot_fencing_epoch); w_u64(&w, c->journal_generation);
            w_u64(&w, c->digest); w_u64(&w, c->chunk_digest);
            w_u8(&w, (uint8_t)c->entry_count); w_u8(&w, c->final_chunk ? 1u : 0u);
            for (size_t i = 0; i < c->entry_count; i++) encode_entry(&w, &c->entries[i]);
            break;
        }
        default: return false;
    }
    if (!w.ok) return false;
    *out_len = w.n;
    return true;
}

bool qihse_consensus_wire_encode(const qihse_user_t* principal,
                                 const qihse_consensus_msg_t* message,
                                 uint8_t* out, size_t out_cap,
                                 size_t* out_len) {
    return wire_encode(principal, message, NULL, 0u, out, out_cap, out_len);
}

bool qihse_consensus_wire_encode_bound(const qihse_user_t* principal,
                                       const qihse_consensus_msg_t* message,
                                       const uint8_t history_id[32],
                                       uint64_t writer_epoch,
                                       uint8_t* out, size_t out_cap,
                                       size_t* out_len) {
    if (!history_valid(history_id, writer_epoch)) return false;
    return wire_encode(principal, message, history_id, writer_epoch,
                       out, out_cap, out_len);
}

static bool wire_decode(const qihse_user_t* principal,
                        const uint8_t* wire, size_t wire_len,
                        const uint8_t history_id[32], uint64_t writer_epoch,
                        qihse_consensus_msg_t* out) {
    if (!principal || !wire || !out ||
        wire_len < QCS_HEADER_SIZE + (history_id ? QCS_BOUND_SIZE : 0u) ||
        wire_len > QIHSE_CONSENSUS_WIRE_MAX) return false;
    if (history_id && !history_valid(history_id, writer_epoch)) return false;
    qihse_consensus_msg_t m;
    memset(&m, 0, sizeof(m));
    reader_t r = {wire, wire_len, 0u, true};
    uint8_t magic[4]; r_bytes(&r, magic, sizeof(magic));
    const uint8_t expected_legacy[4] = {'Q', 'C', 'S', '1'};
    const uint8_t expected_bound[4] = {'Q', 'C', 'S', '2'};
    uint16_t version = r_u16(&r);
    m.type = (qihse_consensus_msg_type_t)r_u8(&r);
    uint8_t group_len = r_u8(&r);
    r_bytes(&r, m.from.bytes, sizeof(m.from.bytes)); r_bytes(&r, m.to.bytes, sizeof(m.to.bytes));
    m.term = r_u64(&r); m.fencing_epoch = r_u64(&r);
    if (!r.ok || memcmp(magic, history_id ? expected_bound : expected_legacy,
                        sizeof(magic)) != 0 ||
        version != (history_id ? 2u : 1u) ||
        group_len == 0u || group_len > QIHSE_CONSENSUS_GROUP_ID_MAX) return false;
    if (history_id) {
        uint8_t remote_history[32];
        r_bytes(&r, remote_history, sizeof(remote_history));
        uint64_t remote_epoch = r_u64(&r);
        if (!r.ok || memcmp(remote_history, history_id, 32u) != 0 ||
            remote_epoch != writer_epoch) return false;
    }
    r_bytes(&r, m.group_id, group_len); m.group_id[group_len] = '\0';
    if (!r.ok) return false;
    switch (m.type) {
        case QIHSE_CONSENSUS_MSG_REQUEST_VOTE:
            m.u.vote.last_log_index = r_u64(&r); m.u.vote.last_log_term = r_u64(&r); break;
        case QIHSE_CONSENSUS_MSG_VOTE_REPLY: {
            uint8_t v = r_u8(&r); if (v > 1u) r.ok = false; m.u.vote_reply.granted = v != 0u; break;
        }
        case QIHSE_CONSENSUS_MSG_APPEND: {
            m.u.append.prev_log_index = r_u64(&r); m.u.append.prev_log_term = r_u64(&r);
            m.u.append.leader_commit = r_u64(&r); m.u.append.entry_count = r_u8(&r);
            if (m.u.append.entry_count > QIHSE_CONSENSUS_MAX_ENTRIES_PER_MSG) { r.ok = false; break; }
            for (size_t i = 0; i < m.u.append.entry_count && r.ok; i++) decode_entry(&r, &m.u.append.entries[i]);
            break;
        }
        case QIHSE_CONSENSUS_MSG_APPEND_REPLY: {
            uint8_t v = r_u8(&r); if (v > 1u) r.ok = false;
            m.u.append_reply.success = v != 0u; m.u.append_reply.match_index = r_u64(&r); break;
        }
        case QIHSE_CONSENSUS_MSG_SNAPSHOT: {
            m.u.snapshot.last_included_index = r_u64(&r); m.u.snapshot.last_included_term = r_u64(&r);
            m.u.snapshot.fencing_epoch = r_u64(&r); m.u.snapshot.journal_generation = r_u64(&r);
            m.u.snapshot.digest = r_u64(&r); m.u.snapshot.entry_count = r_u8(&r);
            if (m.u.snapshot.entry_count > QIHSE_CONSENSUS_SNAPSHOT_MAX_ENTRIES) { r.ok = false; break; }
            for (size_t i = 0; i < m.u.snapshot.entry_count && r.ok; i++) decode_entry(&r, &m.u.snapshot.entries[i]);
            break;
        }
        case QIHSE_CONSENSUS_MSG_SNAPSHOT_REPLY: {
            uint8_t v = r_u8(&r); if (v > 1u) r.ok = false;
            m.u.snapshot_reply.success = v != 0u; m.u.snapshot_reply.match_index = r_u64(&r); break;
        }
        case QIHSE_CONSENSUS_MSG_SNAPSHOT_CHUNK: {
            qihse_consensus_snapshot_chunk_t* c = &m.u.snapshot_chunk;
            c->transfer_id = r_u64(&r); c->total_entries = r_u64(&r);
            c->first_entry_index = r_u64(&r); c->last_included_term = r_u64(&r);
            c->snapshot_fencing_epoch = r_u64(&r); c->journal_generation = r_u64(&r);
            c->digest = r_u64(&r); c->chunk_digest = r_u64(&r);
            c->entry_count = r_u8(&r);
            uint8_t final = r_u8(&r);
            if (final > 1u || c->entry_count > QIHSE_CONSENSUS_SNAPSHOT_CHUNK_MAX_ENTRIES) {
                r.ok = false;
                break;
            }
            c->final_chunk = final != 0u;
            for (size_t i = 0; i < c->entry_count && r.ok; i++) decode_entry(&r, &c->entries[i]);
            break;
        }
        default: r.ok = false; break;
    }
    size_t ignored = 0u;
    if (!r.ok || r.n != r.len || !prevalidate(principal, &m, &ignored)) return false;
    *out = m;
    return true;
}

bool qihse_consensus_wire_decode(const qihse_user_t* principal,
                                 const uint8_t* wire, size_t wire_len,
                                 qihse_consensus_msg_t* out) {
    return wire_decode(principal, wire, wire_len, NULL, 0u, out);
}

bool qihse_consensus_wire_decode_bound(const qihse_user_t* principal,
                                       const uint8_t* wire, size_t wire_len,
                                       const uint8_t history_id[32],
                                       uint64_t writer_epoch,
                                       qihse_consensus_msg_t* out) {
    if (!history_valid(history_id, writer_epoch)) return false;
    return wire_decode(principal, wire, wire_len, history_id,
                       writer_epoch, out);
}
