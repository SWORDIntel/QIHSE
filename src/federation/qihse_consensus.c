/*
 * QIHSE scoped consensus — implementation.
 *
 * Tick-driven, single-threaded, deterministic state machine for ONE scoped
 * replication group.  Read include/qihse_consensus.h first: it states the
 * honest scope of this module — the election, log-matching, majority-commit,
 * current-term-commit, step-down, fencing, log-compaction/snapshot-install,
 * single-server-membership-change, and restart mechanics that ARE
 * implemented, and the joint-consensus, pre-vote, read-lease, and
 * transport-authentication mechanics that are NOT.
 *
 * Persistence is an append-only record file: one line per record, each
 * checksummed, replayed with a single reusable heap line buffer.  A record
 * write happens BEFORE the corresponding in-memory state change takes
 * effect, and a failed record write fails the operation closed.
 *
 * INDICES ARE ABSOLUTE everywhere in this file after compaction: the active
 * log array cs->log[] holds absolute indices (snapshot_index + 1) .. (last
 * log index), and entries below the boundary live in cs->snap.  Every
 * log-position computation goes through qcs_abs_last_index()/qcs_entry_at();
 * nothing indexes cs->log with a raw absolute index.
 */

#include "qihse_consensus.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* ── Constants ───────────────────────────────────────────────────────────── */

#define QCS_DEFAULT_ELECTION_BASE_MS 150u
#define QCS_DEFAULT_ELECTION_SPREAD_MS 300u
#define QCS_DEFAULT_HEARTBEAT_MS 50u

/* One record line, header included.  The largest record is an L line with a
 * full 128-byte payload hex (256 chars) plus numeric fields; 640 leaves
 * generous slack without inviting oversized lines. */
#define QCS_RECORD_LINE_CAP 640u

#define QCS_RECORD_MAGIC "QHCNS"
#define QCS_RECORD_VERSION 1u

/* ── Small helpers ───────────────────────────────────────────────────────── */

static uint64_t qcs_splitmix64(uint64_t z) {
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}

static uint64_t qcs_fnv1a(const char* data, size_t len) {
    uint64_t h = 0xCBF2CE48D222D25BULL; /* FNV-1a 64 */
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)data[i];
        h *= 0x100000001B3ULL;
    }
    return h;
}

/* ── Snapshot state and digest ───────────────────────────────────────────── */

/* Installed snapshot: the compacted prefix [1 .. last_included_index],
 * retained in full (payloads + classification metadata) because this
 * module's state machine IS the log — committed reads below the boundary
 * are served from here, under the same per-entry authorization. */
typedef struct {
    qihse_consensus_entry_t* entries; /* entry i lives at [i-1]; NULL if none */
    size_t count;                     /* == last_included_index, always */
    size_t cap;
    uint64_t last_included_index;
    uint64_t last_included_term;
    uint64_t epoch;                   /* fencing epoch recorded at compaction */
    uint64_t journal_generation;      /* highest generation compacted */
    uint64_t digest;                  /* canonical FNV-1a over the entries */
} qcs_snapshot_t;

/* Canonical snapshot digest (documented in the header): FNV-1a folding the
 * little-endian 8-byte encodings of each numeric field, then the payload
 * bytes, entry by entry in index order.  Recomputed and compared by every
 * consumer — never trusted from storage or the wire. */
static uint64_t qcs_digest_fold_u64(uint64_t h, uint64_t v) {
    for (unsigned i = 0; i < 8u; i++) {
        h ^= (uint8_t)(v & 0xFFu);
        h *= 0x100000001B3ULL;
        v >>= 8;
    }
    return h;
}

static uint64_t qcs_digest_entry(uint64_t h, const qihse_consensus_entry_t* e) {
    h = qcs_digest_fold_u64(h, e->index);
    h = qcs_digest_fold_u64(h, e->term);
    h = qcs_digest_fold_u64(h, e->journal_generation);
    h = qcs_digest_fold_u64(h, e->hlc.physical_ms);
    h = qcs_digest_fold_u64(h, e->hlc.logical);
    h = qcs_digest_fold_u64(h, e->classif);
    h = qcs_digest_fold_u64(h, e->sci);
    h = qcs_digest_fold_u64(h, (uint64_t)e->type);
    h = qcs_digest_fold_u64(h, (uint64_t)e->payload_len);
    for (size_t b = 0; b < e->payload_len; b++) {
        h ^= e->payload[b];
        h *= 0x100000001B3ULL;
    }
    return h;
}

static uint64_t qcs_snapshot_digest(const qihse_consensus_entry_t* entries,
                                    size_t count) {
    uint64_t h = 0xCBF2CE48D222D25BULL;
    for (size_t i = 0; i < count; i++) {
        h = qcs_digest_entry(h, &entries[i]);
    }
    return h;
}

static int qcs_hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void qcs_hex_encode(const uint8_t* in, size_t len, char* out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 0x0Fu];
    }
    out[2 * len] = '\0';
}

/* Decode exactly hex_len hex chars into out_cap bytes.  The declared length
 * is validated against BOTH the encoded length (must be even, must fit the
 * buffer) and the expected fixed size (out_need) before anything decodes. */
static bool qcs_hex_decode(const char* s, size_t hex_len,
                           uint8_t* out, size_t out_cap, size_t out_need) {
    if (out_need > out_cap) return false;
    if (hex_len != out_need * 2u) return false;
    for (size_t i = 0; i < out_need; i++) {
        int hi = qcs_hex_val(s[2 * i]);
        int lo = qcs_hex_val(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static bool qcs_parse_u64(const char* s, uint64_t* out) {
    if (!s || !*s) return false;
    /* Refuse signs and whitespace: strtoull would happily wrap "-1" into a
     * huge unsigned value and accept it as a term. */
    if (s[0] < '0' || s[0] > '9') return false;
    errno = 0;
    char* end = NULL;
    unsigned long long v = strtoull(s, &end, 10);
    if (errno == ERANGE || !end || *end != '\0') return false;
    *out = (uint64_t)v;
    return true;
}

/* ── Instance ────────────────────────────────────────────────────────────── */

struct qihse_consensus {
    qihse_consensus_config_t cfg;
    void* transport;
    qihse_consensus_send_fn send_fn;

    FILE* rec;
    char* rec_buf; /* the one reusable encode buffer */
    bool rec_quarantined; /* a snapshot transaction failed mid-write */

    qihse_consensus_role_t role;
    uint64_t term;
    uint64_t epoch; /* fencing epoch floor; always >= term */
    qihse_uuid_t voted_for;
    bool has_vote;
    qihse_uuid_t leader;
    bool has_leader;

    qihse_consensus_entry_t* log;
    size_t log_len;   /* entries at absolute (snap.count + 1) .. tail */
    size_t log_cap;

    qcs_snapshot_t snap;         /* compacted prefix; count == boundary */

    /* Membership: cfg.members/member_count is the EFFECTIVE config (base
     * folded over the config entries in the log); base_* is the static
     * baseline captured at open.  See the header's MEMBERSHIP CHANGES. */
    qihse_uuid_t base_members[QIHSE_CONSENSUS_MAX_MEMBERS];
    size_t base_count;

    /* Lame-duck members: uuids dropped by the latest config change.  While
     * that transition is uncommitted, the leader keeps OFFERING them the
     * transition entry (their acknowledgements never count — they are not
     * voters), so a reachable removed node learns of its removal and steps
     * down cleanly; a partitioned one is fenced by membership instead. */
    qihse_uuid_t rm_uuid[QIHSE_CONSENSUS_MAX_MEMBERS];
    uint64_t rm_next[QIHSE_CONSENSUS_MAX_MEMBERS];
    bool rm_committed[QIHSE_CONSENSUS_MAX_MEMBERS];
    size_t rm_count;

    uint64_t commit;

    uint64_t now_ms;                  /* last tick's timestamp */
    uint64_t last_leader_contact_ms;  /* valid append or granted vote */
    uint64_t last_heartbeat_ms;       /* leader: last replication sweep */
    uint64_t last_ack_ms[QIHSE_CONSENSUS_MAX_MEMBERS];

    uint32_t votes_granted_mask; /* candidate: peers + self that voted for us */

    uint64_t next_index[QIHSE_CONSENSUS_MAX_MEMBERS];
    uint64_t match_index[QIHSE_CONSENSUS_MAX_MEMBERS];
    int self_index;
    uint64_t self_hash;

    qihse_consensus_counters_t counters;
};

/* ── Configuration validation ────────────────────────────────────────────── */

static bool qcs_group_id_valid(const char* id) {
    if (!id || !*id) return false;
    size_t len = strlen(id);
    if (len > QIHSE_CONSENSUS_GROUP_ID_MAX) return false;
    for (size_t i = 0; i < len; i++) {
        char c = id[i];
        bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '.' || c == '_' ||
                  c == '-' || c == '/' || c == ':' || c == '+';
        if (!ok) return false;
    }
    return true;
}

static bool qcs_record_path_valid(const char* p) {
    if (!p || !*p) return false;
    size_t len = strlen(p);
    if (len > QIHSE_CONSENSUS_RECORD_PATH_MAX) return false;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)p[i];
        if (c < 0x20u || c == 0x7Fu) return false; /* no control chars */
    }
    return true;
}

/* ── Absolute log addressing ───────────────────────────────────────────────
 * After compaction the active log array starts just past the snapshot
 * boundary; these are the ONLY sanctioned ways to turn an absolute index
 * into storage. */

static uint64_t qcs_abs_last_index(const qihse_consensus_t* cs) {
    return (uint64_t)cs->snap.count + (uint64_t)cs->log_len;
}

static const qihse_consensus_entry_t* qcs_entry_at(const qihse_consensus_t* cs,
                                                   uint64_t index) {
    if (index == 0u || index > qcs_abs_last_index(cs)) return NULL;
    if (index <= (uint64_t)cs->snap.count) {
        return &cs->snap.entries[index - 1u];
    }
    return &cs->log[index - (uint64_t)cs->snap.count - 1u];
}

static uint64_t qcs_term_at(const qihse_consensus_t* cs, uint64_t index) {
    const qihse_consensus_entry_t* e = qcs_entry_at(cs, index);
    return e ? e->term : 0u;
}

/* Journal generation of the last appended entry, across the snapshot
 * boundary — propose() must keep generations strictly increasing even
 * directly after a compaction that emptied the active log. */
static uint64_t qcs_last_gen(const qihse_consensus_t* cs) {
    if (cs->log_len) return cs->log[cs->log_len - 1u].journal_generation;
    if (cs->snap.count) {
        return cs->snap.entries[cs->snap.count - 1u].journal_generation;
    }
    return 0u;
}

/* ── Membership fold ───────────────────────────────────────────────────────
 *
 * The effective member set is a PURE FUNCTION OF THE LOG: the static base
 * configuration captured at open, folded over every config entry (snapshot
 * prefix included) in index order.  A config entry takes effect when it is
 * appended — never when its commit is learned — which is what keeps a
 * node's quorum basis equal to its log (the election-safety argument in
 * the header). */

static bool qcs_config_entry_valid(const qihse_consensus_entry_t* e) {
    if (e->type == QIHSE_CONSENSUS_ENTRY_DATA) return true;
    if (e->type != QIHSE_CONSENSUS_ENTRY_CONFIG_ADD &&
        e->type != QIHSE_CONSENSUS_ENTRY_CONFIG_REMOVE) return false;
    if (e->payload_len != QIHSE_UUID_BYTES) return false;
    if (e->classif != 0u || e->sci != 0u) return false;
    qihse_uuid_t uid;
    memcpy(uid.bytes, e->payload, QIHSE_UUID_BYTES);
    return !qihse_uuid_is_nil(&uid);
}

static void qcs_fold_apply(qihse_uuid_t* members, size_t* count,
                           const qihse_consensus_entry_t* e,
                           bool* overflow) {
    qihse_uuid_t uid;
    memcpy(uid.bytes, e->payload, QIHSE_UUID_BYTES);
    size_t at = 0;
    while (at < *count && !qihse_uuid_equal(&members[at], &uid)) at++;
    if (e->type == QIHSE_CONSENSUS_ENTRY_CONFIG_ADD) {
        if (at < *count) return;          /* already a member: no-op */
        if (*count >= QIHSE_CONSENSUS_MAX_MEMBERS) { *overflow = true; return; }
        members[(*count)++] = uid;
    } else {
        if (at == *count) return;         /* not a member: no-op */
        memmove(members + at, members + at + 1u,
                (*count - at - 1u) * sizeof(*members));
        (*count)--;
    }
}

/* Fold the base config over every config entry in the log (snapshot
 * included), optionally with `extra` participating as the next appended
 * entry — used to validate a candidate config entry BEFORE it is
 * persisted.  Fails (returns false) when the result would be invalid:
 * empty, over MAX_MEMBERS, structurally malformed config entries, or a
 * log/snapshot hole.  Callers treat false as hostile input. */
static bool qcs_fold_membership(const qihse_consensus_t* cs,
                                const qihse_consensus_entry_t* extra,
                                qihse_uuid_t* out_members,
                                size_t* out_count) {
    size_t count = cs->base_count;
    memcpy(out_members, cs->base_members, count * sizeof(*out_members));
    bool overflow = false;
    uint64_t last = qcs_abs_last_index(cs);
    for (uint64_t i = 1; i <= last; i++) {
        const qihse_consensus_entry_t* e = qcs_entry_at(cs, i);
        if (!e || !qcs_config_entry_valid(e)) return false;
        if (e->type == QIHSE_CONSENSUS_ENTRY_DATA) continue;
        qcs_fold_apply(out_members, &count, e, &overflow);
        if (overflow) return false;
    }
    if (extra) {
        if (!qcs_config_entry_valid(extra)) return false;
        qcs_fold_apply(out_members, &count, extra, &overflow);
        if (overflow) return false;
    }
    if (count < 1u) return false; /* a group may never fold to empty */
    *out_count = count;
    return true;
}

/* ── Record file: encoding ───────────────────────────────────────────────── */

/* Append one checksummed record.  body must already be in cs->rec_buf (no
 * trailing newline); the checksum covers exactly those bytes.  Returns
 * false (and the record file must be treated as suspect) on any I/O
 * failure; callers propagate the failure instead of applying the state
 * change.  Once a snapshot transaction has failed mid-write, the file
 * ends with an unterminated S block that replay can only roll back if
 * NOTHING follows it — so further writes are refused (the node is
 * quarantined: it keeps serving reads but makes no durable progress). */
static bool qcs_record_append(qihse_consensus_t* cs, size_t body_len) {
    if (cs->rec_quarantined) return false;
    char cksum[24];
    snprintf(cksum, sizeof(cksum), " %016llx",
             (unsigned long long)qcs_fnv1a(cs->rec_buf, body_len));
    memcpy(cs->rec_buf + body_len, cksum, strlen(cksum) + 1u);
    strcat(cs->rec_buf, "\n");

    if (fputs(cs->rec_buf, cs->rec) == EOF) return false;
    if (fflush(cs->rec) != 0) return false;
    if (fsync(fileno(cs->rec)) != 0) return false;
    cs->counters.record_writes++;
    return true;
}

static bool qcs_persist_vote(qihse_consensus_t* cs) {
    char voted[2 * QIHSE_UUID_BYTES + 1u];
    if (cs->has_vote) qcs_hex_encode(cs->voted_for.bytes, QIHSE_UUID_BYTES, voted);
    else snprintf(voted, sizeof(voted), "-");
    int n = snprintf(cs->rec_buf, QCS_RECORD_LINE_CAP, "V %llu %s %llu",
                     (unsigned long long)cs->term, voted,
                     (unsigned long long)cs->epoch);
    if (n < 0 || (size_t)n >= QCS_RECORD_LINE_CAP) return false;
    return qcs_record_append(cs, (size_t)n);
}

static bool qcs_persist_entry(qihse_consensus_t* cs,
                              const qihse_consensus_entry_t* e) {
    char hex[2 * QIHSE_CONSENSUS_PAYLOAD_MAX + 1u];
    if (e->payload_len > QIHSE_CONSENSUS_PAYLOAD_MAX) return false;
    qcs_hex_encode(e->payload, e->payload_len, hex);
    int n = snprintf(cs->rec_buf, QCS_RECORD_LINE_CAP,
                     "L %llu %llu %llu %llu %u %u %u %s",
                     (unsigned long long)e->index,
                     (unsigned long long)e->term,
                     (unsigned long long)e->journal_generation,
                     (unsigned long long)e->hlc.physical_ms,
                     (unsigned)e->hlc.logical,
                     (unsigned)e->classif, (unsigned)e->sci, hex);
    if (n < 0 || (size_t)n >= QCS_RECORD_LINE_CAP) return false;
    return qcs_record_append(cs, (size_t)n);
}

static bool qcs_persist_truncate(qihse_consensus_t* cs, uint64_t from_index) {
    int n = snprintf(cs->rec_buf, QCS_RECORD_LINE_CAP, "T %llu",
                     (unsigned long long)from_index);
    if (n < 0 || (size_t)n >= QCS_RECORD_LINE_CAP) return false;
    return qcs_record_append(cs, (size_t)n);
}

/* Config entry on disk: one checksummed LC line, fsynced BEFORE the
 * in-memory config folds it in — the record IS the swap point.  A torn LC
 * tail fails the load closed, leaving the previous config in force. */
static bool qcs_persist_config_entry(qihse_consensus_t* cs,
                                     const qihse_consensus_entry_t* e) {
    if (e->type != QIHSE_CONSENSUS_ENTRY_CONFIG_ADD &&
        e->type != QIHSE_CONSENSUS_ENTRY_CONFIG_REMOVE) return false;
    if (e->payload_len != QIHSE_UUID_BYTES) return false;
    char hex[2 * QIHSE_UUID_BYTES + 1u];
    qcs_hex_encode(e->payload, QIHSE_UUID_BYTES, hex);
    char op = (e->type == QIHSE_CONSENSUS_ENTRY_CONFIG_ADD) ? 'A' : 'R';
    int n = snprintf(cs->rec_buf, QCS_RECORD_LINE_CAP, "LC %c %s %llu %llu %llu",
                     op, hex,
                     (unsigned long long)e->index,
                     (unsigned long long)e->term,
                     (unsigned long long)e->journal_generation);
    if (n < 0 || (size_t)n >= QCS_RECORD_LINE_CAP) return false;
    return qcs_record_append(cs, (size_t)n);
}

static bool qcs_persist_commit(qihse_consensus_t* cs) {
    int n = snprintf(cs->rec_buf, QCS_RECORD_LINE_CAP, "C %llu",
                     (unsigned long long)cs->commit);
    if (n < 0 || (size_t)n >= QCS_RECORD_LINE_CAP) return false;
    return qcs_record_append(cs, (size_t)n);
}

/* Snapshot transaction on disk: an S header, one SE line per compacted
 * entry, and a terminating T (the swap point).  An S block is only
 * meaningful once its T lands; an unterminated trailing block is a crash
 * mid-compaction and rolls back on replay. */
static bool qcs_persist_snapshot_begin(qihse_consensus_t* cs, uint64_t last_index,
                                       uint64_t last_term, uint64_t epoch,
                                       uint64_t gen_hi, uint64_t digest,
                                       size_t count) {
    int n = snprintf(cs->rec_buf, QCS_RECORD_LINE_CAP,
                     "S %llu %llu %llu %llu %016llx %llu",
                     (unsigned long long)last_index,
                     (unsigned long long)last_term,
                     (unsigned long long)epoch,
                     (unsigned long long)gen_hi,
                     (unsigned long long)digest,
                     (unsigned long long)count);
    if (n < 0 || (size_t)n >= QCS_RECORD_LINE_CAP) return false;
    return qcs_record_append(cs, (size_t)n);
}

static bool qcs_persist_snapshot_entry(qihse_consensus_t* cs,
                                       const qihse_consensus_entry_t* e) {
    /* A config entry inside a snapshot transaction keeps its LC form —
     * an SE record carries no entry type, and losing it would corrupt
     * the fold AND the digest on replay. */
    if (e->type != QIHSE_CONSENSUS_ENTRY_DATA) {
        return qcs_persist_config_entry(cs, e);
    }
    char hex[2 * QIHSE_CONSENSUS_PAYLOAD_MAX + 1u];
    if (e->payload_len > QIHSE_CONSENSUS_PAYLOAD_MAX) return false;
    qcs_hex_encode(e->payload, e->payload_len, hex);
    int n = snprintf(cs->rec_buf, QCS_RECORD_LINE_CAP,
                     "SE %llu %llu %llu %llu %u %u %u %s",
                     (unsigned long long)e->index,
                     (unsigned long long)e->term,
                     (unsigned long long)e->journal_generation,
                     (unsigned long long)e->hlc.physical_ms,
                     (unsigned)e->hlc.logical,
                     (unsigned)e->classif, (unsigned)e->sci, hex);
    if (n < 0 || (size_t)n >= QCS_RECORD_LINE_CAP) return false;
    return qcs_record_append(cs, (size_t)n);
}

/* ── Record file: decoding (fail closed) ───────────────────────────────────
 *
 * Decoder discipline (AGENTS.md "federation record decoders"): ONE reusable
 * heap buffer (the line buffer), explicit goto-done cleanup, declared
 * lengths validated against both the encoded length and the fixed size,
 * and a per-record checksum recomputed and compared rather than trusted.
 * Worst-case stack frame is a handful of scalars plus one entry struct. */

static bool qcs_check_line_checksum(char* line, size_t len) {
    /* line ends "... <cksum16hex>\n"; find the last space before it. */
    if (len < 3u || line[len - 1u] != '\n') return false;
    line[len - 1u] = '\0';
    size_t body_len = strlen(line);
    long sp = -1;
    for (long i = (long)body_len - 1; i >= 0; i--) {
        if (line[i] == ' ') { sp = i; break; }
    }
    if (sp <= 0) return false;
    const char* ck = &line[sp + 1];
    if (strlen(ck) != 16u) return false;
    uint64_t actual = 0;
    for (size_t i = 0; i < 16u; i++) {
        int v = qcs_hex_val(ck[i]);
        if (v < 0) return false;
        actual = (actual << 4) | (uint64_t)v;
    }
    if (qcs_fnv1a(line, (size_t)sp) != actual) return false;
    line[sp] = '\0'; /* strip the checksum token from the token stream */
    return true;
}

/* Forward declarations for the loader. */
static bool qcs_log_push(qihse_consensus_t* cs, const qihse_consensus_entry_t* e);
static void qcs_log_truncate(qihse_consensus_t* cs, size_t keep);
static bool qcs_entry_identical(const qihse_consensus_entry_t* a,
                                const qihse_consensus_entry_t* b);
static bool qcs_recompute_membership(qihse_consensus_t* cs);

static bool qcs_load_records(qihse_consensus_t* cs, const char* path,
                             bool* out_created) {
    bool ok = false;
    FILE* f = NULL;
    char* line = NULL; /* the single reusable heap buffer */
    bool header_seen = false;

    /* Replay state (absolute indices throughout). */
    uint64_t cur_term = 0, cur_epoch = 0;
    bool has_vote = false;
    qihse_uuid_t voted_for;
    memset(&voted_for, 0, sizeof(voted_for));
    uint64_t next_index = 1;   /* next expected L index (absolute) */
    uint64_t last_entry_term = 0, last_gen = 0;
    uint64_t commit = 0;

    /* Pending (uncommitted) snapshot transaction.  S starts it, SE lines
     * fill it, T commits it — anything else while it is open, or EOF
     * before its T, is a crash mid-compaction and rolls it back, leaving
     * the previously replayed (uncompacted) state standing. */
    qihse_consensus_entry_t* pend = NULL; /* bounded by the S header */
    uint64_t pend_last_index = 0, pend_last_term = 0, pend_epoch = 0;
    uint64_t pend_gen_hi = 0, pend_digest = 0, pend_count = 0, pend_have = 0;
    uint64_t pend_run = 0;     /* digest recomputed over the SE stream */
    uint64_t pend_term_prev = 0, pend_gen_prev = 0;
    bool pend_active = false;

    *out_created = false;

    f = fopen(path, "r");
    if (!f) {
        if (errno != ENOENT) return false; /* unreadable but present: closed */
        /* New file: create and write the header. */
        f = fopen(path, "w");
        if (!f) return false;
        *out_created = true;
        ok = true;
        goto done;
    }

    line = malloc(QCS_RECORD_LINE_CAP + 1u);
    if (!line) goto done;

    while (fgets(line, (int)(QCS_RECORD_LINE_CAP + 1u), f)) {
        size_t len = strlen(line);
        if (len == 0u || line[len - 1u] != '\n') {
            /* Torn tail or overlong line: if more bytes follow it is an
             * overlong (hostile) line — fail closed.  A genuine torn tail
             * (crash mid-append) also fails the load, EXCEPT while a
             * snapshot transaction is open: that is a crash between the
             * snapshot write and its truncation record, and rolling the
             * transaction back preserves the previous durable state. */
            bool more = (fgets(line, (int)(QCS_RECORD_LINE_CAP + 1u), f) != NULL);
            if (!more && pend_active) {
                free(pend);
                pend = NULL;
                cs->term = cur_term;
                cs->epoch = cur_epoch;
                cs->has_vote = has_vote;
                cs->voted_for = voted_for;
                cs->commit = commit;
                ok = true;
                goto done;
            }
            goto done;
        }
        if (len > QCS_RECORD_LINE_CAP) goto done;
        if (!qcs_check_line_checksum(line, len)) goto done;
        len = strlen(line); /* checksum helper stripped the newline */

        /* Tokenize on spaces; every field must be present and non-empty. */
        char* save = NULL;
        char* tok = strtok_r(line, " ", &save);
        if (!tok) goto done;

        if (strcmp(tok, QCS_RECORD_MAGIC) == 0) {
            if (header_seen) goto done; /* header exactly once, first */
            char* ver = strtok_r(NULL, " ", &save);
            char* gid = strtok_r(NULL, " ", &save);
            if (!ver || !gid || strtok_r(NULL, " ", &save)) goto done;
            uint64_t v = 0;
            if (!qcs_parse_u64(ver, &v) || v != QCS_RECORD_VERSION) goto done;
            if (strcmp(gid, cs->cfg.group_id) != 0) goto done; /* foreign file */
            header_seen = true;
            continue;
        }
        if (!header_seen) goto done; /* records before the header */

        if (strcmp(tok, "V") == 0) {
            if (pend_active) goto done; /* S transaction must finish first */
            char* s_term = strtok_r(NULL, " ", &save);
            char* s_vote = strtok_r(NULL, " ", &save);
            char* s_epoch = strtok_r(NULL, " ", &save);
            if (!s_term || !s_vote || !s_epoch) goto done;
            if (strtok_r(NULL, " ", &save)) goto done;
            uint64_t t = 0, e = 0;
            if (!qcs_parse_u64(s_term, &t) || !qcs_parse_u64(s_epoch, &e)) goto done;
            if (t < cur_term) goto done;        /* term regressed */
            if (e < t) goto done;               /* epoch fences the term */
            if (e < cur_epoch) goto done;       /* epoch regressed */
            if (strcmp(s_vote, "-") == 0) {
                has_vote = false;
                memset(&voted_for, 0, sizeof(voted_for));
            } else {
                if (!qcs_hex_decode(s_vote, strlen(s_vote),
                                    voted_for.bytes, QIHSE_UUID_BYTES,
                                    QIHSE_UUID_BYTES)) goto done;
                has_vote = true;
            }
            cur_term = t;
            cur_epoch = e;
        } else if (strcmp(tok, "L") == 0) {
            if (pend_active) goto done; /* S transaction must finish first */
            char* s_idx = strtok_r(NULL, " ", &save);
            char* s_term = strtok_r(NULL, " ", &save);
            char* s_gen = strtok_r(NULL, " ", &save);
            char* s_phys = strtok_r(NULL, " ", &save);
            char* s_logi = strtok_r(NULL, " ", &save);
            char* s_cl = strtok_r(NULL, " ", &save);
            char* s_sci = strtok_r(NULL, " ", &save);
            char* s_payload = strtok_r(NULL, " ", &save);
            if (!s_idx || !s_term || !s_gen || !s_phys || !s_logi ||
                !s_cl || !s_sci || !s_payload) goto done;
            if (strtok_r(NULL, " ", &save)) goto done;

            qihse_consensus_entry_t e;
            memset(&e, 0, sizeof(e));
            uint64_t phys = 0, logi = 0, cl = 0, sci = 0;
            if (!qcs_parse_u64(s_idx, &e.index) ||
                !qcs_parse_u64(s_term, &e.term) ||
                !qcs_parse_u64(s_gen, &e.journal_generation) ||
                !qcs_parse_u64(s_phys, &phys) ||
                !qcs_parse_u64(s_logi, &logi) ||
                !qcs_parse_u64(s_cl, &cl) ||
                !qcs_parse_u64(s_sci, &sci)) goto done;
            if (phys > UINT64_MAX / 2u || logi > 0xFFFFFFFFu) goto done;
            if (cl > 0xFFFFu || sci > 0xFFFFu) goto done;
            e.hlc.physical_ms = phys;
            e.hlc.logical = (uint32_t)logi;
            e.classif = (uint16_t)cl;
            e.sci = (uint16_t)sci;

            if (e.index != next_index) goto done;      /* gap or replay */
            if (e.term > cur_term) goto done;          /* entry from the future */
            if (e.term < last_entry_term) goto done;   /* terms must not regress */
            if (qcs_abs_last_index(cs) >= 1u &&
                e.journal_generation <= last_gen) goto done;

            /* Payload: declared by the hex field; validated against the
             * even encoding and the fixed maximum BEFORE decoding. */
            size_t hex_len = strlen(s_payload);
            if (hex_len == 0u || (hex_len & 1u)) goto done;
            if (hex_len > 2u * QIHSE_CONSENSUS_PAYLOAD_MAX) goto done;
            e.payload_len = hex_len / 2u;
            if (!qcs_hex_decode(s_payload, hex_len, e.payload,
                                QIHSE_CONSENSUS_PAYLOAD_MAX, e.payload_len)) {
                goto done;
            }

            if (!qcs_log_push(cs, &e)) goto done;
            next_index++;
            last_entry_term = e.term;
            last_gen = e.journal_generation;
        } else if (strcmp(tok, "LC") == 0) {
            /* Config entry: A/R, the changed member UUID (hex, exactly
             * 2*UUID_BYTES chars — declared == encoded == fixed), then the
             * entry triple (index, term, generation).  classif/sci/hlc are
             * implied zero; the payload IS the UUID.  Outside a snapshot
             * transaction this is a log append; INSIDE one it is the
             * config variant of an SE line. */
            char* s_op = strtok_r(NULL, " ", &save);
            char* s_uuid = strtok_r(NULL, " ", &save);
            char* s_idx = strtok_r(NULL, " ", &save);
            char* s_term = strtok_r(NULL, " ", &save);
            char* s_gen = strtok_r(NULL, " ", &save);
            if (!s_op || !s_uuid || !s_idx || !s_term || !s_gen) goto done;
            if (strtok_r(NULL, " ", &save)) goto done;
            if (strlen(s_op) != 1u || (s_op[0] != 'A' && s_op[0] != 'R')) goto done;
            size_t hex_len = strlen(s_uuid);
            if (hex_len != 2u * QIHSE_UUID_BYTES) goto done;

            qihse_consensus_entry_t e;
            memset(&e, 0, sizeof(e));
            if (!qcs_hex_decode(s_uuid, hex_len, e.payload, QIHSE_UUID_BYTES,
                                QIHSE_UUID_BYTES)) goto done;
            e.payload_len = QIHSE_UUID_BYTES;
            qihse_uuid_t uid;
            memcpy(uid.bytes, e.payload, QIHSE_UUID_BYTES);
            if (qihse_uuid_is_nil(&uid)) goto done;
            if (!qcs_parse_u64(s_idx, &e.index) ||
                !qcs_parse_u64(s_term, &e.term) ||
                !qcs_parse_u64(s_gen, &e.journal_generation)) goto done;
            e.type = (s_op[0] == 'A')
                         ? QIHSE_CONSENSUS_ENTRY_CONFIG_ADD
                         : QIHSE_CONSENSUS_ENTRY_CONFIG_REMOVE;

            if (pend_active) {
                /* Config entry of a snapshot block: same discipline as SE. */
                if (pend_have >= pend_count) goto done;
                if (e.index != pend_have + 1u) goto done;  /* contiguous */
                if (e.term > cur_term) goto done;
                if (e.term < pend_term_prev) goto done;
                if (pend_have > 0u && e.journal_generation <= pend_gen_prev) {
                    goto done;
                }
                if (e.index < next_index) {
                    const qihse_consensus_entry_t* ex = qcs_entry_at(cs, e.index);
                    if (!ex || !qcs_entry_identical(ex, &e)) goto done;
                }
                pend_run = qcs_digest_entry(pend_run, &e);
                pend[pend_have++] = e;
                pend_term_prev = e.term;
                pend_gen_prev = e.journal_generation;
            } else {
                if (e.index != next_index) goto done;      /* gap or replay */
                if (e.term > cur_term) goto done;          /* future */
                if (e.term < last_entry_term) goto done;   /* regression */
                if (qcs_abs_last_index(cs) >= 1u &&
                    e.journal_generation <= last_gen) goto done;
                if (!qcs_log_push(cs, &e)) goto done;
                next_index++;
                last_entry_term = e.term;
                last_gen = e.journal_generation;
            }
        } else if (strcmp(tok, "S") == 0) {
            if (pend_active) goto done; /* nested snapshot transaction */
            char* s_last = strtok_r(NULL, " ", &save);
            char* s_lterm = strtok_r(NULL, " ", &save);
            char* s_epoch = strtok_r(NULL, " ", &save);
            char* s_gen = strtok_r(NULL, " ", &save);
            char* s_dig = strtok_r(NULL, " ", &save);
            char* s_count = strtok_r(NULL, " ", &save);
            if (!s_last || !s_lterm || !s_epoch || !s_gen || !s_dig || !s_count) {
                goto done;
            }
            if (strtok_r(NULL, " ", &save)) goto done;
            uint64_t last = 0, lterm = 0, ep = 0, gen = 0, cnt = 0;
            if (!qcs_parse_u64(s_last, &last) ||
                !qcs_parse_u64(s_lterm, &lterm) ||
                !qcs_parse_u64(s_epoch, &ep) ||
                !qcs_parse_u64(s_gen, &gen) ||
                !qcs_parse_u64(s_count, &cnt)) goto done;
            /* Digest token: declared as 16 hex chars, validated as such. */
            if (strlen(s_dig) != 16u) goto done;
            uint64_t dig = 0;
            for (size_t i = 0; i < 16u; i++) {
                int v = qcs_hex_val(s_dig[i]);
                if (v < 0) goto done;
                dig = (dig << 4) | (uint64_t)v;
            }
            if (last < 1u || cnt != last) goto done; /* contiguous 1..last */
            if (cnt > QIHSE_CONSENSUS_SNAPSHOT_MAX_ENTRIES) goto done;
            if (lterm < 1u || lterm > cur_term) goto done;
            if (ep < lterm || ep > cur_epoch) goto done; /* epoch fences */
            if (last <= (uint64_t)cs->snap.count) goto done; /* not newer */
            if (gen < 1u) goto done;
            pend = malloc((size_t)cnt * sizeof(*pend));
            if (!pend) goto done;
            pend_last_index = last;
            pend_last_term = lterm;
            pend_epoch = ep;
            pend_gen_hi = gen;
            pend_digest = dig;
            pend_count = cnt;
            pend_have = 0;
            pend_run = 0xCBF2CE48D222D25BULL;
            pend_term_prev = 0;
            pend_gen_prev = 0;
            pend_active = true;
        } else if (strcmp(tok, "SE") == 0) {
            if (!pend_active) goto done; /* SE outside an S transaction */
            if (pend_have >= pend_count) goto done; /* more than declared */
            char* s_idx = strtok_r(NULL, " ", &save);
            char* s_term = strtok_r(NULL, " ", &save);
            char* s_gen = strtok_r(NULL, " ", &save);
            char* s_phys = strtok_r(NULL, " ", &save);
            char* s_logi = strtok_r(NULL, " ", &save);
            char* s_cl = strtok_r(NULL, " ", &save);
            char* s_sci = strtok_r(NULL, " ", &save);
            char* s_payload = strtok_r(NULL, " ", &save);
            if (!s_idx || !s_term || !s_gen || !s_phys || !s_logi ||
                !s_cl || !s_sci || !s_payload) goto done;
            if (strtok_r(NULL, " ", &save)) goto done;

            qihse_consensus_entry_t e;
            memset(&e, 0, sizeof(e));
            uint64_t phys = 0, logi = 0, cl = 0, sci = 0;
            if (!qcs_parse_u64(s_idx, &e.index) ||
                !qcs_parse_u64(s_term, &e.term) ||
                !qcs_parse_u64(s_gen, &e.journal_generation) ||
                !qcs_parse_u64(s_phys, &phys) ||
                !qcs_parse_u64(s_logi, &logi) ||
                !qcs_parse_u64(s_cl, &cl) ||
                !qcs_parse_u64(s_sci, &sci)) goto done;
            if (phys > UINT64_MAX / 2u || logi > 0xFFFFFFFFu) goto done;
            if (cl > 0xFFFFu || sci > 0xFFFFu) goto done;
            e.hlc.physical_ms = phys;
            e.hlc.logical = (uint32_t)logi;
            e.classif = (uint16_t)cl;
            e.sci = (uint16_t)sci;

            if (e.index != pend_have + 1u) goto done; /* contiguous block */
            if (e.term > cur_term) goto done;
            if (e.term < pend_term_prev) goto done;   /* no regression inside */
            if (pend_have > 0u && e.journal_generation <= pend_gen_prev) goto done;

            size_t hex_len = strlen(s_payload);
            if (hex_len == 0u || (hex_len & 1u)) goto done;
            if (hex_len > 2u * QIHSE_CONSENSUS_PAYLOAD_MAX) goto done;
            e.payload_len = hex_len / 2u;
            if (!qcs_hex_decode(s_payload, hex_len, e.payload,
                                QIHSE_CONSENSUS_PAYLOAD_MAX, e.payload_len)) {
                goto done;
            }

            /* The block re-states history this file may already hold:
             * wherever a replayed entry exists at this index it must be
             * IDENTICAL — divergence fails closed. */
            if (e.index < next_index) {
                const qihse_consensus_entry_t* ex = qcs_entry_at(cs, e.index);
                if (!ex || !qcs_entry_identical(ex, &e)) goto done;
            }

            pend_run = qcs_digest_entry(pend_run, &e);
            pend[pend_have++] = e;
            pend_term_prev = e.term;
            pend_gen_prev = e.journal_generation;
        } else if (strcmp(tok, "T") == 0) {
            char* s_from = strtok_r(NULL, " ", &save);
            if (!s_from || strtok_r(NULL, " ", &save)) goto done;
            uint64_t from = 0;
            if (!qcs_parse_u64(s_from, &from)) goto done;
            if (pend_active) {
                /* Commit the snapshot transaction: this T is the swap
                 * point the S block was waiting for. */
                if (from != pend_last_index + 1u) goto done;
                if (pend_have != pend_count) goto done;    /* incomplete */
                if (pend_run != pend_digest) goto done;    /* digest */
                if (pend_term_prev != pend_last_term) goto done;
                if (pend_gen_prev != pend_gen_hi) goto done;
                uint64_t tail_total = qcs_abs_last_index(cs);
                size_t keep = (tail_total > pend_last_index)
                                  ? (size_t)(tail_total - pend_last_index)
                                  : 0u;
                if (keep && cs->log_len > keep) {
                    memmove(cs->log, cs->log + (cs->log_len - keep),
                            keep * sizeof(*cs->log));
                }
                cs->log_len = keep;
                free(cs->snap.entries);
                memset(&cs->snap, 0, sizeof(cs->snap));
                cs->snap.entries = pend;
                cs->snap.cap = cs->snap.count = (size_t)pend_count;
                cs->snap.last_included_index = pend_last_index;
                cs->snap.last_included_term = pend_last_term;
                cs->snap.epoch = pend_epoch;
                cs->snap.journal_generation = pend_gen_hi;
                cs->snap.digest = pend_digest;
                pend = NULL;
                pend_active = false;
                /* The writer's log was continuous: entries beyond the new
                 * boundary that were already replayed (written before the
                 * S block) stay put, so the next expected L index is the
                 * surviving tail's successor, and the term/gen bookkeeping
                 * describes that same tail. */
                if (next_index < pend_last_index + 1u) {
                    next_index = pend_last_index + 1u;
                }
                if (cs->log_len) {
                    last_entry_term = cs->log[cs->log_len - 1u].term;
                    last_gen = cs->log[cs->log_len - 1u].journal_generation;
                } else {
                    last_entry_term = cs->snap.last_included_term;
                    last_gen = cs->snap.journal_generation;
                }
                /* commit never regresses and stays <= the (absolute) tail;
                 * a follower's installed snapshot may run ahead of the
                 * commit it had when it wrote the transaction. */
            } else {
                if (from < 1u || from > next_index) goto done; /* nothing to drop */
                if (from <= (uint64_t)cs->snap.count) goto done; /* snapshot */
                if (from < next_index) {
                    qcs_log_truncate(cs, (size_t)(from - 1u - cs->snap.count));
                    next_index = from;
                    if (cs->log_len > 0u) {
                        last_entry_term = cs->log[cs->log_len - 1u].term;
                        last_gen = cs->log[cs->log_len - 1u].journal_generation;
                    } else if (cs->snap.count > 0u) {
                        last_entry_term = cs->snap.last_included_term;
                        last_gen = cs->snap.journal_generation;
                    } else {
                        last_entry_term = 0;
                        last_gen = 0;
                    }
                }
            }
        } else if (strcmp(tok, "C") == 0) {
            if (pend_active) goto done; /* S transaction must finish first */
            char* s_commit = strtok_r(NULL, " ", &save);
            if (!s_commit || strtok_r(NULL, " ", &save)) goto done;
            uint64_t c = 0;
            if (!qcs_parse_u64(s_commit, &c)) goto done;
            if (c < commit) goto done;            /* commit regressed */
            if (c > next_index - 1u) goto done;   /* past the log tail */
            commit = c;
        } else {
            goto done; /* unknown record type */
        }
    }
    if (ferror(f)) goto done;
    if (!header_seen) goto done; /* empty / header-less file */
    if (pend_active) {
        /* Clean EOF with an open snapshot transaction: crash after the
         * snapshot write but before the truncation record.  Roll the
         * transaction back — the uncompacted state above still stands. */
        free(pend);
        pend = NULL;
    }

    cs->term = cur_term;
    cs->epoch = cur_epoch;
    cs->has_vote = has_vote;
    cs->voted_for = voted_for;
    cs->commit = commit;
    ok = true;

done:
    if (f) fclose(f);
    free(line);
    free(pend);
    /* Replay lands on the config of the LAST CONFIG ENTRY IN THE
     * RECONSTRUCTED LOG (append semantics — see header): by one-in-flight
     * that is the last committed config or the single pending transition.
     * A history that folds to an invalid config (empty / oversized /
     * malformed) fails the whole load closed. */
    if (ok && !qcs_recompute_membership(cs)) ok = false;
    if (!ok) {
        qcs_log_truncate(cs, 0u);
        free(cs->snap.entries);
        memset(&cs->snap, 0, sizeof(cs->snap));
    }
    return ok;
}

/* ── Log storage ─────────────────────────────────────────────────────────── */

static bool qcs_log_push(qihse_consensus_t* cs, const qihse_consensus_entry_t* e) {
    if (cs->log_len == cs->log_cap) {
        size_t ncap = cs->log_cap ? cs->log_cap * 2u : 16u;
        qihse_consensus_entry_t* nlog = realloc(cs->log, ncap * sizeof(*nlog));
        if (!nlog) return false;
        cs->log = nlog;
        cs->log_cap = ncap;
    }
    cs->log[cs->log_len++] = *e;
    return true;
}

static void qcs_log_truncate(qihse_consensus_t* cs, size_t keep) {
    if (keep >= cs->log_len) return;
    /* Keep the allocation; entry payloads carry no external resources. */
    cs->log_len = keep;
}

/* ── Internal state helpers ──────────────────────────────────────────────── */

static size_t qcs_majority_needed(const qihse_consensus_t* cs) {
    return cs->cfg.member_count / 2u + 1u;
}

static int qcs_member_index(const qihse_consensus_t* cs, const qihse_uuid_t* id) {
    for (size_t i = 0; i < cs->cfg.member_count; i++) {
        if (qihse_uuid_equal(&cs->cfg.members[i], id)) return (int)i;
    }
    return -1;
}

/* Swap the effective config in place, carrying per-member replication
 * state (next/match/last-ack) across the rename by UUID.  A brand-new
 * member starts at the log tail; a failure hint walks it back.  A node
 * whose own UUID left the config steps down CLEANLY: it may not lead (a
 * removed leader would wrongly count its own ack in the new config) and it
 * may never campaign — it keeps serving reads and its fencing floor. */
static uint64_t qcs_last_config_index(const qihse_consensus_t* cs);

static void qcs_set_membership(qihse_consensus_t* cs,
                               const qihse_uuid_t* members, size_t count) {
    uint64_t nnext[QIHSE_CONSENSUS_MAX_MEMBERS];
    uint64_t nmatch[QIHSE_CONSENSUS_MAX_MEMBERS];
    uint64_t nlast[QIHSE_CONSENSUS_MAX_MEMBERS];
    qihse_uuid_t old_members[QIHSE_CONSENSUS_MAX_MEMBERS];
    size_t old_count = cs->cfg.member_count;
    memcpy(old_members, cs->cfg.members, old_count * sizeof(*old_members));
    for (size_t i = 0; i < count; i++) {
        int old = -1;
        for (size_t j = 0; j < cs->cfg.member_count; j++) {
            if (qihse_uuid_equal(&cs->cfg.members[j], &members[i])) {
                old = (int)j;
                break;
            }
        }
        if (old >= 0) {
            nnext[i] = cs->next_index[old];
            nmatch[i] = cs->match_index[old];
            nlast[i] = cs->last_ack_ms[old];
        } else {
            nnext[i] = qcs_abs_last_index(cs) + 1u;
            nmatch[i] = 0u;
            nlast[i] = 0u;
        }
    }
    memcpy(cs->cfg.members, members, count * sizeof(*members));
    cs->cfg.member_count = count;
    memcpy(cs->next_index, nnext, count * sizeof(*nnext));
    memcpy(cs->match_index, nmatch, count * sizeof(*nmatch));
    memcpy(cs->last_ack_ms, nlast, count * sizeof(*nlast));

    /* Record the members this change dropped (lame ducks, above). */
    cs->rm_count = 0u;
    for (size_t j = 0; j < old_count; j++) {
        bool kept = false;
        for (size_t i = 0; i < count; i++) {
            if (qihse_uuid_equal(&old_members[j], &members[i])) {
                kept = true;
                break;
            }
        }
        if (!kept) {
            cs->rm_uuid[cs->rm_count] = old_members[j];
            /* Start the grace cursor AT the transition entry: the removed
             * node must vouch for exactly the entry that removed it (a
             * failure hint walks further back if it was behind). */
            cs->rm_next[cs->rm_count] =
                qcs_last_config_index(cs) ? qcs_last_config_index(cs) : 1u;
            cs->rm_committed[cs->rm_count] = false;
            cs->rm_count++;
        }
    }

    int self = -1;
    for (size_t i = 0; i < count; i++) {
        if (qihse_uuid_equal(&cs->cfg.members[i], &cs->cfg.self)) self = (int)i;
    }
    cs->self_index = self;
    if (self < 0) {
        cs->role = QIHSE_CONSENSUS_FOLLOWER;
        cs->has_leader = false;
        memset(&cs->leader, 0, sizeof(cs->leader));
        cs->votes_granted_mask = 0u;
    }
    cs->counters.membership_changes_applied++;
}

/* Re-fold the effective config from the log after any append or truncation
 * of config entries (and after a snapshot install, whose prefix may carry
 * them).  Returns false when the fold is invalid — possible only for a
 * hostile record file, whose load then fails closed. */
static bool qcs_recompute_membership(qihse_consensus_t* cs) {
    qihse_uuid_t members[QIHSE_CONSENSUS_MAX_MEMBERS];
    size_t count = 0;
    if (!qcs_fold_membership(cs, NULL, members, &count)) return false;
    bool same = (count == cs->cfg.member_count);
    for (size_t i = 0; same && i < count; i++) {
        same = qihse_uuid_equal(&cs->cfg.members[i], &members[i]);
    }
    if (same) return true;
    qcs_set_membership(cs, members, count);
    return true;
}

/* Index of the latest config entry in the log (snapshot included); 0 when
 * the log holds none.  A transition is in flight exactly while this index
 * sits above the commit index. */
static uint64_t qcs_last_config_index(const qihse_consensus_t* cs) {
    for (uint64_t i = qcs_abs_last_index(cs); i >= 1u; i--) {
        const qihse_consensus_entry_t* e = qcs_entry_at(cs, i);
        if (e && e->type != QIHSE_CONSENSUS_ENTRY_DATA) return i;
    }
    return 0u;
}

static uint64_t qcs_last_log_term(const qihse_consensus_t* cs) {
    if (cs->log_len) return cs->log[cs->log_len - 1u].term;
    if (cs->snap.count) return cs->snap.last_included_term;
    return 0u;
}

/* Deterministic per-(node, term) election timeout.  The member-index bucket
 * guarantees disjoint windows when spread >= member_count, so two members
 * never time out on the same tick and elections do not tie.  A node that
 * has been removed from the config never asks (it cannot campaign). */
static uint64_t qcs_election_timeout_ms(const qihse_consensus_t* cs,
                                        uint64_t term) {
    uint64_t spread = cs->cfg.election_timeout_spread_ms;
    uint64_t n = cs->cfg.member_count ? (uint64_t)cs->cfg.member_count : 1u;
    uint64_t self_index = cs->self_index >= 0 ? (uint64_t)cs->self_index : 0u;
    uint64_t bucket = self_index * spread / n;
    uint64_t jitter_range = spread / n ? spread / n : 1u;
    uint64_t jitter = qcs_splitmix64(cs->self_hash ^ (term * 0x9E3779B97F4A7C15ULL)) % jitter_range;
    return cs->cfg.election_timeout_base_ms + bucket + jitter;
}

static void qcs_send(qihse_consensus_t* cs, qihse_consensus_msg_t* m) {
    snprintf(m->group_id, sizeof(m->group_id), "%s", cs->cfg.group_id);
    m->from = cs->cfg.self;
    m->term = cs->term;
    m->fencing_epoch = cs->epoch;
    cs->counters.messages_sent++;
    if (cs->send_fn) cs->send_fn(cs->transport, m);
}

/* Persist-then-apply adoption of a newer term / higher fencing epoch.
 * Returns false when the record write fails; the caller must then ignore
 * the message that caused the transition (fail closed). */
static bool qcs_sync_term_epoch(qihse_consensus_t* cs, uint64_t term,
                                uint64_t epoch, bool reset_vote) {
    if (term < cs->term) return true; /* nothing to do (caller checked) */
    uint64_t new_term = (term > cs->term) ? term : cs->term;
    uint64_t new_epoch = cs->epoch;
    if (epoch > new_epoch) new_epoch = epoch;
    if (new_term > new_epoch) new_epoch = new_term;
    if (new_term == cs->term && new_epoch == cs->epoch) return true;

    bool old_has = cs->has_vote;
    qihse_uuid_t old_vote = cs->voted_for;
    uint64_t old_term = cs->term, old_epoch = cs->epoch;

    cs->term = new_term;
    cs->epoch = new_epoch;
    if (reset_vote || new_term > old_term) {
        cs->has_vote = false;
        memset(&cs->voted_for, 0, sizeof(cs->voted_for));
    }
    if (!qcs_persist_vote(cs)) {
        cs->term = old_term;
        cs->epoch = old_epoch;
        cs->has_vote = old_has;
        cs->voted_for = old_vote;
        return false;
    }
    if (new_term > old_term) {
        cs->role = QIHSE_CONSENSUS_FOLLOWER;
        cs->has_leader = false;
        cs->votes_granted_mask = 0u;
    }
    return true;
}

static void qcs_start_election(qihse_consensus_t* cs) {
    if (cs->self_index < 0) return; /* removed member: never campaigns */
    uint64_t new_term = cs->term + 1u;
    uint64_t new_epoch = cs->epoch + 1u;
    if (new_epoch < new_term) new_epoch = new_term;

    /* Durably record the new term AND the self-vote before campaigning: a
     * crash mid-candidacy must not leave a term in which this node could
     * vote twice. */
    if (!qcs_sync_term_epoch(cs, new_term, new_epoch, true)) {
        /* Could not durably persist the candidacy: retry after a full
         * timeout rather than spinning on a broken disk. */
        cs->last_leader_contact_ms = cs->now_ms;
        return;
    }
    if (!cs->has_vote || !qihse_uuid_equal(&cs->voted_for, &cs->cfg.self)) {
        bool old_has = cs->has_vote;
        qihse_uuid_t old_vote = cs->voted_for;
        cs->has_vote = true;
        cs->voted_for = cs->cfg.self;
        if (!qcs_persist_vote(cs)) {
            cs->has_vote = old_has;
            cs->voted_for = old_vote;
            cs->last_leader_contact_ms = cs->now_ms;
            return;
        }
    }
    cs->role = QIHSE_CONSENSUS_CANDIDATE;
    cs->has_leader = false;
    cs->votes_granted_mask = (uint32_t)1u << cs->self_index;
    cs->last_leader_contact_ms = cs->now_ms;
    cs->counters.election_timeouts++;

    qihse_consensus_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = QIHSE_CONSENSUS_MSG_REQUEST_VOTE;
    m.u.vote.last_log_index = qcs_abs_last_index(cs);
    m.u.vote.last_log_term = qcs_last_log_term(cs);
    for (size_t i = 0; i < cs->cfg.member_count; i++) {
        if ((int)i == cs->self_index) continue;
        m.to = cs->cfg.members[i];
        qcs_send(cs, &m);
    }
}

/* A follower whose next-needed index has been compacted away gets the
 * snapshot instead of an append: one message carrying the whole compacted
 * prefix, over the same injected transport. */
static void qcs_send_snapshot_to(qihse_consensus_t* cs, const qihse_uuid_t* to) {
    qihse_consensus_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = QIHSE_CONSENSUS_MSG_SNAPSHOT;
    m.to = *to;
    m.u.snapshot.last_included_index = cs->snap.last_included_index;
    m.u.snapshot.last_included_term = cs->snap.last_included_term;
    m.u.snapshot.fencing_epoch = cs->snap.epoch;
    m.u.snapshot.journal_generation = cs->snap.journal_generation;
    m.u.snapshot.digest = cs->snap.digest;
    m.u.snapshot.entry_count = cs->snap.count;
    for (size_t i = 0; i < cs->snap.count; i++) {
        m.u.snapshot.entries[i] = cs->snap.entries[i];
    }
    qcs_send(cs, &m);
}

/* Core replication send: entries from *next_io to `to`.  *next_io is read
 * and (for lame ducks) advanced in place.  A peer whose needed prefix was
 * compacted gets the snapshot instead. */
static void qcs_send_append_from(qihse_consensus_t* cs, const qihse_uuid_t* to,
                                 uint64_t* next_io) {
    uint64_t next = *next_io;
    if (next < 1u) next = 1u;

    /* The entry the log-matching check would anchor on has been compacted
     * on this leader: catch the peer up through the snapshot instead. */
    if (cs->snap.count > 0u && next - 1u < (uint64_t)cs->snap.count) {
        qcs_send_snapshot_to(cs, to);
        return;
    }

    qihse_consensus_msg_t m;
    memset(&m, 0, sizeof(m));
    m.type = QIHSE_CONSENSUS_MSG_APPEND;
    m.to = *to;

    m.u.append.prev_log_index = next - 1u;
    m.u.append.prev_log_term = qcs_term_at(cs, m.u.append.prev_log_index);
    m.u.append.leader_commit = cs->commit;

    uint64_t idx = next;
    while (m.u.append.entry_count < QIHSE_CONSENSUS_MAX_ENTRIES_PER_MSG &&
           idx <= qcs_abs_last_index(cs)) {
        m.u.append.entries[m.u.append.entry_count++] = *qcs_entry_at(cs, idx);
        idx++;
    }
    qcs_send(cs, &m);
}

static void qcs_send_append_to(qihse_consensus_t* cs, size_t peer) {
    qcs_send_append_from(cs, &cs->cfg.members[peer], &cs->next_index[peer]);
}

static void qcs_advance_commit(qihse_consensus_t* cs) {
    if (cs->role != QIHSE_CONSENSUS_LEADER) return;
    for (uint64_t n = qcs_abs_last_index(cs); n > cs->commit; n--) {
        if (qcs_term_at(cs, n) != cs->term) continue; /* current-term rule */
        size_t acks = 1u; /* self */
        for (size_t i = 0; i < cs->cfg.member_count; i++) {
            if ((int)i == cs->self_index) continue;
            if (cs->match_index[i] >= n) acks++;
        }
        if (acks >= qcs_majority_needed(cs)) {
            uint64_t old = cs->commit;
            cs->commit = n;
            if (!qcs_persist_commit(cs)) {
                cs->commit = old; /* fail closed: stay uncommitted */
                return;
            }
            return;
        }
    }
}

/* ── Leader-side log compaction ────────────────────────────────────────────
 *
 * Trigger: the retained active log (last index − snapshot index) exceeds
 * cfg.snapshot_threshold entries.  Target: every committed entry, capped so
 * one snapshot transaction carries at most SNAPSHOT_MAX entries.  The
 * durable order is S header, SE line per compacted entry, T swap record —
 * only after the T lands does the in-memory prefix disappear, so a crash at
 * any earlier point replays to the uncompacted state. */
static void qcs_try_compact(qihse_consensus_t* cs) {
    if (cs->cfg.snapshot_threshold == 0u) return; /* disabled */
    if (cs->role != QIHSE_CONSENSUS_LEADER) return;

    uint64_t base = (uint64_t)cs->snap.count;
    if (cs->commit < base) return; /* invariant; nothing committed to add */
    if (cs->commit == base) return;
    uint64_t tail = qcs_abs_last_index(cs);
    if (tail - base <= cs->cfg.snapshot_threshold) return; /* under trigger */

    uint64_t target = cs->commit;
    if (target - base > QIHSE_CONSENSUS_SNAPSHOT_MAX_ENTRIES) {
        target = base + QIHSE_CONSENSUS_SNAPSHOT_MAX_ENTRIES;
    }
    size_t new_count = (size_t)target;

    /* Build the new snapshot buffers FIRST; nothing observable changes
     * until the whole transaction is durable. */
    qihse_consensus_entry_t* entries = malloc(new_count * sizeof(*entries));
    if (!entries) return;
    if (base) {
        memcpy(entries, cs->snap.entries, (size_t)base * sizeof(*entries));
    }
    /* Active log position 0 is absolute index base + 1. */
    memcpy(entries + base, cs->log, (new_count - (size_t)base) * sizeof(*entries));
    uint64_t digest = qcs_snapshot_digest(entries, new_count);
    uint64_t last_term = entries[new_count - 1u].term;
    uint64_t gen_hi = entries[new_count - 1u].journal_generation;

    if (!qcs_persist_snapshot_begin(cs, target, last_term, cs->epoch,
                                    gen_hi, digest, new_count)) {
        free(entries);
        cs->rec_quarantined = true; /* trailing partial block must stay last */
        return; /* fail closed; a trailing partial block rolls back */
    }
    for (size_t i = 0; i < new_count; i++) {
        if (!qcs_persist_snapshot_entry(cs, &entries[i])) {
            free(entries);
            cs->rec_quarantined = true;
            return;
        }
    }
    if (!qcs_persist_truncate(cs, target + 1u)) {
        free(entries);
        cs->rec_quarantined = true;
        return;
    }

    /* Transaction durable: swap it in and drop the compacted prefix. */
    free(cs->snap.entries);
    cs->snap.entries = entries;
    cs->snap.cap = cs->snap.count = new_count;
    cs->snap.last_included_index = target;
    cs->snap.last_included_term = last_term;
    cs->snap.epoch = cs->epoch;
    cs->snap.journal_generation = gen_hi;
    cs->snap.digest = digest;

    size_t drop = new_count - (size_t)base;
    cs->log_len -= drop;
    if (cs->log_len) {
        memmove(cs->log, cs->log + drop, cs->log_len * sizeof(*cs->log));
    }
    /* Absolute indices did not move: match/next arrays stay valid; peers
     * whose next_index now falls at or below the boundary get the
     * snapshot on the next replication sweep. */
    cs->counters.snapshots_created++;
}

/* ── Open / close ────────────────────────────────────────────────────────── */

qihse_consensus_t* qihse_consensus_open(const qihse_consensus_config_t* cfg,
                                        void* transport,
                                        qihse_consensus_send_fn send) {
    if (!cfg) return NULL;
    if (!qcs_group_id_valid(cfg->group_id)) return NULL;
    if (!qcs_record_path_valid(cfg->record_path)) return NULL;
    if (cfg->member_count == 0u ||
        cfg->member_count > QIHSE_CONSENSUS_MAX_MEMBERS) return NULL;
    if (qihse_uuid_is_nil(&cfg->self)) return NULL;

    qihse_consensus_t* cs = calloc(1u, sizeof(*cs));
    if (!cs) return NULL;

    cs->cfg = *cfg;
    cs->cfg.election_timeout_base_ms =
        cfg->election_timeout_base_ms ? cfg->election_timeout_base_ms
                                      : QCS_DEFAULT_ELECTION_BASE_MS;
    cs->cfg.election_timeout_spread_ms =
        cfg->election_timeout_spread_ms ? cfg->election_timeout_spread_ms
                                        : QCS_DEFAULT_ELECTION_SPREAD_MS;
    cs->cfg.heartbeat_interval_ms =
        cfg->heartbeat_interval_ms ? cfg->heartbeat_interval_ms
                                   : QCS_DEFAULT_HEARTBEAT_MS;
    if (cs->cfg.election_timeout_spread_ms < (uint64_t)cs->cfg.member_count) {
        /* Disjoint per-member buckets are what keep elections from tying. */
        free(cs);
        return NULL;
    }
    if (cs->cfg.heartbeat_interval_ms >= cs->cfg.election_timeout_base_ms) {
        free(cs);
        return NULL;
    }

    cs->transport = transport;
    cs->send_fn = send;
    cs->role = QIHSE_CONSENSUS_FOLLOWER;
    cs->self_index = -1;
    for (size_t i = 0; i < cs->cfg.member_count; i++) {
        for (size_t j = i + 1u; j < cs->cfg.member_count; j++) {
            if (qihse_uuid_equal(&cs->cfg.members[i], &cs->cfg.members[j])) {
                free(cs);
                return NULL;
            }
        }
        if (qihse_uuid_equal(&cs->cfg.members[i], &cs->cfg.self)) {
            cs->self_index = (int)i;
        }
    }
    if (cs->self_index < 0) {
        free(cs);
        return NULL;
    }

    /* Baseline for the membership fold: the static member list at open.
     * Config entries replayed from the record file (and any that follow)
     * transform THIS list; editing it behind an existing record file's
     * back is undetected (documented residual limit). */
    cs->base_count = cs->cfg.member_count;
    memcpy(cs->base_members, cs->cfg.members,
           cs->base_count * sizeof(qihse_uuid_t));

    cs->self_hash = qcs_fnv1a((const char*)cs->cfg.self.bytes, QIHSE_UUID_BYTES);

    cs->rec_buf = malloc(QCS_RECORD_LINE_CAP + 32u);
    if (!cs->rec_buf) {
        free(cs);
        return NULL;
    }

    bool created = false;
    if (!qcs_load_records(cs, cs->cfg.record_path, &created)) {
        free(cs->rec_buf);
        free(cs->log);
        free(cs);
        return NULL; /* corrupt / foreign / unreadable: fail closed */
    }

    cs->rec = fopen(cs->cfg.record_path, created ? "w" : "a");
    if (!cs->rec) {
        free(cs->rec_buf);
        free(cs->log);
        free(cs);
        return NULL;
    }
    if (created) {
        int n = snprintf(cs->rec_buf, QCS_RECORD_LINE_CAP, "%s %u %s",
                         QCS_RECORD_MAGIC, QCS_RECORD_VERSION, cs->cfg.group_id);
        if (n < 0 || (size_t)n >= QCS_RECORD_LINE_CAP ||
            !qcs_record_append(cs, (size_t)n)) {
            qihse_consensus_close(cs);
            return NULL;
        }
    }

    /* A single-member group is its own majority: lead immediately after a
     * clean tick rather than sitting through a timeout. */
    for (size_t i = 0; i < cs->cfg.member_count; i++) {
        cs->next_index[i] = qcs_abs_last_index(cs) + 1u;
        cs->match_index[i] = 0u;
        cs->last_ack_ms[i] = 0u;
    }
    return cs;
}

void qihse_consensus_close(qihse_consensus_t* cs) {
    if (!cs) return;
    if (cs->rec) fclose(cs->rec);
    free(cs->rec_buf);
    free(cs->log);
    free(cs->snap.entries);
    free(cs);
}

/* ── Tick ────────────────────────────────────────────────────────────────── */

void qihse_consensus_tick(qihse_consensus_t* cs, uint64_t now_ms) {
    if (!cs) return;
    cs->now_ms = now_ms;

    if (cs->role == QIHSE_CONSENSUS_LEADER) {
        qcs_try_compact(cs); /* tick-driven, deterministic, threshold-gated */
        if (cs->now_ms - cs->last_heartbeat_ms >= cs->cfg.heartbeat_interval_ms) {
            cs->last_heartbeat_ms = cs->now_ms;
            for (size_t i = 0; i < cs->cfg.member_count; i++) {
                if ((int)i == cs->self_index) continue;
                qcs_send_append_to(cs, i);
            }
            /* Grace catch-up: the leader keeps OFFERING the transition
             * entry to the members that change dropped, until their
             * cursor vouches for it AND one offer has gone out after the
             * leader's own commit covered it (that offer carries the
             * leader_commit that lets the removed node settle).  Their
             * acknowledgements never count (they are not voters); this
             * only lets a reachable removed node learn of its removal and
             * step down cleanly.  A permanently partitioned removed node
             * is simply re-offered alongside normal heartbeats. */
            for (size_t i = 0; i < cs->rm_count; i++) {
                uint64_t lci = qcs_last_config_index(cs);
                if (!lci) break; /* the transition was reverted away */
                if (cs->rm_next[i] - 1u < lci || !cs->rm_committed[i]) {
                    qcs_send_append_from(cs, &cs->rm_uuid[i], &cs->rm_next[i]);
                    if (cs->commit >= lci) cs->rm_committed[i] = true;
                }
            }
        }
        return;
    }
    if (cs->self_index < 0) return; /* removed member: no campaign, no leader */
    if (cs->now_ms - cs->last_leader_contact_ms >=
        qcs_election_timeout_ms(cs, cs->term)) {
        qcs_start_election(cs);
    }
}

/* ── Message handling ────────────────────────────────────────────────────── */

static void qcs_handle_request_vote(qihse_consensus_t* cs,
                                    const qihse_consensus_msg_t* msg) {
    int from = qcs_member_index(cs, &msg->from);
    if (from < 0) { cs->counters.messages_ignored++; return; }

    bool up_to_date =
        msg->u.vote.last_log_term > qcs_last_log_term(cs) ||
        (msg->u.vote.last_log_term == qcs_last_log_term(cs) &&
         msg->u.vote.last_log_index >= qcs_abs_last_index(cs));

    if (cs->has_vote && !qihse_uuid_equal(&cs->voted_for, &msg->from)) {
        up_to_date = false; /* already voted elsewhere this term */
    }

    qihse_consensus_msg_t r;
    memset(&r, 0, sizeof(r));
    r.type = QIHSE_CONSENSUS_MSG_VOTE_REPLY;
    r.to = msg->from;
    r.u.vote_reply.granted = false;

    if (up_to_date) {
        if (!(cs->has_vote && qihse_uuid_equal(&cs->voted_for, &msg->from))) {
            bool old_has = cs->has_vote;
            qihse_uuid_t old_vote = cs->voted_for;
            cs->has_vote = true;
            cs->voted_for = msg->from;
            if (!qcs_persist_vote(cs)) {
                cs->has_vote = old_has;
                cs->voted_for = old_vote;
                qcs_send(cs, &r); /* deny: the vote is not durable */
                return;
            }
        }
        /* Granting a vote resets the election timer. */
        cs->role = QIHSE_CONSENSUS_FOLLOWER;
        cs->last_leader_contact_ms = cs->now_ms;
        r.u.vote_reply.granted = true;
    }
    qcs_send(cs, &r);
}

static void qcs_handle_vote_reply(qihse_consensus_t* cs,
                                  const qihse_consensus_msg_t* msg) {
    if (cs->role != QIHSE_CONSENSUS_CANDIDATE) return;
    if (!msg->u.vote_reply.granted) return;

    int from = qcs_member_index(cs, &msg->from);
    if (from < 0) { cs->counters.messages_ignored++; return; }
    cs->votes_granted_mask |= (uint32_t)1u << from;

    uint32_t votes = 0;
    for (uint32_t m = cs->votes_granted_mask; m; m >>= 1) votes += (m & 1u);
    if ((size_t)votes >= qcs_majority_needed(cs)) {
        cs->role = QIHSE_CONSENSUS_LEADER;
        cs->leader = cs->cfg.self;
        cs->has_leader = true;
        cs->counters.elections_won++;
        for (size_t i = 0; i < cs->cfg.member_count; i++) {
            cs->next_index[i] = qcs_abs_last_index(cs) + 1u;
            cs->match_index[i] = 0u;
        }
        cs->match_index[cs->self_index] = qcs_abs_last_index(cs);
        cs->last_heartbeat_ms = cs->now_ms - cs->cfg.heartbeat_interval_ms;
        for (size_t i = 0; i < cs->cfg.member_count; i++) {
            if ((int)i == cs->self_index) continue;
            qcs_send_append_to(cs, i);
        }
    }
}

static void qcs_reply_append(qihse_consensus_t* cs, const qihse_uuid_t* to,
                             bool success, uint64_t match) {
    qihse_consensus_msg_t r;
    memset(&r, 0, sizeof(r));
    r.type = QIHSE_CONSENSUS_MSG_APPEND_REPLY;
    r.to = *to;
    r.u.append_reply.success = success;
    r.u.append_reply.match_index = match;
    qcs_send(cs, &r);
}

static void qcs_send_reply_snapshot(qihse_consensus_t* cs,
                                    qihse_consensus_msg_t* r,
                                    bool success, uint64_t match) {
    r->u.snapshot_reply.success = success;
    r->u.snapshot_reply.match_index = match;
    qcs_send(cs, r);
}

static bool qcs_entry_identical(const qihse_consensus_entry_t* a,
                                const qihse_consensus_entry_t* b) {
    if (a->type != b->type) return false;
    if (a->term != b->term || a->journal_generation != b->journal_generation) {
        return false;
    }
    if (a->hlc.physical_ms != b->hlc.physical_ms ||
        a->hlc.logical != b->hlc.logical) return false;
    if (a->classif != b->classif || a->sci != b->sci) return false;
    if (a->payload_len != b->payload_len) return false;
    return memcmp(a->payload, b->payload, a->payload_len) == 0;
}

static void qcs_handle_append(qihse_consensus_t* cs,
                              const qihse_consensus_msg_t* msg) {
    int from = qcs_member_index(cs, &msg->from);
    if (from < 0) { cs->counters.messages_ignored++; return; }
    if (msg->u.append.entry_count > QIHSE_CONSENSUS_MAX_ENTRIES_PER_MSG) {
        cs->counters.messages_ignored++; /* hostile batch size */
        return;
    }

    const uint64_t prev = msg->u.append.prev_log_index;
    if (prev == 0u && msg->u.append.prev_log_term != 0u) {
        cs->counters.messages_ignored++; /* inconsistent prefix claim */
        return;
    }

    cs->role = QIHSE_CONSENSUS_FOLLOWER; /* same-term candidate steps down */
    cs->leader = msg->from;
    cs->has_leader = true;
    cs->last_leader_contact_ms = cs->now_ms;

    /* Log matching: the predecessor entry must agree exactly, whether it
     * lives in the snapshot or at the head of the active log. */
    uint64_t abs_last = qcs_abs_last_index(cs);
    if (prev > abs_last) {
        qcs_reply_append(cs, &msg->from, false, abs_last);
        return;
    }
    if (prev >= 1u && qcs_term_at(cs, prev) != msg->u.append.prev_log_term) {
        qcs_reply_append(cs, &msg->from, false, prev - 1u);
        return;
    }

    uint64_t idx = prev;
    bool config_touched = false; /* a config entry appended or a suffix dropped */
    for (size_t i = 0; i < msg->u.append.entry_count; i++) {
        const qihse_consensus_entry_t* e = &msg->u.append.entries[i];
        if (e->payload_len > QIHSE_CONSENSUS_PAYLOAD_MAX) {
            qcs_reply_append(cs, &msg->from, false, idx);
            return;
        }
        idx++;
        if (idx <= abs_last) {
            const qihse_consensus_entry_t* have = qcs_entry_at(cs, idx);
            if (have->term == e->term) {
                if (!qcs_entry_identical(have, e)) {
                    /* Same (index, term) must be the same entry; anything
                     * else is a hostile or buggy leader. */
                    qcs_reply_append(cs, &msg->from, false, idx - 1u);
                    return;
                }
                continue; /* already replicated here */
            }
            if (idx <= (uint64_t)cs->snap.count) {
                /* The snapshot is committed state: a leader appending a
                 * different entry over it is hostile, never truncated. */
                qcs_reply_append(cs, &msg->from, false, idx - 1u);
                return;
            }
            /* Conflicting suffix: durably drop it, then append the
             * leader's entry in its place. */
            if (!qcs_persist_truncate(cs, idx)) {
                qcs_reply_append(cs, &msg->from, false, idx - 1u);
                return;
            }
            qcs_log_truncate(cs, (size_t)(idx - 1u - cs->snap.count));
            cs->counters.log_conflicts++;
            config_touched = true; /* the dropped suffix may hold config */
            abs_last = qcs_abs_last_index(cs);
        }
        if (e->index != idx) {
            /* Entries must be addressed at the position they occupy. */
            qcs_reply_append(cs, &msg->from, false, idx - 1u);
            return;
        }
        if (e->type != QIHSE_CONSENSUS_ENTRY_DATA) {
            /* A config entry carries exactly one member UUID (validated
             * structurally by the fold) and must keep the folded member
             * set legal; both are checked BEFORE anything is durable. */
            qihse_uuid_t folded[QIHSE_CONSENSUS_MAX_MEMBERS];
            size_t fcount = 0;
            if (!qcs_fold_membership(cs, e, folded, &fcount)) {
                qcs_reply_append(cs, &msg->from, false, idx - 1u);
                return;
            }
            config_touched = true;
        }
        /* Persist with the entry-kind encoder: a config entry must land
         * as an LC record or its type would be lost to replay. */
        bool persisted =
            (e->type == QIHSE_CONSENSUS_ENTRY_DATA)
                ? qcs_persist_entry(cs, e)
                : qcs_persist_config_entry(cs, e);
        if (!persisted) {
            qcs_reply_append(cs, &msg->from, false, idx - 1u);
            return;
        }
        if (!qcs_log_push(cs, e)) {
            qcs_reply_append(cs, &msg->from, false, idx - 1u);
            return;
        }
        abs_last = qcs_abs_last_index(cs);
    }

    if (config_touched) {
        /* Re-derive the effective config from the log.  Unreachable-false:
        * every config entry was dry-run-validated as it was appended and
        * truncation only removes validated entries. */
        (void)qcs_recompute_membership(cs);
    }

    uint64_t new_commit = msg->u.append.leader_commit;
    if (new_commit > qcs_abs_last_index(cs)) new_commit = qcs_abs_last_index(cs);
    if (new_commit > cs->commit) {
        uint64_t old = cs->commit;
        cs->commit = new_commit;
        if (!qcs_persist_commit(cs)) {
            cs->commit = old; /* fail closed: the entry stays uncommitted */
            qcs_reply_append(cs, &msg->from, false, qcs_abs_last_index(cs));
            return;
        }
    }
    qcs_reply_append(cs, &msg->from, true, prev + msg->u.append.entry_count);
}

/* Slot of a lame-duck (removed-pending) member UUID, or -1. */
static int qcs_removed_slot(const qihse_consensus_t* cs, const qihse_uuid_t* id) {
    for (size_t i = 0; i < cs->rm_count; i++) {
        if (qihse_uuid_equal(&cs->rm_uuid[i], id)) return (int)i;
    }
    return -1;
}

static void qcs_handle_append_reply(qihse_consensus_t* cs,
                                    const qihse_consensus_msg_t* msg,
                                    bool success, uint64_t match_index) {
    if (cs->role != QIHSE_CONSENSUS_LEADER) return;
    int from = qcs_member_index(cs, &msg->from);
    if (from < 0) {
        /* A lame duck answering its grace catch-up: advance only its
         * catch-up cursor.  It is not a voter — no match bookkeeping, no
         * commit effect, never availability. */
        int rm = qcs_removed_slot(cs, &msg->from);
        if (rm < 0) { cs->counters.messages_ignored++; return; }
        if (success) {
            if (match_index + 1u > cs->rm_next[rm]) cs->rm_next[rm] = match_index + 1u;
        } else {
            uint64_t hinted = match_index + 1u;
            if (hinted < cs->rm_next[rm]) cs->rm_next[rm] = hinted;
        }
        return;
    }

    if (success) {
        if (match_index > cs->match_index[from]) {
            cs->match_index[from] = match_index;
        }
        if (cs->next_index[from] <= cs->match_index[from]) {
            cs->next_index[from] = cs->match_index[from] + 1u;
        }
        cs->last_ack_ms[from] = cs->now_ms;
        qcs_advance_commit(cs);
    } else {
        uint64_t hinted = match_index + 1u;
        if (hinted < cs->next_index[from]) cs->next_index[from] = hinted;
        else if (cs->next_index[from] > 1u) cs->next_index[from]--;
        /* The next heartbeat tick resends from the backed-up index — or
         * hands the peer the snapshot once that index is compacted. */
    }
}

/* ── Follower-side snapshot install ────────────────────────────────────────
 *
 * Every check runs BEFORE any state changes; the install itself allocates
 * and verifies first and swaps pointers last, so there is no intermediate
 * state in which the old log is half-replaced.  Digest mismatch, internal
 * inconsistency, or a snapshot we cannot use is refused, journaled in
 * snapshot_rejections, and leaves the follower exactly as it was (a stale
 * carrying epoch was already fenced off with stale_epoch_rejections before
 * this function runs). */
static void qcs_handle_snapshot(qihse_consensus_t* cs,
                                const qihse_consensus_msg_t* msg) {
    int from = qcs_member_index(cs, &msg->from);
    if (from < 0) { cs->counters.messages_ignored++; return; }

    const uint64_t last = msg->u.snapshot.last_included_index;
    const size_t count = msg->u.snapshot.entry_count;

    qihse_consensus_msg_t r;
    memset(&r, 0, sizeof(r));
    r.type = QIHSE_CONSENSUS_MSG_SNAPSHOT_REPLY;
    r.to = msg->from;

    /* Structural validation: contiguous 1..last, bounded, internally
     * consistent, addressed where it claims, and from the epoch it says. */
    if (count != last || last == 0u ||
        count > QIHSE_CONSENSUS_SNAPSHOT_MAX_ENTRIES) {
        cs->counters.snapshot_rejections++;
        qcs_send_reply_snapshot(cs, &r, false, qcs_abs_last_index(cs));
        return;
    }
    uint64_t prev_term = 0, prev_gen = 0;
    for (size_t i = 0; i < count; i++) {
        const qihse_consensus_entry_t* e = &msg->u.snapshot.entries[i];
        if (e->index != (uint64_t)i + 1u) {
            cs->counters.snapshot_rejections++;
            qcs_send_reply_snapshot(cs, &r, false, qcs_abs_last_index(cs));
            return;
        }
        if (e->term > msg->term || e->term < prev_term ||
            e->payload_len > QIHSE_CONSENSUS_PAYLOAD_MAX ||
            !qcs_config_entry_valid(e) ||
            (i > 0u && e->journal_generation <= prev_gen)) {
            cs->counters.snapshot_rejections++;
            qcs_send_reply_snapshot(cs, &r, false, qcs_abs_last_index(cs));
            return;
        }
        prev_term = e->term;
        prev_gen = e->journal_generation;
    }
    if (msg->u.snapshot.last_included_term != prev_term ||
        msg->u.snapshot.journal_generation != prev_gen ||
        msg->u.snapshot.fencing_epoch < prev_term ||
        msg->u.snapshot.fencing_epoch > msg->fencing_epoch) {
        cs->counters.snapshot_rejections++;
        qcs_send_reply_snapshot(cs, &r, false, qcs_abs_last_index(cs));
        return;
    }
    /* Recompute the digest — never trust the wire's claim. */
    if (qcs_snapshot_digest(msg->u.snapshot.entries, count) !=
        msg->u.snapshot.digest) {
        cs->counters.snapshot_rejections++;
        qcs_send_reply_snapshot(cs, &r, false, qcs_abs_last_index(cs));
        return;
    }
    /* Pre-check the membership fold (base + this snapshot's config
     * entries; the install discards the whole log): a hostile snapshot
     * with a self-consistent digest must still fail closed BEFORE any
     * state changes if its config sequence is illegal. */
    {
        qihse_uuid_t folded[QIHSE_CONSENSUS_MAX_MEMBERS];
        size_t fcount = cs->base_count;
        memcpy(folded, cs->base_members, fcount * sizeof(*folded));
        bool over = false;
        for (size_t i = 0; i < count && !over; i++) {
            const qihse_consensus_entry_t* e = &msg->u.snapshot.entries[i];
            if (e->type == QIHSE_CONSENSUS_ENTRY_DATA) continue;
            qcs_fold_apply(folded, &fcount, e, &over);
        }
        if (over || fcount < 1u) {
            cs->counters.snapshot_rejections++;
            qcs_send_reply_snapshot(cs, &r, false, qcs_abs_last_index(cs));
            return;
        }
    }
    /* Nothing to learn: we already hold it committed, or an equal/newer
     * snapshot.  Not an anomaly — the leader re-sent; answer with our own
     * match so replication resumes past it. */
    if (last <= cs->commit || last <= (uint64_t)cs->snap.count) {
        qcs_send_reply_snapshot(cs, &r, false, qcs_abs_last_index(cs));
        return;
    }

    /* Leader traffic: adopt the sender as leader before installing. */
    cs->role = QIHSE_CONSENSUS_FOLLOWER;
    cs->leader = msg->from;
    cs->has_leader = true;
    cs->last_leader_contact_ms = cs->now_ms;

    /* Durable first: write the same S/SE/T transaction the leader would
     * have written, so the install survives our own restart. */
    if (!qcs_persist_snapshot_begin(cs, last, msg->u.snapshot.last_included_term,
                                    msg->u.snapshot.fencing_epoch,
                                    msg->u.snapshot.journal_generation,
                                    msg->u.snapshot.digest, count)) {
        cs->counters.snapshot_rejections++;
        cs->rec_quarantined = true; /* unterminated S block must stay last */
        qcs_send_reply_snapshot(cs, &r, false, qcs_abs_last_index(cs));
        return;
    }
    for (size_t i = 0; i < count; i++) {
        if (!qcs_persist_snapshot_entry(cs, &msg->u.snapshot.entries[i])) {
            cs->counters.snapshot_rejections++;
            cs->rec_quarantined = true;
            qcs_send_reply_snapshot(cs, &r, false, qcs_abs_last_index(cs));
            return;
        }
    }
    if (!qcs_persist_truncate(cs, last + 1u)) {
        cs->counters.snapshot_rejections++;
        cs->rec_quarantined = true;
        qcs_send_reply_snapshot(cs, &r, false, qcs_abs_last_index(cs));
        return;
    }

    /* Transaction durable: install atomically.  New buffers are ready;
     * the swap below is the only state mutation. */
    qihse_consensus_entry_t* entries = malloc(count * sizeof(*entries));
    if (!entries) {
        cs->counters.snapshot_rejections++;
        qcs_send_reply_snapshot(cs, &r, false, qcs_abs_last_index(cs));
        return;
    }
    memcpy(entries, msg->u.snapshot.entries, count * sizeof(*entries));

    free(cs->snap.entries);
    memset(&cs->snap, 0, sizeof(cs->snap));
    cs->snap.entries = entries;
    cs->snap.cap = cs->snap.count = count;
    cs->snap.last_included_index = last;
    cs->snap.last_included_term = msg->u.snapshot.last_included_term;
    cs->snap.epoch = msg->u.snapshot.fencing_epoch;
    cs->snap.journal_generation = msg->u.snapshot.journal_generation;
    cs->snap.digest = msg->u.snapshot.digest;
    cs->log_len = 0u; /* the old log is discarded whole, never half */
    cs->counters.snapshots_installed++;
    /* The installed prefix may carry config entries: re-derive the
     * effective config from the new log state (digest-validated entries,
     * so the fold cannot fail; belt-and-braces below). */
    (void)qcs_recompute_membership(cs);

    qcs_send_reply_snapshot(cs, &r, true, last);
}

void qihse_consensus_receive(qihse_consensus_t* cs,
                             const qihse_consensus_msg_t* msg) {
    if (!cs || !msg) return;
    cs->counters.messages_received++;

    if (strcmp(msg->group_id, cs->cfg.group_id) != 0) {
        cs->counters.messages_ignored++; /* not this group's traffic */
        return;
    }
    {
        int from_member = qcs_member_index(cs, &msg->from);
        if (from_member == cs->self_index) {
            cs->counters.messages_ignored++; /* spoofed self */
            return;
        }
        /* Grace catch-up: a removed-pending member's traffic reaches its
         * handler, which still membership-checks everything it acts on
         * (votes, appends).  Only the catch-up replies are ever used. */
        if (from_member < 0 && qcs_removed_slot(cs, &msg->from) < 0) {
            cs->counters.messages_ignored++; /* non-member */
            return;
        }
    }
    if (!qihse_uuid_equal(&msg->to, &cs->cfg.self)) {
        cs->counters.messages_ignored++; /* misrouted */
        return;
    }

    /* Fencing first (plan §7.3, acceptance criterion 4): traffic below the
     * highest epoch durably observed is dropped before any term or log
     * logic can act on it. */
    if (msg->fencing_epoch < cs->epoch) {
        cs->counters.stale_epoch_rejections++;
        return;
    }

    if (msg->term < cs->term) {
    /* Stale-term traffic: reject and answer with the current term so a
     * lagging leader can step down. */
    cs->counters.term_rejections++;
    if (msg->type == QIHSE_CONSENSUS_MSG_REQUEST_VOTE) {
        qihse_consensus_msg_t r;
        memset(&r, 0, sizeof(r));
        r.type = QIHSE_CONSENSUS_MSG_VOTE_REPLY;
        r.to = msg->from;
        r.u.vote_reply.granted = false;
        qcs_send(cs, &r);
    } else if (msg->type == QIHSE_CONSENSUS_MSG_APPEND) {
        qcs_reply_append(cs, &msg->from, false, 0u);
    }
    /* A stale-term snapshot carries nothing worth answering: drop it. */
    return;
    }

    /* Adopt a higher term / floor a higher epoch, durably, before acting. */
    if (msg->term > cs->term || msg->fencing_epoch > cs->epoch) {
        if (!qcs_sync_term_epoch(cs, msg->term, msg->fencing_epoch, false)) {
            return; /* could not persist: ignore, fail closed */
        }
    }

    switch (msg->type) {
        case QIHSE_CONSENSUS_MSG_REQUEST_VOTE:
            qcs_handle_request_vote(cs, msg);
            break;
        case QIHSE_CONSENSUS_MSG_VOTE_REPLY:
            qcs_handle_vote_reply(cs, msg);
            break;
        case QIHSE_CONSENSUS_MSG_APPEND:
            qcs_handle_append(cs, msg);
            break;
        case QIHSE_CONSENSUS_MSG_APPEND_REPLY:
            qcs_handle_append_reply(cs, msg, msg->u.append_reply.success,
                                    msg->u.append_reply.match_index);
            break;
        case QIHSE_CONSENSUS_MSG_SNAPSHOT:
            qcs_handle_snapshot(cs, msg);
            break;
        case QIHSE_CONSENSUS_MSG_SNAPSHOT_REPLY:
            qcs_handle_append_reply(cs, msg, msg->u.snapshot_reply.success,
                                    msg->u.snapshot_reply.match_index);
            break;
        default:
            cs->counters.messages_ignored++;
            break;
    }
}

/* ── Client paths ────────────────────────────────────────────────────────── */

bool qihse_consensus_propose(qihse_consensus_t* cs, const qihse_user_t* user,
                             uint64_t journal_generation, qihse_hlc_t hlc,
                             uint16_t classif, uint16_t sci,
                             const void* payload, size_t payload_len) {
    if (!cs) return false;
    if (cs->role != QIHSE_CONSENSUS_LEADER) return false;
    /* An entry must carry a payload: the record encoder writes the payload as
     * a hex token, and a zero-length token is not a form the replay decoder
     * accepts — an accepted empty proposal would be unreplayable. */
    if (payload_len == 0u || payload_len > QIHSE_CONSENSUS_PAYLOAD_MAX) return false;
    if (!payload) return false;
    if (qcs_abs_last_index(cs) > 0u &&
        journal_generation <= qcs_last_gen(cs)) {
        return false; /* journal generations advance strictly along the log */
    }

    /* The write boundary is the read boundary: the proposing principal must
     * cover the classification it is writing.  NULL is not a bypass. */
    if (!qihse_auth_can_access(user, classif, sci)) {
        cs->counters.auth_failures++;
        return false;
    }

    qihse_consensus_entry_t e;
    memset(&e, 0, sizeof(e));
    e.index = qcs_abs_last_index(cs) + 1u;
    e.term = cs->term;
    e.journal_generation = journal_generation;
    e.hlc = hlc;
    e.classif = classif;
    e.sci = sci;
    if (payload_len > 0u) memcpy(e.payload, payload, payload_len);
    e.payload_len = payload_len;

    if (!qcs_persist_entry(cs, &e)) return false; /* durable first */
    if (!qcs_log_push(cs, &e)) return false;
    cs->match_index[cs->self_index] = qcs_abs_last_index(cs);
    /* A single-member group is its own majority and commits immediately;
     * larger groups still need peer acknowledgements here. */
    qcs_advance_commit(cs);
    return true;
}

bool qihse_consensus_propose_membership(qihse_consensus_t* cs,
                                        const qihse_user_t* user,
                                        qihse_consensus_membership_op_t op,
                                        const qihse_uuid_t* member) {
    if (!cs) return false;
    if (cs->role != QIHSE_CONSENSUS_LEADER) {
        cs->counters.membership_proposals_refused++;
        return false;
    }
    /* A membership change reshapes the group that guards classified
     * replication: an identified OPERATOR principal is mandatory.  NULL is
     * refused outright — never a bypass (AGENTS.md invariants 1 and 2). */
    if (!user || qihse_user_get_role(user) != QIHSE_ROLE_OPERATOR ||
        !qihse_auth_can_access(user, 0u, 0u)) {
        cs->counters.membership_proposals_refused++;
        return false;
    }
    if (!member || qihse_uuid_is_nil(member) ||
        (op != QIHSE_CONSENSUS_MEMBER_ADD &&
         op != QIHSE_CONSENSUS_MEMBER_REMOVE)) {
        cs->counters.membership_proposals_refused++;
        return false;
    }
    /* ONE transition in flight: the latest config entry must be committed
     * (or gone).  A second proposal is refused, not queued. */
    if (qcs_last_config_index(cs) > cs->commit) {
        cs->counters.membership_proposals_refused++;
        return false;
    }

    bool present = qcs_member_index(cs, member) >= 0;
    if (op == QIHSE_CONSENSUS_MEMBER_ADD) {
        if (present ||
            cs->cfg.member_count >= QIHSE_CONSENSUS_MAX_MEMBERS ||
            cs->cfg.member_count + 1u > cs->cfg.election_timeout_spread_ms) {
            /* The spread guard keeps per-member election-timeout buckets
             * disjoint (see qcs_election_timeout_ms). */
            cs->counters.membership_proposals_refused++;
            return false;
        }
    } else {
        if (!present || cs->cfg.member_count <= 1u) {
            /* A group may never be emptied by remove. */
            cs->counters.membership_proposals_refused++;
            return false;
        }
    }

    /* The fold pre-check makes the pending entry provably legal before it
     * becomes durable (qcs_config_entry_valid runs inside the fold). */
    qihse_uuid_t folded[QIHSE_CONSENSUS_MAX_MEMBERS];
    size_t fcount = 0;
    qihse_consensus_entry_t e;
    memset(&e, 0, sizeof(e));
    e.index = qcs_abs_last_index(cs) + 1u;
    e.term = cs->term;
    e.journal_generation = qcs_last_gen(cs) + 1u; /* consumes a generation */
    e.type = (op == QIHSE_CONSENSUS_MEMBER_ADD)
                 ? QIHSE_CONSENSUS_ENTRY_CONFIG_ADD
                 : QIHSE_CONSENSUS_ENTRY_CONFIG_REMOVE;
    memcpy(e.payload, member->bytes, QIHSE_UUID_BYTES);
    e.payload_len = QIHSE_UUID_BYTES;
    if (!qcs_fold_membership(cs, &e, folded, &fcount)) {
        cs->counters.membership_proposals_refused++;
        return false;
    }

    /* Write-then-apply: the LC record is fsynced BEFORE the in-memory
     * config folds it in; a failed write refuses the change closed. */
    if (!qcs_persist_config_entry(cs, &e)) {
        cs->counters.membership_proposals_refused++;
        return false;
    }
    if (!qcs_log_push(cs, &e)) {
        cs->counters.membership_proposals_refused++;
        return false;
    }
    /* Takes effect NOW (append semantics).  Removing ourselves steps us
     * down immediately: a removed leader must not count its own ack in
     * the new config, and the entry then resolves through the ordinary
     * mid-transition rule (new leader completes or truncates it). */
    (void)qcs_recompute_membership(cs);
    if (cs->self_index >= 0 && cs->role == QIHSE_CONSENSUS_LEADER) {
        cs->match_index[cs->self_index] = qcs_abs_last_index(cs);
        qcs_advance_commit(cs);
    }
    return true;
}

bool qihse_consensus_read_committed(const qihse_consensus_t* cs,
                                    const qihse_user_t* user,
                                    uint64_t from_index,
                                    qihse_consensus_entry_t* out_entries,
                                    size_t out_cap, size_t* out_count) {
    if (!cs || !out_count) return false;
    if (out_cap > 0u && !out_entries) return false;
    *out_count = 0u;

    /* Classified-capable read primitive: an explicit authenticated
     * principal is mandatory (AGENTS.md invariant 1).  NULL fails closed. */
    if (!user) {
        /* The handle is read-only for payload purposes; the denial counter
         * is observability state, not data state. */
        ((qihse_consensus_t*)cs)->counters.auth_failures++;
        return false;
    }

    uint64_t start = from_index ? from_index : 1u;
    for (uint64_t idx = start; idx <= cs->commit && *out_count < out_cap; idx++) {
        const qihse_consensus_entry_t* e = qcs_entry_at(cs, idx);
        if (!e) continue; /* below a follower's installed boundary (narrower,
                           * never wider, than the un-compacted path) */
        if (!qihse_auth_can_access(user, e->classif, e->sci)) {
            ((qihse_consensus_t*)cs)->counters.auth_failures++;
            continue; /* withheld: never disclosed to this principal */
        }
        out_entries[(*out_count)++] = *e;
    }
    return true;
}

/* ── Introspection ───────────────────────────────────────────────────────── */

const char* qihse_consensus_role_name(qihse_consensus_role_t role) {
    switch (role) {
        case QIHSE_CONSENSUS_FOLLOWER: return "FOLLOWER";
        case QIHSE_CONSENSUS_CANDIDATE: return "CANDIDATE";
        case QIHSE_CONSENSUS_LEADER: return "LEADER";
    }
    return "UNKNOWN";
}

qihse_consensus_role_t qihse_consensus_role(const qihse_consensus_t* cs) {
    return cs ? cs->role : QIHSE_CONSENSUS_FOLLOWER;
}

uint64_t qihse_consensus_term(const qihse_consensus_t* cs) {
    return cs ? cs->term : 0u;
}

uint64_t qihse_consensus_fencing_epoch(const qihse_consensus_t* cs) {
    return cs ? cs->epoch : 0u;
}

uint64_t qihse_consensus_commit_index(const qihse_consensus_t* cs) {
    return cs ? cs->commit : 0u;
}

uint64_t qihse_consensus_last_log_index(const qihse_consensus_t* cs) {
    return cs ? qcs_abs_last_index(cs) : 0u;
}

uint64_t qihse_consensus_last_log_term(const qihse_consensus_t* cs) {
    return cs ? qcs_last_log_term(cs) : 0u;
}

uint64_t qihse_consensus_snapshot_index(const qihse_consensus_t* cs) {
    return cs ? (uint64_t)cs->snap.count : 0u;
}

bool qihse_consensus_voted_for(const qihse_consensus_t* cs, qihse_uuid_t* out) {
    if (!cs || !out) return false;
    *out = cs->voted_for;
    return cs->has_vote;
}

bool qihse_consensus_leader_id(const qihse_consensus_t* cs, qihse_uuid_t* out) {
    if (!cs || !out) return false;
    *out = cs->leader;
    return cs->has_leader;
}

bool qihse_consensus_is_stale_epoch(const qihse_consensus_t* cs, uint64_t epoch) {
    if (!cs) return true;
    return epoch < cs->epoch;
}

bool qihse_consensus_get_membership(const qihse_consensus_t* cs,
                                    qihse_consensus_membership_t* out) {
    if (!cs || !out) return false;
    out->member_count = cs->cfg.member_count;
    memcpy(out->members, cs->cfg.members,
           cs->cfg.member_count * sizeof(qihse_uuid_t));
    out->majority_needed = cs->cfg.member_count / 2u + 1u;
    out->last_config_index = qcs_last_config_index(cs);
    out->pending_config_index =
        (out->last_config_index > cs->commit) ? out->last_config_index : 0u;
    out->self_removed = cs->self_index < 0;
    return true;
}

bool qihse_consensus_group_available(const qihse_consensus_t* cs, uint64_t now_ms) {
    if (!cs) return false;
    if (cs->self_index < 0) return false; /* removed from the config */
    uint64_t timeout = qcs_election_timeout_ms(cs, cs->term);
    if (cs->role == QIHSE_CONSENSUS_LEADER) {
        size_t live = 1u; /* self */
        for (size_t i = 0; i < cs->cfg.member_count; i++) {
            if ((int)i == cs->self_index) continue;
            if (cs->last_ack_ms[i] != 0u &&
                now_ms - cs->last_ack_ms[i] <= timeout) {
                live++;
            }
        }
        return live >= qcs_majority_needed(cs);
    }
    if (cs->role == QIHSE_CONSENSUS_FOLLOWER && cs->has_leader) {
        return now_ms - cs->last_leader_contact_ms <= timeout;
    }
    return false;
}

void qihse_consensus_get_counters(const qihse_consensus_t* cs,
                                  qihse_consensus_counters_t* out) {
    if (!out) return;
    if (!cs) {
        memset(out, 0, sizeof(*out));
        return;
    }
    *out = cs->counters;
}
