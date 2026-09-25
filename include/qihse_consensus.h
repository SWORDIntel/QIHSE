#ifndef QIHSE_CONSENSUS_H
#define QIHSE_CONSENSUS_H

/* QIHSE scoped consensus — leader-based agreement for a single replication
 * group (plan §15, §16, §43; acceptance criteria 3, 4, 10, 13).
 *
 * WHAT THIS IS
 * ------------
 * A tick-driven, single-threaded state machine that gives one scoped
 * replication group (explicit member UUID configuration) a leader term, a
 * replicated log, and majority commitment.  The mechanics implemented:
 *
 *   - persistent current term, voted-for, and a monotonic fencing epoch,
 *     appended to a per-group record file before any vote or term change
 *     takes effect in memory;
 *   - log entries addressed by (index, term) with the prev-index/prev-term
 *     consistency check (log matching), and conflicting-suffix truncation;
 *   - leader election restricted to candidates whose log is at least as
 *     up-to-date as the voter's (last term, then last index);
 *   - commit index advancing only when a strict majority of voters (the
 *     leader itself included) have acknowledged the entry AND the entry is
 *     from the current term (the current-term commit rule);
 *   - any node stepping down to follower on observing a higher term;
 *   - stale fencing epochs rejected: a message whose fencing epoch is below
 *     the highest epoch the receiver has durably observed is dropped before
 *     any term or log logic runs;
 *   - leader-side log compaction and follower snapshot install (the
 *     InstallSnapshot equivalent — see LOG COMPACTION below);
 *   - single-server membership changes: add/remove-one-member config
 *     entries in the replicated log, with one transition in flight at a
 *     time (see MEMBERSHIP CHANGES below);
 *   - crash/restart through replay of the append-only record file.
 *
 * WHAT THIS IS NOT (honest naming, plan §16)
 * ------------------------------------------
 * This is NOT a complete Raft implementation and MUST NOT be named, aliased,
 * or documented as one.  Mechanics the full algorithm requires that are
 * deliberately absent here:
 *
 *   - joint consensus (C_old,new): membership changes are SINGLE-SERVER
 *     changes only (see MEMBERSHIP CHANGES below for the protocol, its
 *     safety argument, and what is traded away);
 *   - client session and dedup semantics at this layer (the F2 request
 *     ledger owns idempotency);
 *   - pre-vote, leadership transfer, and leader-lease linearizable reads;
 *   - peer authentication: messages are trusted to come from the named
 *     member UUID.  The injected transport owns authentication (mTLS /
 *     signed gossip, F5); this module only checks that the sender is a
 *     configured member of THIS group;
 *   - dynamic batching or backpressure beyond the fixed per-message entry
 *     batch below.
 *
 * LOG COMPACTION / SNAPSHOT INSTALL (implemented; residual limits)
 * ------------------------------------------------------------------
 * The ACTIVE log — the region the leader matches, re-transmits, and
 * truncates on conflict — is bounded by leader-side compaction.  When the
 * retained log (last index − snapshot index) exceeds
 * cfg.snapshot_threshold entries, the leader durably writes a SNAPSHOT
 * transaction to its record file — an S header (last-included index/term,
 * fencing epoch, highest journal generation, FNV-1a digest over the
 * compacted entries), one SE record per compacted entry, and a terminating
 * T record that commits the transaction — then truncates the log prefix.
 * The T record is the swap point: an S transaction that is not terminated
 * by its T (a crash mid-write) is rolled back on replay, so the previous
 * durable state (the uncompacted log) is never lost.
 *
 * The snapshot digest is FNV-1a over the compacted entries in index order,
 * folding, for each entry, the little-endian 8-byte encodings of index,
 * term, journal_generation, hlc.physical_ms, hlc.logical, classif, sci,
 * entry type and payload_len, then the raw payload bytes — a fixed
 * canonical form so the receiver (and the record-file replayer) recomputes
 * and compares rather than trusting the stored value.
 *
 * A follower whose next-needed index has been compacted on the leader
 * receives the snapshot as one QIHSE_CONSENSUS_MSG_SNAPSHOT message over
 * the same injected transport, followed by the surviving tail as normal
 * appends.  The follower verifies the digest and the fencing epoch before
 * touching its own state, then installs atomically (new buffers first,
 * pointer swap last — never a half-replaced log).  Snapshots are refused
 * and counted when the digest mismatches, the structure is inconsistent,
 * or the carrying epoch is stale.
 *
 * A snapshot retains the FULL compacted entries (payloads and their
 * classification/SCI metadata): this module's state machine IS the log —
 * there is no external state machine to apply entries into — so committed
 * reads below the snapshot boundary stay byte-identical before and after
 * compaction, and every snapshot-served read passes the same per-entry
 * qihse_auth_can_access() check as the un-compacted path (compaction never
 * widens visibility).  Residual limits, stated honestly:
 *
 *   - the snapshot transfers as ONE message carrying at most
 *     QIHSE_CONSENSUS_SNAPSHOT_MAX_ENTRIES entries; each compaction
 *     advances the boundary by at most that many entries, and there is no
 *     chunked/streamed or resumable cross-session snapshot transfer;
 *   - the snapshot structure in memory retains the compacted prefix, so
 *     what compaction bounds is the active log and catch-up traffic, not
 *     the process footprint; likewise the append-only record file is
 *     never reclaimed (a later compaction re-writes the whole snapshot);
 *   - there is no snapshot throttling beyond the threshold itself:
 *     compaction is re-evaluated on every leader tick and fires whenever
 *     the threshold is exceeded.
 *
 * MEMBERSHIP CHANGES (implemented; single-server protocol; residual limits)
 * -----------------------------------------------------------------------
 * Protocol choice: SINGLE-SERVER changes — one add-or-remove per committed
 * transition, Raft-dissertation §4.2.2 style.  The safety invariant ("at no
 * point can two disjoint majorities each elect a leader in the same term")
 * holds because consecutive configs differ by exactly one member, so any
 * majority of C_old and any majority of C_new intersect (|M_old|+|M_new| >
 * |C_old ∪ C_new| for a single-member delta); combined with the two rules
 * below, any two configs simultaneously in force anywhere in the group are
 * adjacent configs, never two steps apart.  Tradeoffs versus full joint
 * consensus: a multi-member change is a SEQUENCE of committed one-member
 * transitions (no atomic bulk reconfiguration), and there is no C_old,new
 * phase in which both configs must agree.  What is gained is a far smaller
 * state machine — no joint quorum arithmetic, no two-phase config records —
 * which fits this module's deterministic, bounded-buffer discipline.
 *
 * Shape of the implementation:
 *
 *   - membership is part of the replicated log: a config entry is a log
 *     entry (QIHSE_CONSENSUS_ENTRY_CONFIG_ADD / _CONFIG_REMOVE below)
 *     carrying the one changed member UUID as its 16-byte payload.  It
 *     replicates, commits, and truncates like any entry, participates in
 *     the election up-to-date restriction like any entry, and is visible
 *     in committed reads under the same per-entry authorization.
 *   - THE CONFIG IN FORCE IS A FUNCTION OF THE LOG: the effective member
 *     set is the caller-supplied base configuration folded over every
 *     config entry in the log (snapshot prefix included).  A config entry
 *     takes effect when it is APPENDED — on the leader at proposal, on a
 *     follower when the append lands — not when its commit is learned.
 *     This is deliberate: election safety requires a node's quorum basis
 *     to be its log, never its (lagging, local) knowledge of commit; a
 *     commit-based rule would let a restarted node regress to a config
 *     two transitions behind the group, which is precisely the hole the
 *     one-in-flight rule exists to close.
 *   - ONE transition in flight: qihse_consensus_propose_membership()
 *     refuses a second proposal while the latest config entry in the
 *     leader's log is uncommitted.  Refused — not queued.
 *   - quorum evaluation (election majority, commit majority, message
 *     membership filtering) always uses the effective config above; a
 *     transition therefore needs no special joint arithmetic — the old
 *     and new configs' majorities already intersect.
 *   - durability follows the module's write-then-apply discipline: the
 *     LC record is fsynced BEFORE the in-memory config folds it in, so a
 *     crash mid-write leaves the previous config in force; the record is
 *     the swap point.  (A torn LC tail fails the whole load closed, the
 *     same as a torn L tail.)  Restart replays the config history and
 *     lands on the config of the LAST CONFIG ENTRY IN THE RECONSTRUCTED
 *     LOG — which, by one-in-flight, is either the last committed config
 *     or the single uncommitted transition exactly as the group sees it.
 *   - mid-transition leader change resolves through ordinary log
 *     mechanics — there is no special abort protocol.  A new leader that
 *     HOLDS the pending entry completes it: the entry commits as a
 *     prefix of that leader's first committed current-term entry.  A new
 *     leader that LACKS it overwrites it — conflicting-suffix truncation
 *     removes the entry from followers and the fold reverts the group to
 *     the previous config.  Either way the new leader may not start its
 *     own membership change until a config entry is either committed or
 *     gone from its log.
 *   - a node removed from the effective config steps down cleanly: it
 *     never campaigns, recognizes no leader, reports the group
 *     unavailable, and its fencing state (term/epoch floor) persists and
 *     still applies.  It cannot win an election in the new config —
 *     remaining members ignore its traffic at the membership filter —
 *     and it cannot commit, since no C_new leader counts its
 *     acknowledgements.  The leader keeps OFFERING the transition entry
 *     to a removed node until its cursor vouches for it (grace catch-up:
 *     the removed node's replies advance only its own catch-up cursor
 *     and never count as votes or acknowledgements), so a reachable
 *     removed node learns of its removal and folds it; a partitioned one
 *     is fenced by membership instead.  A leader that
 *     removes ITSELF steps down the moment the entry is appended (it is
 *     no longer entitled to count its own ack in C_new); the entry then
 *     resolves through the mid-transition rule above.
 *
 * Residual limits, stated honestly:
 *
 *   - no voter weights, witnesses, or non-voting learners — every member
 *     is an equal voter (plan §15's voters/witnesses split is future);
 *   - no automated drift detection or healing of member-set divergence
 *     across members: a node whose static baseline configuration is
 *     edited behind its record file's back is not detected; membership
 *     changes must go through the replicated API;
 *   - the caller-supplied member list at open() is trusted as the fold
 *     BASELINE; config entries before the first ones a node witnesses
 *     are not re-validated against it;
 *   - transitions to fewer than two members are refused (a single-member
 *     group cannot be emptied by remove), and additions stop at
 *     QIHSE_CONSENSUS_MAX_MEMBERS.
 *
 * LOCAL NAMESPACES ARE NEVER GATED (plan §3.1, §3.2; acceptance criteria 1-2)
 * --------------------------------------------------------------------------
 * Consensus exists per scoped group only.  This module holds no reference to
 * any namespace registry, KV store, or federation-wide state: a group that
 * cannot make progress cannot make any other namespace read-only.  Callers
 * map qihse_consensus_group_available() onto federation state for STRONG
 * namespaces (which fail closed under insufficient consensus, acceptance
 * criterion 3) and never onto LOCAL ones.
 *
 * TIME AND DETERMINISM
 * --------------------
 * There are no threads and no wall-clock reads.  All time enters through
 * qihse_consensus_tick()'s caller-supplied timestamp, and all messages enter
 * through qihse_consensus_receive() on an injected transport callback, in the
 * style of the F8 simulation harness.  Election timeouts are derived
 * deterministically from the member UUID and the term, so a scenario
 * reproduces exactly on every run.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "qihse_auth.h"          /* qihse_user_t — every classified-capable
                                  * read/write path takes an explicit
                                  * authenticated principal (AGENTS.md
                                  * invariant 1). */
#include "qihse_federation.h"    /* qihse_uuid_t, qihse_hlc_t */

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_CONSENSUS_GROUP_ID_MAX 63u
#define QIHSE_CONSENSUS_MAX_MEMBERS 32u
#define QIHSE_CONSENSUS_PAYLOAD_MAX 128u
#define QIHSE_CONSENSUS_MAX_ENTRIES_PER_MSG 8u
#define QIHSE_CONSENSUS_RECORD_PATH_MAX 255u
/* One snapshot message / record transaction carries the compacted prefix
 * whole; this caps how far a single compaction advances the boundary. */
#define QIHSE_CONSENSUS_SNAPSHOT_MAX_ENTRIES 24u

/* ── Roles ───────────────────────────────────────────────────────────────── */

typedef enum {
    QIHSE_CONSENSUS_FOLLOWER = 0,
    QIHSE_CONSENSUS_CANDIDATE,
    QIHSE_CONSENSUS_LEADER
} qihse_consensus_role_t;

const char* qihse_consensus_role_name(qihse_consensus_role_t role);

/* ── Log entries ───────────────────────────────────────────────────────────
 *
 * An entry carries the F2 event-journal generation it replicates, so the
 * consensus log references journal state instead of duplicating it.  The
 * classification metadata rides with the entry: a committed entry is a
 * classified-capable read primitive and is only disclosed through
 * qihse_consensus_read_committed() with an authenticated principal.
 *
 * A CONFIG entry is a membership transition: its payload is exactly the
 * 16-byte UUID of the one member being added or removed (classif and sci
 * are zero).  Config entries replicate, commit, and truncate like data
 * entries; see MEMBERSHIP CHANGES above for when they take effect. */

typedef enum {
    QIHSE_CONSENSUS_ENTRY_DATA = 0,         /* operator/journal payload */
    QIHSE_CONSENSUS_ENTRY_CONFIG_ADD = 1,   /* payload = added member UUID */
    QIHSE_CONSENSUS_ENTRY_CONFIG_REMOVE = 2 /* payload = removed member UUID */
} qihse_consensus_entry_type_t;

typedef struct {
    uint64_t index;             /* 1-based; entries form a contiguous log */
    uint64_t term;              /* term of the leader that appended it */
    uint64_t journal_generation;/* F2 event-journal generation (strictly
                                 * increasing along the log; a config
                                 * entry consumes one too) */
    qihse_hlc_t hlc;            /* causal timestamp from the journal */
    uint16_t classif;           /* classification level of the payload */
    uint16_t sci;               /* SCI compartment bitmask of the payload */
    qihse_consensus_entry_type_t type; /* DATA, or a config transition */
    uint8_t payload[QIHSE_CONSENSUS_PAYLOAD_MAX];
    size_t payload_len;
} qihse_consensus_entry_t;

/* ── Messages ────────────────────────────────────────────────────────────── */

typedef enum {
    QIHSE_CONSENSUS_MSG_REQUEST_VOTE = 1,
    QIHSE_CONSENSUS_MSG_VOTE_REPLY = 2,
    QIHSE_CONSENSUS_MSG_APPEND = 3,
    QIHSE_CONSENSUS_MSG_APPEND_REPLY = 4,
    QIHSE_CONSENSUS_MSG_SNAPSHOT = 5,      /* leader -> lagging follower */
    QIHSE_CONSENSUS_MSG_SNAPSHOT_REPLY = 6 /* follower -> leader */
} qihse_consensus_msg_type_t;

typedef struct {
    qihse_consensus_msg_type_t type;
    char group_id[QIHSE_CONSENSUS_GROUP_ID_MAX + 1u];
    qihse_uuid_t from;          /* sending member UUID */
    qihse_uuid_t to;            /* receiving member UUID */
    uint64_t term;              /* sender's current term */
    uint64_t fencing_epoch;     /* sender's fencing epoch (>= its term) */
    union {
        /* QIHSE_CONSENSUS_MSG_REQUEST_VOTE */
        struct {
            uint64_t last_log_index;
            uint64_t last_log_term;
        } vote;
        /* QIHSE_CONSENSUS_MSG_VOTE_REPLY */
        struct {
            bool granted;
        } vote_reply;
        /* QIHSE_CONSENSUS_MSG_APPEND */
        struct {
            uint64_t prev_log_index;
            uint64_t prev_log_term;
            uint64_t leader_commit;
            size_t entry_count;
            qihse_consensus_entry_t entries[QIHSE_CONSENSUS_MAX_ENTRIES_PER_MSG];
        } append;
        /* QIHSE_CONSENSUS_MSG_APPEND_REPLY */
        struct {
            bool success;
            uint64_t match_index;      /* hint on failure: highest index the
                                        * follower can vouch for */
        } append_reply;
        /* QIHSE_CONSENSUS_MSG_SNAPSHOT — the compacted prefix [1 ..
         * last_included_index] in one message, with the digest and the
         * fencing epoch the leader recorded when it compacted.  The
         * receiver recomputes the digest and refuses on any mismatch. */
        struct {
            uint64_t last_included_index;   /* == entry_count (contiguous) */
            uint64_t last_included_term;    /* term of entry at that index */
            uint64_t fencing_epoch;         /* epoch recorded at compaction */
            uint64_t journal_generation;    /* highest generation compacted */
            uint64_t digest;                /* canonical FNV-1a, see header */
            size_t entry_count;
            qihse_consensus_entry_t entries[QIHSE_CONSENSUS_SNAPSHOT_MAX_ENTRIES];
        } snapshot;
        /* QIHSE_CONSENSUS_MSG_SNAPSHOT_REPLY */
        struct {
            bool success;
            uint64_t match_index;      /* on success: the snapshot boundary;
                                        * on failure: highest index the
                                        * follower can vouch for */
        } snapshot_reply;
    } u;
} qihse_consensus_msg_t;

/* ── Configuration ───────────────────────────────────────────────────────── */

typedef struct {
    char group_id[QIHSE_CONSENSUS_GROUP_ID_MAX + 1u];
    qihse_uuid_t self;          /* this node's member UUID; must be a member */
    size_t member_count;        /* 1..QIHSE_CONSENSUS_MAX_MEMBERS, no dupes */
    qihse_uuid_t members[QIHSE_CONSENSUS_MAX_MEMBERS];
    /* Timing, in caller-supplied virtual milliseconds.  Election timeouts
     * are base + (member_index * spread / member_count) + jitter, with
     * jitter derived from (self UUID, term); spread must be >= member_count
     * so the per-member buckets are disjoint and elections do not tie. */
    uint64_t election_timeout_base_ms;   /* 0 = default 150 */
    uint64_t election_timeout_spread_ms; /* 0 = default 300 */
    uint64_t heartbeat_interval_ms;      /* 0 = default 50 */
    /* Log-compaction trigger, in entries: when the retained log
     * (last log index − snapshot index) exceeds this many entries, the
     * leader durably snapshots the committed prefix and truncates it from
     * the active log.  0 (default) DISABLES compaction — the log then
     * grows without bound, exactly as before this existed.  Each
     * compaction advances the boundary by at most
     * QIHSE_CONSENSUS_SNAPSHOT_MAX_ENTRIES entries. */
    uint64_t snapshot_threshold;
    /* Append-only record file (term, votes, epoch, log, commit).  Relative
     * or dynamically resolved paths only — never a hard-coded absolute
     * path.  One file per (node, group). */
    char record_path[QIHSE_CONSENSUS_RECORD_PATH_MAX + 1u];
} qihse_consensus_config_t;

/* Transport: the implementation calls send(transport, msg) to emit.  The
 * callback decides delivery order, dropping, duplication, and partitioning
 * (the F8-style harness); it must not call back into this module from
 * inside send() — queue and deliver from your own loop instead. */
typedef void (*qihse_consensus_send_fn)(void* transport,
                                        const qihse_consensus_msg_t* msg);

/* Opaque instance. */
typedef struct qihse_consensus qihse_consensus_t;

/* Open (or create) a group instance.  Replays the record file if it exists;
 * a corrupt, truncated, semantically inconsistent, or foreign-group record
 * file FAILS CLOSED (returns NULL) rather than starting from partial state.
 * Returns NULL on invalid configuration. */
qihse_consensus_t* qihse_consensus_open(const qihse_consensus_config_t* cfg,
                                        void* transport,
                                        qihse_consensus_send_fn send);
void qihse_consensus_close(qihse_consensus_t* cs);

/* Advance virtual time.  Drives election timeouts and leader heartbeats;
 * message handling is stamped with the most recent tick's timestamp. */
void qihse_consensus_tick(qihse_consensus_t* cs, uint64_t now_ms);

/* Deliver one message to this instance (already routed by the transport). */
void qihse_consensus_receive(qihse_consensus_t* cs,
                             const qihse_consensus_msg_t* msg);

/* ── Client paths ────────────────────────────────────────────────────────── */

/* Propose an entry (leader only; followers return false).  payload must be
 * non-NULL and payload_len strictly positive (an entry carries a payload; a
 * zero-length payload is refused rather than recorded unreplayably).
 * journal_generation must be strictly greater than the last appended entry's.
 * The entry is durable on this node when true is returned, and committed only
 * after a majority acknowledges it (see qihse_consensus_commit_index).
 *
 * The payload's classification metadata is enforced at the boundary exactly
 * like a read: `user` must be an authenticated principal whose clearance and
 * SCI compartments cover (classif, sci).  NULL is never a bypass — a NULL
 * user may only propose unclassified payloads.  (AGENTS.md invariant 1.) */
bool qihse_consensus_propose(qihse_consensus_t* cs, const qihse_user_t* user,
                             uint64_t journal_generation, qihse_hlc_t hlc,
                             uint16_t classif, uint16_t sci,
                             const void* payload, size_t payload_len);

/* Read committed entries at indices [from_index, commit_index], oldest
 * first, into out_entries (up to out_cap; *out_count receives the number
 * written; indices past the returned window can be fetched by a follow-up
 * call with from_index advanced).  Entries below the snapshot boundary are
 * served from the installed snapshot — byte-identical to the un-compacted
 * log, authorization included.
 *
 * This is a classified-capable read primitive: every entry is individually
 * authorized against `user`, and entries above the principal's clearance or
 * outside its SCI compartments are silently withheld (never disclosed).
 * A NULL user is refused outright — fail closed — so an unauthenticated
 * caller cannot mistake denial for an empty log.  Returns false on invalid
 * arguments or unauthenticated callers; true when the scan ran. */
bool qihse_consensus_read_committed(const qihse_consensus_t* cs,
                                    const qihse_user_t* user,
                                    uint64_t from_index,
                                    qihse_consensus_entry_t* out_entries,
                                    size_t out_cap, size_t* out_count);

/* ── Membership changes (single-server; see MEMBERSHIP CHANGES above) ────── */

typedef enum {
    QIHSE_CONSENSUS_MEMBER_ADD = 0,
    QIHSE_CONSENSUS_MEMBER_REMOVE = 1
} qihse_consensus_membership_op_t;

/* Propose a one-member membership transition (leader only).  The transition
 * is a config entry in the replicated log; it takes effect on append and is
 * durable on this node the moment true is returned.  It is COMMITTED only
 * after a majority of the resulting config acknowledges it.
 *
 * Privilege boundary: a membership change re-shapes the group that guards
 * classified replication, so it is an operator-grade act — `user` MUST be a
 * non-NULL authenticated principal holding the OPERATOR role.  NULL is
 * refused outright (never a bypass), and so is any lesser role.  (AGENTS.md
 * invariants 1 and 2: privilege-bearing changes need an identified,
 * sufficient principal.)
 *
 * Refused (returns false, nothing appended) when: this node is not the
 * leader; a previous transition is still uncommitted (one in flight —
 * refused, not queued); the member UUID is nil; ADD names an existing
 * member or would exceed QIHSE_CONSENSUS_MAX_MEMBERS or break the
 * election-timeout bucket invariant; REMOVE names a non-member or would
 * leave the group empty (removal to fewer than one member is refused);
 * or the durable record write fails (fail closed). */
bool qihse_consensus_propose_membership(qihse_consensus_t* cs,
                                        const qihse_user_t* user,
                                        qihse_consensus_membership_op_t op,
                                        const qihse_uuid_t* member);

typedef struct {
    /* Effective member set (base configuration folded over the config
     * entries in the log).  Order: base order, added members appended. */
    size_t member_count;
    qihse_uuid_t members[QIHSE_CONSENSUS_MAX_MEMBERS];
    /* Strict-majority size of the effective config. */
    size_t majority_needed;
    /* Index of the latest config entry in the log (0 = none). */
    uint64_t last_config_index;
    /* Index of the uncommitted transition in flight (0 = none).  A config
     * entry is pending until the commit index covers it or it is truncated
     * by a conflicting leader (which reverts the config). */
    uint64_t pending_config_index;
    /* True when this node's own UUID is absent from the effective config:
     * it has been removed, has stepped down, and no longer campaigns. */
    bool self_removed;
} qihse_consensus_membership_t;

/* Introspection only — member UUIDs and transition state, never payloads.
 * Returns false on invalid arguments; true with *out filled otherwise. */
bool qihse_consensus_get_membership(const qihse_consensus_t* cs,
                                    qihse_consensus_membership_t* out);

/* ── Introspection (no payload disclosure) ───────────────────────────────── */

qihse_consensus_role_t qihse_consensus_role(const qihse_consensus_t* cs);
uint64_t qihse_consensus_term(const qihse_consensus_t* cs);
uint64_t qihse_consensus_fencing_epoch(const qihse_consensus_t* cs);
uint64_t qihse_consensus_commit_index(const qihse_consensus_t* cs);
uint64_t qihse_consensus_last_log_index(const qihse_consensus_t* cs);
uint64_t qihse_consensus_last_log_term(const qihse_consensus_t* cs);
/* Highest index covered by the installed snapshot (0 = no snapshot).
 * Entries at or below it are served from the snapshot on committed reads,
 * under the same per-entry authorization as the un-compacted path. */
uint64_t qihse_consensus_snapshot_index(const qihse_consensus_t* cs);
/* UUID this node voted for in the current term; false when the vote is open. */
bool qihse_consensus_voted_for(const qihse_consensus_t* cs, qihse_uuid_t* out);
/* Leader this node currently recognizes; false / nil when none. */
bool qihse_consensus_leader_id(const qihse_consensus_t* cs, qihse_uuid_t* out);
/* True when `epoch` is below the highest fencing epoch durably observed —
 * i.e. traffic fenced off by this node (plan §7.3, acceptance criterion 4). */
bool qihse_consensus_is_stale_epoch(const qihse_consensus_t* cs, uint64_t epoch);

/* Strong-write availability for THIS GROUP ONLY (never for LOCAL
 * namespaces): true when this node is a leader with a live majority ack
 * window, or a follower with a live leader.  Scoped: an unavailable group
 * says nothing about any other group or about LOCAL namespaces. */
bool qihse_consensus_group_available(const qihse_consensus_t* cs, uint64_t now_ms);

/* ── Observability (plan §41) ─────────────────────────────────────────────── */

typedef struct {
    uint64_t elections_won;          /* times this node became leader */
    uint64_t election_timeouts;      /* elections started here */
    uint64_t stale_epoch_rejections; /* messages fenced as stale epoch */
    uint64_t term_rejections;        /* messages rejected on lower term */
    uint64_t log_conflicts;          /* conflicting-suffix truncations */
    uint64_t auth_failures;          /* user-context denials (read + write) */
    uint64_t messages_sent;
    uint64_t messages_received;
    uint64_t messages_ignored;       /* wrong group / non-member / misrouted */
    uint64_t record_writes;          /* records appended to the record file */
    uint64_t snapshots_created;      /* leader compactions executed */
    uint64_t snapshots_installed;    /* snapshots applied (message or replay) */
    uint64_t snapshot_rejections;    /* refused snapshots: digest mismatch /
                                      * inconsistent structure / out of order */
    uint64_t membership_changes_applied; /* config entries that changed the
                                          * effective member set (append,
                                          * replay, or truncation-revert) */
    uint64_t membership_proposals_refused; /* propose_membership denials:
                                            * one-in-flight / non-leader /
                                            * authorization / bad request */
} qihse_consensus_counters_t;

void qihse_consensus_get_counters(const qihse_consensus_t* cs,
                                  qihse_consensus_counters_t* out);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_CONSENSUS_H */
