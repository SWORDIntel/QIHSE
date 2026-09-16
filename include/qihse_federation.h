#ifndef QIHSE_FEDERATION_H
#define QIHSE_FEDERATION_H

/* QIHSE federation — stage F0 primitives.
 *
 * The federation data plane (consistency classes, local-authority
 * namespaces, event journal, watches, leases, trust plane) builds on these
 * primitives. F0 deliberately changes no existing cluster behaviour: it adds
 * the identity, time, version, and fencing vocabulary the later stages need.
 * See docs/plans/qihse_federation_upgrade_plan.md.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QIHSE_UUID_BYTES 16u
#define QIHSE_UUID_STR_LEN 36u /* "8-4-4-4-12" without NUL */

typedef struct {
    uint8_t bytes[QIHSE_UUID_BYTES];
} qihse_uuid_t;

/* Identity. A federation node/object identity is a UUID — never an IP, a
 * hostname, or a topology index (plan §18). */
bool qihse_uuid_generate(qihse_uuid_t* out);
/* Deterministic identity for a seed (SHA-384 derived, version/variant bits
 * set): same seed, same UUID, on every node. */
bool qihse_uuid_from_seed(const void* seed, size_t seed_len, qihse_uuid_t* out);
bool qihse_uuid_parse(const char* text, qihse_uuid_t* out);
bool qihse_uuid_format(const qihse_uuid_t* id, char out[QIHSE_UUID_STR_LEN + 1u]);
bool qihse_uuid_is_nil(const qihse_uuid_t* id);
bool qihse_uuid_equal(const qihse_uuid_t* a, const qihse_uuid_t* b);

/* Hybrid logical clock (plan §7.1): physical milliseconds plus a logical
 * counter, monotonic on a node and causally ordered across nodes. */
typedef struct {
    uint64_t physical_ms;
    uint32_t logical;
} qihse_hlc_t;

void qihse_hlc_init(qihse_hlc_t* clock);
/* Local event: strictly greater than any previous tick and any observed
 * remote timestamp. */
void qihse_hlc_tick(qihse_hlc_t* clock, qihse_hlc_t* out);
/* Receive path: advance the local clock past a remote timestamp so the next
 * local tick is ordered after the remote event. */
void qihse_hlc_observe(qihse_hlc_t* clock, const qihse_hlc_t* remote);
/* Total order across nodes: -1, 0, +1. */
int qihse_hlc_compare(const qihse_hlc_t* a, const qihse_hlc_t* b);
/* Sortable 64-bit encoding (48-bit ms + 16-bit logical counter). */
uint64_t qihse_hlc_pack(const qihse_hlc_t* clock);
void qihse_hlc_unpack(uint64_t packed, qihse_hlc_t* out);

/* Object generation (plan §7.2): per-object version bumped on every mutation,
 * carrying the HLC stamp of the bump. */
typedef struct {
    qihse_uuid_t object;
    uint64_t generation;
    qihse_hlc_t stamp;
} qihse_object_version_t;

void qihse_object_version_init(qihse_object_version_t* version, const qihse_uuid_t* object);
/* Bump to the next generation and stamp it with the clock's next tick. */
void qihse_object_version_bump(qihse_object_version_t* version, qihse_hlc_t* clock);
/* Order by generation first, HLC stamp as the tie-break: -1, 0, +1. */
int qihse_object_version_compare(const qihse_object_version_t* a,
                                 const qihse_object_version_t* b);

/* Fencing epoch (plan §7.3): monotonic ownership epoch for exclusive state.
 * A holder may only act while its epoch is the highest it has observed. */
typedef struct {
    uint64_t epoch;
    qihse_uuid_t holder;
} qihse_fencing_token_t;

void qihse_fencing_token_init(qihse_fencing_token_t* token);
/* Acquire exclusive state: succeeds only when `observed_epoch` is strictly
 * older than the new epoch, and always advances the epoch. Fails closed. */
bool qihse_fencing_acquire(qihse_fencing_token_t* token, uint64_t observed_epoch,
                           const qihse_uuid_t* holder);
/* Is this token still the highest the caller has observed? */
bool qihse_fencing_valid(const qihse_fencing_token_t* token, uint64_t observed_epoch);

#ifdef __cplusplus
}
#endif

#endif /* QIHSE_FEDERATION_H */
