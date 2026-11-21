#include "qihse_auth.h"
#include "qihse_kv_store.h"
#include "qihse_ct_codec.h"
#include "qihse_ct1_recovery_manifest.h"
#include "qihse_cluster_ownership_journal.h"

#include <assert.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Disposable fixture mirror of QCTST003. Never use this to edit a live store:
 * the source handle is destroyed before the WAL and state are replaced. A
 * layout change fails closed at the exact-size/magic/checksum checks below. */
typedef struct {
    char magic[8];
    uint8_t mode, fence_state;
    uint16_t fence_first, fence_last;
    uint32_t tenant_id, tenant_policy;
    uint64_t baseline_lsn, durable_lsn, ack_lsn, retained_bytes, limit_bytes;
    unsigned char baseline_digest[32];
    uint8_t baseline_sealed;
    uint64_t fence_cut_position;
    char source_id[QIHSE_KV_CT_ID_MAX + 1u];
    char target_id[QIHSE_KV_CT_ID_MAX + 1u];
    char successor_id[QIHSE_KV_CT_ID_MAX + 1u];
    char generation[QIHSE_KV_CT_ID_MAX + 1u];
    char transfer_id[QIHSE_KV_CT_ID_MAX + 1u];
    uint8_t transfer_phase;
    char transfer_source_id[QIHSE_KV_CT_ID_MAX + 1u];
    char transfer_source_generation[QIHSE_KV_CT_ID_MAX + 1u];
    uint64_t transfer_source_cut, transfer_target_position;
    unsigned char transfer_image_digest[32], transfer_group_digest[32];
    unsigned char transfer_range_digest[32];
    unsigned char owner_token[QIHSE_KV_CT_TOKEN_BYTES];
    unsigned char last_group_digest[32];
    unsigned char moved_slots[QIHSE_CLUSTER_SLOT_COUNT / 8u];
    uint64_t transfer_base_change_seq, transfer_applied_records;
    uint8_t transfer_chunked;
    uint64_t checksum;
} fixture_ct_state_t;

static uint64_t state_checksum(const fixture_ct_state_t *state)
{
    uint64_t hash = 14695981039346656037ULL;
    const unsigned char *bytes = (const unsigned char *)state;
    for (size_t i = 0; i < offsetof(fixture_ct_state_t, checksum); ++i) {
        hash ^= bytes[i];
        hash *= 1099511628211ULL;
    }
    return hash;
}

static void fixture_path(char out[512], const char *dir, const char *name)
{
    int n = snprintf(out, 512, "%s/%s", dir, name);
    assert(n > 0 && n < 512);
}

static fixture_ct_state_t read_state(const char *dir)
{
    char path[512];
    fixture_path(path, dir, "ct-state.bin");
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    fixture_ct_state_t state;
    assert(fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == 0 && st.st_nlink == 1 && !(st.st_mode & 077) &&
        st.st_size == (off_t)sizeof(state) &&
        read(fd, &state, sizeof(state)) == (ssize_t)sizeof(state) &&
        close(fd) == 0 && !memcmp(state.magic, "QCTST003", 8) &&
        state.checksum == state_checksum(&state));
    return state;
}

void ct1_fixture_reemit_historical(const char *dir, qihse_user_t *operator_user,
    const qihse_kv_ct_group_t *original, uint64_t baseline_seq,
    const unsigned char baseline_digest[32], uint64_t source_high)
{
    struct stat directory;
    assert(geteuid() == 0 && lstat(dir, &directory) == 0 &&
        S_ISDIR(directory.st_mode) && directory.st_uid == 0 &&
        (directory.st_mode & 07777) == 0700 &&
        source_high == baseline_seq + 7 &&
        original && original->records && original->count == 1 &&
        original->stream_position == 1 && original->first_seq == baseline_seq + 1 &&
        original->last_seq == original->first_seq &&
        original->records[0].change_seq == original->first_seq &&
        !original->records[0].tombstone && original->records[0].value &&
        !strcmp(original->records[0].key, "commons/fixture-key") &&
        original->records[0].classification == 4 &&
        original->records[0].sci_compartment == 2 && source_high > original->first_seq);
    fixture_ct_state_t state = read_state(dir);
    assert(state.mode == 1 && state.baseline_sealed == 1 &&
        state.baseline_lsn == baseline_seq &&
        !memcmp(state.baseline_digest, baseline_digest, 32) &&
        state.durable_lsn == 7 && state.ack_lsn == 7 &&
        state.retained_bytes == 0 && state.limit_bytes >= QIHSE_CT1_RECOVERY_FRAME_BYTES &&
        !strcmp(state.source_id, original->source_id) &&
        !strcmp(state.generation, original->generation) &&
        !strcmp(state.successor_id, "target:fixture") &&
        state.transfer_phase == 0 && !state.fence_state);

    qihse_kv_ct_group_t retransmission = *original;
    retransmission.stream_position = 8; /* Re-send the original row, not a new mutation. */
    size_t size = 0, written = 0;
    assert(qihse_ct_codec_encoded_size(operator_user, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
        0, QIHSE_CT_CODEC_MODE_SOURCE, &retransmission, 65536, &size) &&
        size == QIHSE_CT1_RECOVERY_FRAME_BYTES);
    unsigned char group_digest[32];
    assert(qihse_ct_codec_group_digest(operator_user, QIHSE_KV_CT_TENANT_SYSTEM_ALL,
        0, &retransmission, group_digest));
    char wal[512];
    fixture_path(wal, dir, "wal.log");
    int fd = open(wal, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    struct stat st;
    assert(fd >= 0 && fstat(fd, &st) == 0 && S_ISREG(st.st_mode) &&
        st.st_uid == 0 && st.st_nlink == 1 && !(st.st_mode & 077) && st.st_size == 0);
    FILE *out = fdopen(fd, "wb");
    assert(out && qihse_ct_codec_write(out, operator_user,
        QIHSE_KV_CT_TENANT_SYSTEM_ALL, 0, QIHSE_CT_CODEC_MODE_SOURCE,
        &retransmission, 65536, &written) && written == size &&
        fflush(out) == 0 && fsync(fd) == 0 && fclose(out) == 0);

    state.durable_lsn = 8;
    state.retained_bytes = size;
    memcpy(state.last_group_digest, group_digest, sizeof(group_digest));
    state.checksum = state_checksum(&state);
    char path[512], tmp[512];
    fixture_path(path, dir, "ct-state.bin");
    fixture_path(tmp, dir, "ct-state-fixture-XXXXXX");
    fd = mkstemp(tmp);
    assert(fd >= 0 && write(fd, &state, sizeof(state)) == (ssize_t)sizeof(state) &&
        fsync(fd) == 0 && close(fd) == 0 && rename(tmp, path) == 0);
    fd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    assert(fd >= 0 && fsync(fd) == 0 && close(fd) == 0);
    fixture_ct_state_t persisted = read_state(dir);
    assert(!memcmp(&persisted, &state, sizeof(state)) &&
        persisted.durable_lsn == 8 && persisted.ack_lsn == 7 &&
        persisted.retained_bytes == QIHSE_CT1_RECOVERY_FRAME_BYTES &&
        !memcmp(persisted.last_group_digest, group_digest, 32));
}
