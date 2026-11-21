#!/usr/bin/env bash
set -euo pipefail
umask 077

build_flags=(-O2)
if [[ $# == 1 && $1 == --sanitize ]]; then
    build_flags=(-O1 -g -fno-omit-frame-pointer '-fsanitize=address,undefined' -fno-sanitize-recover=undefined)
    export ASAN_OPTIONS=abort_on_error=1:detect_leaks=1
elif [[ $# != 0 ]]; then
    printf 'usage: %s [--sanitize]\n' "$0" >&2
    exit 2
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
mkdir -p build
run_dir="$(mktemp -d "build/w11_combined_recovery.XXXXXX")"
cleanup() {
    status=$?
    trap - EXIT
    printf 'preserving W11 recovery evidence at %s (status=%s)\n' "$run_dir" "$status" >&2
    exit "$status"
}
trap cleanup EXIT
mkdir -m 700 "$run_dir/source-data" "$run_dir/restored-data" "$run_dir/auth" "$run_dir/auth/state" "$run_dir/keys" "$run_dir/sql" "$run_dir/sql-restored" "$run_dir/blobs"
# Append diagnostics within this attempt; failed trees and prior runs are retained.
exec > >(tee -a "$run_dir/run.log") 2>&1
export LD_LIBRARY_PATH=.

make -s lib keygen >&2
"$repo_root/qihse_keygen" "$run_dir/keys" >&2
"${CC:-cc}" -std=c11 "${build_flags[@]}" -Wall -Wextra -Iinclude -Icore -I. \
    -o "$run_dir/w11_combined_recovery" benchmarks/w11_combined_recovery.c \
    -L. -lqihse -Wl,-rpath,"$repo_root" -Wl,--export-dynamic -lpthread -lcrypto

unset QIHSE_OPERATOR_PASSWORD
export QIHSE_FIPS_MODE=optional
export QIHSE_AUTH_STATE_DIR="$run_dir/auth"
# The shared package is authenticated, not encrypted. Its random key and payloads
# stay in this private fixture; identity authority/PQC keys remain out of band.
# Do not pre-create restore-input or blobs-restored: native publication is fresh.
fixture_args=("$run_dir" "$run_dir/auth" "$run_dir/keys")
QIHSE_DATA_DIR="$run_dir/source-data" "$run_dir/w11_combined_recovery" seed "${fixture_args[@]}"
export QIHSE_DATA_DIR="$run_dir/restored-data"
"$run_dir/w11_combined_recovery" recover "${fixture_args[@]}"
# Only this fresh fixture attempt may supply the exact durable hook witness.
# The parent distinguishes child SIGKILL from watchdog expiry; both the exact
# hook witness and a non-watchdog signal exit are required.
for interrupt_phase in first last before_swap private_ready; do
interrupt_nonce="$(python3 -c 'import secrets; print(secrets.token_hex(16))')"
witness="$run_dir/index-interrupt.$interrupt_phase.witness"
test ! -e "$witness"
python3 - "$run_dir/w11_combined_recovery" --interrupt-index \
    "${fixture_args[@]}" "$interrupt_nonce" "$interrupt_phase" <<'PY'
import signal, subprocess, sys
child = subprocess.Popen(sys.argv[1:])
try:
    status = child.wait(timeout=120)
except subprocess.TimeoutExpired:
    child.kill()
    child.wait(timeout=5)
    raise SystemExit("index interruption watchdog expired; never accept its SIGKILL")
if status != -signal.SIGKILL:
    raise SystemExit(f"expected child SIGKILL, got returncode {status}")
print("verified child SIGKILL without watchdog expiry", file=sys.stderr, flush=True)
PY
python3 - "$witness" "$interrupt_nonce" "$interrupt_phase" <<'PY'
import pathlib, sys
phase = sys.argv[3]
entries = 1 if phase == 'first' else 8
assert pathlib.Path(sys.argv[1]).read_bytes() == (
    f"w11-index-{phase}-{entries}-synced:" + sys.argv[2] + "\n").encode(), "exact hook witness"
PY
printf 'verified fresh-process index SIGKILL at %s\n' "$interrupt_phase" >&2
# Reopen the SAME restored native stores: no interruption phase restores again.
timeout --signal=TERM --kill-after=5s 120s \
    "$run_dir/w11_combined_recovery" --recover-index "${fixture_args[@]}"
done
result="$(timeout --signal=TERM --kill-after=5s 120s \
    "$run_dir/w11_combined_recovery" final "${fixture_args[@]}")"
printf '%s\n' "$result" | python3 -c '
import json, sys
report = json.load(sys.stdin)
assert report["schema"] == "w11-combined-recovery-v2"
# Reached only after BOTH exact-at-hook witness and SIGKILL status checks above.
report["evidence"]["bounded_post_restore_index_sigkill_after_first_synced_candidate"] = True
report["evidence"]["bounded_private_ready_sigkill_with_unique_synced_witness"] = True
report["bounded_shared_restore"]["index_interruption_boundaries"] = ["first", "last", "before_swap", "private_ready"]
for field in ("blob_backup_coverage", "authenticated_blob_archive_export_restore",
              "blob_archive_low_clearance_export_restore_denied",
              "blob_archive_wrong_key_denied", "blob_restored_metadata_and_pins",
              "blob_restored_fresh_process_readback",
              "authenticated_aimem_index_rebuild",
              "aimem_index_rebuild_fresh_process_persistence",
              "aimem_index_low_clearance_denied",
              "aimem_index_rebuild_exact_source_rows_preserved",
              "bounded_cross_store_cohort_provenance",
              "bounded_local_shared_package_export_verify_unpack",
              "fresh_process_native_shared_payload_restore",
              "shared_sql_blob_receipts_restored",
              "authenticated_and_participant_floors_before_replay",
              "common_decision_replayed_twice_before_app_exposure",
              "shared_package_immutable_after_restore",
              "ordinary_uwp_commits_one_phase",
              "shared_package_low_clearance_denied",
              "shared_package_wrong_key_denied",
              "packaged_aimem_source_rows_rebuilt",
              "bounded_packaged_aimem_two_version_supersession",
              "bounded_packaged_aimem_nonempty_provenance",
              "bounded_packaged_aimem_exact_get_latest_asof_event",
              "bounded_packaged_aimem_provenance_low_clearance_denied",
              "bounded_post_restore_interrupted_index_recovered",
              "bounded_post_restore_interrupted_index_ready_persistence",
              "bounded_post_restore_interrupted_index_source_provenance_preserved",
              "bounded_post_restore_index_sigkill_after_first_synced_candidate",
              "bounded_private_ready_sigkill_with_unique_synced_witness",
              "bounded_private_ready_committed_unavailable_reopened",
              "bounded_private_ready_explicit_recover_preserves_committed_state",
              "bounded_private_ready_explicit_rebuild_ready_persistence"):
    assert report["evidence"][field] is True, field
bounded = report["bounded_shared_restore"]
assert bounded["member_count"] >= 5
assert bounded["journal_bytes"] > 0
assert bounded["manifest_next_txn_id"] > bounded["common_decision_id"] + 1
assert bounded["restored_next_id_floor"] >= bounded["manifest_next_txn_id"]
assert (bounded["sql_engine_id"], bounded["blob_engine_id"]) == (81, 82)
assert bounded["replay_passes_per_restart"] == 2
assert bounded["knowledge_source_rows"] == 8
assert bounded["expected_knowledge_source_versions"] == 9
assert bounded["knowledge_current_rows"] == 8
assert bounded["expected_provenance_events"] == 1
# Historical remaining_gaps values are evidence flags, NOT completion flags.
assert "legacy evidence flags" in report["remaining_gaps_semantics"]
assert report["remaining_gaps"]["all_four_representative_adapters"] is True
assert report["remaining_gaps"]["deployment_auth_readiness"] is False
assert report["remaining_gaps"]["cross_model_atomicity"] is False
assert report["remaining_gaps"]["combined_cross_store_backup_atomicity"] is False
assert report["remaining_gaps"]["node_partition_faults"] is False
assert report["remaining_gaps"]["w11_scale_gate"] is False
assert report["remaining_gaps"]["aimem_index_interrupted_build_faults"] is False
for field in ("full_node_recovery", "partition_faults", "storage_faults", "scale",
              "interrupted_index_rebuild"):
    assert report["acceptance_gates"][field] is False, field
assert report["w11_6_complete"] is False
json.dump(report, sys.stdout, indent=4)
print()
'
