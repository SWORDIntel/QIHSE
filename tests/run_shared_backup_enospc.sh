#!/usr/bin/env bash
# Bounded rootless capacity test; never mount over an existing fixture.
set -euo pipefail
umask 077

self=$(realpath -e -- "${BASH_SOURCE[0]}")
CDPATH='' cd -- "$(dirname -- "$self")/.."

if [[ ${1-} == --inside ]]; then
    [[ $# == 6 ]]
    root=$2
    binary=$3
    mode=$4
    [[ $mode == --capacity || $mode == --capacity-export ]]
    [[ $(readlink /proc/self/ns/mnt) != "$5" ]]
    [[ $(readlink /proc/self/ns/user) != "$6" ]]
    [[ $root == build/shared-backup-enospc-* && -d $root && ! -L $root ]]
    limited=$root/limited
    evidence=$root/evidence
    [[ -d $limited && ! -L $limited && -d $evidence && ! -L $evidence ]]
    if mountpoint -q -- "$limited"; then
        printf 'ERROR: fixture mountpoint was already mounted\n' >&2
        exit 1
    fi
    child=
    cleanup() {
        local rc=$1
        trap - EXIT
        trap '' HUP INT TERM
        if [[ -n $child ]]; then
            kill -TERM -- "-$child" 2>/dev/null || :
            wait "$child" 2>/dev/null || :
        fi
        # Check the mount even if mount(8) returned an error after publication.
        if mountpoint -q -- "$limited"; then
            until mkdir -p -- "$evidence/remaining" &&
                  cp -a -- "$limited/." "$evidence/remaining/" &&
                  sync -f "$evidence"; do
                rc=1
                printf 'ERROR: evidence copy failed; namespace PID %s STOPPED with tmpfs retained. Repair backing storage, then CONT to retry capture.\n' \
                    "$BASHPID" >&3
                # Do not discard the only complete image. Resume is explicit,
                # not a polling/retry loop; the eventual target still fails.
                kill -STOP "$BASHPID"
            done
            if ! umount -- "$limited"; then
                printf 'ERROR: private tmpfs unmount failed\n' >&2
                rc=1
            fi
        fi
        printf 'namespace_exit=%s\n' "$rc" >> "$evidence/supervisor.txt" || rc=1
        exit "$rc"
    }
    trap 'cleanup "$?"' EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM
    mount -t tmpfs -o size=4m,nr_inodes=128,nodev,nosuid,noexec,mode=0700 \
        qihse-capacity-fixture "$limited"
    findmnt --mountpoint "$limited" --noheadings \
        --output TARGET,FSTYPE,OPTIONS,PROPAGATION > "$evidence/mount.txt"
    printf 'mount_namespace=%s\nuser_namespace=%s\n' \
        "$(readlink /proc/self/ns/mnt)" "$(readlink /proc/self/ns/user)" \
        > "$evidence/supervisor.txt"
    # Separate the fixture group so a trapped supervisor signal can stop and
    # reap it before copying the still-mounted filesystem.
    setsid --wait env LD_LIBRARY_PATH=. "$binary" "$mode" "$root" "$limited" &
    child=$!
    rc=0
    wait "$child" || rc=$?
    if (( rc != 0 )); then
        # A failed fixture can leave descendants after its direct PID exits.
        kill -TERM -- "-$child" 2>/dev/null || :
    fi
    child=
    cleanup "$rc"
fi

[[ $# -le 2 ]]
binary=${1:-./tests/test_shared_backup}
mode=${2:---capacity}
[[ $mode == --capacity || $mode == --capacity-export ]]
[[ -f $binary && -x $binary ]]
mkdir -p build
root=$(mktemp -d build/shared-backup-enospc-XXXXXX)
printf 'shared backup real-ENOSPC artifacts: %s (preserved)\n' "$root"
mkdir -- "$root/limited" "$root/evidence"
parent_mnt=$(readlink /proc/self/ns/mnt)
parent_user=$(readlink /proc/self/ns/user)
printf 'parent_mount_namespace=%s\nparent_user_namespace=%s\n' \
    "$parent_mnt" "$parent_user" > "$root/evidence/parent.txt"
runner=
cancel_status=0
cancel_signal=TERM
forward_signal() {
    cancel_signal=$1
    cancel_status=$2
    if [[ -n $runner ]]; then
        kill -"$cancel_signal" "$runner" 2>/dev/null || :
    fi
}
trap 'forward_signal HUP 129' HUP
trap 'forward_signal INT 130' INT
trap 'forward_signal TERM 143' TERM
# No --fork: unshare execs the namespace supervisor at this exact child PID.
# Launcher-only signals can therefore be forwarded without a PID-file race.
env --default-signal=HUP,INT,TERM unshare --user --map-root-user --mount --propagation private \
    bash "$self" --inside "$root" "$binary" "$mode" "$parent_mnt" "$parent_user" \
    3>&2 > "$root/run.log" 2>&1 &
runner=$!
if (( cancel_status != 0 )); then
    forward_signal "$cancel_signal" "$cancel_status"
fi
rc=0
while :; do
    wait "$runner" && { rc=0; break; } || rc=$?
    # A trapped signal interrupts wait before cleanup finishes. Wait again,
    # blocking on that same child, rather than abandoning its namespace.
    if ! kill -0 "$runner" 2>/dev/null; then break; fi
done
runner=
trap - HUP INT TERM
if (( cancel_status != 0 )); then rc=$cancel_status; fi
cat -- "$root/run.log"
if mountpoint -q -- "$root/limited"; then
    printf 'ERROR: mount unexpectedly visible in parent namespace\n' >&2
    rc=1
fi
exit "$rc"
