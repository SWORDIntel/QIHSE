# Local Fix Notes

## Branch

`security/keystone-regression-hardening-20260908`

## Current CI state

At handoff, the native/security portions of the branch are passing. The remaining failing product gate is the **Python SDK test job**.

Confirmed green on the current hardened branch state before this handoff:

- Full native core test suite
- Security regression tests
- APT41 tests
- Dashboard tests
- ASan/UBSan sanitizer job

Remaining failure:

- Python SDK tests — GitHub Actions job ID `102298527490`
- Associated workflow run: `34297944557`
- The failure was intentionally left for local reproduction/debugging rather than applying further remote changes.

## Native crash resolved

The earlier native crash in `qihse_tsdb_create()` (`src/marmalade/qihse_timeseries.c`, observed around the `tsdb->chunk_head = NULL` initialization) was traced to insufficient allocation alignment for a type containing a 64-byte-aligned member. The failing revision used plain `malloc()`; the current branch uses 64-byte `posix_memalign()`, and the native suite subsequently passed.

## Local follow-up

Reproduce the Python SDK failure locally from this branch and fix only that remaining gate. No further CI/product changes were applied after deciding to hand the branch back for local debugging.
