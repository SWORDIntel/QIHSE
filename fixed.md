# QIHSE operational fixes — 2026-10-21

Applied against the live 3-node cluster (node0 t420 brain `192.168.1.91:7100`,
node5 `192.168.1.90:7115`, node1 `192.168.1.250:7101`). Verify each entry's
evidence commands before re-applying; state below is what was measured.

---

## 1. FTS indexes were empty on every node (fixed)

**Symptom.** `FTS.SEARCH <term>` returned an empty array on all three seeds while
the tool library counted 338 tools / 103 chains.

**Cause.** The BM25 index is per-node, in-memory, and is lost on daemon restart.
Nothing rebuilt it after the last bounce.

**Fix.** Rebuilt on every seed, with the operator password:

```bash
# per node
AUTH <operator-password>
FTS.BUILD sabot/tool:*     # -> 338
FTS.BUILD sabot/chain:*    # -> 103
FTS.SEARCH "port scan"     # -> ranked hits, 20 returned by default limit
```

Verified identical on node0/node1/node5. **This is not persistent**: rebuild after
any daemon restart, or run `scripts/load_cluster_tools.py --all`, whose post-pass
rebuilds every seed.

---

## 2. AUTH accepts only the single-argument operator form

**Finding.** `AUTH <password>` → `+OK`. `AUTH <user> <password>` → `WRONGPASS`
for every principal tried (including `operator`, `kp15_operator`). A failed AUTH
does **not** close the socket, but a rejected principal cannot be used at all.

**Secret location changed.** The daemons read `EnvironmentFile=/etc/qihse/cluster-node0.env`
with key `QIHSE_OPERATOR_PASSWORD`. Consumers that look for `QIHSE_CLUSTER_PASSWORD`
get it from there (`/etc/parrotagent/qihse.env` mirrors it for the Go agent).
`bringup.sh` now resolves it with `sudo -n`; it is never written to the repo.

**Client requirement.** Any cluster client must try the principal form only when a
user is supplied, then fall back to `AUTH <password>` **on a fresh connection** if
the first reply is an error (error replies are fatal to that connection in some
clients).

---

## 3. Clients must follow MOVED on writes

**Finding.** `SET`/`GET`/`EXISTS` for a key whose slot is owned elsewhere return
`MOVED <slot> <host:port>`. A naive client that treats the first non-`OK` reply as
fatal stops writing at the seed's slot range.

**Fix.** `Exploit-Index/scripts/index_keystone_qihse.py` now follows MOVED
(re-auth at the destination, ≤5 hops) and falls back to operator AUTH. Without
this the `cve:record:*` projection could not be updated.

```bash
# evidence: write a key in node5's range, then read from node0
SET zz:probe:<slot-in-4550-10922> v   # on node5 -> +OK
GET  zz:probe:<...>                   # on node0 -> MOVED 4753 192.168.1.90:7115
```

---

## 4. Slot-map divergence on node0 (FIXED 2026-10-21, no restart)

**Applied.** `CLUSTER SETSLOT <slot> NODE <node1-id>` on node0 for every slot in
`10923-16383` (5,461 calls, 0 errors). It goes through the broadcast path
(`qihse_cluster_set_range_owner`), and node1/node5 already agreed, so their maps
were unchanged. `CLUSTER SLOTS` is now identical on all three seeds; node0 returns
`MOVED` for top-range keys. No restart, so FTS indexes were not lost.
Check any time with `scripts/check_slot_agreement.py`. The dual-write mirror copies
on node0 are now unreachable and can be deleted later.

(Original finding and mitigation below, kept for history.)

**Finding.** `CLUSTER SLOTS` disagrees:

| Node | View of `10923-16383` |
|------|------------------------|
| node0 | claims it for itself |
| node1 | claims it for itself |
| node5 | node1 |

node0's unit file is correct — `ExecStart` carries `--slot-range 0-4549` and
`--slot-range-of 1:10923-16383` — so this is runtime slot state (a `SETSLOT`
broadcast or brain rebalance that did not converge), not static config.

Consequences: keys in that range exist on both node0 and node1; `SET` sent to the
canonical owner leaves node0 returning `nil` for a slot it believes it owns, and
`GET` on node0 for keys it does have returns the local value (so stale copies
mask the divergence on reads).

**Mitigation in use.** The full-corpus projector writes `10923-16383` records to
node1 (canonical, per node1/node5) **and** node0 (mirror), so reads succeed from
any seed. ~47k extra SETs for the full corpus.

**Root fix (not applied).** Re-assert ownership and restart the brain in a
maintenance window:

```bash
# preferred: re-broadcast the static map, then confirm agreement
CLUSTER SETSLOT 10923 NODE <node1-id>     # and the rest of the range, per engine support
# or restart node0 so the daemon reloads --slot-range / --slot-range-of
sudo systemctl restart qihse-node0
```

Re-check with `CLUSTER SLOTS` on all three seeds; rebuild FTS after the restart.

---

## 5. `KEYS` / `SCAN` are single-page (counting caveat)

Both return at most ~4,096 keys and `SCAN` returns cursor `0` after one page, so
neither can be used to count a namespace. `DBSIZE` is per-node and includes all
prefixes. Counts in this session were taken by sampling (`GET` with MOVED
following) rather than by `KEYS`.

node0 also timed out on `DBSIZE` under load (~32 load average, `KEYS` 13.5 s vs
0.15 s on the workers). Watch node0 before bulk operations.

---

## 6. Full CVE corpus projected into `cve:record:*`

Executed 2026-10-21 with `Exploit-Index/scripts/index_full_qihse.py`:

| Metric | Value |
|---|---|
| Corpus scanned (`data/CVE_list.json`) | 152,004 |
| New `cve:record:*` | 149,417 |
| Enriched manifest records preserved | 2,587 present in CVE_list (5,110 manifest total) |
| SET operations incl. mirrors | 189,197 |
| Failures | 0 |
| Runtime / rate | 10m 33s / 242 records/s |
| Readback | 50/50 in-run, 300/300 independent random sample |

Routing: CRC16-XMODEM slot (`& 0x3FFF`, Redis hash-tag semantics) from
`CLUSTER SLOTS`, MOVED fallback, resume log `data/full_projection.done.jsonl`.
Records already in `keystone_cve_manifest.json` are enriched and skipped unless
`--overwrite`; the projector fails closed if that manifest is caught mid-rewrite.

---

## Verification checklist

```bash
# cluster agrees on slots
for p in 7100 7101 7115; do ... CLUSTER SLOTS ...; done
# FTS alive on every seed
FTS.SEARCH "port scan"
# projection readable from each seed
GET cve:record:CVE-2020-1472
GET cve:record:CVE-2026-0001   # top range: readable from node0 and node1
```

---

# RESP compatibility fixes — 2026-10-23

Applied to `/opt/QIHSE` (now the single source of truth; `Documents/QIHSE`
is a symlink to it). Verified with a raw RESP probe suite (22 checks) and a
Celery/broker-primitive suite (7 checks): **22/22 and 7/7** against the live
AIMEM service on `127.0.0.1:6401`.

## 1. `MULTI`/`EXEC` segfaulted and lost every queued write

`EXEC` dispatched the queue **while `in_multi` was still true**, so each queued
command was re-queued into the array being iterated: the `realloc` invalidated
the iterator (SIGSEGV; second client saw EOF) and nothing executed. `EXEC` also
replied `*1` and left the client in transaction state.
Fix: detach the queue and clear the transaction **before** dispatch
(`src/spinnaker/qihse_resp_engine.c`, `qihse_resp_handle_exec`).

## 2. Queued commands held dangling `argv` pointers

`memcpy(slot, request, sizeof(...))` copied the struct only; `argv[].data`
points into the connection read buffer, which the next command reuses.
Fix: deep-clone each queued request (`qihse_resp_request_clone`), free on
EXEC/DISCARD/MULTI.

## 3. Every collection member lost its last character

`"__h__:KEY:FIELD"` builders allocated `5 + klen + 1 + mlen + 1`, but the family
prefix is **six** characters (`__h__:`), so `snprintf` truncated one byte:
`f1`→`f`, `m1`/`m2`→`m`. `HSET h f1 a f2 b` stored a single field, `SADD` one
member, `ZADD` one score.
Fix: one `qihse_resp_member_key()` helper sized from the literals.
Known limitation (pre-existing key format): a KEY or MEMBER containing `:` is
ambiguous; changing the format would orphan stored members.

## 4. Reads were stubs returning nothing

`HGETALL`/`HKEYS`/`HVALS`/`HLEN`/`SCARD`/`SMEMBERS`/`ZCARD`/`ZRANGE`/`ZRANGEBYSCORE`
returned empty arrays or `0` (`hgetall` carried "Without iteration, return empty").
Fix: implemented over `qihse_kv_foreach_prefix_user` under the session
principal — the same authorization gate `GET` uses — with `WITHSCORES`, `LIMIT`,
`-inf/+inf` and `(exclusive` bounds.

## 5. `BLPOP`/`BRPOP`/`BRPOPLPUSH` did not exist

`-ERR unknown command`; a Celery worker cannot consume a queue without them.
Fix: implemented with a 20 ms poll bounded at 30 s (a forever-block would pin a
session thread), plus the push side for `BRPOPLPUSH`.

## 6. `DEL` leaked collection records

A hash/set/zset key exists only as `__h__:k:*` records, so `DEL` answered `0` and
the members survived. Fix: `DEL` also removes the list record and every h/s/z
member record, counting keys as Redis does.

## 7. Standalone servers enforced cluster rules

`qihse_resp_route` rejected ordinary multi-key `DEL` with `CROSSSLOT` with no
sharded topology. Fix: a single-node view executes locally; cluster rules still
apply with ≥2 nodes.

## 8. `--password` silently overrode `QIHSE_OPERATOR_PASSWORD`

`docs/OPERATIONS.md` promises "mismatch = exit 2", but the argv value won
silently and rotated the operator credential (`AUTH env` → WRONGPASS,
`AUTH flag` → OK).
Fix: `tools/qihse_redis_server.c` refuses the mismatch with exit 2 and a clear
message; match / env-only paths unchanged.

## 9. Binaries could load a stale `libqihse.so`

`qihse-redis-server` resolved `libqihse.so` from `ld.so.cache`
(`/rpool/data/db/qihse/lib`) instead of its freshly built sibling; the resulting
header/ABI mismatch corrupted `qihse_resp_server_config_t` and every start
failed with a generic "auth gate or bind error".
Fix: link with `-Wl,-rpath,'$ORIGIN'` (DT_RUNPATH) — **and** keep the loader copy
in sync, since a cache hit still wins for other consumers — plus the create()
failure path now prints errno, auth state, bind, port and the limits.

## 10. Operator credential held an unexpanded placeholder

`~/.config/qihse-aimem/operator-password.cred` decrypted to the literal string
`${QIHSE_AUTH_PASSWORD}`; the launcher assigns it verbatim, so the daemon's
operator password was the placeholder and the real 48-character secret in
`~/.config/qihse-aimem/env` was unused.
Fix: re-encrypted the credential with the real secret (old cred kept as
`.bak-*`), and `start-qihse-aimem` now pins `LD_LIBRARY_PATH` to its own
directory so the engine next to the launcher is always the one loaded.

## Verification commands

    # engine build + probe suites (reply-level, no redis-cli required)
    make redis-server && ./qihse-redis-server --require-auth ...
    # live service (AIMEM, :6401)
    systemd-creds decrypt --user --name=operator-password \
      ~/.config/qihse-aimem/operator-password.cred - | ...
    # documented password rule
    QIHSE_OPERATOR_PASSWORD=… ./qihse-redis-server --require-auth --password other  # exit 2
