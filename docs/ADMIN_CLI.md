# QKP admin CLI and SDK

Build with `make admin-cli`; verify with `make test-admin-cli`. The regression
suite starts an isolated QKP server with temporary keys, users and storage; it
is also part of `make test`.

## Connection and authorization

Configure `QIHSE_HOST`, `QIHSE_PORT` (default 7100), `QIHSE_IDENTITY_DIR`,
`QIHSE_TRUSTED_PUB`, and `QIHSE_NODE_ID`, or supply the equivalent CLI flags.
The identity directory contains `qihse_dsa_key.pem`, `qihse_kem_key.pem`, and
`qihse_kem_pub.pem`. The server pin is mandatory. No cleartext fallback exists.

A matching server-side admin node-ID/key pin grants the operator identity. For
user-scoped access, use `--user USER --password-env ENV_NAME`, or set both
`QIHSE_AUTH_USER` and `QIHSE_AUTH_PASSWORD`. AUTH runs **inside the same sealed
session**, before any requested commands. A rejected AUTH terminates without
executing them, even without `--fail-on-error`. Passwords need not appear in
process arguments. Existing server role, tenant, clearance and SCI checks apply.
For services, use their own QKP identity and explicit service principal rather
than distributing operator signing keys.

`--timeout-ms` defaults to 30000. It bounds each address's connection attempt and
each blocking socket send/receive wait, including the handshake; it is not an
end-to-end command deadline and does not bound DNS resolution. A transport or
protocol failure invalidates the connection. Commands are never replayed.

## Commands and modes

All synchronous RESP2 server commands are available directly, without aliases.
Use `COMMAND`, `COMMAND LIST`, or `COMMAND INFO <name>` to inspect capabilities.
The existing cluster/health shortcuts remain available.

```sh
./qihse-admin-cli --json COMMAND INFO GET AIMEM VECSEARCH
./qihse-admin-cli --json --fail-on-error AIMEM COUNT
./qihse-admin-cli --json --fail-on-error AIMEM SEARCH 'previous design decision' 5
./qihse-admin-cli --json CLUSTER SLOTS
./qihse-admin-cli --json USER LIST
./qihse-admin-cli --resp -x ECHO < payload.bin
./qihse-admin-cli --stdin --json --fail-on-error < commands.txt
./qihse-admin-cli --interactive
```

This same path covers KV/hash/list/set/sorted-set commands, vector/search/graph
operations, AIMEM (including direct-ID/event/handoff subcommands), security,
snapshots, replication, fabric and cluster commands implemented by the server.
Feature availability and argument syntax remain server-defined. A transport that
accepts binary data does not imply every storage backend accepts binary keys or
values: for example, the current string KV backend rejects NUL-containing keys.

Options precede the positional command. Everything after the command, including
strings beginning with `-`, is an argument. `--arg` appends exact text arguments;
`-c`/`--command` parses quotes and escapes and can be followed by `--arg` values.
`-x` appends stdin as the last argument **without stripping NUL, CR or LF**. This
corrects the previous newline stripping; use `printf`, not `echo`, when a text
value must not end in a newline.

`--stdin` and `--interactive` reuse one QKP handshake and server session, allowing
AUTH, CLIENT state and transaction sequences. Lines support single/double quotes,
backslash escapes and `#` comments at token boundaries. Double quotes recognize
`\n`, `\r`, and `\t`. Blank/comment lines are ignored. Malformed batch input
terminates with status 2; it is never split into additional commands. Embedded
NUL requires `-x` or the native API rather than line input. `EXIT` exits locally;
`QUIT` is sent to the server and ends the loop. Batch modes cannot be combined
with a positional command or `-x`.

## Output and errors

* Default: legacy human-readable text (flattened arrays).
* `--resp`: exact RESP2 bytes, retaining types, nested arrays, nulls and binary
  strings. No newline is added between replies.
* `--json`: one JSON value per reply, retaining arrays, integers and nulls.
  Error replies become `{"error":"message"}` even when nested. For arbitrary
  bytes, JSON string characters map to U+0000..U+00FF. In Python, recover bytes
  with `value.encode('latin-1')`, then decode UTF-8 if desired. `--resp` is the
  preferred machine protocol when exact RESP types are needed.
* `--fail-on-error`: status 5 for RESP errors, including nested transaction
  errors. Bulk strings beginning with `ERR`, `MOVED`, etc. are ordinary data.
  Batch execution stops at the first error; interactive mode keeps the failure
  status but permits subsequent commands.

Exit codes: 0 success, 2 usage/config, 3 connection/handshake, 5 command/I/O.
Requests/replies are bounded to 64 MiB including framing (request allocation
reserves framing headroom); replies permit at most 64 levels of nesting. CLI
commands allow 256 arguments; the native API allows 65536.

This is a synchronous RESP2 interface, not a pub/sub or MONITOR streaming client.
Do not switch it to RESP3 with `HELLO 3`. Automatic MOVED/ASK following is not
implemented: redirection must not implicitly trust a new server. Choose the
correct endpoint and pin explicitly. The standalone AIMEM server supports
`--pqc-require --pqc-identity-dir <server-keys> --pqc-trusted-pub
<service-client-pub> --pqc-node-id <server-id>` alongside `--require-auth`.
The service key is transport-only (not an admin-peer pin); authenticate as
`AIMEM_SERVICE` inside QKP. The standalone loopback AIMEM listener is deployed
QKP-only and keeps its original store, separate from the production cluster.
HAX native/Python clients, Supermemory, Codex/ZCode hooks and G510 use the
pinned service identity. Automatic recall uses BM25 to stay within hook
budgets; explicit scoped semantic/hybrid requests can exceed 60 seconds
because matching records are re-embedded on each request. This is not a
transport fallback or a fixed vector index. The isolated `test-admin-cli`
fixture verifies cleartext rejection, unauthenticated denial, and AIMEM-only
service access.

## Native API

`include/qihse_qkp.h` exposes:

* `qihse_qkp_admin_open`: pinned QKP handshake, timeout configuration.
* `qihse_qkp_admin_command`: persistent command with explicit argument lengths;
  returns allocated exact RESP bytes and length. `lengths == NULL` uses strlen.
* `qihse_qkp_admin_format`: validated text/JSON output and error detection.
* `qihse_qkp_admin_close` and `qihse_qkp_admin_free`: release session and buffers.

One caller per client at a time. A server RESP error is a valid reply (return 0),
not a transport error. Inspect the wire type or use the formatter's error flag.
Close after transport/protocol failures; no retries are safe by default. Send
AUTH explicitly before data operations when using a user principal.

The existing `qihse_qkp_admin_exec` ABI remains: one command on a fresh connection,
legacy text output. Prefer the length-aware API for integrations.

## Python SDK

```python
from qihse_admin import ClusterAdmin

admin = ClusterAdmin(node_id='memory-client', identity_dir='keys')
with admin.session(host, port, server_pin,
                   user=service_user, password=service_password,
                   timeout_ms=10000) as session:
    count = session.execute('AIMEM', 'COUNT')
    hits = session.execute('AIMEM', 'SEARCH', 'design decision', '5')
    binary = session.execute('ECHO', b'payload\x00\n')
    wire_reply = session.execute_resp('AIMEM', 'GET', memory_id)
```

`execute` returns `bytes`, `int`, `None`, or nested lists, and raises
`QihseAdminError` for actual RESP errors (including nested errors).
`execute_resp` returns raw bytes, including error replies. Strings in arguments
are UTF-8 encoded; `bytes` arguments are passed verbatim. `execute_typed` on
`ClusterAdmin` offers the same typed result for one-shot requests.

These methods require the current native library and readable keys. They fail
explicitly if the library is old/unavailable or sudo mode is selected, rather
than silently dropping session state through a subprocess fallback. Legacy
`ClusterAdmin.execute` and existing convenience methods retain text output and
the old subprocess fallback. Neither the CLI nor SDK reads QIHSE storage files.
