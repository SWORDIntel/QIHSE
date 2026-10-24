# QIHSE Backup & Restore Runbook

## Model

`qihse-backup` is a **local** tool — it opens the store directly (it does not
connect over RESP), so it works unchanged on QKP-hardened masters
(`pqc_require`). Authentication is the operator credential
(`--password-file` or `QIHSE_OPERATOR_PASSWORD` env), verified against the
local auth store.

## Consistency requirement

The daemon must be **stopped** while a snapshot is taken (and while a
restore runs), so the KV store and audit writer are quiesced:

```bash
systemctl stop qihse-node0.service
```

Each master owns a slot range and its own sovereign-local namespaces, so a
full-cluster recovery needs a backup **per node**, not one global backup.

## Backup

```bash
systemctl stop qihse-node0.service
sudo env QIHSE_DATA_DIR=/opt/qihse-data/node0 \
     QIHSE_BACKUP_PATH=/var/backups/qihse-node0-$(date +%F).bin \
     QIHSE_OPERATOR_PASSWORD="$(sudo grep -E '^QIHSE_OPERATOR_PASSWORD=' /etc/qihse/cluster-node0.env | cut -d= -f2- | tr -d \"\')" \
     ./qihse-backup backup
systemctl start qihse-node0.service
```

Output is a single container: `{"ok":true,"operation":"backup",...,
"size_bytes":N,"checksum":"...","writer_user_id":0,"classification":65535}`.

## Verify a backup

```bash
systemctl stop qihse-node0.service
sudo env QIHSE_DATA_DIR=/opt/qihse-data/node0 \
     QIHSE_BACKUP_PATH=/var/backups/qihse-node0-….bin \
     QIHSE_OPERATOR_PASSWORD="…" \
     ./qihse-backup verify
systemctl start qihse-node0.service
```

Expect `{"ok":true,"operation":"verify","result":"valid"}`.

## Restore

```bash
systemctl stop qihse-node0.service
sudo env QIHSE_DATA_DIR=/opt/qihse-data/node0 \
     QIHSE_BACKUP_PATH=/var/backups/qihse-node0-….bin \
     QIHSE_OPERATOR_PASSWORD="…" \
     ./qihse-backup restore
systemctl start qihse-node0.service
```

Expect `{"ok":true,"operation":"restore","result":"restored"}`, then `verify`
returns `valid`. Restore is a whole-store replace; it must run against a
stopped node (same consistency rule as backup).

## Caveats

- Backups are full-store and classification/SCI-bounded to the operator
  (writer_user_id 0, classification 65535). Treat them as classified
  artifacts — store 0600, encrypt at rest if required.
- A replica's store is read-only and can be rebuilt by re-pulling from its
  source, so replicas do not need backups.
- After a restore + restart, the node rejoins the cluster bus and resumes its
  30s replication pass automatically.
