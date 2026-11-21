# QKP administrator-pin rotation

This procedure uses the optional second administrator pin to overlap one old and
one replacement QKP identity. Both configured identities receive the same full
system-Operator command authority. Keep the overlap short and protect both
private keys accordingly.

## Preconditions

- Confirm the exact QKP node ID and ML-DSA public-key file for each identity.
  The node ID and public key are a pair; do not reuse a node ID with an
  unintended key.
- Add the replacement public key as a trusted anchor on each server with an
  additional `--pqc-trusted-pub` option. Trusting an anchor alone does not grant
  administrator authority.
- The server pin options are:

  ```text
  --admin-peer-node-id OLD_ID --admin-peer-dsa-pub OLD_PUBLIC_KEY
  --admin-peer-node-id-2 NEW_ID --admin-peer-dsa-pub-2 NEW_PUBLIC_KEY
  ```

  The second node ID and public-key path must be configured together. The
  existing first pair remains supported in `qihse_qkp_config_t`; configure the
  overlap pair on the created server, before listening, with
  `qihse_resp_server_add_admin_peer(server, node_id, dsa_pub_path, grantor)`.
  The setter copies both values and requires an active system Operator grantor.
- Plan any required daemon restarts against current quorum, service availability,
  and recovery requirements. If the future rolling-upgrade plan includes these
  systems, it must include both the 730xd and T320 nodes. No uninterrupted
  rolling-rotation guarantee has been established.

## Rotation sequence

1. Distribute and verify the replacement public key as a trusted QKP anchor on
   every server, while retaining the old anchor. Do not enable the replacement
   pin until its exact node-ID/key pair has been checked.
2. Configure both administrator pin pairs on every server. Apply the change
   using the deployment's approved restart procedure; do not assume a live
   configuration reload.
3. Before changing the client, authenticate with both the old and replacement
   identities against **each** server. Verify an authorized administrative
   operation and confirm that an ordinary low-clearance principal still cannot
   read protected data.
4. Switch the administrative client to the replacement identity. Verify its
   node ID, key, and successful authorized access against every server.
5. Remove the old administrator pin and old trusted anchor from each server,
   again using the approved restart procedure. Verify that the replacement
   identity still succeeds and the old identity is denied on every server.
6. Retire the old private key under the organization's key-destruction policy
   only after the denial checks and rollout evidence are recorded.

## Evidence and limits

`make test-admin-cli` exercises an isolated API-level overlap and retirement
case with disposable identities. It does not exercise this procedure on a
cluster, verify rollout ordering, prove service continuity, or authorize a
production key change. No cluster deployment, daemon restart, real key
provisioning, or uninterrupted rotation test is claimed here. This procedure
also does not change PostgreSQL wire authentication or TLS readiness.
