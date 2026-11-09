# Cluster membership diagnosis, 2026-11-09

Status: live neighbour mapping repaired at the user's request; cluster daemons
were not restarted. This is evidence for Step 1 of the
[recovery plan](../plans/cluster_recovery_20261109.md).

## Established fault

730xd cannot resolve the Ethernet address of T320's service alias
`192.168.1.250`. This prevents its cluster-bus packets reaching T320, although
T320 can send packets to 730xd. T320's primary address `192.168.1.95` remains
reachable from 730xd.

This is a demonstrated asymmetric network fault explaining T320's failure
detection of 730xd. It is not evidence that the cluster credential differs,
or that a client connection from T420 establishes every peer-to-peer path.
It does not, by itself, establish the history of every ownership change.

## Evidence

Observations were collected around 16:46–16:48 UTC on November 9. Subprocesses
were bounded to ten seconds; packet captures were bounded to four to eight
seconds and displayed headers only. No memory/application payload was read.

| Observation | Result |
| --- | --- |
| T320 addresses | `192.168.1.95/24` is primary and `192.168.1.250/24` is secondary on `vmbr0`, MAC `e0:db:55:12:eb:3e`. |
| T320 bus listener | UDP `192.168.1.250:17101`; the live listener does not bind `.95`. |
| 730xd neighbour entry for `.250` | Alternates `INCOMPLETE` and `FAILED`; no resolved MAC. |
| 730xd neighbour entry for `.95` | `REACHABLE`, MAC `e0:db:55:12:eb:3e`. |
| T420 neighbour entry for `.250` | `REACHABLE`, same T320 MAC. This explains why T420's probes can succeed. |
| 730xd route to `.250`, source `.90` | Directly through `vmbr0`; no IP router is involved. |
| 730xd bus `sendto()` | Successfully queues datagrams for `.250:17101`; successful return is not wire delivery. UDP socket showed a nonzero send queue. |
| 730xd packet capture | Repeated ARP `who-has 192.168.1.250 tell 192.168.1.90`, visible on both `vmbr0` and physical `eno1`. |
| Simultaneous T320 capture | No corresponding ARP requests on either `vmbr0` or physical `nic0` during the bounded windows. |
| T320-to-730xd bus packets | UDP `.250:17101 -> .90:17115` seen at both endpoints. |
| 730xd-to-T320 bus packets | No reverse UDP wire traffic in the six-second peer-specific capture. |
| 730xd ping to `.95` | One reply, approximately 0.6 ms. |
| 730xd ping to `.250` | Local `Destination Host Unreachable`. |

T320 reports `arp_ignore=0` and `arp_filter=0` for both `all` and `vmbr0`.
Its bridge has VLAN filtering disabled, physical `nic0` is forwarding, and
reverse-path filtering is loose (`2`). Both hosts' ARP and bridge filter
tables were empty with ACCEPT policies. The inspected IP rules did not
explain the absent ARP reception.

The exact intervening switch/link mechanism dropping or suppressing these
broadcasts is not proven by this host-only inspection. Changing credentials,
clearing ownership maps, or enabling a balancer does not fix unresolved ARP.

## Current cluster views

Authenticated QKP `CLUSTER NODES` still reports:

| Observer | Ownership and health |
| --- | --- |
| T420 | All slots owned by 730xd; T320 and 730xd connected. |
| 730xd | Owns `0–5181,5183–16383`; T320 owns `5182`; both peers connected. |
| T320 | Owns `0–5181,5183–16383`; 730xd owns `5182` and is failed/disconnected. |

The old 730xd service repeatedly attempts failback of its large ranges and
logs `key enumeration incomplete (will retry)`. Thus there are two issues:
the demonstrated one-way network path and pre-existing contradictory
ownership/failback state. Restoring connectivity alone does not constitute
data or ownership recovery.

The source bus uses UDP, not the QKP client's TCP connection. Heartbeats carry
the sender's stable node ID and are resolved to receiver-local topology
indices. Sending enumerates all known peers, including unhealthy peers.
The current source paths are:

- [Heartbeat and send paths](../../src/spinnaker/qihse_cluster_bus.c)
- [Membership table](../../src/spinnaker/qihse_cluster_slot.c)
- [Startup configuration](../../tools/qihse_cluster_daemon.c)

A four-second header-suppressed syscall trace on the old 730xd process
confirmed attempts to send to both peers. The trace detached afterward.
No listener was restarted or reconfigured.

## Original deployment recommendation (before the live repair)

Use T320's demonstrated reachable primary address `.95` in the fresh release
topology. Keep the existing pins and authentication identities unless the
final release explicitly provisions replacements. A network endpoint and a
QKP identity are distinct namespaces.

These are endpoint substitutions, not complete daemon commands:

| Configuration location | Required endpoint |
| --- | --- |
| New T320 owner listener | `--bind 192.168.1.95 --port 7101 --bus-port 17101` |
| T420 topology entry for T320 | `--node 1:192.168.1.95:7101:17101` |
| 730xd topology entry for T320 | `--node 1:192.168.1.95:7101:17101` |
| Other T320 transport destinations | Replace the `.250` network address with `.95`, retaining the correct peer pin and identity mapping. |

Generate the complete common topology and topology-to-QKP map for the fresh
generation, including all successor processes. Preserve the current QKP
node name `192.168.1.250` if retaining that identity; do not silently rename
it merely because its listener address changes. Update client endpoint
configuration during cutover as needed.

Do not apply neighbour-table workarounds or change the live old listener as
part of this diagnosis. Renewed bus contact can immediately trigger the old
unfenced ownership/failback machinery. Apply the endpoint correction within
the coordinated backup/recovery cutover, with the new startup holds active.

## Acceptance for the staged release

1. Confirm `.95` remains assigned on T320 and resolves to its expected MAC
   from both other hosts. Confirm the replacement listener actually binds
   `.95`; a `.250`-only listener cannot accept `.95` traffic.
2. Observe bidirectional UDP bus packets for every host pair after starting
   the recovered cluster under its maintenance/failover holds. A successful
   `sendto()` or TCP `PING` is insufficient.
3. Check authenticated `INTROSPECTION BUS` counters advance on each peer and
   authenticated `CLUSTER NODES` reports the same memberships and endpoints.
4. Hold the observation beyond the configured failure timeout and verify no
   false failure or ownership churn. Validate replicated data and ownership
   separately before releasing application writes.

## Live repair at the user's request

At approximately 16:49 UTC, the user requested fixing 730xd networking before
continuing source integration. The verified T320 bridge MAC was installed as
730xd's permanent neighbour for `192.168.1.250` on `vmbr0`:

```sh
ip neigh replace 192.168.1.250 lladdr e0:db:55:12:eb:3e nud permanent dev vmbr0
```

The repair is persisted by an enabled, active `qihse-t320-neighbor.service`
oneshot unit ordered after network-online and before `qihse-node5-host.service`.
An executable `qihse-t320-neighbor` if-up hook reapplies the entry when `vmbr0`
comes up. The hook was also exercised with `IFACE=vmbr0`. No network interface
or QIHSE daemon was restarted. The existing `.250` listeners and peer identities
were retained. Changing the alias to `.95` is therefore no longer required to
restore the demonstrated path.

Verification after the repair:

- Neighbour state is `PERMANENT` with the verified MAC.
- Three sourced pings from 730xd to `.250` succeeded, with zero loss and about
  0.625 ms average latency.
- A TCP connection from 730xd to T320 port 7101 succeeded.
- Authenticated QKP queries show T320 and 730xd both report `cluster_state:ok`
  and zero failed or potentially failed slots. T320 now reports 730xd connected.
- Cluster-bus packet captures verify the repaired path separately from client
  port reachability.

This bypasses the failed alias ARP resolution. It does not establish the exact
intervening switch/link fault, and the mapping must be updated if T320's MAC
changes. Existing conflicting ownership maps remain a separate recovery issue.

## Progress

The demonstrated 730xd-to-T320 network failure is repaired and persisted.
Source integration, data reconciliation and ownership convergence continue
under the recovery plan. Network repair does not imply the cluster recovery
is complete.
