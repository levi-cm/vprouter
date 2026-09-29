# First-site router verification, revision 3

This record covers `max-vprouter` on the current host and the root-owned
release at `/opt/vprouter/current`. The pinned image is
`sha256:18c1d8c5c87df13ed665a6bf72511115dee288caa24854193400918d1879dd1f`.
The previous hardened images
`sha256:1648a13ad7c7a2e9d08b055fb5945b4b40bad0bd7212b17ca5fe9fdc94fb0e16`
and `sha256:5e005133781efb99ae9c8687b6ad442c76905d3d65b464c08387300f76e0c893`
and their source are retained for rollback. The legacy router is not a rollback
target. Package versions are in [RELEASE-INVENTORY-2026-09-27.txt](RELEASE-INVENTORY-2026-09-27.txt).

## Changes verified

- READY now requires Tailscale `Self.ExitNodeOption=true`, meaning the exit-node
  offer is approved as well as advertised. Pending approval remains BLOCKED;
  revocation after READY makes the runtime withdraw its Tailscale service.
- The host compiles `router.nft` from the root-owned release in an isolated
  network namespace and compares the complete normalized policy with the
  router's live nftables table before provisioning, on every monitor cycle,
  and in status. Only handles and counter values are ignored.
- An atomic runtime heartbeat advances during BLOCKED and RECOVERING as well
  as READY. A 45-second stale or malformed record triggers containment and
  restart; fresh BLOCKED remains in place. systemd's 90-second watchdog
  restarts a stalled host monitor.
- An independent host nftables quarantine at priority -310 blocks the
  dedicated bridge and subnet before Docker cleanup. Startup removes it only
  after verifying the bridge, router policy, host guard, and WireGuard
  interface. Stop keeps quarantine if container shutdown cannot be confirmed.

## Verification matrix

| Check | Result | Evidence and limit |
| --- | --- | --- |
| Python unit and contract suite | PASS, 31 tests | Approval, heartbeat, malformed health, nft comparison, cleanup failure and quarantine behavior |
| Isolated host packet probe | PASS | Approved UDP endpoint and reply passed; wrong port, host input, renamed bridge and Docker cleanup failure remained blocked |
| Isolated WireGuard namespace probe | PASS | Router and synthetic tailnet packets traversed a real WireGuard tunnel; plaintext on transport was false |
| Disposable router packet injection | PASS | Two unguarded positive controls emitted payloads; eight guarded faults emitted zero plaintext packets on test WAN |
| Live stop/start | PASS | Quarantine present during stop; both managed containers inactive; READY after 35 seconds; physical capture had zero test payloads |
| Live frozen router container | PASS | Quarantine and restart; READY after 35 seconds; physical capture had zero test payloads |
| Live WireGuard deletion | PASS | Quarantine and restart; READY after 40 seconds; physical capture had zero test payloads |
| Live router nftables drift | PASS | Status failed and installed quarantine; monitor restarted; READY after 45 seconds; physical capture had zero test payloads |
| Live frozen runtime | PASS | Stale heartbeat triggered quarantine and restart after about 47 seconds; READY after 84 seconds; physical capture had zero test payloads |
| 30-minute limited CPU and memory pressure | COMPLETED WITH TWO STATUS FAILURES | Container limited to 0.25 CPU and 1 GiB with a 512 MiB workload. Of 180 status samples, 178 were READY and two failed around 17:28 UTC; READY returned by the next sample. The physical capture recorded 19,531 packets, zero kernel drops, and no packets to the reserved test destination. These observations do not establish zero plaintext leakage for every packet. |
| Host monitor watchdog | PASS | On r3 the systemd watchdog restarted a frozen monitor; journal recorded READY 116 seconds after fault, and the physical capture had zero test payloads |
| Full host reboot leak capture | INCOMPLETE | The host rebooted and the synthetic sender reported sending a packet. The physical capture failed because `ens18` was not up when `tcpdump` started; no reboot pcap exists, so boot-time leak acceptance is unproven. |
| Real disposable tailnet client | NOT_RUN | Only the user's regular CachyOS client is available; its reported Mullvad egress and reserved-destination timeout are observations without a synchronized physical capture |
| Admin approval revocation and node-key expiry | NOT_RUN | Pending admin-controlled drills; the user's independent admin route is available |
| Current-image disposable Compose provisioning | NOT_RUN | The lab probe refuses the live host's existing bridge and guard; the prior hardened image passed this test |

Completed live physical captures filter the provider endpoint and the reserved
synthetic destination on `ens18`. Test payloads are unique per fault and are
searched as byte sequences in the capture. Provider transport packets are
expected; an unprotected test payload count of zero is the acceptance check
for these injections. Packet captures and a detailed manifest are kept with
root-only access under `/var/lib/vprouter/evidence-2026-09-27-r2/` and
`/var/lib/vprouter/evidence-2026-09-27-r3/`; only
sanitized results and hashes are published here.

This is a bounded first-site result. It cannot establish end-to-end client
fail-closed behavior without a real disposable client test, boot-time leak
containment without a successful reboot capture, or the effect of
admin-controlled node-key expiry without inducing that event. On 2026-09-29,
the router also entered short BLOCKED and RECOVERING periods before returning
to READY; this protects against unverified egress but interrupts availability.
No finite test rules out host-root or kernel compromise. The second location
and client-side kill switches remain deferred. Scheduled Tailscale update
automation remains deferred until a second tested exit node can carry traffic
during updates.
