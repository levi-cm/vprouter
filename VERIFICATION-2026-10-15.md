# Exit-node runtime storage repair — 2026-10-15

## Cause

The retained host journal records 2,186 failed automatic restart attempts before
the router recovered at 13:55 CEST. Around the final failed attempts, Docker
logged `OCI runtime exec failed: write /tmp/runc-process...: no space left on
device`. The host `/tmp` is a shared 7.8 GiB tmpfs, still 98% used during this
investigation, while the root disk had about 63 GiB available. Exhaustion of
runtime temporary storage prevented the host's firewall-ready exec check from
succeeding. Its stderr was discarded until a generic timeout, and the entry
point logged only `SiteError`, obscuring the storage failure.

A process trace confirmed the router's old containerd shim created those files
in `/tmp`. Temporary-file creation belongs to the shim, so a Docker-only
`DOCKER_TMPDIR` setting would not fix the observed failure.

## Change

Installed `host/containerd-tmp.conf` as a containerd systemd drop-in. It creates
root-only `/var/lib/containerd-tmp` on the disk-backed filesystem and sets
`TMPDIR` for new shims. Verified `KillMode=process` before restarting containerd.
Existing unrelated shims retain their previous environment until their own
containers are recreated; they were not deliberately restarted by this repair.

The firewall wait now reports runtime ENOSPC immediately, and authored
`SiteError` details reach the journal. Raw external command output remains
excluded from the error log. Firewall rules, default-deny behavior, endpoint
pinning, Tailscale identity and the private WireGuard profile were preserved.

Rebuilt the router image and installed the reviewed host supervisor. Drained
the coordinator and dependent workers, recreated the router under the shared
gateway lock, rebound suggestions and restored the coordinator. The deployment
script initially held that lock while starting the coordinator, whose required
reconciler also uses it. Released the lock before coordinator restoration;
restoration succeeded. No request, archive, acknowledgement or provider-hold
state was reset.

The latest Web UI/application source was rebuilt and deployed with the existing
service bindings. Served JavaScript and CSS bytes match the running rebuilt
image. The live application health endpoint succeeds.

## Verification

- Regression test failed before the fix: runtime storage exhaustion was hidden
  behind the firewall-ready timeout. It passes with the corrected handling.
- All 38 unit tests pass; `git diff --check` passes.
- Isolated host endpoint filtering and real WireGuard namespace packet tests
  pass, including protected forwarded traffic and return packets.
- Disposable leak probe: two unguarded positive controls emitted their markers;
  all eight guarded fault scenarios emitted zero plaintext packets on the
  synthetic WAN.
- Live drained-router fault test: disabling WireGuard blocked IPv4, DNS and
  IPv6 probes from an unprivileged, capability-free client. The router was
  recreated and protected Mullvad egress recovered.
- The new router shim's environment contains the disk-backed `TMPDIR`; a real
  exec trace shows `runc-process` files under `/var/lib/containerd-tmp` and none
  under `/tmp`. This verifies deployment beyond the service configuration.
- Host and a separate Tailscale container can reach the preserved exit node.
- Four full 20-minute foreground waits and rechecks are required before the
  final stability result is recorded below.

## Historical IP exposure limits

No confirmed real client traffic leak to websites was found in the retained
reports or this incident's logs. The legacy-router security audit concerns an
older `max-vprouter` deployment, not this current `nico-vpn` deployment. It
reproduced plaintext bypasses in disconnected synthetic tests; it establishes
historical vulnerabilities, not observed real browsing leakage. An early live teardown
emitted provider-facing ICMP quoting encrypted outer transport packets. The
VPN provider already observes the host's transport address; this is distinct
from leaking inner client traffic to websites.

The original historical packet captures were not available on this machine
for reinspection.
There is no continuous packet history for this outage and remote client
fallback behavior was not observed. Current containment tests support the
router's failure behavior; they cannot establish that an IP never leaked.

## Stability result

All four required full foreground waits and rechecks passed consecutively.
Each wait ran `sleep 1200` before its recheck; none was shortened.

| Check | Seconds including recheck | Samples | Handshakes | Failures | New restarts |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 1204.0 | 40 | 10 | 0 | 0 |
| 2 | 1203.6 | 39 | 10 | 0 | 0 |
| 3 | 1203.6 | 40 | 10 | 0 | 0 |
| 4 | 1203.5 | 39 | 10 | 0 | 0 |

Total: 158 clean samples and 40 distinct per-window handshake observations.
The same router container remained READY and online throughout the fresh
streak. Both Tailscale reachability checks and protected provider egress
passed at every recheck. The router journal contains no state changes or
errors during this final streak. This proves bounded stability of the exit
node and restored dependencies; it does not claim useful provider downloads.


The first attempt passed its initial 20-minute check (40 clean samples,
11 distinct handshakes). An independent application deployment subsequently
stopped/restarted the coordinator and replaced the Web UI, failing a dependency
sample during the second wait. The router remained READY, online and unchanged
with zero new restarts. Preserved that deployment and retained the interrupted
monitoring evidence separately. The entire four-wait streak was restarted;
the interrupted attempt does not count toward final acceptance.
