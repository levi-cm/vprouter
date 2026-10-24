# Rust v2 implementation contract

Source: user implementation handoff, 2026-10-24. This is an implementation,
not authorization to bypass any mandatory acceptance gate.

## Binding requirements

Preserve local retry repair and existing credentials, identity, IPs, state,
approvals, container and service compatibility. Never mutate unrelated services.
Linux 6.1+, cgroup v2, nftables, kernel WireGuard, TUN; Debian 13,
Arch/CachyOS systemd and Void glibc runit; x86_64 and ARM64.
One gateway and independent Rust host guard. Each explicitly enabled exit owns
its data namespace, transport namespace, policy, state and worker. Single exit
has no placeholder additional runtime resources. WireGuard is created in its
transport namespace and moved into data namespace. No plaintext transport link
inside Mullvad data namespace. Direct is explicitly configured only, public IPv4
only, independently isolated, never a fallback. IPv6 forwarding blocked.
Launch helper single threaded: validate owned container/PID/root/cgroup/ns,
private mount view, join cgroup, close FDs, drop caps then exec. No persistent
SYS_ADMIN, privileged Docker, socket inside container or host networking.
Atomic nft policy; quarantine before transport, per-exit ownership, persistent
allocation records, ambiguous cleanup retains quarantine. No unrelated flushes.
Native netlink/Docker Unix API/Tailscale LocalAPI; no steady-state shell/CLI.
Pinned Rust, lockfile, Tailscale version and OCI base digests. HTTPS bounded,
certificate checked and namespace-local; no cross-exit pooled connections.
Provider check every 5s, handshake <180s, heartbeat <45s, host watchdog 90s.
One retry after 1s for HTTP 408/429/5xx or eligible transport errors, with fresh
interfaces/routes/handshake; permanent/malformed/negative/wrong server fail closed.

Schema v2: deployment ID, required site (debdev here), pinned image; stable exit
IDs, enabled flag, tagged mullvad/direct mode, absolute private state directories,
Mullvad profile+expected server, explicit adapters and client policy references.
Unknown fields/version, duplicate state/key, unpinned image, resource conflicts,
mixed-mode metadata and automatic fallback rejected. Legacy unversioned site
converts to one Mullvad exit retaining paths. Naming: mullvad-{site}-exit-{server}
and unsafe-direct-host-ip-{site}-exit; DNS label <=63; append stable exit IDs to
ALL duplicate names; no truncation. State and node IDs never derive from display
names. Root-owned locked, generation checked, atomic fsync allocation files.

CLI JSON: validate; status/probe (observational, fresh verified fields or
not_tested); exit add/remove/enable/disable; migrate inspect/plan/apply/rollback;
client install/select/status; diagnose. No passwords/keys in argv/logs/reports.
Direct reports direct-exposed, never protected. Legacy wrappers remain during
compatibility release without persistent Python. Adapters absolute argv with
bounded idempotent drain/stop/rebind/start/health-check. Uncertain dependency
ownership or missing adapters blocks unattended cutover.

Migration: inspect, stage, fingerprinted plan, independent quarantine and client
coverage, drain+stop+verify, stopped-state root-only backup, transactional REAL
release directory activation, restore and verify same identity/IP/server then
rename, actual client/isolation/dependency verification, commit+resume. Failure:
quarantine first, compatible release AND state restoration or leave offline.
Idempotent under lock; interrupted resume/reversal. No concurrent identity copies,
no enrollment cloning, no credential recreation, no Docker daemon restarts.
Unknown external hostname dependencies must be declared before unattended rename.

## Work packages and gates

1. Baseline/fixtures: source/main/retry/runtime inventory, hooks and CLI shapes,
   fresh same-host performance samples, no secrets.
2. Config/state: strict schemas, naming, allocation records, reason codes,
   STARTING/BLOCKED/RECOVERING/READY/STOPPING/FAILED; adversarial tests.
3. Single-exit guard: native ownership/namespace/firewall/quarantine/watchdog;
   prove parity before multi-exit runtime.
4. Worker: native monitoring, exact server, bounded retry and safe logs.
5. Container/helper: minimal Rust init and namespace/cgroup/capability isolation,
   no Python image runtime.
6. Multiple Mullvad exits: independent identity/profile/lifecycle; shared endpoint
   and overlapping tunnel IP fault tests.
7. Explicit direct mode: public destination policy and strict separation.
8. Persistent Linux client guards incl userspace SOCKS/HTTP, no DNS/IPv6 fallback,
   narrowly identified Tailscale daemon exemption; direct explicit node+mode.
9. Migration/adapters/wrappers: inspect/plan/apply/resume/rollback; current main,
   retry variant, custom hooks and interruption at every transaction boundary.
10. Services/releases: systemd/runit, x86_64+ARM64 artifacts, checksums/provenance,
    install/reboot/update/rollback/uninstall ownership tests and agent guide.
11. Performance: repeated 10min runs, one/five/six exits. >=50% supervision CPU
    reduction; total memory <= baseline (control PSS targets 16/48 MiB); throughput
    >=95%, p95 latency <=105%; no monitor misses/restarts/OOM, full overhead.
12. Independent acceptance and canary: namespace/firewall/unsafe review; debdev
    preserving primary identity; second existing installation; 24h mixed soak.

Every package requires focused tests, reviewable commit and recorded evidence.
Runtime must not be activated until prerequisites pass. Release cannot be claimed
from synthetic namespace tests or configuration tests.

## Mandatory acceptance

Real disposable Tailscale clients generating IPv4, DNS, IPv6, TCP, UDP; capture
at client WAN, host WAN, transports and data. One Mullvad, five Mullvad, direct,
and five+direct configurations. Positive capture controls; zero forbidden
plaintext/cross-exit markers; host IP as Mullvad app egress immediately fails.
Failures cover deleted/down/stale/wrong peer/key/endpoint/provider responses;
route/default/endpoint/Docker/IPv6/interface/source spoof drift; firewall removal,
failed atomic update and foreign ownership; crashes/freezes/OOM/container/Docker
restart; full disk/API timeout/reboot; revoked identity/control/approval/name;
one failed exit beside direct/healthy exits; client disappear/select/restart/
route/DNS/proxy/bypass; migration kills at every boundary. Boot capture must be
operational BEFORE protected traffic. Skips/unknowns are unverified and block
claims. No unmanaged/non-Linux client guarantee.

Artifacts: schema + 1/5/mixed examples, exact agent/systemd/runit migration,
validation/recovery/rollback guide, compatibility matrix, redacted reports,
security-to-test mapping, workload/accounted benchmarks, immutable artifacts,
SBOM/provenance, unsupported environments. Do not publish until all gates pass.

## Execution-scope amendment: local testing only

On2026-10-24 the user explicitly required: "i want you to do all the testing
locally". Run acceptance on this host and isolated local VMs/disposable clients;
do not seek or use SSH access to remote immo/other installations. Tailscale and
Mullvad protocol/provider traffic from those local test systems remains part of
the required real-client tests. The second migration case uses a separate local
legacy deployment with an independently enrolled test identity, recorded state
and declared adapters; preserve that existing test identity through cutover and
rollback. Label this evidence as local compatibility-deployment migration, not
validation of a remote installation. Preserve all fault, containment, identity,
benchmark and soak gates; unavailable platform/hardware checks remain explicit.
