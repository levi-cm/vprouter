# Controlled performance accounting and optimization

PREPARATION ONLY; dispatch after reviewed actual runtime/client/migration/release
integration. Workdir /DATA/AppData/vprouter-rust-v2, rust/v2, no subagents. Binding
IMPLEMENTATION.md/user handoff. Root alone controls credential-bearing owned-lab
workloads. No production benchmark/fault/restart, publication or identity cloning.

Build repeatable old/new comparisons on the SAME isolated host, pinned Tailscale
version, identity/peers, traffic and network conditions. Never run same identity
concurrently; stopped-state compatibility/backup and reviewed quarantine remain
required. Earlier20/45second uncontrolled samples are orientation, not baseline.
Repeated ten-minute steady-state runs plus controlled loads, separately for one,
five and six exits, with exact source/artifact/config/workload and clock binding.

Account hostguard, workers, init/shim, Docker work, relevant kernel traffic and
runtime overhead; separate Tailscale/kernel buffers from control PSS targets while
reporting total footprint. Measure actual CPU/PSS/throughput/p95latency/deadlines/
restarts/OOM, not configured limits as savings. Gates: one-exit supervision CPU
>=50% below newly measured Python baseline; total memory<=baseline; Rust control
PSS target<=16MiB one/<=48MiB five; throughput>=95%baseline; p95latency<=105%; no
monitor deadline miss, unexpected restart or OOM. No security-check suppression,
provider interval change, weakened verification or traffic coverage reductions.
Cadence5s, retry1s/rechecks, handshake180s, health45s/watchdog90s retained. Adjust
intervals only through separately justified explicit detection-latency decision.

Optimize actual native monitoring/client reuse/timers/allocations/resource ceilings
only when measured bottleneck warrants; never pool sockets across namespaces.
Tighten limits only after controlled load. Independently review code changes and
compare behavior/fault evidence on exact optimized bytes. Focused checks and
explicit commits; task-14-report.md includes raw machine-readable samples,
accounting/workload details, repeated-run summaries, uncertainty and unavailable
gates. Unsupported/skipped host/platform workloads remain NOT_RUN; synthetic-only
numbers cannot satisfy mandatory real Tailscale-client release claims.
