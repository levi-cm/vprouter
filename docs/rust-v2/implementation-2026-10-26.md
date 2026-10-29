# Complete the nine verification findings

## Authority and specification

User instruction: "launch a subaent to impliment all of this then teest and a verification subagent".
The nine-item verification summary and docs/rust-v2/IMPLEMENTATION.md define the
scope. The original task briefs under .superpowers/sdd/rust-v2/task-8c-brief.md
through task-15-brief.md provide the detailed runtime, client, migration, service,
performance and acceptance requirements. They are implementation requirements,
not proof of completed work. Existing approved architecture is retained.

## Global constraints

- Work in the existing isolated /DATA/AppData/vprouter-rust-v2 worktree on rust/v2.
  Preserve all existing uncommitted work. Baseline HEAD c6a138c; last tested source
  snapshot 1b0d7e723f51c54e0c2d624f2fb15a8d32b6fdaa. No reset, clean or discard.
- Preserve production Python router, services, containers, state, credentials,
  identity, IPs and approval. No production activation, benchmark, faults, network
  changes, Docker daemon restart, remote installation access or publishing.
- Testing is local: unprivileged ordinary tests plus owned isolated local VMs.
  The root controller exclusively runs privileged/credential-bearing lab actions;
  the implementer supplies exact frozen artifacts and instructions.
- No plaintext or automatic direct fallback; no broad root/UDP/DNS exemptions.
  Quarantine precedes usable networking and persists through uncertainty/stop.
  All new production authority must be verified through native ownership tokens,
  process/namespace/cgroup identity and exact policy. No bool bypasses or test
  flags in production. Keep unsafe operations in the reviewed Linux boundary.
- Retain 5s provider cadence, one eligible retry after 1s with fresh checks,
  handshake <180s, health <45s and independent 90s host watchdog.
- Meaningful regression tests precede fixes. Run appropriate tests, fmt, clippy
  and static x86/ARM builds; stage-only or compile-only is not runtime evidence.
  Maintain source/artifact binding and failed-run history.
- All nine areas stay in scope. A report must identify what is implemented,
  tested, not run or externally blocked. Never substitute a plan, schema or
  mock-only suite for the requested production behavior. No release-ready claim
  until mandatory acceptance actually passes.
- One implementation subagent works sequentially through this connected scope;
  it must not spawn agents. An independent verification subagent follows the
  completed implementation/testing. Controller handles review fixes through the
  original implementer and repeats only the affected verification.

## Task 1: Implement, integrate and test all nine findings

### Phase A: Secret lifetime and shared health contract

1. Replace optimizable key erasure and ordinary owned profile buffers with
   compiler-resistant zeroization, including parser error paths and duplicate-key
   canonical-scalar tracking. Preserve duplicate identity detection and redaction.
2. Define a shared versioned health wire format binding deployment, exit, mode,
   generation, config, boot, expected server and actual evidence. Connect the
   worker publisher to an authenticated host publication bridge and CLI reader.
   Paths, ownership, staleness and replay checks must agree end to end; cached
   health alone must never grant readiness. Add producer-to-reader tests.

### Phase B: Shared host authority and operational runtime

3. Replace mutually interfering frozen whole-host baselines with a shared,
   generation-bound authoritative host model. Adding/removing exit B must not
   falsely quarantine A. Preserve exact per-exit namespaces and reject genuine
   host policy/route/source/ownership drift. Handle legitimate unrelated host
   resources explicitly instead of accepting arbitrary live state.
4. Finish authenticated guard/worker/init startup, periodic monitoring, native
   provider checks, quarantine, shutdown/recovery and independent watchdog. Wire
   actual CLI/lifecycle operations through verified placement authority; remove
   refusal paths only after real enforcement prerequisites are established.
   Integrate independent multiple Mullvad exits and explicit isolated direct mode
   (public IPv4 only, direct-exposed, never fallback). Reuse existing components.

### Phase C: Persistent clients and migration

5. Implement client install/select/status for kernel Tailscale clients and
   scoped userspace HTTP/SOCKS gateways. Persistent owned enforcement must prevent
   ordinary WAN, DNS and IPv6 fallback on exit loss, daemon stop, route reset,
   proxy failure and bypass. Bind exact authorized node ID and explicit mode;
   unsupported/unowned application scopes refuse protected readiness.
6. Implement locked durable inspect/plan/apply/resume/rollback with independent
   quarantine, declared bounded adapters, stopped-state private backups, REAL
   release activation and exact identity/config/state preservation. Never run two
   copies of one identity. Tests use two separately established local disposable
   legacy installations; keep production untouched. Compatible rollback or offline.

### Phase D: Supported services, hostile faults and measured performance

7. Implement supported systemd and runit cgroup/service admission and native
   lifecycle integration, immutable install/update/rollback/uninstall artifacts,
   pinned provenance/checksums/SBOM and static x86/ARM outputs. Preflight unsupported
   layouts before mutation. Actual ARM runtime and Void/Arch tests require actual
   local environments; record availability honestly.
8. Extend actual VM tests with live post-pin TUN/rule/address/route drift,
   guard/worker/daemon crash/freeze, real interrupted transactions and persistence
   across restart/reboot. Use real disposable Tailscale clients and all four
   configuration shapes in acceptance.json with IPv4/DNS/IPv6/TCP/UDP, positive
   capture controls and zero forbidden markers/drops. Map tests to requirements.
9. Build repeatable same-host Python/Rust one/five/six-exit workload comparisons,
   repeated ten-minute samples with complete CPU/PSS/throughput/p95 accounting.
   Optimize measured bottlenecks without reducing monitoring coverage. Prepare and
   run the real mixed 24-hour soak once prerequisites pass; elapsed time cannot be
   replaced by short tests. Keep incomplete workload/platform gates open.

### Execution and report contract

Read the complete binding specification and actual interfaces before code.
Maintain a nine-area status table in the report and send the controller concise
milestone updates, including exact local-lab test requests. Continue independent
implementation while controller-owned lab actions run unless source freeze or
interface dependencies require waiting. Do not silently drop difficult areas.
If the scope cannot fit one context, persist the state and exact next step in
the report and request continuation; do not declare the overall task done.

Write a full report in the plan workspace with changed files, implemented
behavior, commands/results, failed attempts, source/artifact bindings, resource
and unsafe/capability inventory, and remaining gaps. Return short status plus
report path. The controller will perform final independent verification.
