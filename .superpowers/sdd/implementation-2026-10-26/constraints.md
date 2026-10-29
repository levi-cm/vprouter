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
