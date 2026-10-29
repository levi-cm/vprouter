# Continue implementation: authenticated health bridge and operational runtime

Read constraints.md first, then this brief and task-1-report.md's exact resume
section. User authorized all nine findings, implementation, tests and a final
verification subagent. This is a focused continuation of that active task, not
a new scope or a request to stop after preparation. Do not spawn agents.

Baseline tested source now 899a874ac70b1710b23d766d498f5068297a5657 (immutable local
candidate; branch HEAD remains c6a138c with all changes uncommitted). Existing
shared health/schema clock, zeroization and aggregate host model are implemented.
Controller actual run24 passed, including four post-pin faults; transport rerun
is ongoing. The whole nine-area task is incomplete.

## Focused deliverable

Finish the authenticated host health bridge and connect the actual production
guard/worker/init single-exit lifecycle to it. Work in existing interfaces before
inventing parallel fake orchestration. Bind the shared health schema to exact
live process/program/cgroup/netns, allocation generation, deployment, exit,
configuration, boot and worker-lifecycle nonce/sequence. Worker publications must
be accepted through authenticated retained authority, validated, atomically
published by the host and actually consumable by the CLI. Root-owned files and
cached status are not runtime readiness authority.

Complete a fixed immutable operational worker role, protected bootstrap and
unforgeable production placement. The existing ObserveOnce observer remains
observation-only; do not turn it into a generic executable/argv override.
Wire the existing native Engine provider/retry/LocalAPI implementation to actual
guard enforcement states, fresh network observations, safe advertisement, exact
node/server/mode and independent expiration/watchdog. Preserve quarantine-first
failure/shutdown and actual bounded child cleanup; no automatic direct fallback.
Provide an actual CLI/startup route that refuses insufficient authority and can
operate when native prerequisites are established. Do not merely remove refusal
returns or add a caller-supplied protected/ready boolean.

Critical integration dependencies already identified:
- GuardTransport currently owns Transaction's exclusive deployment allocation
  lock. Fleet runtime needs a shared lock/journal owner; independent locks for
  exits deadlock. Resolve the ownership model for actual add/remove lifecycle.
- Operational daemon metadata must allow only identity-bound authorized
  Tailscale addresses/routes/rules. Existing daemon_data intentionally handles
  only the fixed unenrolled no-address observation fixture. No recaptured live
  baseline or broad table52/IPv6 authorization.
- Native WG inspection privileges, worker/guard responsibilities and confinement
  must be demonstrated with exact fixed-role capability/seccomp authority.
- A provider stall cannot stall the independent host expiry/watchdog.
- Shared host changes must preserve unaffected exits while rejecting real drift;
  explicit per-exit namespace authority remains mandatory.

Read docs/rust-v2/IMPLEMENTATION.md and earlier task-8c/task-9 briefs as binding
detailed specifications. Preserve cadence5s/retry1s/handshake180s/health45s/
hostwatchdog90s, imported identities/profiles and all existing tests. Root alone
runs privileged and credential-bearing lab tests; send artifact/source-freeze
requests and exact harness cases. Root has local Debian/x86, Arch/x86/systemd,
Debian/ARM64 underTCG and a Void/runit environment being staged. Do not touch them
directly or read secrets. Ordinary tests/static builds allowed; coordinate
manifest/context refresh. Driver target/continue-nine-area-build.py includes
new Rust files through alternate index; confirm exact filename in prior report.

Use meaningful red/green tests, preserve all prior dirty work and test records.
No production changes, root test actions, publishing, reset/clean or real-index
mutations. Never claim real-client or release acceptance from synthetic tests.

Maintain runtime-bridge-report.md with exact changed APIs, tests and source
bindings, actual versus pending authority, nine-area status, and exact resume
steps. Send progress at milestones. Continue implementable runtime work rather
than stopping at a sketch or plan. If context handoff is necessary, save precise
state and return NEEDS_CONTEXT; do not claim the overall task complete. After
runtime integration, remaining client/migration/platform/performance scope will
continue under the same parent task and final independent verification.
