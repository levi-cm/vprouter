# Task 8c — autonomous single-exit guard integration

Status on 2026-10-29: **IN_PROGRESS**. The first implementation slice is
component-tested and independently approved; full task8c is not complete.
Production invocation remains unavailable. No privileged/VM/container/profile/
identity operation was performed by this implementer.

The starting checkpoint was clean `b678e7bf98e0c311109ce82a3893b40127ef0825`,
branch `rust/v2`. Root retains Git staging/commit/push, cross-platform freezes,
program manifests/image contexts and all privileged local testing. There are no
new enrollments, cloned identities, runtime invocations or release claims here.

## Slice 8c.1 — implemented, focused checks and independent review passed

See [task-8c-slice1-report.md](task-8c-slice1-report.md) for the exact owned files,
hashes, commands, initial failed check outcomes and final results.

The private operational wire path now reports the actual read-back policy as
Offline/Bootstrap/Ready with the complete exit/generation Binding. A health state
or a successful recording acknowledgement cannot substitute for that receipt.
Failure publication requires bound Offline before advertisement withdrawal;
failed Blocked, Stopping and Failed commits remain Offline. The worker returns
the original sample error only after successful quarantine publication, and
returns the safety-transaction error if acknowledgement fails. It does not issue
another provider request behind full Offline containment.

Healthy evidence-bearing recovery samples retain Bootstrap; Ready still requires
the guard's independent HealthMachine streak, native policy, exact host evidence
and independent executor lease proof. Stopping/Failed are evidence-free,
reason-bound terminal states in the guard's independent observation machine;
subsequent state changes cannot revive that machine.

Checks: worker library 62 passed; launch library 147 passed; focused strict
Clippy, whole-workspace formatting check and `git diff --check` passed. These are
unprivileged component checks. New native policy-receipt execution, actual
enrolled provider/approval/client behavior and static platform builds for this
delta are **NOT_RUN** by this implementer.

## Slice 8c.2 — necessary retained runtime continuation, not implemented yet

The existing secret-free foundation is retained and must be reused. The
`BootstrappedOwner` in `attachment/operational/bootstrap.rs` owns the complete
original `OperationalOwner`, exact canonical Server/Source and three original
scope query/Bootstrap completions. Its native Bootstrap fixture remains a
separate Root qualification gate. It exposes no producer placement, UP,
readiness or fresh present-tense policy authority, deliberately.

The older `GuardTransport::activate` is not a valid bridge: it requires a
host-side protected `Profile`, creates a fresh ProducerGroup, opens fresh native
actuators and performs its own creation sequence. Reconstructing its owners from
new history bytes, calling it after secret-free Bootstrap, or adding arbitrary
raw-descriptor getters would discard original custody and the secret boundary.

Concrete continuation map:

| Existing file/interface | Required next connection |
| --- | --- |
| `attachment/operational/bootstrap.rs::BootstrappedOwner` | Consuming runtime transition retains the same heap owner and all three original scope completions; interrupted construction must retain that entire owner. Historical `verify_bootstrap_chain` is not a refreshed native audit. |
| `kernel/bootstrap.rs::Verified`, `netfilter/fixed_bootstrap.rs::VerifiedBootstrap` | Add a narrowly typed original-owner continuation for fresh native policy/network observation and fixed UP mutations. Keep the original sockets/timer/sequence/producer ancestry and registrations; do not export a general actuator or mint a SocketProducer from wire data. |
| `owned/preparation/bootstrap.rs`, canonical preparation records | Persist runtime-transition intent/birth/result and original resource provenance through the existing serialized Server. Fixed per-operation budgets and actual original-child reap/cancellation remain necessary; fresh epochs cannot revive expired history. |
| `attachment/operational.rs`, `kernel/producer_creation.rs` | Carry the same original producer identity into fixed daemon/worker placement. Empty producer at Bootstrap installation is not evidence that a later placed process is authorized. Fresh process/cgroup/netns/program identity must be bracketed independently. |
| `handoff.rs::Handoff`, `transport.rs::ObservationAudit` | Reuse bounded authenticated protocol and independent expiry behavior through a private retained runtime authority rather than the old host-Profile creation constructor. The newly tested receipts remain wire observations only. |
| `owner.rs`, `expiry.rs`, `expiry_owner.rs` | Join the new runtime owner to independently scheduled host/network terminal writers before any usable link/Ready transition; retain full quarantine if owner, native audit, Docker, worker or publisher stalls. |
| worker `engine.rs`, `localapi.rs` | After a failed sample the worker now terminates safely. Actual failure-to-Bootstrap recovery still needs a fresh host-authorized lifecycle with independently observed withdrawal and original custody; no caller boolean may authorize it. Preserve bounded retry/three successes and fresh offered-and-approved same identity. |

The next increment must produce live connected enforcement/lifecycle behavior,
not merely a public preparation wrapper around this table. Existing fixed
manifests, confinement, init, namespace placement, original Source and bounded
role mechanisms remain the foundation; no whole-project restart is needed.

One concrete ordering barrier is visible in
`network/guarded.rs::activate_quarantined`: every UP/address/route step requires
fresh three-scope **Offline**, while the new native Bootstrap operation has
already installed Bootstrap policy. Therefore Bootstrap history cannot be used
directly as link-activation permission. The new runtime must first restore and
freshly verify full Offline through the retained original policy owners, arm
independent terminal protection, perform fixed guarded link/address/route
mutations, place only the exact admitted daemons, observe stale-advertisement
withdrawal, then independently permit producer-only Bootstrap. Each subsequent
operation needs a fresh bounded native observation; the original two-second
Bootstrap clock is historical and cannot simply be extended or reused.

## Root fixture requirements and mandatory remaining gates

First qualify the existing exact-source native Bootstrap family separately from
run397's 17 actual-program regressions. Then bind new runtime source/artifact
hashes to actual fixed guard/worker/init execution and packet observations.
Required integrated cases include a preexisting resource-name collision,
SIGKILL at durable activation/cleanup boundaries, freeze/crash/OOM/container
death, stale complete verification despite responsive heartbeats, stalled
Docker/provider/fsync, route/link/peer/policy/producer drift, failed atomic
updates, exact ownership retirement, independent terminal scheduling and bounded
shutdown. Bootstrap must block consumer OUTPUT and spoofed-source Tailscale
forwarding under each independent policy; continuous IPv4/DNS/IPv6/TCP/UDP
markers require positive capture controls and zero forbidden markers/drops.

Only Root may execute those privileged local checks. The stopped-state move of
the approved lab identity and actual distinct-device protected profile/client
tests remain mandatory, with node/IP/state preserved and no concurrent identity
use. Ready/advertised is not real-client egress proof. Client-side guards remain
an explicit gate where required. No multi-exit/direct/migration runtime is
enabled by these slices. ARM64/static runtime, other platform/service, full
performance, reboot, migration, real-client and 24-hour acceptance remain open.

## Prior evidence reconciliation

Task8a/8b scoped approvals are retained. The task8b2 independent review is bound
to `90a7dcc` and run396; the separate current-source regression review is bound
to `b51b5d7`, its 202 exact source inputs and run397. Neither certifies new native
Bootstrap execution or this task8c delta. Historical failed attempts, retained
resources and NOT_RUN gates are unchanged. See the new parent
[task-8-report.md](task-8-report.md) for the scoped evidence index.

## Root review reconciliation

Independent review `task-8c-1-review.md` approves bounded slice8c.1 spec and
quality with no findings. Root separately ran 209 focused tests, fmt/diff and
strict Clippy successfully and matched all six source hashes. Coherent static
freeze completed as recorded below; no new native receipt/runtime acceptance is claimed.
Prior-source Bootstrap attempt398 failed before its first Bootstrap writer;
see `docs/rust-v2/task8c-bootstrap-attempt398.json` and the diagnosis report.
All failed resources and six selectors remain retained. Full8c stays ACTIVE.

Root coherent offline static freeze `5a224c16a79c1e90f0d720e41cdbbc2e816d9580`
completed successfully: 202 exact current/archive/Git inputs, both static ELF
payloads, both pinned seven-file public contexts and all program hashes/sizes
verified. Exact AMD64 filter preflight passed. Both contexts copied into the
immutable candidate directory `target/continuation-20261029T124811Z`. See
`docs/rust-v2/task8c-slice1-verification.json` for public hashes. ARM64 execution,
new native receipts and integrated runtime/client gates remain NOT_RUN.
