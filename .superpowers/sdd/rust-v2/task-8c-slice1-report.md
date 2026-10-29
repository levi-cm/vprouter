# Task 8c.1 — explicit enforcement receipts and terminal failure publication

2026-10-29. Base `b678e7bf98e0c311109ce82a3893b40127ef0825`; uncommitted
implementer delta pending Root checkpoint. **Focused checks and independent
spec/quality review passed; actual kernel execution of this delta pending.**

## Changes and ordering

`operation.rs` adds observational PolicyState/PolicyReceipt wire data. The
receipt contains the complete Binding (including deployment, exit, generation,
node, config fingerprint and boot) rather than only worker HealthState.
Prepared and Enforced replies require that receipt; old no-policy ACKs refuse.
Lifecycle, exact monotonic sequence and original frame/publication deadlines
remain checked by the existing authenticated channel.

`transport.rs::policy_receipt` first reads back retained native policy for the
current stage. `handoff.rs` emits that receipt only after the existing exact
sender, daemon, allocation, independent executor and deadline checks. All
non-Ready preparations install/read back Offline first. Ready preparation may
report existing Bootstrap or Ready; Ready persistence still requires private
ReadyPublication proof and independent executor leases.

`apply_health` now receives the already independently validated snapshot so it
can distinguish a failed Blocked snapshot (reason/no evidence) from healthy
evidence-bearing Blocked recovery samples. Failed Blocked/Stopping/Failed use
Offline; fresh Starting/recovery use Bootstrap; Ready still uses native proof.

`engine.rs::operational_publish` rejects wrong preparation policy/binding before
withdrawal and wrong commit policy/binding/state afterwards. The production
loop calls `operational_complete`: quarantine publication must complete first;
then its original sample error terminates the worker. ACK/withdrawal/publisher
failure takes precedence. No post-failure provider sampling is attempted behind
Offline. Fresh autonomous rebootstrap is explicitly deferred to slice8c.2.

`expiry.rs::observe_original` admits only evidence-free, reason-bound terminal
Stopping/Failed observations, and latches against subsequent state changes.
Its timers, liveness messages, margins and complete-evidence expiry are unchanged.

## Verification

Toolchain: rustc `1.97.0 (2d8144b78 2026-07-07)`, Cargo
`1.97.0 (c980f4866 2026-06-30)`.

| Command | Result |
| --- | --- |
| `cargo test --locked -p vprouter-worker --lib` | Final PASS: 62 passed, 0 failed, 12.08s test runtime. |
| `cargo test --locked -p vprouter-launch --lib` | Final PASS: 147 passed, 0 failed, 2.10s test runtime. Earlier pre-terminal-extension run also passed 146/146. |
| `cargo clippy --locked -p vprouter-worker -p vprouter-launch --lib --tests -- -D warnings` | PASS. |
| `cargo fmt --all -- --check` | Final PASS. |
| `git diff --check` | PASS. |

Initial formatting check failed on the new delta; formatting was applied only to
owned Rust paths. Initial worker run was 60 passed/2 failed: the existing scripted
peer supplied Offline for Ready preparation, and the new malformed-receipt test
expected GuardUnavailable while the existing decoder correctly returned
Malformed. Both fixture expectations were corrected; the final full worker run
passed. Those failures are not rewritten as passes.

New real UnixStream matrix covers ten receipt cases: valid full transaction,
Bootstrap/Ready preparation forgery, changed preparation generation/exit,
Bootstrap/Ready commit forgery, changed commit generation, changed health state,
and historical missing-policy ACK. It asserts no withdrawal before the bound
Offline receipt, no provider call, safety-error precedence and original
ProviderNegative only after successful publication. Actual HealthMachine
transitions exercise failed Blocked versus fresh evidence-bearing recovery,
three-success Recovering, later Ready, Stopping and Failed policy expectations.
The independent guard terminal test covers reason binding and no revival.

Existing tests also passed for original 34s operation timeout during heartbeat
IO, replay/generation mismatch, separate90s watchdog, stale complete verification
despite liveness, original2s host evidence expiry, retry after1s with fresh
structure, three-success recovery and bounded stalled publisher behavior.
The scripted fresh-sample test is deliberately named as such; it is not native
same-lifecycle recovery through full Offline policy.

## Exact owned source files

| Path | SHA256 |
| --- | --- |
| `crates/vprouter-worker/src/operation.rs` | `2ec561f7beac44fe84a542baff1c0d37152303f22dffa323b32d7422e85c1771` |
| `crates/vprouter-worker/src/engine.rs` | `5b7045736012a472573af427ad65b20f1e70fd8d5e63957607ffc2ea477b894a` |
| `crates/vprouter-worker/src/engine/tests.rs` | `dd3e39bfb7d3e6f1b26cff59656d8bfa46e25e1972c157c8dac38cb5b76196b9` |
| `crates/vprouter-launch/src/handoff.rs` | `da8e6c7b07bcbe3eca9bc44ed398e4eaaa33cd98a9b7162950671adf1a6585c7` |
| `crates/vprouter-launch/src/transport.rs` | `ba7d139e1370205ec223a0c13236713b8fdadf28ccaaebd0d1419cac296b51ab` |
| `crates/vprouter-launch/src/expiry.rs` | `914033572568cfa628bda81a7f38b1611286a581df3493d90f1950a8f105ba21` |

## Boundary inventory and remaining work

No unsafe code, native syscall, capability, process spawn, executable/argv,
socket constructor, namespace entry, profile read, credential path, dependency,
manifest or image-context change was added. All changed host/worker modules
retain their existing unsafe prohibition. No public start/launch authority was
enabled. The wire change is private and requires a coherently pinned host/worker
artifact; Root owns the ensuing manifest/static-build/context freeze.

NOT_RUN for this delta: new native policy ACK execution, integrated real
guard/worker failure-to-rebootstrap, protected provider/enrolled-daemon/client
traffic, SIGKILL/collision/packet captures, static x86_64/ARM64 qualification and
all release/platform/performance/migration/soak acceptance. No privileged checks
were attempted by this implementer. Full8c remains IN_PROGRESS.

## Root independent verification

`task-8c-1-review.md`: scoped spec PASS and quality PASS, no findings. Root
matched all six source hashes above and independently ran both library suites
(209 passed), fmt/diff checks and focused strict Clippy offline successfully.
Logs remain private under `target/task8c-20261029T123514Z`; tests log SHA256
`d1443a8578a384b16179f9eb090725a2b54565a1a9a2049bf76394f43428098a`,
Clippy log SHA256 `a5f4c585ee974ca44916ac30a98bbc189e067a7e0a6bc6d2e8d6bc525be724af`.
The native/static/recovery and broader acceptance boundaries above are retained.

Root coherent offline static freeze `5a224c16a79c1e90f0d720e41cdbbc2e816d9580`
completed successfully: 202 exact current/archive/Git inputs, both static ELF
payloads, both pinned seven-file public contexts and all program hashes/sizes
verified. Exact AMD64 filter preflight passed. Both contexts copied into the
immutable candidate directory `target/continuation-20261029T124811Z`. See
`docs/rust-v2/task8c-slice1-verification.json` for public hashes. ARM64 execution,
new native receipts and integrated runtime/client gates remain NOT_RUN.
