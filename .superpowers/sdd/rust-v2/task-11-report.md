# Task 11 implementation report

Status: IMPLEMENTED / OFFLINE_PREPARATION_ONLY; final validation completed. Base rust/v2 at
067069186f9106232fded16bb3707dcdd4dc891d; initial index/tree clean.
Task8c runtime/ARM/client acceptance remains OPEN. No subagents, sudo, external
network, VM, stage/commit/push, real profile/state reads, native network calls,
activation flag or caller verification booleans are authorized by this increment.

## Design and owned files (updated incrementally)

Extend existing core fleet selection and atomic fleet-preparation transactions,
not a parallel live store. Add strict client guard config, offline persistent
ordering/state contract and bounded userspace request policy in core; add offline
ruleset construction using existing netfilter expression/codec contracts.
Dedicated namespace enclosure is required for all supported client workloads;
userspace proxy settings alone cannot establish protection. Actual native
installation, durable client journal, authority identification and reconciliation
remain gated. Plans/public expected data never authenticate native authority.

## Test inventory and RED evidence

Commands run strictly sequentially with CARGO_BUILD_JOBS=4 and
--locked --offline -j 4 for all Cargo build/test/check/clippy operations.
Logs retained in target/task11-checks/. Compile failures will be distinguished
from behavioural REDs. Final command/exit inventory appended as executed.

## NOT_RUN and open risks

Owned-guest/real-client continuous IPv4/DNS/IPv6/TCP/UDP capture, positive controls,
boot, Tailscale stop/restart/disappearance, route/nft drift, proxy bypass/failure,
native ownership/cgroup/socket authority, durable SIGKILL/full-disk recovery,
service installation, ARM execution, migration, benchmark/soak/release acceptance:
NOT_RUN; preparation only, Task8c OPEN and no privileges/VM/network permitted.
Four ignored acceptance placeholders deliberately fail if forced.

## Initial transaction RED

No runtime acceptance or release readiness is claimed.

Initial behavioural RED: `cargo test --locked --offline -j 4 -p vprouter-core
--test client_transactions`, exit101; existing ExitChange rejected install_client
before any preparation. GREEN after extending the same enum/transaction, exit0
(1 test). Logs red-transactions.log / green-transactions.log. Fixture exit IDs
were corrected from provisional names to existing example IDs before GREEN.

## Implementation progress / evidence checkpoint

- Core client config/planner, instance+epoch callbacks, persistent quarantine
  ordering and bounded SOCKS5 CONNECT/HTTP CONNECT request planning implemented.
  Initial compiled scaffolding produced five behavioural failures (red-guards.log,
  exit101); implemented suite passed (green-guards.log, exit0). New scoped API
  compilation succeeded; this was a behavioural RED, not missing-symbol evidence.
- Renderer initial fixture referred to absent single.json: compile failure only
  (red-renderer.log, exit101); corrected to existing five.json truncated to one.
  Stub then failed all three behavioural rule/render tests
  (red-renderer-behavior.log, exit101); actual renderer passed
  (green-renderer.log, exit0). The same native Table/expression grammar and bounded
  attribute codec are reused; no client plan is accepted by native Actuator.
- Systematic sweep added preservation checks for every callback, terminal state,
  watchdog renewal, repeated poll/no catch-up, parser truncations, IPv6 and numeric
  aliases, scope and deterministic disjoint endpoint tuples. It found acceptance
  of infrastructure transport IPv4 168.63.129.16 (red-sweep.log, exit101).
  Reused direct.rs's conservative denied ranges for transport AND proxy literals.
- Explicit selection test failed when the minimal selection callback retained
  Prepared (red-selection.log, exit101). New selection quarantines/increments
  epoch before validation, requires same client/deployment/namespace/boot plus
  strictly newer generation, and requires all startup ordering again. Direct
  requires existing configured node+mode and is labeled direct-exposed.
- Core sweep+selection+transaction GREEN: green-sweep-selection.log, exit0,
  10 guard tests +1 transaction. Netfilter extended sweep: green-renderer-sweep.log,
  exit0,6 tests. Preservation/adversarial tests added after the initial core/rule
  REDs are controls; no claim that each individually failed before implementation.

All above `cargo test` commands used `CARGO_BUILD_JOBS=4 cargo test --locked
--offline -j 4`; targets were `-p vprouter-core --test client_guards`,
`-p vprouter-core --test client_guards --test client_transactions` or
`-p vprouter-netfilter --lib client::tests` as named above. No test opened a
mutating/native network socket. Four new owned-guest acceptance specifications
in client_owned_guest.rs are ignored and deliberately panic if forced.

## Final implementation inventory / entry-point sweep

Owned tracked/new paths:

- crates/vprouter-core/src/{client,direct,fleet,lib,transaction}.rs
- crates/vprouter-core/tests/{client_guards,client_transactions,client_owned_guest}.rs
- crates/vprouter-netfilter/src/{client,actuator,lib,policy}.rs
- crates/vprouter-netfilter/src/client/tests.rs
- docs/rust-v2/client-guards-preparation.md
- this ignored .superpowers/sdd/rust-v2/task-11-report.md

No Cargo manifest/lock, runtime/worker/launch/Linux/network/CLI, acceptance ledger,
controller progress, previous report or service file changed. `policy.rs` shares
existing expression helpers internally; its independent test packet interpreter
now supports ifindex metadata for client tests. `actuator.rs` only exposes the
existing semantic verifier as crate-private for generated-table tests.

Core parse AND typed construction validate all config bounds and identity scope;
configured selection reuses the existing exact client/node/mode binding. All
seven operational callbacks (complete/disappear/reconcile/restart/select/stop/poll)
check integer host high-water and independent5s poll watchdog first. Every
callback preserves terminal STOPPED/FAILED; status is read-only and refuses a
regressing or out-of-domain clock, degrading an expired plan to quarantined.
Tokens are policy-instance/epoch-specific and selection invalidates old epochs
before generation/scope validation. Failed selection leaves old node intent
quarantined, never uses it as fallback. Each new/reopened instance begins with
quarantine/capture/commit/reconcile obligations; no persisted booleans are trusted.
Only poll renews enforcement watchdog; missed ticks coalesce to at most one
quarantine action; terminal repeats cannot rearm a drained request. Recovery and
successful selections share1024 total per-instance admissions; bounded counters,
not growing histories. All proxy parsing checks total size/deadline first.

File race sweep: no new filesystem API or native journal introduced. Both new
ExitChange variants enter the existing FleetRecord::prepare -> full build ->
existing AllocationStore::commit_preparation path. The existing root/private/
single-link/inode/flock/NOFOLLOW/O_EXCL/fsync and generation+content CAS checks
remain intact and are exercised by the full touched-crate tests. Filesystem
aliases, malicious privileged writers, interrupted native service installation
and power-loss journaling remain outside this offline layer's proof.

Additional behavioural RED: Linux-invalid interface name '.' accepted
(red-ifname.log, exit101; `cargo test --locked --offline -j 4 -p vprouter-core
--test client_guards directly_deserialized`). Reject '.'/'..'; typed invalid
configs cannot bypass preparation validation. GREEN focused core final:
green-core-final-focused.log, exit0,11 guard +2 client transaction tests.
Maximum32 disjoint daemon tuples, deterministic ordering, native semantic roundtrip,
rule order/extra/missing/foreign mutation matrix and exact reverse tuple tests
are controls added after the renderer RED, not individually claimed REDs.
Initial strict clippy exited101 for two collapsible-if style findings
(clippy-initial.log); both fixed; retry exited0 (clippy-retry.log).

Production capability/syscall/subprocess inventory: ZERO new capability grants,
unsafe blocks, syscalls, network/filesystem operations, native FDs, processes,
threads, timers or subprocesses. Existing dependency implementations and the
ordinary existing workspace tests are not claimed syscall-free. New default
tests are in-memory only; ignored guest specs perform no operation and panic if
forced. No optional verify booleans, CLI activation flag or native activation
bridge exists. Proxy parsing is CONNECT intent, not an operational gateway.

## Final self-review correction: strict kernel-path fields

The first complete validation cut passed all six requested commands, including
workspace499 passed/14 ignored, but is superseded by this source correction.
Its logs/source/artifact hashes are retained under before-kernel-path-fix/.
Self-review inspected pinned Serde's internally tagged unit-variant visitor:
it discards additional fields even with enum deny_unknown_fields. A new
behavioural RED (`CARGO_BUILD_JOBS=4 cargo test --locked --offline -j 4
-p vprouter-core --test client_guards kernel_path_rejects`, exit101,
red-kernel-path.log) reproduced acceptance of path.fallback=true.
Changed ClientPath::Kernel from a unit to an empty STRUCT variant, preserving
its JSON shape while enforcing unknown-field rejection. The same test then
passed (exit0, green-kernel-path.log), covering fallback/verify/userspace metadata.
All other tagged input variants were swept: they already use structs, or are
externally tagged string enums. No production native path was introduced.
All requested validation commands are repeated sequentially on this corrected
cut; these final results supersede the earlier passing source cut.


## Final validation

All commands completed on the corrected final source, sequentially with
CARGO_BUILD_JOBS=4. Every build/test/check/clippy used --locked --offline -j 4.
No ignored test was forced; no foreign cargo process was killed. The workspace
test was the last Cargo invocation. These results supersede the initial source
cut (before-kernel-path-fix/); runtime acceptance remains OPEN.

| Exact command | Exit | Real result / log |
| --- | --- | --- |
| `cargo fmt --all -- --check` | 0 | clean; 3.83s; `fmt-check.log` |
| `cargo clippy --locked --offline -j 4 -p vprouter-core -p vprouter-netfilter --all-targets -- -D warnings` | 0 | clean; 1.75s; `clippy.log` |
| `cargo test --locked --offline -j 4 -p vprouter-core -p vprouter-netfilter --all-targets` | 0 | 150 passed, 0 failed, 13 ignored; 2.01s; `touched-all-targets.log` |
| `CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER='rust-lld' RUSTFLAGS='-C relocation-model=static' cargo test --locked --offline -j 4 -p vprouter-core -p vprouter-netfilter --all-targets --target x86_64-unknown-linux-musl` | 0 | 150 passed, 0 failed, 13 ignored; 3.1s; `x86_64-musl.log` |
| `cargo check --locked --offline -j 4 -p vprouter-core -p vprouter-netfilter --all-targets --target aarch64-unknown-linux-musl` | 0 | clean; 8.81s; `arm64-check.log` |
| `cargo test --locked --offline -j 4 --workspace --all-targets` | 0 | 500 passed, 0 failed, 14 ignored; 194.16s; `workspace-all-targets.log` |

New final coverage:12 client guard/config/proxy/callback tests,2 client transaction
tests and7 generated netfilter tests (21 new passing tests), plus4 ignored client
acceptance specifications. Touched tests include all existing file/CAS/symlink/
hardlink/lock, fleet and native netfilter offline regressions. The13 touched ignored
cases comprise12 core guest specifications and1 existing native nft harness;
workspace additionally ignores the existing native network harness. The custom
privileged lab executables printed explicit SKIP/ignored messages without a guest
run. x86_64-musl tests ran; ARM64 was compile-only, with no execution/link claim.

## Final source and artifact binding

Base HEAD remains067069186f9106232fded16bb3707dcdd4dc891d on rust/v2.
Index remains unchanged/empty; no stage/commit/push. All14 owned source/doc files
are listed below. Report excluded from its own hash. The earlier source hashes
are retained in before-kernel-path-fix/source-hashes.json and superseded here.

```text
07d805a36c75ddb331a5b326415a7a4b8fc7916ea6655be5a86d78a074a2e53b  crates/vprouter-core/src/client.rs
1852d3c9c72a787cb989ba65320734eac93e500b9f5e8cd4f161dfc365a4ec12  crates/vprouter-core/src/direct.rs
38b77b789a008cffa0f9042a50a4916f65fbb84a8f14c23731262bd3099b0c68  crates/vprouter-core/src/fleet.rs
320cccb44120e291522fd837affc3a063a8f464f68ea3c288dbebfed5f8b4e5b  crates/vprouter-core/src/lib.rs
6fe2e8cbb6aa583de7d401643906cd23eedf81b23bf34b0e03ac69ef2dfbf1d9  crates/vprouter-core/src/transaction.rs
3a7602bb7f90aaa5046796ed942724fe97834b7aabd72c2a57e209fcbcc901c4  crates/vprouter-core/tests/client_guards.rs
9c9c43b47ab67192c9bcfea1ef051da4989f5d468590900d634ab7cff96527ba  crates/vprouter-core/tests/client_transactions.rs
e48f9d11a8580f910c0695bbe2541e84ffd3a1dfe0714e210e9cd9c3cc72511d  crates/vprouter-core/tests/client_owned_guest.rs
8f62aaae77d5446372124febd0abbdea013dfac601db4b847e630e3ef032ad30  crates/vprouter-netfilter/src/client.rs
67fb85ed8f7a5e7dcf321d24b7757f38f57bcd5c546cf3db0479b2d948322c70  crates/vprouter-netfilter/src/actuator.rs
c62c5c40cc0bbf0a7f4a75955d5910a75ef9055836f9764a2b90839383130cd5  crates/vprouter-netfilter/src/lib.rs
af278a3dcb4210989d33029028c55de1e3d6126b4a6c44e592445efff1c8d08a  crates/vprouter-netfilter/src/policy.rs
c14ac85995b5cd8d046bd26ce3399d8da0fe047626190e8995f17540017b2160  crates/vprouter-netfilter/src/client/tests.rs
1cc44074656d2cdd52a9ac56fa6014ac3d3823c3ea401ebf1120cdde91bed5c1  docs/rust-v2/client-guards-preparation.md
```

Executed x86_64-musl debug test artifacts (ELF64 machine62, no PT_INTERP or
PT_DYNAMIC); they are test payloads, not release binaries:

| Test executable | SHA256 | Bytes |
| --- | --- | --- |
| `target/x86_64-unknown-linux-musl/debug/deps/client_guards-00619a0c90f7e330` | `f8f742e8528c3719534f159c99326bb2af5446f8692ae9c12e3d4804d9672667` | 22617096 |
| `target/x86_64-unknown-linux-musl/debug/deps/client_transactions-42928e51d5930ac7` | `408db7414f2e5440aeec0b08dd061a38cb74513da8a990ce99dcf3ae26cff959` | 21272944 |
| `target/x86_64-unknown-linux-musl/debug/deps/vprouter_netfilter-d1371d67778d901b` | `ced580438111d7f3bf22c3a57c2a8c4ae64e40e578e168e12b004b81b49f831d` | 29894200 |

All logs are under target/task11-checks/; log-hashes.json records retained log
SHA256, validation-results.json the exact command/exit/totals and artifacts.json
the ELF observations. git diff --check and unchanged index/HEAD checks passed.
The report is ignored by the repository rules; it exists on disk and was not
force-added. Only the14 listed source/doc paths and this report are task-owned.

## Remaining review and runtime gates

Independent review is pending. Task8c, owned-guest and real-client captures, native
Linux guard installation/identity/socket/cgroup verification, durable client
journal/power-loss recovery, proxy server/authorized connector and resolver, boot
service integration, ARM64 runtime, migration, performance and soak acceptance
remain NOT_RUN/unimplemented as detailed above and in client-guards-preparation.md.
Public digests and step callbacks are offline assertions, never retained native
authority. Native CLOCK_BOOTTIME source and watchdog scheduling must be admitted;
matching in-memory clocks cannot establish actual host enforcement. Actual daemon
identity changes require fresh expected bindings; no old plan may silently adopt
a restarted daemon. No protection, activation or release acceptance is claimed;
acceptance.json remains unchanged with release_ready=false.

Operational scope notes: the initial ancestor-instruction search enumerated
sibling AGENTS pathnames and permission errors; no sibling contents/credentials/
state were read. An index fingerprint used git write-tree once and returned the
already-existing HEAD tree; HEAD/index were unchanged and no staging/commit/push
was performed. All subsequent Git checks were read-only.

## Review round 1

2026-11-06: read the complete independent FAIL review before editing. This
section supersedes the original source/validation binding above for the current
uncommitted cut; historical logs and claims above are retained as history. The
review file itself is unchanged. No subagents, sudo, external network requests, VM operations,
Git staging/commit/push or process termination were used. Cargo commands were
strictly sequential with CARGO_BUILD_JOBS=4 and --locked --offline -j 4; fmt does
not accept build flags. No ignored test was forced.

I1: replaced the partial numeric-host heuristic with address.rs, the shared
reject-only syntax parser and conservative public-target classifier. Client
transport and all three userspace socket fields use its Serde adapters, including
callers deserializing GuardConfig directly. HTTP authorities, SOCKS target text,
direct-host evidence and prefixes, profile transport endpoints and netfilter
transport subnet preparation use the same parser. Typed netfilter Endpoint and
profile public_ipv4 now use the same conservative range classification as client
and direct policy. The endpoint sweep found six additional special/provider
addresses previously admitted by the old profile/netfilter classifier; all now
refuse. The profile endpoint parser also accepted a leading-zero port; its RED
preceded routing that input through the common socket parser. Existing IPv6
profile metadata is still metadata, not an admitted IPv6 target.

Canonical dotted-decimal IPv4 is the only numeric host form. Legacy leading-zero,
octal/hex/integer/short and mixed forms refuse rather than normalize; so do IPv6
mapped/compatible/wrapped forms, zones, brackets, trailing dots, uppercase hosts,
userinfo/embedded ports/paths, Unicode/IDNA/punycode labels, host whitespace and
controls. DNS names are restricted to lowercase ASCII, nonnumeric TLDs and
bounded labels; local/internal special suffixes refuse as proxy targets. Context
still matters: canonical loopback listeners, tailnet upstreams and private host
evidence are necessary and permitted only in those specific contexts. Public
targets and transport endpoints cannot use those addresses.

Independent test helper tests/support/address_cases.rs generates a five-way
cross-product for every IPv4 component plus whole/short forms and wrapper,
Unicode, control and overlength shapes. Twenty-two special/provider representatives
plus public 8.8.8.8 exercise HTTP, SOCKS, transport config, listeners/upstream,
direct-host address and prefix fields, direct packet policy and netfilter
endpoint admission. Profile endpoint encodings also run through the synthetic
profile parser. A leading space at a profile key=value boundary is existing
field grammar padding, not part of the extracted address; that dimension is
covered at raw host APIs, JSON and both protocols instead. No libc/DNS/network
numeric conversion is used to compute expectations. Existing range-edge tests
remain in the full suites; public target/domain positive controls prevent a
reject-everything implementation from satisfying the matrix.

I2: ClientGuard::poll now always drains a pending quarantine obligation, including
regression and out-of-domain time. Clock failure still latches Failed before any
work is returned; it cannot recover admission or lower the high-water mark. A
failed/expired poll does not renew the watchdog. One coalesced quarantine action
is delivered even while time remains broken; subsequent polls do not re-arm it.
Other operational callbacks return errors and retain pending safety work. Old
poll-error assertions were updated to the reviewed terminal-action-drain contract.

The documentation enumerates every host-time input: ClientGuard constructor,
seven operational callbacks and status; immutable GuardPlan::proxy_request's
started/now; FleetPolicy constructor, observe, observe_bytes, sample_finished,
restart, reconcile_direct_host, poll and status. Matrices test valid, regressing,
nonfinite, negative and out-of-domain inputs as representable, both with and
without queued safety work, plus pending/drained terminal cases and late callbacks.
Fleet/direct operational failures remain fleet-wide EmergencyQuarantineAndStop;
that implementation passed the new matrix unchanged. Status stays observational:
it returns no authority on invalid time, consumes no obligations, and does not
advance operational time or mutate lifecycle state (existing Task9/10 contract).
NaN/infinity/negative cannot inhabit the client u64 API: explicit serialized/type
boundary refusals test that dimension, without lossy casts manufacturing zero.
Constructors and immutable parsing have no pre-existing queue dimension.

M1: HTTP/1.1 CONNECT now requires exactly one matching Host. Header value padding
uses only SP/HTAB, eliminating the VT/FF acceptance exposed by the matrix. Shared
authority parsing also refuses leading-zero/sign/ambiguous ports. The table covers
HTTP/1.0, authority/absolute form, duplicate/conflicting/missing Host, folded or
whitespace-before-colon headers, controls, framing/smuggling/pipelined requests,
truncation and oversize. Exact8192/8193 byte and253/254 domain boundaries,63/64-label
limits, valid CONNECTs and ordinary lowercase DNS/public IPv4 are controls.
HTTP/1.0 and ordinary absolute-form forwarding remain explicitly unsupported.

### RED/GREEN evidence and commands

All paths below are relative to target/task11-review-round1/. REDs were successful
compilations followed by behavioral assertion failures, not compiler errors.

| Exact command (CARGO_BUILD_JOBS=4 for every row) | Exit | Evidence/result |
| --- | --- | --- |
| `cargo test --locked --offline -j 4 -p vprouter-core --test client_guards round1_` (before production edits) | 101 | red-review.log: I1, I2 and M1 all fail,0 passed/3 failed |
| `cargo test --locked --offline -j 4 -p vprouter-core --test client_guards round1_` (class tests added, still before production edits) | 101 | red-classes.log:0 passed/6 failed;10,340 generated boundary escapes; HTTP also admits VT/FF padding and0443; client clock matrix withholds quarantine |
| `cargo test --locked --offline -j 4 -p vprouter-core --test direct_fleet round1_` (baseline) | 0 | clock-fleet-baseline.log: mixed-fleet clock/queue matrix passes unchanged |
| `cargo test --locked --offline -j 4 -p vprouter-netfilter round1_all_ruleset` (before classifier unification) | 101 | red-endpoint-class.log: admits192.31.196.1,192.52.193.1,192.175.48.1,168.63.129.16,147.75.207.207,192.80.8.124 |
| `cargo test --locked --offline -j 4 -p vprouter-core --test client_guards round1_profile` (before profile parser change) | 101 | red-profile-endpoint.log: accepts185.65.134.81:051820 |
| `cargo test --locked --offline -j 4 -p vprouter-core --test client_guards round1_` (after fixes) | 0 | green-classes.log: original six REDs pass; generated escapes zero |
| `cargo test --locked --offline -j 4 -p vprouter-netfilter round1_` | 0 | green-endpoint-class.log: both classifier/encoding tests pass |
| `cargo test --locked --offline -j 4 -p vprouter-core --test client_guards --test direct_fleet --test direct_policy` | 0 | green-core-final.log:38 passed,0 failed; includes profile-port RED now GREEN (before final constructor control addition) |

Initial strict Clippy exited101 for a manual range-expression style finding in
new test code (clippy-initial.log); corrected without lint suppression. An initial
full touched-package run exited101 for one expanded profile fixture expecting
field-padding whitespace to be part of its address (touched-initial.log). The
fixture was corrected to test extracted address boundaries consistently with the
existing profile grammar; no production refusal or policy assertion was weakened.
Final validation below supersedes those attempts and the intermediate GREEN cut.

### Final round 1 validation

All four required final commands completed sequentially with exit0. The workspace
test was the last Cargo invocation; no test/build was run concurrently by this
delegate, and no foreign Cargo process was stopped. These results bind the final
source/doc hashes in source-hashes.json (nineteen paths, report excluded).

| Exact command | Exit | Fresh result / log |
| --- | --- | --- |
| `CARGO_BUILD_JOBS=4 cargo fmt --all -- --check` | 0 | clean; fmt-check.log |
| `CARGO_BUILD_JOBS=4 cargo clippy --locked --offline -j 4 -p vprouter-core -p vprouter-netfilter --all-targets -- -D warnings` | 0 | strict/no warnings; clippy.log |
| `CARGO_BUILD_JOBS=4 cargo test --locked --offline -j 4 -p vprouter-core -p vprouter-netfilter --all-targets` | 0 |163 passed,0 failed,13 ignored; touched-all-targets.log |
| `CARGO_BUILD_JOBS=4 cargo test --locked --offline -j 4 --workspace --all-targets` | 0 |513 passed,0 failed,14 ignored; workspace-all-targets.log |

Thirteen additional passing tests cover this round: eight core client tests,
two mixed fleet/direct clock/constructor tests, one direct-target cross-product,
and two netfilter classifier/encoding tests. All original suites and ignored
specifications remain in the workspace run. Custom privileged lab executables
reported their explicit guest/--ignored SKIP; none was forced.
validation-results.json records exact final and behavioral RED commands, exits
and totals; log-hashes.json binds all retained round1 logs. Existing controlled
local TLS/Unix tests are ordinary workspace tests, not real provider/client
runtime acceptance and not claimed to be syscall-free.

Final preservation checks: git diff --check exit0; git diff --cached --quiet
exit0; branch rust/v2, HEAD067069186f9106232fded16bb3707dcdd4dc891d unchanged.
Review SHA256 remains
05b809f3ac7d03bd5ed651a8b3a698791f07d03faa3fd6f45658e12648f7b51e
(the pre-edit SHA256 check succeeds). No Git write command was used in round1.

### Round 1 ownership and remaining gates

This round changes twelve source/doc paths: core src/address.rs (new), src/client.rs,
src/direct.rs, src/lib.rs, src/profile.rs; tests/client_guards.rs,
tests/direct_fleet.rs, tests/direct_policy.rs, tests/support/address_cases.rs (new);
netfilter src/policy.rs and src/client/tests.rs; and
 docs/rust-v2/client-guards-preparation.md. Paths are under their respective
crates/vprouter-core/ and crates/vprouter-netfilter/ roots unless fully specified.
The report is the additional task-owned write. The five additions to the original
Task11 ownership list are address.rs, profile.rs, direct_fleet.rs, direct_policy.rs
and support/address_cases.rs (nineteen source/doc files in the combined increment).
Seven original Task11 paths not needed for this fix retain their reviewed hashes;
baseline-file-comparison.json records the comparison. No unrelated work was reset,
reverted, stashed or staged. Review SHA256 and unchanged HEAD/index are rechecked.

Native quarantine delivery/installation, real-client IPv4/DNS/IPv6/TCP/UDP captures,
DNS resolution and post-resolution address validation, socket/cgroup custody,
boot/journal/power-loss integration, ARM execution, migration/performance/soak and
release acceptance remain NOT_RUN/unimplemented. The stricter lowercase/ASCII,
no-IDNA/numeric-TLD and special-domain subset is intentional refusal of unsupported
spellings, not a promise of general HTTP/DNS compatibility. Profile/native endpoint
admission is now more conservative for the six recorded special addresses.
No runtime or release acceptance is inferred from passing offline tests.
Independent re-review remains pending; the original FAIL review is not rewritten.
The previous cross-target/ELF artifact binding above is historical and was not
rerun for this source cut; this round claims host validation only.
