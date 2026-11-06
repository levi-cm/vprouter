# Task 10 implementation report

Status: IMPLEMENTED / OFFLINE_PREPARATION_ONLY; final validation completed. Base `rust/v2`
at `20936b4a05d789efa659425e8a93ad65a2748537`, clean at start. No subagents,
sudo, external network, VM, staging, commits or pushes. Task8c runtime/ARM/client
acceptance remains OPEN; `release_ready=false` is unchanged. No native activation,
privileged module, unsafe Rust, capability/LSM/syscall expansion, CLI flag or
runtime import path was added. Independent review remains controller-owned.

## Owned files

- `crates/vprouter-core/src/{allocation,config,direct,fleet,lib,transaction}.rs`
- `crates/vprouter-core/tests/{direct_fleet,direct_policy,direct_owned_guest,fleet,transactions}.rs`
- `docs/rust-v2/{direct-exit-preparation,multi-exit-preparation}.md`
- `.superpowers/sdd/rust-v2/task-10-report.md` (ignored by existing repository rules;
  present on disk; no force-add performed).

Cargo manifests/lock/toolchain, native Linux/network/netfilter/launch/worker/CLI
implementation, acceptance ledger, controller progress and existing reports,
production, identities and credentials remain untouched. Build/check evidence
lives under ignored `target/task10-checks/`; no foreign cargo process was killed.
Ordinary test harnesses may use loopback/synthetic fixtures; no external provider
or real identity operations were run by this delegate.

## Design

Task9's fleet, schema, allocation and atomic preparation store are extended,
not forked. Direct/mixed preparation supports explicit add/remove/enable/disable,
full revalidation including disabled peers and existing canonical-content plus
generation CAS. `pin_server` refuses direct rather than converting identity/mode.
Direct enrollment-key input refuses; fresh interactive enrollment remains future
native work. No state or credential filesystem mutation follows exit removal.
Existing naming supplies `unsafe-direct-host-ip-debdev-exit`, suffixes ALL
collisions (disabled entries included), rejects >63 bytes without truncation and
keeps stable IDs/state separate from hostname. Mixed metadata, unknown/fallback
fields, protected client selection of direct and direct selection of Mullvad
refuse. Client plans require exact enabled exit ID + stable node + explicit mode,
label direct-exposed and leave observed egress/DNS/IPv6 not_tested. Status reuses
existing fresh health evidence; no direct protected/Mullvad confirmation claim.

`direct::DirectPlan` validates complete matching config/allocations and explicit
path + host snapshot. It renders bounded JSON policy intent and supplies a pure
packet/flow evaluator. Public IPv4 TCP/UDP only, nonzero ports, exact ingress/WAN
ifindices and Tailscale client source100.64/10. DNS follows identical rules.
IPv6/unsupported protocols/new inbound/mismatched flows refuse. Special-purpose
ranges, known public infrastructure metadata, all observed host public/local
addresses and connected/declared local prefixes are denied. The conservative
manual version and source links are documented; no registry refresh was fetched.
Host snapshot: strict<=64KiB, generation>0, nonempty address/connected-prefix
lists, <=256 entries/list, canonical CIDRs, revalidated even after raw serde
construction. Exact flow scope binds deployment/ID/generation/zone/configuration,
policy version, allocation/path and host content; return/NAT require exact
original/reverse tuples and scope. Zone collisions across reservations refuse.
No native packet parser/NAT/conntrack enforcer is implemented.

The same FleetPolicy now allows six active exits, at most five Mullvad; disabled
reservations still have no state machine/session/deadline. Opaque callback tokens
retain instance+exit+epoch binding and the1024-lifecycle budget. Direct restart
preserves mode. Host snapshot reconciliation checks the shared clock first,
then exact plan/binding/snapshot; unknown/drift queues scoped quarantine before
sample work, revokes the session and cannot refresh health or release quarantine.
Every provider's scoped failure leaves direct and healthy peers unchanged.
Unknown direct egress verification cannot yield policy READY. Generic existing
Evidence.provider_ok is only a successful direct reachability witness in direct
mode; no native direct witness producer or provider query path is added.

## Entry-point and race sweep

- `new` validates constructor time, complete enabled/disabled bindings, exact mode/
  server/name/config/generation/boot, identity/lifecycle uniqueness and allocations.
- All six time-bearing operational callbacks (`observe`, `observe_bytes`,
  `sample_finished`, `restart`, `poll`, `reconcile_direct_host`) validate the same
  host high-water mark before token/transition checks or decoding malformed input.
  Nonfinite/negative/regressing clocks fail fleet-wide. A new behavioral RED found
  that a huge finite f64 could lose cadence precision: clocks>1e12 seconds now
  fail closed. Worker timestamps remain separate. Only polls renew the90s watchdog.
- `worker_failed`, `cancel`, `cleanup_failed`, observation/completion/restart and
  host reconciliation cannot revive FAILED/STOPPING or weaken fleet emergency.
  A new behavioral RED found repeated `container_failed` could re-arm drained
  emergency actions; it is now idempotent. Queries/client plans remain observational.
- Sampling remains nonoverlapping, expiry-first and no-catch-up, including direct
  alone and mixed six-exit fleets. Actions are bounded to12 per poll. No extra
  thread, timer, socket, pool or task is created by policy calls.
- Preparation reuses structure/profile validation and the one-file atomic bundle.
  Every storage transaction rechecks the retained lock against the currently
  named private single-link inode; a behavioral RED reproduced accepted lock
  replacement. Before rename the original temporary FD must remain private,
  single-link and equal to the named temporary inode. Existing NOFOLLOW/O_EXCL/
  directory pinning/flock/file+directory fsync and generation/content CAS remain.
  Foreign symlink/hardlink/lock bytes are refused and retained; incomplete temps
  remain evidence. Protected directories/cooperative locks are the concurrency
  boundary: check+rename is not atomic against malicious privileged mutation.

## Test inventory and RED evidence

All Cargo build/test/check/clippy commands below ran sequentially from the repo
root with `CARGO_BUILD_JOBS=4` and `--locked --offline -j 4`. Cargo fmt does not
accept those build flags. Logs below are relative to `target/task10-checks/`.
Primary tests were added before their implementing increments. New APIs initially needed
compilable scaffolding; compile failures are explicitly separate from behavioral
REDs. Later preservation/adversarial controls passed immediately and are not
misrepresented as previously failing. Host-reconciliation sensitivity was also
checked by a temporary mutation restored in a Python finally block.

| Command / purpose | Exit | Evidence |
| --- | --- | --- |
| `cargo test --locked --offline -j 4 -p vprouter-core --test direct_fleet` initial direct/mixed admission | 101 | 3 requirement failures: direct preparation, direct policy admission and six slots; `red-fleet.log` |
| `cargo test --locked --offline -j 4 -p vprouter-core --test fleet repeated_container_failure` | 101 | drained emergency request rearmed; `red-terminal.log` |
| `cargo test --locked --offline -j 4 -p vprouter-core --test direct_policy --test direct_fleet` initial API | 101 | missing new module/client API COMPILE failure only; `red-policy-api.log` |
| Same two-target command, minimal compiled API | 101 | protected selection of direct accepted; `red-policy-behavior.log` |
| `cargo test --locked --offline -j 4 -p vprouter-core --test direct_policy` | 101 | special-purpose destination accepted, reverse flow missing, invalid host metadata accepted; 3 assertion failures, `red-policy-ranges.log` |
| `cargo test --locked --offline -j 4 -p vprouter-core --lib preparation_lock_replacement` | 101 | named lock inode replacement accepted; `red-storage.log` |
| `cargo test --locked --offline -j 4 -p vprouter-core --test direct_fleet direct_enrollment` | 101 | direct unattended enrollment-key input accepted; `red-enrollment.log` |
| `cargo test --locked --offline -j 4 -p vprouter-core --test direct_fleet selection_plans` | 101 | direct exposure was mislabeled unverified; `red-selection-plan.log` |
| `cargo test --locked --offline -j 4 -p vprouter-core --test fleet finite_host_time` | 101 | huge finite callback time did not enter emergency; `red-clock-precision.log` |
| `cargo test --locked --offline -j 4 -p vprouter-core --test direct_policy changing_configuration` | 101 | old established flow accepted after configuration changed; `red-flow-config.log` |
| `cargo test --locked --offline -j 4 -p vprouter-core --test direct_policy rendered_policy` | 101 | source/default-drop predicates absent from JSON intent; `red-render.log` |
| `cargo test --locked --offline -j 4 -p vprouter-core --test direct_fleet direct_drift` with snapshot-match check temporarily removed | 101 | unknown host witness accepted; assertion failure, `red-drift-mutation.log`; source restored in finally |

Intermediate GREEN commands/logs (all exit0):

- `cargo test --locked --offline -j 4 -p vprouter-core --test direct_fleet --test fleet --test transactions`: 3+19+5 cases, `green-fleet.log`.
- `cargo test --locked --offline -j 4 -p vprouter-core --test direct_policy --test direct_fleet`: 3+4, then4+7, then6+9 cases; `green-policy.log`, `green-enrollment-limits.log`, `green-flow-render.log`.
- `cargo test --locked --offline -j 4 -p vprouter-core --test direct_policy --test direct_fleet --lib`: 3+6+19 cases, `green-drift-storage.log`.
- `cargo test --locked --offline -j 4 -p vprouter-core --test direct_fleet --test fleet --test direct_policy`: 9+20+4 cases, `green-clock-selection.log`.

Final new coverage: six direct-policy cases (every special-range endpoint/neighbor,
known public metadata, public/host/global-LAN/local denials, DNS/IPv6, exact flow/
reverse/zone/interfaces/config+host fingerprint, malformed/unknown/duplicate/
unbounded metadata and paths, JSON predicates); ten direct fleet/transaction
cases (explicit selection/exposure, CRUD/name stability/no mode conversion,
interactive enrollment input refusal, one/six slot scheduling, instance/epoch/
lifecycle replay, unknown direct egress, all five provider scoped failures,
host drift field matrix, six timed callback boundaries/foreign token ordering,
terminal callbacks); two shared fleet regressions (idempotent emergency/finite
clock precision); two real temporary-file storage cases (direct commit/reopen/
disable/orphan/no-provider-read and lock replacement/hardlink preservation).
Existing tests retain full configuration/naming/strict-mode/profile/key, clock,
cadence, callback/token, resource/CAS/symlink/hardlink/interrupted-file coverage.

## Final validation

Completed on the final recorded source cut. Every command below exited0.
`CARGO_BUILD_JOBS=4` applies throughout; all build/test/check/clippy commands use
`--locked --offline -j 4` and ran strictly sequentially. Platform commands use
target-specific linker/RUSTFLAGS only for that invocation. No ARM binary ran.

| Exact command | Exit | Real result / log |
| --- | --- | --- |
| `cargo fmt --all -- --check` | 0 | clean; `fmt-check.log` |
| `cargo clippy --locked --offline -j 4 -p vprouter-core --all-targets -- -D warnings` | 0 | clean; `clippy.log` |
| `cargo test --locked --offline -j 4 -p vprouter-core --all-targets` | 0 | 102 passed,0 failed,8 ignored; `core-all-targets.log` |
| `cargo check --locked --offline -j 4 -p vprouter-core --all-targets --target aarch64-unknown-linux-musl` | 0 | compile only; `arm64-check.log` |
| `CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld RUSTFLAGS='-C relocation-model=static' cargo test --locked --offline -j 4 -p vprouter-core --all-targets --target x86_64-unknown-linux-musl` | 0 | 102 passed,0 failed,8 ignored; `x86_64-musl.log` |
| `CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld RUSTFLAGS='-C relocation-model=static' cargo test --locked --offline -j 4 -p vprouter-core --all-targets --target aarch64-unknown-linux-musl --no-run` | 0 | 13 test executables linked, execution NOT_RUN; `arm64-link.log` |
| `cargo test --locked --offline -j 4 --workspace --all-targets` | 0 | 478 passed,0 failed,10 ignored; `workspace-all-targets.log`; last Cargo invocation |
| `git diff --check` | 0 | clean; final repeat recorded in `diff-check.log` |

Workspace compilation completed in3m50s; no cargo process was killed. Custom
privileged localapi binary printed its explicit SKIP and did not run a guest.
Result-line totals were independently summed from complete logs. The eight
ignored core tests comprise four retained Task9 and four new Task10 specifications;
workspace additionally retains the two existing ignored native component tests.
No ignored case was forced. All13 recorded source/doc hashes were rechecked
unchanged after final workspace completion. HEAD remains20936b4 on rust/v2;
index is unchanged/unstaged. Only the13 declared source/doc paths and this ignored
report are task-owned changes. Independent review of this final diff is pending.

## NOT_RUN and open risks

Four new `#[ignore]` cases in `tests/direct_owned_guest.rs` deliberately panic if
forced: actual direct public positive/forbidden IPv4-DNS-IPv6-TCP-UDP captures;
five Mullvad+direct cross-exit/established-flow/every-provider-fault captures;
fresh interactive identity/private proc-state-FD-cgroup/no-primary path; and
native quarantine-first startup/address-drift/SIGKILL/interrupted-transaction/
exact-owned cleanup. These are specifications, not implemented native harnesses.
They are NOT_RUN because Task10 is preparation only, Task8c is OPEN, and this
delegate is forbidden to use privileges/VMs or real identities.

All native direct enforcement, independently complete/fresh host inventory,
WAN/namespace/flow/epoch custody, startup quarantine and emergency authority,
conntrack/NAT cleanup, protected interactive enrollment, retained private roles,
address monitoring, power-loss/full-disk/SIGKILL recovery and real Tailscale client
traffic remain unimplemented/unqualified here. Plans are public expected data,
not observation/admission capabilities. An adversarial caller can forge inputs;
a native driver must authenticate them using existing reviewed guard/launch
receipts and cannot treat library readiness as authority. The library does not
prove filesystem-alias isolation of configured state paths or freshness/
completeness of caller-supplied host metadata. No preparation record is a live
native journal or activation input. No observed provider or DNS/IPv6 safety,
ARM kernel execution, integration, migration/rollback, performance/efficiency,
reboot/service/platform acceptance, 24-hour soak or release readiness is claimed.
No measured overhead/savings results exist. Independent review and all mandatory
controller-owned client/runtime gates precede any integration or cutover.

## Source and static artifact binding

Base HEAD plus the following changed/new files identifies this source cut.
Report excluded to avoid a recursive self-hash. No source edits follow these
hashes; final validation records are appended separately.

```text
c53745c9e147c5f68d91997407c126743fbb63561d2198e752727474df11d16f  crates/vprouter-core/src/allocation.rs
2779591c6f014f403fc9f263ab779446cd431c6504b4de67f33f3577d77c0e9d  crates/vprouter-core/src/config.rs
50f0ff5e6b21ec94f0c61cb7ee39b7ba5193f947d29f0d88fa09eaee41c6a942  crates/vprouter-core/src/direct.rs
b6bcc1ebb9e78a1c64ed6679a5bc292e65a551ea863dc27d231f75eac2df597b  crates/vprouter-core/src/fleet.rs
0cbd64ba94ebb22cfd4d206ea0765e799e3c07d7494040b8e235c822153d40b5  crates/vprouter-core/src/lib.rs
bfafb1730846c64bb7cf6628e50f15bca002ba7b3134e6947afbb91f19e583fb  crates/vprouter-core/src/transaction.rs
24f527b3ed39ce85720e81c9ab532ab93a36ec824c3877d14e7e2b03e71e6cf2  crates/vprouter-core/tests/direct_fleet.rs
879ad28bc32d858ffe698355fbd62d9eec5840535bd00ff93e8a1f08c00c22e3  crates/vprouter-core/tests/direct_policy.rs
e3476064fb154a1aa770ed28df99b9a108731c9c96fbcd060d3422045d123e25  crates/vprouter-core/tests/direct_owned_guest.rs
2cdaa68f10297adc3ec57789ba1f49f70421325062f8ed80de3d84a38fbfbeea  crates/vprouter-core/tests/fleet.rs
bcf6bba2ebbf9d6e6c58c8d914605d900ef4a85b3024d4a5225a98c03ee7def1  crates/vprouter-core/tests/transactions.rs
07621dc9f4571e0c38c15ef963dbf21c3aa65d3caf53fe060917de2f92105505  docs/rust-v2/direct-exit-preparation.md
646b04ed9596eef05c604b81c6c9c7a713c8f631acf4fe3cc2794f6da44d6532  docs/rust-v2/multi-exit-preparation.md
```

Static ELF inspection used Python struct parsing of ELF64 little-endian machine
and every program-header type. Both direct suites have no PT_INTERP/PT_DYNAMIC.
These are debug test executables, not deployable release artifacts. ARM binaries
were linked only, never executed. Details: artifact-inspection.json.

| Artifact | Machine / bytes | SHA256 | Scope |
| --- | --- | --- | --- |
| `target/x86_64-unknown-linux-musl/debug/deps/direct_fleet-62062b922a93b647` | 62 / 21787568 | `e9905fcd1c8ebf03d9cee4e9677bc698e59316d473369d43fc85b45b8fe9412c` | tests executed |
| `target/x86_64-unknown-linux-musl/debug/deps/direct_policy-9ff3630295893933` | 62 / 20546200 | `bb5c6fea5fc3cccc97006a4ce6284db026e242b0ee1cff606b8669b9174c63cf` | tests executed |
| `target/aarch64-unknown-linux-musl/debug/deps/direct_fleet-d22807f7d3fd156c` | 183 / 21750712 | `41c81d32760c9a86a5f35a22f237f7c46661579df5cc553ec1185b459e53d841` | NOT_RUN execution; link only |
| `target/aarch64-unknown-linux-musl/debug/deps/direct_policy-6d98741e48f7e901` | 183 / 20491072 | `91ff4504936c58640fc7860bf47a01a65a0dc28596f09c106fe25e80bb8bfbe5` | NOT_RUN execution; link only |

## Retained validation log hashes

Paths are relative to target/task10-checks/. Report edits do not change source
or executable artifacts.

```text
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  fmt-check.log
a35b01b0d047c8ce3e0bb7bac7d3c92351e9fbc01c8dad8777eeeee692c734ed  clippy.log
003639fe9d2bb9bfe27eb35c8a329b66345791570dceb909d144f99be1d1853c  core-all-targets.log
4e9acf5b9e6cb4837c5716d41eb7a72a31c45416d5594225118fec26ae8c00e6  arm64-check.log
053e94b7f03ff510a91b9e4785a9bcef6712984b24d40e80827315e362ac2ecd  x86_64-musl.log
bb1e17a9af6aa8150d41c7a1cfe86cd359c955eb4be7f8d0a1628a80c692e484  arm64-link.log
f8cd5b0bbe3f6eb2339368f3f1be0733a139fc3d72bd3c4d38a8bcfca5ec0ac5  workspace-all-targets.log
200f6d4c82afe33bed63a816d297226e6ee154f40e1305fcc64ed5a70aad0b8b  red-fleet.log
4362eec82dd2b275fcedad4023af1e76d55a41d82dc78fe41eb956536702b843  red-terminal.log
94bcb5aea9bad5785b65d1bfaa453acef11dcfb24ae1fe78fb93cb3ab5a82762  red-policy-api.log
fd195f5f415051e22fed5aa3194baa48095d7ca2df774ae99e2ecfb31751b5fc  red-policy-behavior.log
c35439b5364c5c13a8035e8a0118053625f1abc8fe315b2aaf0f3f7d50515166  red-policy-ranges.log
a8ccf0219b7c69bf7d51d9b23946184dcf1993c3146e165717b4c14c8ea37a69  red-storage.log
e7969eda958d28043ed41046f26ceb46efb53e5709619796651767924241335d  red-enrollment.log
a26a187bfdf2a5c7b19271e0f2e43ce83e50b647970a8fcaf0dc71640c57cc50  red-selection-plan.log
515959bd5b726331bba80cbf5ed6483288956035c014886259fda6a6a4eee7f0  red-clock-precision.log
11ee4261b1cb6ac5cb2aa673a75c87ddf7f1388de0a3dc0f497e54cc3a8a2895  red-flow-config.log
6eb83e7f8115107ad72c1c44f506bc5253ead4a476478ee5e5dd8203ca94011d  red-render.log
8cf0164c91131b10665e10cf639fb0f27a8a91a07bca2728f512e33ff35b4984  red-drift-mutation.log
61a00788da35e4b82bdea537588142612cf42649a1323aa8bffbeaebaa1ce2e0  artifact-inspection.json
d3ad31326238ff359f84cc95d2fbde269489d4adceb0e1519e03052802f4ef01  source-hashes.json
```

## Review round 1 (controller)

`task-10-review.md`: FAIL with one Minor (M1: `FleetPolicy::status` accepted a host
time behind the fleet high-water mark; pre-existing since Task 9, found by the
time-entry sweep). Fixed by the controller: `status` now refuses non-finite, negative
or regressing `now` read-only (no high-water advance, watchdog renewal or
quarantine); regression `status_refuses_host_time_behind_the_high_water_mark_without_
side_effects` in tests/fleet.rs. fmt, strict clippy and `-p vprouter-core --all-targets`
re-run clean. Still an OFFLINE_PREPARATION_ONLY layer; owned-guest tests NOT_RUN; no
runtime/release acceptance.
