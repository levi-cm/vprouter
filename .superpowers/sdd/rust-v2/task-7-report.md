# Task7 native monitoring worker implementer report

Latest review-fix source: `59550207f81937024a6275e5472df60998fbfcae`.
The appended round1 section binds current source and focused evidence; original
implementation evidence/hashes below remain historical and are not overwritten.

Status: **DONE_WITH_CONCERNS**. Final implementation source is
`ad9b38d4e238c7e0418cbb7db822a7d23a66f97d`; implementation commit `3eb5dba`
adds the engine, and `ad9b38d` moves clock injection to dev dependencies only.
Worktree `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`. This report is a
separate report-only commit. Controller-owned task8/evidence/tools files were
left unstaged. No subagents, production reads/mutations, credential/state reads,
privileged mutations or external network tests were performed by this worker.

Production `start()` returns `StructuralGap` before runtime/client/socket/thread
creation. There is no production placement token constructor, activation flag,
manifest bridge or guard server. Genuine controlled transports exercise the
compiled private engine through a test-only structural boundary. This is engine
preparation, not deployed/activated monitoring, quarantine enforcement or client
traffic acceptance. Independent review is controller-owned and remains pending.

## Implementation and boundaries

- Private non-Send/non-Sync placement binds namespace device/inode. Only cfg(test)
  constructors exist; clients check placement before use and HTTP clients after
  requests. No async setns, unsafe code, subprocess monitoring, host resolver,
  proxy environment, global/cross-exit pool or pre-placement clients exist.
- Reusable bounded Hyper/Rustls HTTPS and Unix LocalAPI clients cancel their
  connection driver tasks on drop. Fixed provider URL/SNI is
  `https://am.i.mullvad.net/json`; pinned Mozilla roots retain genuine CA and
  hostname verification. Native bounded UDP DNS uses an explicitly supplied
  private resolver, exact fixed A question/transaction, bounded CNAME chain,
  public IPv4 and trailing-byte checks through maintained Hickory parsing.
- Provider attempts include DNS/connect/TLS/headers/body in a12s deadline.
  Headers32/8192bytes; bodies provider16KiB, LocalAPI64KiB, control256bytes.
  No redirect/compression/trailers. Duplicate keys at every JSON depth, wrong
  types, malformed/oversize framing and negative/wrong-server results fail closed.
  Success requires true `mullvad_exit_ip`, public IPv4 `ip` and exact configured
  `mullvad_exit_ip_hostname`, matching the controller's real field-shape oracle.
- One retry after1s only for408/429/5xx or eligible transport/attempt timeout.
  Full structural/handshake audit before request, immediately after failure,
  after retry delay, after successful provider and after LocalAPI. Permanent/TLS/
  malformed/negative/repeated errors and drift block. Outer sample timeout34s;
  the existing synchronous native dump can delay cancellation by at most its5s
  budget, yielding a nominal bound below39s and below45s, not a hard realtime
  scheduler guarantee.
- LocalAPI fixed GET `/localapi/v0/status?peers=false`, GET/PATCH prefs; pinned
  version1.102.5 or observed1.102.5-1-t5fb2a81b0. Stable ID and exact top-level/self
  IPs, Running/Online and exact safe prefs required. Initialization FIRST withdraws
  advertisements and reads emptiness, then narrowly sets NetfilterMode0,
  RunSSHfalse, NoSNATtrue and corresponding Set bits. No reset/enrollment/name/
  auth changes or AuthURL projection/logging. Safe prefs additionally require
  WantRunning, no LoggedOut/RouteAll/CorpDNS/selected exit,
  NoStatefulFilteringtrue, and empty or exact two default advertisements.
- Reviewed HealthMachine and one monotonic5s cadence, deterministic core offset
  (one exit zero), no overlapping samples or catch-up bursts. Strict freshness
  <45s and known/nonfuture handshake <180s. Heartbeats continue during provider
  work; control requests also keep polling the sample. DNS/IPv6 `not_tested`.
  Direct mode refused.
- Controller correction: ExitNodeOption means offered AND approved. False while
  withdrawn is normal. Three independent successes reach RECOVERING; offering
  requires future task8 retained health-only bootstrap authority. Actual offered
  routes and approval must then be observed before READY. Awaiting approval stays
  RECOVERING; revocation from READY blocks and withdraws. No bool bypass exists.
- On failure/shutdown cancel, block, notify guard FIRST, then withdraw/read back
  within4s; otherwise fixed separate-init stop-tailscaled request within2s. Draft
  control uses version/monotonic sequence/fixed reasons and exact `recorded:true`
  ACK. ACK is observational, never quarantine authority. No quarantine-removal
  request, actual guard/init endpoints or independent90s watchdog exist yet.
- Descriptor-relative publication uses0700 directory,0600/single-link regular
  output, O_EXCL/NOFOLLOW pending, fsync-file/rename/fsync-parent. Dedicated placed
  writer thread has one-in-flight bounded channel and2s caller deadline. A disk
  syscall can complete late; no queued work growth or loop blockage. Task8 must
  check health freshness and exit/generation and never authorize release from a
  health file; separate init must bound termination without joining a stuck writer.
- Minimal network changes retain Rule action/flags/mark/mask/suppression/goto/
  realm/protocol. Unknown other functional attributes fail. Independently captured
  raw fixture decodes7IPv4+6IPv6 rules (families128/129 excluded). Strict Plan still
  REJECTS real Tailscale marked rules and unexpected link-local IPv6. No arbitrary
  table52/default/LAN routes were accepted; actual approved route/control witness
  and link-local suppression remain task8 gates. Baseline rule audit explicitly
  requires observed protocol2 and suppress-prefix MAX metadata.

## Verification

Executed with pinned Rust1.97.0 in the assigned worktree:

```text
cargo test --workspace --all-targets
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo check --workspace --all-targets
cargo clippy -p vprouter-worker -p vprouter-network --all-targets -- -D warnings
cargo check -p vprouter-worker --lib
cargo check -p vprouter-worker --all-targets --target aarch64-unknown-linux-musl
git diff --check
```

All passed. Full workspace at implementation `3eb5dba`: **139 passed,0 failed,
2 existing privileged tests ignored**; custom lab targets explicitly skip.
Worker26; network16 plus1 ignored. The later manifest-only `ad9b38d` leaves
runtime source and test feature configuration unchanged; focused clippy/lib check
and cross-builds passed afterward. No repeated full-suite claim at `ad9b38d`.

Meaningful controlled tests exercise real loopback TLS with synthetic CA,
trust/name/unknown-CA refusal, connection reuse, malformed/chunked/oversize/
compressed responses and real slow headers/body12s deadlines; actual loopback
UDP DNS; actual Unix LocalAPI methods/path/narrow masked bodies, reuse, duplicate/
type/identity/IP/prefs refusal, malformed parser/2s deadline/EOF cancellation;
actual TLS503->200 retry timing and post-delay drift preventing a second request.
Injected boundary/clock faults cover one retry, structural timing,180s boundary,
approval recover/wait/revoke,34s operation bound and stale health. Real Unix
control observes heartbeats at5/10s during slow provider and shutdown at11s,
ACK refusal and withdrawal/init fallback. Protected file tests cover symlinks,
hardlinks, collisions, atomic publication and stalled one-in-flight2s deadline.
These synthetic decisions do not prove actual guard activation or isolation.

Development failures retained here, corrected before final checks: attempted use
of private core server_name API replaced by public HealthMachine validation;
old network tests expecting mark/suppression projection refusal corrected to
retention plus strict audit refusal; Hickory0.26 public-field API and trailing-dot
question mismatch fixed; a cadence method-signature replacement compile failure
fixed before the full suite. No unresolved compile/test failure remains.

## Cross-build reproducibility and artifacts

Exact additions: rustls0.23.46 (default off,ring/std/tls12), tokio-rustls0.26.6
(default off,ring/tls12), webpki-roots1.0.11, hickory-proto0.26.3 (default off,std),
rcgen0.14.10 dev-only (default off,ring/crypto). Existing pinned Tokio1.52.3,
Hyper1.12.0/Hyper-util0.1.21 retained. Tokio sync is production, test-util dev-only.
Cargo.lock SHA256 `1084f6aad9ae3724707f1eef24236861bf7da377869da88dc02d0df60f779f5e`.

No cross C compiler was installed. Controller explicitly authorized an unprivileged
checksum-pinned Zig toolchain under ignored target, without system package/root
mutation. PyPI ziglang0.15.2 wheel URL:
`https://files.pythonhosted.org/packages/db/81/f9f5c7fd68d80b8edff2a641a1c95ac4125356387d298374227040b8e1e8/ziglang-0.15.2-py3-none-manylinux_2_12_x86_64.manylinux2010_x86_64.musllinux_1_1_x86_64.whl`
SHA256 `806316453d1ede7174ed3fefb8e5348154629089c3bb5fe812dfd0e172fac130`.
Origin retained `target/toolchains/ziglang-origin.json`. Fixed target wrappers
under target/toolchains strip cc-rs's incompatible Rust --target triple and use
Zig's ARCH-linux-musl target. Zig additionally used its normal user cache.

```sh
CC_x86_64_unknown_linux_musl="$PWD/target/toolchains/x86_64-linux-musl-cc" cargo rustc -p vprouter-worker --release --target x86_64-unknown-linux-musl --test localapi_lab -- -C relocation-model=static
CC_aarch64_unknown_linux_musl="$PWD/target/toolchains/aarch64-linux-musl-cc" cargo rustc -p vprouter-worker --release --target aarch64-unknown-linux-musl --test localapi_lab -- -C relocation-model=static -C linker=/home/opsec/.rustup/toolchains/1.97.0-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld -C linker-flavor=ld.lld
CC_aarch64_unknown_linux_musl="$PWD/target/toolchains/aarch64-linux-musl-cc" cargo build -p vprouter-worker --lib --target aarch64-unknown-linux-musl
```

Both labs are ELF64 EXEC statically linked; readelf asserts no INTERP or DYNAMIC.
Final source artifacts:

| Artifact | SHA256 |
| --- | --- |
| target/x86_64-unknown-linux-musl/release/deps/localapi_lab-4312258affff21a6 | b00029b8b140c473212e3f90fd7a4d3ffcb6b7d243263121812f787d006fc1f2 |
| target/aarch64-unknown-linux-musl/release/deps/localapi_lab-7e8abf8dcc222bcf | 5e284da4ea8d6d71945ee91f4c0027c0466b83c52316fc8f890bbea52cede441 |
| target/aarch64-unknown-linux-musl/debug/libvprouter_worker.rlib | c7bd4eaff61547226407fef3c02a5e71be37ccd981401bf081b377a60bcbf644 |

x86 lab bytes unchanged by dev-feature cleanup. Direct unprivileged invocation
prints `SKIP: requires controller-owned disposable guest and --ignored` before
marker/socket access. ARM64 typecheck/library codegen/static linking passed;
ARM64 execution/kernel/runtime NOT_RUN. Earlier cross failures: missing musl-gcc;
initial Zig wrapper incompatible Rust triple; ARM Zig linker duplicate crt1
_start; unstable gnu-lld spelling. Corrected fixed wrappers and stable rust-lld
ld.lld produced the final successful builds above.

## Controller-owned actual LocalAPI parser smoke

Controller alone installed the exact x86 static artifact in its disposable guest,
verified SHA, and ran its protected isolated harness. No guest operation was run
by this implementer. Reproducible setup now lives in controller-owned
`tools/worker-localapi-parser-oracle.py` and
`tools/worker-localapi-parser-guest.py`; guest setup SHA256
`85503f2e7896351782e0b1ccc4ba944d32677ff5bac28a09ae62e6ccbcbf8a75`.
Original driver `target/lab-state/run-worker-localapi.py` SHA256
`512684eeac2baaa78f662be0d655f48617592f8430c97b1d92c3dd486b649d2b`.
Controller command (worktree-relative artifact):

```text
python3 target/lab-state/run-worker-localapi.py target/x86_64-unknown-linux-musl/release/deps/localapi_lab-4312258affff21a6 b00029b8b140c473212e3f90fd7a4d3ffcb6b7d243263121812f787d006fc1f2 ad9b38d4e238c7e0418cbb7db822a7d23a66f97d
```

Driver invokes `sudo timeout --kill-after=3s 14s unshare --net --mount
--propagation private python3 -` inside the owned guest. Setup validates root
marker0600/single-link, exact pinned enrolled-only container, root-owned socket,
private mount/network namespaces; private readonly tmpfs exposes a fixed symlink
to the validated exact proc-root socket and checks matching device+inode.
This is client-parser access, not actual namespace worker placement. Harness
performs only two fixed GETs; no preference/state/daemon writes, no WAN.

- Attempt1, `target/lab-state/worker-localapi-run-1.json`,14:57:47Z: setup FAIL
  exit1/.191s before executable invocation, missing fixed socket after directory
  bind. util-linux canonicalized the foreign proc-root source into private empty
  /run; --no-canonicalize cannot import that mount. Original failed setup retained
  `target/lab-state/run-worker-localapi-guest-attempt1.py`, SHA256
  `b7313ebc93dc0f82625f5b2fa77b62728e922cf699556889bba79d2e46dd2ae0`.
  Parser NOT_RUN in this attempt; no parser/daemon failure inferred.
- Attempt2, `target/lab-state/worker-localapi-run-2.json`,14:58:50Z: exact source
  ad9b38d/artifact b00029b8, PASS_NATIVE_LOCALAPI_PARSER_ONLY, exit0/.150s. Actual
  pinned1.102.5 Running+online, NetfilterMode2,0 advertisements; guard_runtime:false,
  activation_ready:false. Source/socket inode validated as above.
- A prior wrong-SHA controller invocation stopped before guest harness execution;
  it supplies no parser evidence. Both actual setup attempts remain preserved.

Native worker placement, native real-provider TLS, actual preference-write/
withdraw/advertisement approval sequence, guard enforcement and real client
traffic remain NOT_RUN. Parser success against actual daemon is deliberately
narrower than runtime acceptance. Actual NoSNAT/SSH writes remain synthetic;
controller previously tested only narrow mode0 on a separate no-login oracle.

## Task8 gates and residual concerns

1. Bind production placement to reviewed helper's exact allocation, exit,
   generation, selected namespace/cgroup and placement authority, plus production
   manifest/guard/init executable integration. Observed current inode alone is
   insufficient. No production flag or test constructor may bypass this.
2. Core Profile currently validates then discards DNS tokens. Retain protected
   approved private resolver authority and enforce WG-only DNS/HTTPS in the data
   namespace. No host resolver or arbitrary caller authority.
3. Full quarantine blocks provider/control too. Build exact owned health-only
   bootstrap while Tailscale forwarding stays dropped, retained by authenticated
   guard capability. Notification ACK never grants guard release. Bind peers,
   exit/generation and implement independent90s watchdog/fixed init daemon handle.
4. Independently approve exact real marked-rule/active table52 route and control
   witness; suppress/remove random kernel fe80/64 at initialization rather than
   broad acceptance. Rule decode fixture is not policy authorization. Retain all
   strict unexpected-route/LAN/mark negatives.
5. Test actual narrow pref writes, withdrawal/readback, guarded offer/approval/
   pending/revocation and bounded stop against actual daemon. Preserve identity,
   approvals and protected operator lifecycle. No approval timing claim here.
6. Bind redacted health to exit/generation/freshness and never guard authority.
   Bound process termination separately from fsync writer; a late disk write or
   unkillable kernel D-state cannot be promised a userspace completion time.
7. Run independent DNS/IPv6, real client route/leak, fault kill/freeze/full-disk,
   reboot/soak/performance, ARM64 runtime/kernel and release-platform acceptance.
   All unavailable/NOT_RUN here; no deployment, READY, active guard, production
   migration or real traffic claim follows from synthetic tests or parser smoke.

## Exact source hashes

Source-set SHA256 `050ad3d3a39820e203414f1c0ad4b4e018cb61c7c9000defee7a4f1b1cc6cd84`.
Algorithm: construct Cargo.toml, Cargo.lock, worker Cargo.toml, all worker src
*.rs recursively, all network src *.rs recursively, and the rule fixture; order
with Python `sorted(Path(...))` (path-component ordering); hash concatenated
`str(path).encode() + NUL + file_bytes + NUL` in that order. Individual hashes
below bind exact bytes; no controller docs/tools are part of this source set.

| Source | SHA256 |
| --- | --- |
| `Cargo.lock` | `1084f6aad9ae3724707f1eef24236861bf7da377869da88dc02d0df60f779f5e` |
| `Cargo.toml` | `176cc9806b140eb630ab420b704d080b1869b212b1e61f43675859b39a1719e9` |
| `crates/vprouter-network/src/audit.rs` | `2afcf90af2815f405320d2dee6020b37c45fa85a869806b58e2400690c9474fc` |
| `crates/vprouter-network/src/lab.rs` | `77448fd913113e3400c6c47587261703918ca424bad38eec363d95256d38a668` |
| `crates/vprouter-network/src/lib.rs` | `9084a93f46f25ab067d34e4d498c22e5cac8ec2c2865e6da479f890adec2a153` |
| `crates/vprouter-network/src/native.rs` | `b4294d94889c10b2d1a665332f2112941701be8729565c6c61b9b56b2cb2e2bf` |
| `crates/vprouter-network/src/plan.rs` | `bbe4ba0400b1fac0b930c9c2223f0c9b9449ba021768ea6c50cf3fb50eeb65a7` |
| `crates/vprouter-network/src/project.rs` | `f94334771ac83bb4e47069b7134c91e7201d7feb0ca0b7da8303905cdd442f05` |
| `crates/vprouter-network/src/socket.rs` | `ee42502a014a7ffc8de9ff6da467355bad5c91ee683f367769f980ce0cd2400a` |
| `crates/vprouter-network/src/tests.rs` | `8d9c309f7c640efaa8e5dda62fdaba691ce6215154d9bf32e53415545aa1219a` |
| `crates/vprouter-network/tests/fixtures/tailscale-rules.json` | `36bb7fde987e46e03d229bee47c36dabfed65c7e49562cff3f4afad917ed4aeb` |
| `crates/vprouter-worker/Cargo.toml` | `c6112080f5a952598c39870c3eb0e7f773561b78cac43cf53a67bf0ef21e75ca` |
| `crates/vprouter-worker/src/client.rs` | `8a3a78a8cf549963080c190717174016f57374374faf4185ba493945a468f338` |
| `crates/vprouter-worker/src/dns.rs` | `d23d729d928566b6c4a1ffbaba332d55cbcfc404afc01e0b3b4fa223333eb99c` |
| `crates/vprouter-worker/src/engine/tests.rs` | `90a7ea2c502b93161f56ceff0da8f32050493ded8038c16dcab7b9fea3fb5ccd` |
| `crates/vprouter-worker/src/engine.rs` | `8bc7a9d1cb86bcfe3ef4bf42add1f9187cd308dc68b9d5efe23358c83c60da43` |
| `crates/vprouter-worker/src/json.rs` | `4bb9f8db62feb8fb25507a43722e9943c0ea5c560d342253c3a2f49cd8cb92f1` |
| `crates/vprouter-worker/src/lab_main.rs` | `9844bf774b110660eb6f8d17fcbade6c7b3d532607bc6b93cc0ee681127ee20c` |
| `crates/vprouter-worker/src/lib.rs` | `f25cc3efc62b34f8d766e2367145cd9711ce1d5d8688b45219034e2a8f9ba971` |
| `crates/vprouter-worker/src/localapi.rs` | `9bcacc09656313f1657c4bdab754fad1d89e014502a54a9ffd0725374530e53c` |
| `crates/vprouter-worker/src/placement.rs` | `51c3d4da956934ae2966de4d6f5ad66ba1944f9ecbd0b4a58ab1aa41f56447bd` |
| `crates/vprouter-worker/src/provider.rs` | `b349e54d36d2efed4e358c8d0eab996ec33bb5e68e86485cdee3c26d4fa51baa` |
| `crates/vprouter-worker/src/publish.rs` | `92e651d9a36bdbd1b294620d05224252b069131773fd35ab175e41b8759b85dd` |
| `crates/vprouter-worker/src/tests.rs` | `14851fa871fa4de86740577f5dcecea7906c653835ba5da679eee51ffa5d7b03` |

## Independent review fix round1

Status: DONE_WITH_CONCERNS. Review at base
`04ecfc6bb80640fd1d5f17249a134319c6f7335e` found specification FAIL / quality
Needs fixes, two Important findings, no Critical/Minor. Review source is
`.superpowers/sdd/rust-v2/task-7-review.md`. This section records implementation
and verification, not independent re-review acceptance. Exact fix source commit
`59550207f81937024a6275e5472df60998fbfcae` (`fix: retry native transport failures
and enforce health expiry`). Only eight explicit owned source/test/doc paths
were committed. Controller progress/task8 brief/oracle changes remain unstaged.

Important1: Hyper established I/O and TLS negotiation could collapse genuine
transient errors to permanent Malformed/Tls and suppress the allowed retry.
The shared transport classification now follows at most eight typed causes,
using io::Error::get_ref for nested I/O wrappers and Error::source otherwise.
Explicit allowlisted ConnectionReset/Aborted/Refused, NotConnected, BrokenPipe,
UnexpectedEof, TimedOut, Interrupted, WouldBlock, HostUnreachable,
NetworkUnreachable/Down may retry. Any Rustls protocol/certificate error,
nonallowlisted I/O kind or overlong chain overrides transient wrappers and is
nonretryable. Hyper parse/user errors remain permanent; its typed incomplete/
closed/cancelled cases retain transport behavior only absent a known permanent
cause. No error-string parsing/logging, TLS verification relaxation, changed
deadline, extra retry or dependency change was introduced.

Controlled loopback regressions exercise actual EOF and TCP RST at three stages:
TLS negotiation, established HTTP before response, and partial response body.
Each of six cases runs both a successful single retry and drift immediately
after the1s delay. Tests assert connection and HTTP request counts, five fresh
structural checks on success versus three on drift, and an immediate structural
check before the second attempt. Handshake failure has zero first-attempt HTTP
requests; established failure has one. Genuine unknown-CA and wrong-hostname
engine tests assert one connection/zero HTTP requests, one structural check and
permanent Tls without retry. Existing malformed protocol/status/body and injected
permanent/repeated-failure tests remain passing. A focused cause test covers
permanent I/O, nested Rustls overriding ConnectionReset and an overlong chain.

Important2: expiry previously happened inside observe after recovery lifecycle
writes; expiry could also yield successful BLOCKED observation while Runner
heartbeated without withdrawing. Minimal shared API `HealthMachine::expire(now)`
extracts exactly the existing cached-evidence check/block behavior and reports
whether evidence was revoked. `observe` uses it without changing its own
semantics. Worker invokes it before sampling, before recovery advertisement and
before replacing evidence. Revocation returns Structural through the existing
error path so Runner notifies guard FIRST, withdraws/readbacks or invokes init,
and publishes blocked state. A defensive check also rejects any successful
observe that changes previously READY into another state. No production
constructor/authority was added.

Paused-clock tests cover exact45s and46s gaps while RECOVERING/READY and expiry
during a sample starting at44s with2s provider work. No expired-streak offer
occurs; after expiry exactly three renewed successes are required to recover,
then a later fresh sample may offer. A real Unix guard Runner regression checks
that the first request is `/v1/worker/block`, records receipt before withdrawal,
asserts no provider/recovery offer or success heartbeat after the gap, and then
checks a separate cancellation block/withdraw on shutdown. Core tests exercise
partial STARTING/RECOVERING/READY streaks, exact45/>45 boundaries, no-evidence
startup, repeat expiry, nonfinite/backwards/future-relative clock checks and
handshake aging to180s. All use private synthetic boundary/loopback transports;
actual guard enforcement is still NOT_RUN.

Red/green evidence preserved in command outputs from this turn:

```text
cargo test -p vprouter-worker --lib real_transport_eof_and_reset_retry_only_after_fresh_checks -- --nocapture
BEFORE: FAILED HandshakeEof drift=false; left Err(Tls), right Ok(()).
AFTER: 1 passed,0 failed,12.05s (all12 fault/drift cases).
cargo test -p vprouter-worker --lib recovering_expiry_before_sample_or_offer_resets_three_success_gate -- --nocapture
BEFORE: FAILED left Ok(()), right Err(Structural).
AFTER: 1 passed,0 failed.
cargo test -p vprouter-worker --lib expired_ready_runner_notifies_guard_before_withdrawing_without_success_heartbeat -- --nocapture
TEMPORARILY RESTORED ORIGINAL engine.rs FROM04ecfc6: FAILED;
left POST /v1/worker/heartbeat, right POST /v1/worker/block;
withdrawal preceded guard notification. Fixed source restored in finally.
FIXED: 1 passed,0 failed.
```

Final focused commands/output at exact fix source (no new full-workspace claim):

```text
cargo test -p vprouter-worker --lib
31 passed,0 failed;12.07s.
cargo test -p vprouter-core --test health
10 passed,0 failed.
cargo test -p vprouter-worker -p vprouter-core --all-targets
core:9+4+16+1+10=40 passed; worker31 passed; total71 passed,0 failed.
custom localapi_lab: SKIP requires controller-owned disposable guest and --ignored.
cargo clippy -p vprouter-worker -p vprouter-core --all-targets -- -D warnings
Finished dev profile,exit0.
cargo fmt --all -- --check
exit0.
git diff --check
exit0.
CC_aarch64_unknown_linux_musl="$PWD/target/toolchains/aarch64-linux-musl-cc" cargo check -p vprouter-worker -p vprouter-core --all-targets --target aarch64-unknown-linux-musl
Finished dev profile,exit0.
CC_aarch64_unknown_linux_musl="$PWD/target/toolchains/aarch64-linux-musl-cc" cargo build -p vprouter-worker --lib --target aarch64-unknown-linux-musl
Finished dev profile,exit0.
CC_x86_64_unknown_linux_musl="$PWD/target/toolchains/x86_64-linux-musl-cc" cargo rustc -p vprouter-worker --release --target x86_64-unknown-linux-musl --test localapi_lab -- -C relocation-model=static
Finished release profile,exit0.
```

Final x86 lab path unchanged:
`target/x86_64-unknown-linux-musl/release/deps/localapi_lab-4312258affff21a6`,
SHA256 `916a904b0aa4cc97e744576c8eec770ab0a79c12a955a7ae1e051a49f3549599`.
file identifies static ELF64 x86-64 EXEC, readelf confirms no INTERP/DYNAMIC;
normal unprivileged invocation explicitly skips. ARM64 worker rlib SHA256
`d7ab1c87e48a93e71cc80e392818126ebac66dff4498eed0b55d392cbd35c665`.
ARM64 kernel/runtime execution still NOT_RUN. Original ARM64 static lab above was
not rebuilt in this focused fix and is not presented as a current-source artifact.
Pinned dependencies/Cargo.lock unchanged; original Zig origin/hash still applies.

Current source-set SHA256
`ed1e1ec0266190d005f3d63a5cf0f62f4d9834c98078a98585896db66715a69e`.
Algorithm is the original Python sorted(Path)/NUL algorithm above, adding
`crates/vprouter-core/src/state.rs` and `crates/vprouter-core/tests/health.rs` to
the set before sorting. Unchanged source bytes retain their prior individual
hashes; changed/added source and documentation hashes:

| Source | SHA256 |
| --- | --- |
| crates/vprouter-core/src/state.rs | 2e0329971ec8893fdfeff5f52b2444fe0c40ba8fe665f68aaad38282f4304ea8 |
| crates/vprouter-core/tests/health.rs | ef3a6ba666d38e62b9e491da99eb8cb7afe92492515628491ee9f71433be0772 |
| crates/vprouter-worker/src/client.rs | 07e63883b809f6c714e23503f399d9a1aa5ddccc7e1689a884a820f732ec22c9 |
| crates/vprouter-worker/src/engine.rs | 96a722abc752ec5393967e09c403a8e269acec0d85b9afb6a84ba97c880c24a2 |
| crates/vprouter-worker/src/engine/tests.rs | fbc3bc30984ed9286e40e98f97f300c72ba7296ef758b0c70e6cb1a0be00a2d5 |
| crates/vprouter-worker/src/provider.rs | c6c4731a33c84de13da3f4d21464bd6e26644140d9eec77af66b5a529b2195e8 |
| crates/vprouter-worker/src/tests.rs | ad0eb0f192232e6abe30424fd618b733b7bc44d71b56ffdd6a3235e6fde00de5 |
| docs/rust-v2/worker.md | 51c525d3002faca48752e5c939fac2bf4da59ea78462139b964832193445b1ae |

No runtime source edits follow the advertised `5955020` candidate. All original
task8+ actual placement, resolver, routing witness, guard/watchdog/authentication,
preference/approval transition, traffic/DNS/IPv6/platform/fault/soak/reboot gates
remain explicit and unverified; parser smoke alone cannot establish activation.

### Controller exact rebuilt-parser attempt3

Controller alone ran the new exact artifact through tracked driver
`tools/worker-localapi-parser-oracle.py` (SHA256
`44c34419c1fceb4766351921e9be250dff03e4e60304000df2ddbfeedf44d51b`), which now
propagates harness failure as a nonzero process exit after recording JSON.
Guest setup/source remains unchanged at SHA256
`85503f2e7896351782e0b1ccc4ba944d32677ff5bac28a09ae62e6ccbcbf8a75`.

```text
python3 tools/worker-localapi-parser-oracle.py target/x86_64-unknown-linux-musl/release/deps/localapi_lab-4312258affff21a6 916a904b0aa4cc97e744576c8eec770ab0a79c12a955a7ae1e051a49f3549599 59550207f81937024a6275e5472df60998fbfcae
```

`target/lab-state/worker-localapi-run-3.json` records PASS_NATIVE_LOCALAPI_PARSER_ONLY,
exit0/.159s at2026-10-24T15:12:05.877625Z, exact source `5955020` and artifact
`916a904b`. Actual pinned daemon Running/online, NetfilterMode2,0 advertisements,
guard_runtime:false and activation_ready:false. Private no-WAN/mount setup and
matching actual socket device/inode were checked. No preference/state/daemon
writes; production_changes:false. Native worker placement, real provider TLS and
real client traffic remain NOT_RUN. Prior attempts1/2 and original artifacts
remain historical evidence; this read-only parser smoke does not exercise the
fixed monitoring loop against actual traffic or supply guard authority.
