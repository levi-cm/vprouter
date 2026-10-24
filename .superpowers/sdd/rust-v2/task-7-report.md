# Task7 native monitoring worker implementer report

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
