# Nine-area implementation report — active, milestone 1

Overall status: IN_PROGRESS / continuation required. This is not a release or a
completed nine-area implementation. Sole implementer; no delegated agents.
Worktree rust/v2; baseline dirty changes preserved; real index/branch unchanged.
No production operations, credentials/profile reads, privileged tests, Docker
restart, remote installation, enrollment, publication or push.

| Area | Implementation | Verification / remaining gate |
|---|---|---|
| 1 Secret lifetime | Implemented: compiler-resistant key, decoder scratch/partial-output, bounded owned profile inputs and canonical scalar duplicate tracking | Core tests PASS; zeroize is compiler-resistant, not a promise to erase all compiler/register/OS copies of borrowed input |
| 2 Shared health wire and authenticated publication | PARTIAL: shared v2 schema; worker publisher and CLI decoder; CLOCK_BOOTTIME; generation/config/boot/node binding; immutable replay cursor | Shared wire and publisher tests PASS. Authenticated host publication bridge and live lifecycle integration still required; cached reports never grant readiness |
| 3 Shared host multi-exit authority | Implemented in native activation/audit/cleanup: one shared generation-bound aggregate, explicit unrelated declaration, exact owned deltas | Two regression tests PASS; actual multi-exit VM addition/removal test still required. Protected production declaration loader and dynamic allocation-generation lifecycle are part of area 4 |
| 4 Guard/worker/init/watchdog/CLI/direct runtime | PENDING integration; native worker clock corrected, safe startup refusals preserved | No operational guard/watchdog/runtime claimed. Existing observer remains one-use/unenrolled |
| 5 Persistent client protections | PENDING | Real client fault acceptance required |
| 6 Identity-preserving migration | PENDING | Two local established identities and controller-owned tests required |
| 7 Platforms/services/releases | PENDING service/release integration; incremental static x86_64/ARM64 builds PASS | Root preparing local Arch/systemd, Void/glibc/runit and ARM64 environments. Compilation is not runtime acceptance |
| 8 Actual hostile faults | PARTIAL: actual_lab adds post-pin TUN MTU/address, route, rule drift; old daemon authority remains revoked after repair | Controller run24 PASS for four actual post-pin faults; remaining faults/configuration/client matrix open |
| 9 Full-router performance and 24h soak | PENDING | Real repeated ten-minute measured workloads and 24h elapsed soak remain mandatory |

## Implemented behavior and files

1. `crates/vprouter-core/src/profile.rs`: SecretKey uses zeroize; decoded output
   and rolling decoder scratch erase even on errors. Profile::load preallocates
   the bounded input in Zeroizing to avoid secret-bearing reallocations.
   `config.rs` retains canonical clamped keys in a fixed-capacity zeroizing Vec,
   preserving disabled-exit and clamp-equivalent duplicate detection.
2. `crates/vprouter-linux/src/storage.rs` adds bounded read_secret with ownership
   checks and Zeroizing before read; `lib.rs::load_profile` uses it. This is a
   second real loader; changing core Profile::load alone was insufficient.
3. New `crates/vprouter-core/src/health.rs` and `tests/health_wire.rs`: version 2,
   bounded strict serde contract; deployment/exit/mode/generation/display/server/
   authorized node/config fingerprint/boot binding; sequence, publication time,
   original evidence and reason. Snapshot is observational, never a capability.
   ReplayWindow pins its first binding, rejecting later generation/boot rebinding.
   CLOCK_BOOTTIME counts suspend; process-relative or future times refuse.
   `state.rs` exports private evidence/binding helpers only.
4. Worker `publish.rs` serializes this Snapshot atomically, retaining bounded
   one-in-flight fsync queue, exact private inode/owner/mode checks. `engine.rs`
   native Inputs use boot time for every structural/provider/publication timestamp;
   test Inputs retain controlled Tokio clock injection. Worker tests decode actual
   published bytes with the shared reader and verify sequence/identity.
5. Linux `status.rs` consumes the same schema. Expected generation comes from
   independently root-owned `/run/vprouter-v2/<deployment>/allocations.json`,
   validated against config, rather than the received snapshot. Health cache path
   is `/run/vprouter-v2/<deployment>/<exit>/health.json`. Missing allocation or
   host publication is unverified. Root host bridge is not implemented yet.
6. Network `guarded.rs` introduces HostAuthority: shared Rc/RefCell aggregate,
   bound complete allocation membership, generation and host namespace. Admission
   compares a predeclared unrelated host baseline with two native observations;
   it cannot learn unknown resources while reconciling drift. Each activation
   adds only its exactly derived host link/address/routes. Audits compare live
   host against the current aggregate, while transport/data remain exact per-exit.
   Cleanup removes only its member after observing the exact expected remainder.
   Failed add/remove never changes the model. `transport.rs` requires this shared
   authority and checks it before durable transport mutation. Existing disposable
   lab explicitly declares its precreated host fixture before activation.
7. Actual-program lab performs four live post-pin mutations after the real Go
   daemon/Rust observer ran. Each requires native verification failure, offline
   policy, permanently revoked old daemon token even after exact repair, then
   independently verified fresh pin under offline policy. No readiness gained.

## Tests and commands

- RED: `cargo test -p vprouter-core secret_key_explicit_erasure_clears_all_bytes`
  failed missing compiler-resistant erasure contract; GREEN core suite passed.
- RED: new health wire tests failed unresolved shared health contract; GREEN
  roundtrip, stale/process-origin/suspend/boot/generation/config/node, duplicate
  field, unknown field and blocked-evidence tests passed.
- Behavioral RED: `cargo test -p vprouter-core --test health_wire replay_window_cannot`
  failed assertion because replay cursor could be rebound to a new generation;
  after pinning binding in ReplayWindow it passed.
- RED: shared host tests failed missing shared HostModel; GREEN add B/audit A,
  remove B/audit A, generation/ownership/undeclared-resource/rule drift and failed
  transaction preservation passed.
- `cargo test -p vprouter-linux -p vprouter-worker --lib`: 60 PASS.
- Final `cargo test --workspace`: **191 PASS**, zero failures, 2 ignored native
  tests plus intentionally skipped controller-only external harness executables.
  Log: `target/implementation-20261026-tests.log`.
- `cargo fmt --all --check`: PASS after formatting.
- `cargo clippy --workspace --all-targets -- -D warnings`: PASS.
  Log: `target/implementation-20261026-clippy.log`.
- Actual lab new faults: controller run24 PASS on corrected frozen source899a874; NOT_RUN by implementer.
- Static builds/source snapshot: root authorized first milestone freeze and
  manifest refresh. Completed `python3 target/implementation-20261026-build.py`;
  log `target/implementation-20261026-build.log`. Adapted original driver to add
  ALL crates/new build inputs into its alternate index, without real-index edits.
  The original `git add -u` alone would omit new health.rs/health_wire.rs.

## Failed attempts retained

- First worker compile after clock abstraction reported missing now method on
  TlsInputs; implemented forwarding to its Script clock.
- First shared-model compile found borrow overlap around host.observe; observe
  before reading plan alias resolves it without changing authority checks.
- First workspace compile found missing qualified Plan/NativeNetwork names in
  test harness; fixed to explicit vprouter_network paths.
- fmt check detected newly added unformatted tests; cargo fmt fixed, final check
  passed. No fault evidence or historical lab resources discarded.

## Source/artifact binding and controller request

Pending build completion: append exact candidate.json/source_commit and both
architecture payload/context hashes below. Root will run actual-program and seven
transport regressions in the preserved Debian guest. This is incremental native
regression evidence, not real-client or release acceptance.

New build inputs that MUST be present in snapshot: core/src/health.rs and
core/tests/health_wire.rs. Cargo.lock records zeroize in core/linux dependencies;
workspace rustix enables time. Other preexisting dirty changes remain included.

## Resource, unsafe and capability inventory

- No new unsafe code or capabilities. Native networking remains in existing
  reviewed modules; no production subprocess added.
- One bounded health writer thread per actual Publisher, existing one-slot queue;
  shared host aggregate one model per admitted deployment generation.
- New subprocesses only inside cfg(test) actual_lab: fixed `/usr/sbin/ip -n` with
  owned namespace and fixed fault/reversal argv; root exclusively runs these.
- New CLOCK_BOOTTIME syscall uses rustix; fixed seccomp already permits clock
  reads. No extra timeout/interval reduction and no weakening of monitoring.

## Exact next implementation / resume steps

1. Finish frozen milestone build, send candidate.json and logs to controller.
2. Complete area 2 authenticated host bridge. Existing Handoff::serve_once pins
   SO_PEERCRED sender via ProducerGroup::pin_sender (retained pidfd/start/cgroup,
   exact program and namespace) and verifies daemon/transport before ACK. Reuse
   this authority; do not accept a root-owned file alone as producer authority.
   Bridge must validate shared Binding, ReplayWindow and CLOCK_BOOTTIME, then
   publish exact root-owned `/run/.../health.json` and allocation generation.
   Producer must send the shared snapshot over this authenticated channel before
   an ACK; retain worker cache only as observational mirror. Bind a fresh worker
   lifecycle/nonce so restart cannot reset replay authority silently.
3. Area 4: bridge must join actual periodic guard/worker startup (current
   bootstrap Permission only ObserveOnce; Placed has no production constructor;
   producer verifies Role::WorkerObserver; manifest/load/Admission::launch/start
   intentionally refuse). Implement separate reviewed actual worker role and
   authenticated guard enforcement, never change those refusals in isolation.
   GuardTransport owns exact namespaces/producer/policy/allocation transaction;
   Handoff borrows those and live daemon. Existing Engine provides native
   provider/retry/LocalAPI logic but Control is draft ACK-only. Implement actual
   enforced Offline/Bootstrap/Ready responses and guard-first ordering; independent
   expiry/watchdog must remain runnable during stalled provider/IO. Existing
   daemon_data permits only unenrolled fixed TUN/no addresses, so operational
   Tailscale shape needs explicitly identity-bound addresses/routes, not recapture.
4. Shared fleet lifecycle must pass one HostAuthority to all exits, load protected
   explicit unrelated declaration, and manage allocation generations/locked
   transaction lifetimes across add/remove. Current GuardTransport transactions
   retain deployment lock; resolve shared lock ownership rather than separate
   independently locking exits. Direct requires distinct native policy/network
   model; existing Plan/Engine reject direct and must remain safe until built.
5. Continue sequentially area 5 client guard, area 6 durable migration, area 7
   service/release integration, area 8 full hostile matrix, area 9 workloads/soak.
   All detailed briefs8c–15 have been read. Do not silently drop pending areas.
6. Root handles real credentials, privileged tests, existing approved lab client
   and gateway identities, and new platform VMs. Never reenroll/reset them.

## Frozen milestone 1 artifact result

Static x86_64-musl and ARM64-musl build: PASS. Manifest/init-byte checks and frozen build-input verification passed.

```json
{
  "source_commit": "5b4a0c4f399d7ebd692a69db9f906419daeef107",
  "source": "/DATA/AppData/vprouter-rust-v2/target/continuation-20261026T121533Z/source.tar",
  "source_sha256": "e1d129ee324c29746858fb20560b7b06df59143cb9f8e7c4efe4c4f7b99523ca",
  "binding": {
    "source_commit": "5b4a0c4f399d7ebd692a69db9f906419daeef107",
    "source_archive_sha256": "e1d129ee324c29746858fb20560b7b06df59143cb9f8e7c4efe4c4f7b99523ca",
    "tracked_build_inputs_verified": 104,
    "source_aggregate_sha256": "cd0d588de1d942f7e5221146d01cd703a039b299ab9c54741c8d475efaea0827"
  },
  "platforms": {
    "amd64": {
      "artifact": "/DATA/AppData/vprouter-rust-v2/target/continuation-20261026T121533Z/amd64.payload",
      "artifact_sha256": "d7ee4793b2323699ed29aac93243dbe88c7d84d0e0ff3e8927c2546de3e8e6a4",
      "context": "/DATA/AppData/vprouter-rust-v2/target/gateway-context/amd64/context.tar",
      "context_sha256": "d22324ee8386876c2241afe55d8b18979241d7f7d398f26f55f4b71b95f1e089"
    },
    "arm64": {
      "artifact": "/DATA/AppData/vprouter-rust-v2/target/continuation-20261026T121533Z/arm64.payload",
      "artifact_sha256": "099d4312e2fba9cf6935f050b7dc38b9d26d9d54376feb9fa84c103fc9613cf9",
      "context": "/DATA/AppData/vprouter-rust-v2/target/gateway-context/arm64/context.tar",
      "context_sha256": "55332b37fce3ed61011fba916d96629a707390ad5ac048a1bcf482c8af2178ea"
    }
  }
}
```

## Controller regression and corrective freeze

- Controller actual-program run23 on source5b4a0c4 FAILED before cases with
  `descriptor_policy`; raw `target/lab-state/actual-program-run-23.json` retained.
- Cause: new HostAuthority preflight opened NativeNetwork only (route+generic),
  but used Registration::control, which correctly requires route+generic+two nft
  sockets. This was a new integration mistake, not a reason to weaken inventory.
- Fix: typed Registration::network(plan) owns the exact native constructor and
  verifies exactly route+generic; existing control's four-channel policy remains
  unchanged. Both declaration/preflight calls use this path.
- New RED missing-contract test then GREEN tests require route+generic only and
  reject missing/duplicate/wrong/extra sockets; existing control still rejects2.
- `cargo test -p vprouter-launch`: PASS,32unit tests; ignored privileged harnesses
  compiled and skipped. `cargo clippy --workspace --all-targets -- -D warnings`:
  PASS. Build driver rerun preserves first candidate and failure history.
- Root will execute corrected candidate; no privileged operations by implementer.

Corrected frozen milestone1b (latest):

```json
{
  "source_commit": "899a874ac70b1710b23d766d498f5068297a5657",
  "source": "/DATA/AppData/vprouter-rust-v2/target/continuation-20261026T122321Z/source.tar",
  "source_sha256": "aeec478fa946bc221c391799596120b7bcb50d2da63e9edc72ae9181882108ea",
  "binding": {
    "source_commit": "899a874ac70b1710b23d766d498f5068297a5657",
    "source_archive_sha256": "aeec478fa946bc221c391799596120b7bcb50d2da63e9edc72ae9181882108ea",
    "tracked_build_inputs_verified": 104,
    "source_aggregate_sha256": "e301b08cbc80b6bf452ff17f870c6d2ae594552734d5121ead017052593efe04"
  },
  "platforms": {
    "amd64": {
      "artifact": "/DATA/AppData/vprouter-rust-v2/target/continuation-20261026T122321Z/amd64.payload",
      "artifact_sha256": "55beff446077571c932a1857cbc93d295bc1b7d27517d2f614678b347533a9f6",
      "context": "/DATA/AppData/vprouter-rust-v2/target/gateway-context/amd64/context.tar",
      "context_sha256": "a85ff2a110e1148b444caa87b8d14cabe1a561d6c13006c41ae721867b91899d"
    },
    "arm64": {
      "artifact": "/DATA/AppData/vprouter-rust-v2/target/continuation-20261026T122321Z/arm64.payload",
      "artifact_sha256": "ea4d51e63b4f9a7eae19ba3aa7f9e1157bd118117c7e5c1af0e4ef08928110d1",
      "context": "/DATA/AppData/vprouter-rust-v2/target/gateway-context/arm64/context.tar",
      "context_sha256": "7a205912cf06f58230410babc67b03b0734f97c94dea9adf41399c962f2661e5"
    }
  }
}
```

## Controller actual run24 result

Controller-owned Debian VM run24 on899a874ac70b1710b23d766d498f5068297a5657 returned exit0, PASS_PARTIAL_ACTUAL_PROGRAMS. Raw target/lab-state/actual-program-run-24.json. All four injected post-pin DataDrift detections appear before bounded daemon/container shutdown. This is actual unenrolled-program/kernel-fault evidence; real-client readiness/acceptance remains NOT_RUN. Remaining seven transport regression results are controller-owned and pending at this report update.
