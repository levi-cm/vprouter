# Task 5 implementer report

Status: DONE_WITH_CONCERNS. Bounded native route/WireGuard component implemented;
activation and real router acceptance remain explicitly unimplemented/unperformed.

Initial component code commit: `a01d28d4f3d88d691088614e0a610e33fef22f13`
(`feat(network): add bounded native audit and DOWN-only provisioning`).
Parent: `48293d5` (controller's intervening review/enrollment ledger commit;
initial dispatched reviewed code base was `37034ea`). Worktree/branch:
`/DATA/AppData/vprouter-rust-v2`, `rust/v2`.

Initial guest-tested static test executable:
`target/x86_64-unknown-linux-musl/release/deps/vprouter_network-f26312060b05102f`.
SHA256: `d2d739d6bd7e8bfb2ecca88c66d86b70de99c717efb618c83f949d78233cc308`.
No implementation source changed between building that payload and its guest run.
The subsequent code commit includes documentation finalized after that build.

## Implemented

- New `vprouter-network` library; full allocation validation, exact exit membership,
  Mullvad only, public profile endpoint/peer/source and derived X25519 public
  identity. No arbitrary user-supplied link/table/delete API or native JSON input.
- Namespace-local reusable NETLINK_ROUTE and WireGuard generic-netlink sockets,
  safe rustix transport/poll and maintained rust-netlink payload codecs. Direct
  dependencies exact pinned and Cargo.lock updated. Investigated rtnetlink0.23.0;
  chose maintained synchronous packet codecs with explicit bounds instead of an
  async background request stream.
- Bounded projected links/IPv4+IPv6 addresses/all routing tables/all policy rules,
  WG public identity/one peer/endpoint/allowedIPs/handshake time. Fixed errors;
  no raw private-key-bearing GET response, payload or external error exposed.
- Pure structural audit with clock argument and strict handshake age below180s;
  absent, unverified, rejected and observationally valid are distinct. Tests
  reject route/default/endpoint/Docker/rule/IPv6/interface/kind/index/name/key/
  endpoint/source/handshake drift. Positive fixtures contain independent literal
  routes/rules from controller synthetic kernel oracles, not calls to the
  expected-route implementation.
- Exclusive native DOWN WG creation/configuration, native DOWN move to supplied
  data FD, exclusive DOWN host/transport veth creation with peer target FD,
  scoped DOWN-only reconciliation/cleanup. Alias initialization is private and
  possible only immediately after a successful exclusive-create ACK; newly created
  links must be exact/DOWN/unaddressed/unrouted, with empty-or-matching aliases;
  veth indices must already be reciprocal. It never adopts an existing unlabeled
  link. Kernel ignores initial NEWLINK aliases on this tested kernel, so native
  SETLINK assigns missing aliases while DOWN, followed by full verification.
- Minimal borrowed `Profile::with_private_key` closure accessor; no Debug/Serialize
  secrets. Native raw request/reply buffers and completed typed key temporaries
  use zeroize. No guarantee is claimed for ordinary Profile fill-on-drop, all
  compiler/OS copies, or upstream failed-decode temporaries.
- Ignored guest-only harness with the same root marker/ancestor/FD admission
  contract as netfilter. Independent test-only ip/wg controls, direct proc-netns
  FDs obtained through test-only dedicated synchronous namespace threads, fixed
  bounded stage/numeric diagnostics, unrelated sentinel and owned-only cleanup.

## Explicit design boundaries and concerns

No enforced cross-crate quarantine handle exists. Per brief and controller
confirmation, this component has **no activation, address/default/endpoint route
installation or quarantine removal method**. Host and transport subnet +1/+2
addresses are planned only. The later guard must install independent quarantine
before any usable transport and implement those remaining mutators.

NamespaceTarget pins/checks nsfs and direct `net:[inode]` proc-FD form and matches
destination socket identity. It does not prove container/PID/cgroup/allocation
authorization or which namespace is transport/data/host. Caller must establish
that provenance through the future trusted single-threaded helper before opening
sockets and supplying FDs. Persisted bind-mount handles are rejected; a trusted
helper can validate/enter their namespace and reopen a direct proc FD.

Ownership checks and mutations are not an atomic alias/ifindex CAS. Cooperative
lifecycle/allocation exclusion is required. Concurrent privileged writers can
forge aliases, recreate ifindices or bring links UP between checks and mutations;
this component cannot defend against them. Ambiguous errors can leave DOWN,
possibly not-yet-labeled links; no broad cleanup is attempted. No final quarantine
removal exists. The multi-dump snapshot is non-atomic observational evidence,
never no-race enforcement or readiness. Repeating it does not replace nft drop.

Audit intentionally supports only a strict minimal rule/local-route profile.
Actual Tailscale fwmark/table52 rules/routes and automatic FE80/anycast state are
currently unsupported and fail closed. Optional admitted Tailscale ULA/128 local
metadata is modeled precisely; full Tailscale integration remains future work.
Default route must deliberately use static protocol, WG output and exact profile
preferred source. No legacy default or current real router is claimed equivalent.

Transport bounds: total5s per public operation, including final verification;
256KiB datagram/request,4MiB/4096 messages per exchange,2048 attrs/depth8 before
payload parsing; snapshot at most9 exchanges/36MiB, largest DOWN pair create/verify
at most21 exchanges/84MiB. Sender/sequence/embedded ACK request binding, positive
ACK, multipart/DONE/status/interruption/truncation/overflow are verified. Failed
exchanges poison sockets. Unsupported functional attrs, NET_BYTEORDER flags,
split/multiple WG messages, multipath/encapsulation/nexthop IDs/rules fail closed.
Only exact inactive metadata and disabled suppress-prefix U32_MAX sentinel are
accepted; corresponding functional values have rejection regressions.

No production unsafe, FFI, subprocess or setns calls. `#![forbid(unsafe_code)]`.
Native syscall/crypto dependencies have their own platform/unsafe internals;
no claim that the entire dependency graph is unsafe-free is made. The only
Command calls and namespace entry are in cfg(test) `src/lab.rs`; no shell is used.
License inventory: rust-netlink codecs MIT, existing rustix Apache/MIT-compatible,
zeroize Apache-2.0 OR MIT, X25519-dalek BSD-3-Clause (MIT-compatible).

## Verification commands and results

Executed in worktree; default commands did not mutate host network/kernel state
or read real credential profiles:

1. `cargo test --locked --offline -p vprouter-network`: final13 passed,0 failed,
   1 ignored guest harness;0 doctests. The13 tests contain multiple fault cases.
2. `cargo fmt --all -- --check`: PASS, no output.
3. `cargo test --locked --offline --all-targets`:90 passed,0 failed,2 ignored
   (existing netfilter and new network guest harnesses).
4. `cargo test --locked --offline --doc`:1 compile-fail doctest passed.
5. `cargo check --locked --offline --workspace`: PASS.
6. `cargo clippy --locked --offline --all-targets -- -D warnings`: PASS, no warnings.
7. `cargo check --locked --offline --target aarch64-unknown-linux-musl -p vprouter-network --lib`:
   PASS, compile only; ARM64 kernel execution/link/runtime acceptance NOT_RUN.
8. `cargo test --locked --offline --release --target x86_64-unknown-linux-musl -p vprouter-network --lib --no-run`:
   PASS; executable/hash above. Rebuilt only after new code/observed guest failures.
9. `git diff --check` and `git diff --cached --check`: PASS.

No explicit TDD workflow was required by this task. Initial scaffold/check and
fixture iterations had corrected compile errors and fixture schema/profile-reader
assertion mistakes; final results above supersede those, without claiming RED/
GREEN evidence or integration success from unit tests.

## Controller-owned isolated guest attempts (preserved, not erased)

Controller ran, never implementer:
`sudo unshare --net /root/native-network-test --ignored --exact lab::native_acceptance --nocapture`
in owned disposable Debian13 KVM guest, kernel6.12.113+deb13-cloud-amd64.
No provider credentials or peer connectivity were used. Controller evidence:
`docs/rust-v2/network-lab-evidence.json` (not staged/owned by this implementer).

| Attempt | Payload SHA256 | Result and cause/correction |
|---|---|---|
|1|`badf4508fa2920e70a6ef172d610d25a6e4f445661a1532e15ea88a46899ccff`|FAIL101/.01s before firstcase: bind-mount namespace FD rejected. Test helper now returns direct proc FD; production verification retained.|
|2|`a577f624e0467212d3f52124061ad9c3226489e182785ad0fcf9aa3d2cbd112b`|FAIL101/.02s: inactive nested DEVLINK_PORT(0x803e), no cases. Accept only empty metadata; populated association remains unsupported.|
|3|`b07da239e7a8e025f5329c06fc79af0a7c779165687f1e341948c4f4620c2968`|FAIL101/.01s: inactive nested DPLL_PIN(0x8041), no cases. Accept only empty metadata; populated pin remains unsupported.|
|4|`463ff4addc658b0c5dfc5b370b925468009199bb534d1956eb12ad576fa76f94`|FAIL101/.03s: foreign refusal passed; new veth ownership verification failed. Added bounded public property diagnostics.|
|5|`26e9d7b0dd0c5f25049662b4852469bba30a2039c27260fc8cac8886c0abcb56`|FAIL101/.03s: exact newlink kind/DOWN/MTU matched, alias absent. Added exclusive-new DOWN-only native alias initialization, never adoption.|
|6|`13ff8c2b415948b7506acb582c26e4790cdb2608de9445e2eb699d64e3299eb7`|FAIL101/.07s: foreign+veth cases passed; WG create/configure/move completed, full observation hit unsupported rule metadata.|
|7|`867821582b936453cccc7f3d50f42938deb32762d4f27f7eb8cb89c64fd56512`|FAIL101/.06s: same2cases; diagnosed FRA_SUPPRESS_PREFIXLEN=4294967295 disabled sentinel. Only exact sentinel accepted; functional values regressions reject. Root read-only inventory confirmed zero residual named lab namespaces after exit.|
|8|`d2d739d6bd7e8bfb2ecca88c66d86b70de99c717efb618c83f949d78233cc308`|PASS0/.22s;1 test passed,13 filtered; all5cases and final component JSON passed, guard_runtime:false,activation:false.|

Final five cases: foreign-name refusal without replacement; both native veth ends
DOWN/owned and duplicate refusal; WG moved DOWN with public peer endpoint and
allowedIPs independently checked; address projection and address-drift cleanup
refusal; owned-only native cleanup with sentinel preserved. Test-only ip address
addition proves projection/refusal, not a production native address mutator.

Controller's independent synthetic /32, attached-TUN and read-only redacted legacy
route/rule oracles informed exact local-route fixtures. They do not prove native
Tailscale parity, traffic isolation or socket-birth behavior. WG create/move and
absence of data veth are observed; actual UDP socket birth/egress isolation is
NOT_RUN. The kernel's documented socket-birth semantics are a design assumption,
not an independently measured result here.

## Files and unperformed work

Owned: Cargo.toml, Cargo.lock; minimal core profile accessor; new crate manifest
and lib/plan/socket/project/audit/native/tests/lab modules; network.md; this report.
No CLI/core validation/netfilter/controller evidence/progress files were changed
or staged by this implementer. No services, Docker, production networks, releases
or real profiles were modified; no subagents were spawned.

NOT_RUN/unimplemented: namespace ownership/launch helper; native active address/
route/transport setup and quarantine integration; real provider/server identity,
handshake/connectivity, Tailscale/client traffic, packet capture/leak/fault gates,
independent UDP birth namespace proof, ARM64 kernel run, deployment, reboot,
migration, performance/soak and all mandatory full release acceptance. Independent
component review is the controller's next step, not completed by this report.

## Fix round 1: inseparable veth ownership and single-response framing

Code commit: `8a1c97cdcddadb371bf25c7a09c24d39573201f9`
(`fix(network): bind veth cleanup to original namespace pair`). Immediate parent
`d931629` contains controller review/brief/ledger documentation. Prior reviewed
component/report head was `0631fb0`; intervening root documentation is preserved.

Both review findings were verified against the implementation and addressed:

- Important: `VethPair` endpoints are private, with only borrowed `host()` and
  `transport()` inspection getters. The original namespace identities remain in
  the inseparable pair's private tokens. Before any netlink request, cleanup
  binds both supplied socket handles to those identities, requires distinct
  namespaces and equal Plans. Existing exact ownership/DOWN/address/route/peer
  checks still precede deletion. A compile-fail public-API example prevents
  owned token recombination. The focused offline collision regression models
  two same-Plan pairs in H1/T1 and H2/T2 with identical names/aliases and local
  indices 2/2. Cleanup using H1/T2 refuses both intact pairs with
  `NamespaceUnverified`. Test-only sockets reject every request before I/O with
  `SequenceMismatch`, proving the namespace refusal precedes observation and
  deletion. This is an offline ordering regression, not a fresh kernel result.
- Minor: `Completion::Single` rejects `NLM_F_MULTI` data immediately, regardless
  of ACK order. The focused regression first failed against the old framing
  (`Ok(())` instead of `Malformed`), then passed after the fix. It also accepts
  a normal single data message plus ACK in either order and verifies that dump
  multipart data remains incomplete until successful DONE.

Commands/results for this fix, all without host network mutation or credentials:

1. `cargo test --locked --offline -p vprouter-network colliding_veth_indices_in_other_namespace_pairs_refuse_before_io`:
   PASS, 1 focused test. `cargo test --locked --offline --doc -p vprouter-network`:
   PASS, 1 compile-fail recombination doctest.
2. `cargo test --locked --offline -p vprouter-network single_rejects_multipart_data_in_either_ack_order`:
   expected initial FAIL demonstrating the old bug; final PASS, 1 focused test.
3. `cargo fmt --all`, then `cargo test --locked --offline -p vprouter-network`:
   PASS, 15 unit tests, 0 failed, 1 ignored guest harness; 1 compile-fail doctest
   passed. The two new unit tests contain the collision/framing fault cases.
4. `cargo fmt --all -- --check`: PASS.
5. `cargo clippy --locked --offline --all-targets -- -D warnings`: PASS.
6. `cargo check --locked --offline --target aarch64-unknown-linux-musl -p vprouter-network --lib`:
   PASS, compile only; ARM64 kernel execution remains NOT_RUN.
7. `cargo test --locked --offline --release --target x86_64-unknown-linux-musl -p vprouter-network --lib --no-run`:
   PASS. Updated static executable:
   `target/x86_64-unknown-linux-musl/release/deps/vprouter_network-f26312060b05102f`.
   SHA256: `584577685bd0b61a45dc610c0e708ef04f0171e823060681d1f8d6a6b7a2f284`.
8. `git diff --check` and `git diff --cached --check`: PASS.

Because cleanup's public preflight changed, the updated payload is supplied for
controller rerun of the existing ignored guest harness. The earlier attempt8 PASS
above applies only to the previous payload, not this fix. This implementer has
not run the updated payload in a guest. No new ignored lab execution or runtime
acceptance is claimed; controller evidence remains separately owned.

Only `crates/vprouter-network/src/{native,socket}.rs`,
`docs/rust-v2/network.md`, and this report were changed/staged by this implementer.
Root progress/review/evidence/brief files remain untouched. No subagents were
spawned; no production unsafe, FFI, subprocess, activation or namespace-entry API
was added. Existing non-atomic snapshot/alias-ifindex TOCTOU and namespace trust
boundaries remain; all earlier unperformed runtime/release gates still apply.
