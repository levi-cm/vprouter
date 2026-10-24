# Task8a: guard-owned native transport and bootstrap quarantine

Status: IMPLEMENTED_WITH_SCOPED_EVIDENCE; independent review pending.
All seven final candidate18 local guest scenarios passed. This is task8a only.
Task8 integration, real Tailscale-client acceptance and production release remain closed.

## Source and exact artifacts

Implementation commit: 222fa7c (29 explicit owned source/Cargo paths).
Original review base: fefde3d61e6e4d6246704d0d3e1e4d72427f744f.
Parent owns tools, public runtime evidence and privileged execution; this implementer
performed no privileged guest/kernel/network or production operations. All work
and testing stayed local. No remote installation or real identity/profile access.

| Artifact | SHA256 |
|---|---|
| /tmp/task8a-candidate18 | bd7d9a0650f63ce7207d913ba18dd2eee1c85e9c94dbc029c445eae6a0c97521 |
| /tmp/task8a-candidate18-source.tar | 7ce5d888721679bfb2e9a728761a3f3d04ac9df45a8b3b9ba2b2e3b8f87d91c5 |
| x86_64 musl release vprouter-launch-admit | 6794775703caaa34b99cbd2a869aee0b1ccc3927db3cb7a424de0a041145b3b6 |
| ARM64 musl release vprouter-launch-admit | 348434c942b40f1390b36c84bdf924628e9a699fdc1dd79fc92292ed19d2970c |

Immutable source archive contains Cargo manifests/lock, pinned toolchain and complete
crates tree. Source froze before build/copy/archive; parent docs/tools and this report
are separately committed outside the source archive.

## Enforcement and ownership

GuardTransport is private retained host authority, with no production CLI/startup
or readiness constructor. It retains allocation/generation lock, exact owned
namespaces, producer subgroup, three namespace-bound native network/nft descriptors,
actual native active-link tokens, validated resolver metadata and allocation Plan.
Single-threaded synchronous namespace entry uses existing kernel.rs wrappers.

Activation refuses unavailable private IPv4 resolver authority before durable
intent/native changes, persists Activating, exclusively creates the producer group,
installs full three-scope quarantine host-first, creates native DOWN veth/WG in
transport, moves WG to primary Docker base data namespace and persists assigned
ifindices/host namespace before any usable operation. Every UP/address/route mutation
freshly verifies full three-scope quarantine. WG UDP socket retains transport birth
namespace. Actual kernel ENETDOWN requires exact owned links UP behind quarantine
before peer routes, without ONLINK bypass. IPv6 autoconfiguration is disabled before UP.

Independent permit AND main quarantine tables both carry bootstrap restrictions.
Data INPUT/OUTPUT require exact root-owned health/control socket producer, IPv4
family and WG path; established INPUT additionally requires its established
predicate and cannot bypass producer identity. Structural IPv4 addresses are
separately audited; this bootstrap statement does not claim an address predicate.
Application FORWARD remains dropped. Missing producer closes bootstrap. Host and
transport restrict allocated source/path and exact public UDP endpoint plus bounded
NAT. Separate retained emergency policy and preopened second nft descriptor restore
containment after removal/drift/ambiguous exchange without overwriting changed resources.

Docker cooperation adds exactly two native nft endpoint UDP exceptions in existing
IPv4 filter/FORWARD hook2 priority0 DROP. It pins table/chain/rule handles, userdata
and full own expressions. No foreign flush/rewrite, arbitrary action parsing,
iptables CLI or Docker restart. Cooperation and producer validate before ANY cleanup
link deletion after a self-review ordering correction; ambiguity retains quarantine.

Durable ownership binds allocation/generation/exit, namespace dev/inodes, assigned
host/transport/WG ifindices and producer parent/group identities. Acquire refuses
Activating/Bootstrap interruption; no name adoption. Successful cleanup verifies
exact resources, deletes native WG/veth and pinned cooperation, removes only empty
owned group and records Offline. Full quarantine and observation pins remain for inspection.

Profile retains at most eight distinct validated DNS IPs, preserving IPv6/public
metadata compatibility, but derives only explicit private IPv4 resolver authority.
No host/environment fallback. Keys remain protected Profile authority and never
appear in diagnostics, public projections, argv or this report.

Host projection retains bridge/slave, promisc/allmulti, altnames, bounded permanent
address/parent device metadata, full address flags/broadcast/prefix priority and
route nexthop ID/preference. Protected link/address/route/rule/WG acceptance stays
strict. Unknown UAPI gives fixed numeric diagnostics. Full raw local RTM fixture
exercises projection offline. Test WAN disables IPv6 autogeneration BEFORE UP,
avoiding DAD changing strict whole-host baseline. Audit was not relaxed.

## Final ordinary local verification

All use pinned toolchain/lock and offline dependencies:

- cargo fmt --all --check: PASS.
- cargo test --workspace --lib --tests --offline --locked: 152 passed,
  2 ignored, zero failures; custom privileged binaries inert. Focused core,
  network, netfilter and launch portion: 100 passed, 2 ignored.
- cargo clippy -p vprouter-core -p vprouter-netfilter -p vprouter-network
  -p vprouter-launch --all-targets --offline --locked -- -D warnings: PASS.
- cargo check -p vprouter-launch --lib --tests --target
  aarch64-unknown-linux-musl --offline --locked: PASS.
- CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=rust-lld cargo build
  -p vprouter-launch --bin vprouter-launch-admit --release --target
  aarch64-unknown-linux-musl --offline --locked: PASS; static ARM64 ELF.
- cargo build -p vprouter-launch --bin vprouter-launch-admit --release
  --target x86_64-unknown-linux-musl --offline --locked: PASS; static PIE.
- cargo build -p vprouter-launch --test transport_lab --release --target
  x86_64-unknown-linux-musl --offline --locked: PASS; frozen candidate18.
- git diff --check: PASS before source commit.

Tests cover strict DNS/redaction, dual bootstrap producer/forwarding/anti-spoof
policy, protected metadata, full raw host projection, durable activation authority,
allocation/namespace/index/peer mismatch and reviewed native atomic codec boundaries.
Unit policy results do not substitute for actual packets or a running real worker.

## Exact final-artifact controller evidence

Authoritative public ledger: docs/rust-v2/guarded-transport-lab-evidence.json.
Root-only local evidence: target/lab-state/guarded-transport-run-15.json through
run-21.json and corresponding captures, inspect and wan-cleanup records named by
the ledger. Parent alone executed these in the owned local Debian13 KVM guest.
Every case uses entirely owned synthetic WAN 185.65.134.88:51820, exact host /32,
protected fixed synthetic WG keys, one network=none no-identity Docker probe and
per-PID manifests/exact nsfs observation bindings. No external provider.

| Attempt | Candidate18 scenario | Exit | Seconds |
|---|---|---|---|
| 15 | deleted-wg | 0/PASS | 2.473 |
| 16 | deleted-transport | 0/PASS | 2.381 |
| 17 | cooperation-drift | 0/PASS | 2.381 |
| 18 | foreign-collision | 0/PASS | 2.369 |
| 19 | interrupted-activation | 0/PASS | 2.329 |
| 20 | interrupted-cleanup | 0/PASS | 2.180 |
| 21 | reversible | 0/PASS | 3.938 |

Root reports independent PCAP validation and retained inventory for every final
case; exact synthetic WAN cleanup PASS and endpoint clear afterward. See ledger
for authoritative counts, per-attempt ownership and residual inventories.
Every scenario first proves authorized cgroup-owned encrypted health and independent
data/transport/host capture sensitivity, same-data-namespace/destination/port ordinary
producer denial and stale established-input denial. Continuous distinct application
markers bracket fault-before-audit and verified full offline states. Sender must
advance at least three attempts per checkpoint and join before later namespace work.
Missing private DNS also refuses before intent, and actual Offline reacquire succeeds.

Reversible network faults: WG down/up; transport veth down/up; wrong peer endpoint;
deleted peer; deleted data default; data endpoint route via lo; Docker172.17/16;
IPv6 default; policy rule; extra dummy; transport default; deleted transport endpoint;
unrelated host /32 route; wrong private key; wrong peer public key. Each requires
healthy pre-audit, continuous attempts, full quarantine, exact test writer repair,
native bootstrap resume and authorized encrypted health recovery.

Nft matrix: fixed TEST-ONLY CLI failed atomic batch retains exact live policy plus
native audit/health; separate main quarantine and permit removals still deny apps
and restore full quarantine; appended functional accept drift refuses overwrite,
with independent filter/emergency denial. Only the fixture removes its exact
injected handle before recovery. CLI batch is NOT new native failure-API proof;
reviewed task4 native failed-batch proof remains separately applicable.

Terminal cases delete actual WG/transport, replace deleted WG with foreign dummy
at the same name, or remove one exact newly-created cooperation rule after full
JSON identity recheck. Audit fails, full quarantine verifies, cleanup refuses,
and reopened acquire returns Interrupted. Foreign replacement remains untouched.

Activation interruption uses cfg(test)-only checkpoint immediately before durable
Bootstrap commit: actual link/firewall setup complete, record still Activating.
Actual initial controls run, full quarantine is installed, descriptors close, and
real reopened acquire refuses. Cleanup interruption stops after full offline
verification before deletion, retains Bootstrap, then proves reopened refusal.
These are cooperative crash-point simulations, not SIGKILL/freeze/power-loss tests.
No hooks exist in production; synthetic harness cannot release app forwarding.

Historical candidate17 attempt14 also passed reversible packets: payload
70cc35712987786415e215f5dfc8349293fb62e925a4bfc778d50b7fb6f522b9,
source a7e8586897f7d946b51d5a9932c690714db9ded7bf556161d0cfe81863a5a96d.
Root independently verified all capture counts with zero drops, plaintext positive
controls, zero forbidden markers, 737 continuous attempts/55 fresh checkpoints/join,
zero owned native links after normal cleanup, absent subgroup, Offline record,
full/emergency quarantine each scope and original Docker FORWARD handles/rules
ignoring counters. Exact WAN14 alone was removed afterward. This is historical
evidence, not substituted for final candidate18 run21.

## Failed attempts preserved with exact attribution

The ledger retains every binary/source hash, error, resource disposition and
private evidence location. Failures were never erased or relabeled as passes.

| Attempt | Failure and correction |
|---|---|
| 1 | Existing Docker bridge/slave host metadata rejected before links |
| 2 | Additional physical altnames/promisc projection mismatch |
| 3 | Unsupported host link54, verified IFLA_PERM_ADDRESS |
| 4 | Unsupported host link56; full read-only GETLINK oracle collected |
| 5 | Generic pre-veth Unsupported; typed diagnostics added |
| 6 | DOWN pair created, dynamic host IPv6 address flags rejected |
| 7 | Host broadcast attr4 rejected; full raw address/route oracle added |
| 8 | Native WG move passed; quarantined activation KernelRejected |
| 9 | host_peer_route errno100 ENETDOWN; UP-before-route behind quarantine |
| 10 | Initial packet/capture failure; immediate, failure-flushed capture |
| 11 | First WG restoration drift; nonpromiscuous capture avoids interference |
| 12 | WG DOWN removed default; fixture explicitly restores route offline |
| 13 | Synthetic WAN IPv6 DAD changed host baseline; addrgenmode none before UP |

Exact failed-artifact SHA pairs are included in the companion table below.
Candidates02,12,15 are superseded UNRUN. Candidate12's original source archive
was accidentally overwritten; original hash is historical only, current named
archive is NOT a valid binary pair. Parent was explicitly told never to execute12;
valid13 superseded it. Immutable final18 is correctly paired.

## Unsafe, capability, subprocess and platform inventory

No new unsafe Rust statements. New runtime modules forbid unsafe. Existing
kernel.rs remains sole allowed-unsafe launch module. Safe network_scope uses
reviewed setns/die wrappers, restores namespace or terminates122. Cgroup socket_scope
is cfg(test)-only; real worker placement remains8b. No new persistent privileged
worker, async runtime, steady-state shell/ip/nft/wg/iptables CLI or subprocess in
GuardTransport/native network/native netfilter enforcement.

Guard requires admitted root/CAP_SYS_ADMIN namespace access, CAP_NET_ADMIN native
rtnetlink/WG/nft mutation, root cgroup access, protected store/nsfs paths and retained
native descriptors. Workers do not receive guard descriptors/host sockets.
Ignored harness alone uses fixed Docker/ip/wg/nft/tcpdump/mount/touch commands for
synthetic fixtures, captures and faults. Fixed test keys use protected files, not
argv. Captures flush via RAII termination. Nonblocking UDP marker thread starts
after namespace/cgroup setup, is bounded55s and joins on every success/error path;
no main-thread setns while running.

Producer support deliberately requires exact cgroupv2 systemd Docker path
/sys/fs/cgroup/system.slice/docker-<64hex>.scope/<owned-name> and socket-cgroupv2
selector level3. No silent cgroupfs/nested/custom-path support. Feature probe
atomically creates/validates/deletes exclusive selector table before retained
installation. Parent controllers/limits/accounting untouched. Debian evidence
does not certify Void, Arch, other Docker/cgroup layouts or ARM64 runtime;
ARM64 compilation is a build claim only.

## Remaining gates and evidence limits

- Independent task8a source/evidence review mandatory before8b/8c.
- No real Tailscale interface, worker/tailscaled manifest, confined daemon, identity,
  provider query, advertised exit, online approval or actual client egress.
  Readiness, production, migration, direct and multi-exit gates remain closed.
- Task8b must place real worker/tailscaled into exact producer subgroup BEFORE
  sockets/client creation, preserving6b PID/proc/state, LSM/seccomp, capabilities,
  descriptor/config/health confinement and parent accounting.
- Task8c supplies bounded protected cross-process protocol, independent heartbeat
  and verification freshness/watchdog, real process lifecycle/freeze/crash/OOM/
  container death, real-client traffic and release acceptance.
- Spoof-source policy has unit coverage, not independently injected forwarded
  spoof-source packets. No Tailscale forwarding exists in8a; actual forwarded
  spoof-source proof remains mandatory integrated8c/real-client work.
- Same-name foreign WG-to-dummy replacement proves retained generation/index/kind
  and refused adoption. Preexisting startup-name collision is not independently
  packet-tested; preserve it in integrated8c startup faults.
- Cooperative durable interruption proves phase/non-adoption, not autonomous
  daemon crash/freeze/power-loss recovery.
- Root removed only exact synthetic WANs. Failed deployments/quarantine and
  historical failure evidence remain; no broad cleanup/recreation occurred.


## Exact failed-artifact hashes

| Attempt | Binary SHA256 | Source archive SHA256 |
|---|---|---|
| 1 | 723a7336080903962b28e9c71efff322d6f46cf77e1d94abdf969dd31cfe8096 | 5acd43a24ef6c69191c6cae25552c389b99dc8c4c3c99d6413e2e3283af49dcf |
| 2 | e136422ff04eb4eaa68c86ca5dde65122fb6af599496821a2271f21ee4d00d58 | dae8342e678b4b81be5bdd02e88393c0cf91dac44673f7903d36d7eeaadf53a5 |
| 3 | 03057996523490351d434e219aaac5c751692237052736d8feb827c48e0452ba | c77c2f9cbeba0de658ea8d3276e49347068007181354378f3ab5d7ebbef17553 |
| 4 | d6fb1ca62f55ad541207d00c8298ccca6702e5335be443905ba41860347a162f | 5ae23e2254ae90bd2a219f05d9383fcdc8a93c0a4fd5f3909fdad36a4a69fc39 |
| 5 | b3da3ca153fc7537dd1962c5dbe0d664b0d125342219338b73e8c182181099af | 4100baf6cbf93c0431478eafa60d93a59372a0d58be6f1438b195aa33b4133b4 |
| 6 | 07b96451e3327724d4de26ccd229eaff4c8801a7c68d6ff426da718b164dd423 | a52b92d39a46d92e431be09d90ea89e6928453f1391cdccfaaa91dca7b92397f |
| 7 | f80b62b226247c0bd1e60ccd3680a954d32693b7f0c6a64eda0d7cd5c61cc7e0 | 94fd7fdc571f24323bd11aba2ce200e603921c0cd08a5dc640c7f632836ee1fe |
| 8 | b14d76335a285e230855e7b8775f514e870e97fd6f8fc72cb804632e425f2611 | 355bc870ba1e90eceef9e89c1555211a393e162c56805fb2c3e9f7924ab7ca0e |
| 9 | 417497bffe62188ee547a30ce075daba70aaf11ce74fc5aca371652e7dacbe53 | 1ef2d9579e3ebb0d7af8b1072fd1e1bdcc534ae15121e76d85ee2825449b0934 |
| 10 | e191214d5649b0e9c648dfb0fe9b67acc1d8a882be0b4e545022383cbe163c0c | 28bb5a1d9ec6efa8edfd843c908b209d24d1675ca3a446b5900a820a607ce148 |
| 11 | f3ed27dfeb3c1e890bc466b6706d865b74731ff7f8d1d7ed50da6b481c990cfd | 1abe8b3ddfc75156b23f953d7166d39040ca104291b69176e68b1dc5b56ab64e |
| 12 | 5fb811e1b05b8b3351486ef7e73a90f721fba006e397c30e7d6b2355de7e5f1e | 4c39ccfa36407c1aaf5c2206cedc622e21007383a3cd486f8e06a50089cbf701 |
| 13 | 74c23da930055d427a604ea406d021b1a9ba6fc1bd96483a4bc837f9c9add665 | f79dc1a948b4d8bdd3b2a5e77570a1c85102a7445e8500dc79f822956271d9b0 |

Root archive oracle verified all 81 source files against commit 222fa7c; aggregate SHA256 7f63dc65ff573c260341ba518ab1b8e04bc9e0281bdf8a618694171776d4b6af. Public final ledger committed as 3f092c0. Independent final captures, continuous counts, cleanup inspection and exact foreign FORWARD preservation passed all seven runs; reversible attempt21 removed owned links and producer and recorded Offline. Terminal cases intentionally retained empty producer/native ambiguity behind full quarantine.

## Final continuous packet witness counts

| Attempt | Send attempts | Checkpoints | Joined |
|---|---|---|---|
| 15 | 70 | 3 | true |
| 16 | 27 | 3 | true |
| 17 | 36 | 3 | true |
| 18 | 69 | 3 | true |
| 19 | 12 | 3 | true |
| 20 | 13 | 3 | true |
| 21 | 697 | 55 | true |

All seven final attempts independently show zero forbidden markers and zero kernel capture drops on each observed data/transport/host path, with capture record counts reconciled by the parent oracle.
