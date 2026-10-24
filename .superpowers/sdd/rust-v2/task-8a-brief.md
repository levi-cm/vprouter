# Guard-owned native transport activation and bootstrap firewall

PREPARATION ONLY. Part of task8, not completion of the single-exit guard. Dispatch
only after task7 independent review approves. Workdir /DATA/AppData/vprouter-rust-v2,
rust/v2. No subagents. Root alone runs ignored privileged disposable-guest tests;
normal tests offline/loopback. No production access, credentials or identity state.
Read binding docs/rust-v2/IMPLEMENTATION.md, task-8-brief.md, reviewed task4/5/6b
reports and actual interfaces. Preserve all constraints and remaining task8 gates.

Implement an actual native single-exit transport activation component retained by
a new independent host guard, rather than observational or caller-proof scaffolding.
Current NativeNetwork only provisions DOWN links. Establish persistent owned
allocation/namespace/generation locks, exact namespace binding and real quarantine
authority before any UP/address/route operation. Host guard may retain scoped native
netlink/nft descriptors constructed in their intended namespaces by a single-threaded
helper; no async setns or unreviewed persistent privileged worker. Any unsafe stays
in the reviewed launch Linux module; prefer existing safe rustix interfaces.

Create WG in owned transport, move to primary data/base namespace, configure exact
peer/endpoint/key/address using protected Profile authority, and activate exact
owned veth/addresses/routes only behind verified quarantine and permit policies.
Data contains only lo/WG, later tailscale0; never data veth/plaintext WAN. Preserve
WG UDP socket birth namespace. Transport permits only allocated source plus exact
public endpoint UDP; host path independently restricted. Keys never argv/output.
No actual Tailscale or production readiness minted in this subtask.

Add exact atomic offline/bootstrap/ready policy representations. Full quarantine
first; bootstrap permits verified WG health/control output and endpoint transport,
while all protected Tailscale application forwarding remains dropped. Application
forwarding cannot be enabled by a boolean/ACK or by this subtask's lab synthetic
constructor. Final readiness authority depends on later real worker/control proof.
On ownership/operation/drift failure restore full quarantine before stopping or
cleaning owned resources; ambiguous cleanup retains policy and refuses deletion.
Native activation must audit all links/addresses/routes/rules/peer identities and
pin actual assigned indexes, generations and namespace device/inodes. No flexible
acceptance of real Tailscale metadata in this subtask; task8b supplies actual oracle.

Docker-enabled guest has later ip filter FORWARD policy DROP: an earlier ACCEPT
does not override it. Implement narrowly owned, bounded, reconcilable cooperation
using native nft API if necessary. Prove actual packets and preservation of foreign
rules/services. No broad exception, foreign flush, iptables CLI, daemon restart or
unrelated resource mutation. Retained quarantine must still drop if cooperation
drifts/disappears. Add exact owned reconciliation/cleanup; never infer ownership
from names alone or remove a changed foreign resource.

Retain approved private IPv4 DNS from protected Profile for later worker resolver
authority; currently parser discards it. Minimal strict API change plus malformed/
duplicate/unknown/secret-redaction tests; no host resolver or synthetic production
fallback. Do not implement enrollment or copy actual identity/profile state.

Focused tests assert ordering, actual atomic policy stages, ownership/namespace/
generation mismatch, interrupted startup/cleanup, foreign collisions and failure
quarantine. Ignored owned-guest harness must actually create synthetic WG peers,
exercise native socket-birth activation and encrypted round trips, and capture
continuous distinct plaintext markers with independent positive controls on data,
transport and host observation paths. Use an entirely owned synthetic WAN peer
in the disposable guest, avoiding external provider or production resources.
Inject wrong/down/deleted peer/interface/endpoint/default/endpoint/Docker/IPv6
route/rule, nft removal/drift/failed update and host cooperation drift. Assert no
forbidden plaintext, no usable ordinary WAN path and exact owned cleanup or
explicit retained quarantine on ambiguity. Preserve every failed attempt and
source/artifact hashes. Synthetic packets are not real Tailscale-client acceptance.

One-exit component has no placeholder extra namespaces/workers/timers. No steady
state shell/CLI. Do not wire production CLI or release startup prematurely. Actual
Rust/Go manifests, placed worker, cross-process health/init protocol, autonomous
watchdog and daemon lifecycle are subsequent task8b/8c work, not silently complete.
Readiness/multi-exit/direct/migration gates remain closed until full task8 approved.

Focused fmt/tests/clippy, static x86_64 and ARM64 checks/builds, self-review and
explicit owned-file commits. Report .superpowers/sdd/rust-v2/task-8a-report.md with
exact source/artifact hashes, commands/results, packet/ownership evidence, unsafe/
capability/subprocess inventory and remaining gaps. Root runs exact ignored payload
and independent review is mandatory before next implementation.
