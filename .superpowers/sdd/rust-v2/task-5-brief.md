# Native route and WireGuard ownership, provisioning and structural audit

Workdir /DATA/AppData/vprouter-rust-v2, branch rust/v2. No subagents. This is
another bounded component of WP3/4, not a complete guard. Read this brief first;
then docs/rust-v2/IMPLEMENTATION.md binding requirements, reviewed core allocation/
profile/state types, and native netfilter documented policy requirements. Never
read real secret profiles or connect to production. Root owns isolated guest
execution. No host network/kernel mutations during normal tests or builds.

Own new crates/vprouter-network/**, workspace/dependency additions, minimal
profile API needed for key provisioning, docs/rust-v2/network.md and this task's
report .superpowers/sdd/rust-v2/task-5-report.md. Do not change core validation,
existing CLI capabilities, other agent code or root evidence. Exact-pin new
MIT/Apache-compatible dependencies and lockfile. Prefer maintained native
rtnetlink/generic-netlink safe libraries over a second handwritten protocol
stack; investigate capabilities first. No CLI/subprocesses or unsafe in production
crate. Native socket APIs stay bound to construction namespace. Do not call
setns from async tasks. Namespace ownership and validated launch helpers are the
next component; clearly document supplied namespace-FD trust boundaries.

Deliver a library with allocation-bound Mullvad plans and fixed redacted errors.
Direct rejected. Validate the full AllocationRecord and exact caller exit
membership. Never expose arbitrary link names, table deletion or mutation from
untrusted JSON. Profile endpoint/public peer/IPv4 comes from reviewed Profile.
A minimal borrowed secret-access API may be added to core only if required for
native WireGuard configuration; no Debug/Serialize/key-bearing errors, no key
argv/files. Do not claim ordinary fill(0) guarantees zeroization. No real keys
in fixtures; deterministic synthetic keys only. Never serialize raw WG GET replies
(which include private keys), payloads or raw external errors.

Native NETLINK_ROUTE and WireGuard generic-netlink observations must produce a
bounded projected snapshot: links(name/index/type/up/MTU/ownership alias), IPv4
and IPv6 addresses, ALL routes and policy rules relevant to escape checking,
WG device public identity/peer public key/endpoint/allowedIPs/handshake age.
Audit rejects extra non-loopback/non-owned-WG/non-tailscale interfaces, wrong kind,
wrong peer or endpoint, multiple peers, wrong allowedIPs, down/missing device,
wrong source address, any ordinary/default/endpoint/Docker or policy-rule path
that could escape expected WG, unexpected IPv6 routes/addresses beyond necessary
local loopback/tailscale presence. Do not audit only default-route output.
Define precise expected kernel local/main routes and IPv4/IPv6 rules; fail closed
for unsupported forwarding/rule/multipath/encapsulation attributes rather than
ignore functional changes. Snapshot consistency must be considered: a single
non-atomic multi-dump is observational evidence, not a no-race enforcement
boundary; repeat/control-plane checks cannot replace closed nft policy.
Bound whole operations and responses; malformed/truncated/interrupted/error
responses fail closed. Reuse namespace-local sockets; no shared cross-exit pools.
Use a clock argument where handshake expiry is evaluated: <=0/future/NaN/unknown
handshakes rejected; handshake freshness strictly <180s. Keep absent/unverified
separate from structurally valid; no READY/exposure claims from library alone.

Native mutators must be narrowly typed and refuse existing foreign/drifted
resources rather than replacing them. Create WG link initially DOWN in current
transport namespace with generation/deployment/exit ownership alias; set one
peer and configured public IPv4 endpoint, allowed 0.0.0.0/0, private key in native
request only. Move WG to an explicitly supplied validated data-netns FD using
native netlink. Socket birth transport namespace must be preserved by this move.
Configure only expected IPv4 address, link state and WG-only default in data.
Create explicit host/transport veth pair and address/default endpoint route only
under the selected allocation. Veth provisioning must be split create-DOWN and
activate so later guard installs quarantine before any usable host transport.
Require caller quarantine evidence or retained handle minted by netfilter API
if a sound enforced cross-crate contract is feasible; otherwise restrict this
package to DOWN link creation and move, with no public activation method, and
report the remaining integration. Do not invent a boolean `is_quarantined` token
that callers can manufacture. No wildcard deletes/replaces, no arbitrary host
route changes; verify alias/index/kind/peer/addresses before scoped cleanup.
Cleanup failures leave resources DOWN or rely on retained independent quarantine;
never flush unknown routes/rules. No final quarantine removal here.

Tests must cover structural faults (restored default, endpoint/Docker path,
wrong kind/index/name/key/endpoint/handshake, extra interface/routes/rules/IPv6),
input/mode/ownership rejection, secret redaction and bounded malformed responses.
Default tests never mutate kernel. Supply explicitly ignored isolated-lab harness
requiring root-owned marker and distinct PID1/self network namespace (same
admission contract as netfilter lab). Harness can use fixed external ip/wg/nft
commands ONLY in test code for independent controls and disposable namespace
setup; production must use native APIs. It must positively verify interface
kind/alias/address/peer endpoint, WG moved out of transport into data while
preserving intended isolation, foreign resource refusal and owned-only cleanup;
no provider credentials or actual peer connectivity required. If supplied FD
trust cannot be established in test, report unperformed instead of fabricating
proof. Root executes lab harness and records result. Real Tailscale/fault and
provider/server-identity acceptance remains NOT_RUN.

Run focused tests plus fmt/check/clippy appropriate to change. Avoid duplicate
workspace runs absent new failure. Commit explicit files, force-add report;
report exact code hash, tests commands/results, design boundaries, unsafe/FFI or
subprocess inventory, unperformed checks. Return only status, commits, one-line
test evidence and concerns. No deployment/release/runtime acceptance claims.
