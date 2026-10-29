# Native scoped nftables policy and quarantine

Workdir /DATA/AppData/vprouter-rust-v2; branch rust/v2. No subagents. Read
docs/rust-v2/IMPLEMENTATION.md, reviewed core allocation/profile types and
task-3-report.md. Implement a real native netlink firewall component, NOT
an invented active guard or deployment-ready release. No production mutations.
This is the first actuator component of work package3; namespaces, worker,
watchdog, launch helper and migration remain later requirements.

Own new crates/vprouter-netfilter/**, Cargo workspace/dependency additions,
docs/rust-v2/netfilter.md and task-4-report.md. Avoid unrelated paths. Initial
vprouter-linux/CLI capabilities must continue to say guard_runtime:false.

Requirements:

* Native NETLINK_NETFILTER, no nft CLI, shell, lib subprocesses or JSON-to-CLI.
  Prefer small licensed safe Rust socket/packet libraries. Do not add GPL-only
  dependencies to the MIT program. netlink-sys (MIT) safe socket API is an
  option; nftnl-rs0.5.1 only supports sets and is unsuitable. Avoid requiring
  libnftables/libnftnl on the host for release artifacts. Pure Rust UAPI
  encoding is acceptable but isolate codec, bound and test it thoroughly.
  No unsafe in this crate; unforbid unsafe only in the later dedicated Linux
  operation module if necessary, never here. Dependencies exact-pinned.
* Strict typed policies built from a validated AllocationRecord+exit and
  verified public IPv4 endpoint/UDP port, WG interface+kind and explicit WAN
  interface. Names/IDs/interface names cannot inject expressions. IPv6
  forwarding and IPv6 external transport always blocked. Validate entire
  record and caller exit membership, no arbitrary deletion/table names.
* Produce deployment/exit-scoped tables. Separate persistent quarantine from
  data/transport/host permit policy so a failed update never opens traffic.
  Install quarantine first. Native state mutation APIs must only admit
  quarantine release after verifying expected scoped policy exactly. Do not
  expose any CLI command purporting to run the whole router yet.
* Atomic nft batch transactions. Detect ACK errors, interrupted/truncated
  multipart dumps, NLMSG_ERROR (incl positive success ACK), sequence/sender
  mismatch, overflows, oversized replies, total deadlines, generation changes
  and ambiguous ownership. Kernel error payloads are never logged verbatim.
  Verify native ownership (table userdata marker tied to deployment+exit+
  scope+generation, bounded exact format) before replacing/deleting. Use
  kernel generation/CAS or equivalent no-race transaction generation guard.
  Table name alone is not ownership. No foreign table changes, no global
  flush. Preserve quarantine on permit/verify/delete failure.
* Closed data namespace policy equivalent to deployed router.nft:
  input default-drop; lo accepted; authenticated WireGuard-kind input
  established/related; output default-drop lo/WG-kind, narrowly scoped
  tailscale DNS100.100.100.100 if parity requires; forward default-drop
  IPv4 source100.64.0.0/10 tailscale0->owned-WG-kind, reverse established/
  related WG->tailscale0, NAT only that exact source/interface/kind.
  Unexpected interface with reused wg name must not pass; enforce nft
  meta oifkind/iifkind as legacy does. Block IPv6 before any broad accepts.
  Quarantine may allow loopback only, all forwarding/external traffic drops.
* Transport namespace policy default-drop input/output/forward except lo and
  exactly one owned veth, IPv4 source allocated transport-IP, exact configured
  public endpoint + UDP port and corresponding conntrack return. Transport
  contains no data-plane path. Host policy early hooks limits owned veth
  to exact explicit WAN+endpoint UDP (source address anti-spoof), conntrack
  return only, all other traffic to/from interface and allocated subnet drops,
  host input/output inaccessible. Own NAT only exact UDP endpoint flow,
  never general private-subnet WAN NAT. Tables use policy accept for unrelated
  host traffic and have no unrelated accept/drop rules.
* No direct-mode activation in this package; explicitly reject it. Do not
  quietly reuse Mullvad permit logic for direct. No other exit interfaces or
  shared permissive transport. Quarantine changes isolated to selected exit.
* Reconciliation must return fixed reason codes for absent/owned/matching/
  drifted/foreign/unknown. Exact checks include hooks, priority, chain policy,
  expressions and rules order; do not validate only user labels or digest
  of desired policy. Ignore only known kernel-added handles/counters; unknown
  functional attrs/extra chains/rules fail verification. Evidence isn't proof
  against hostile host root, but drift checks must detect actual kernel drift.
* Public error/Debug/Serialize never expose private key or external payload.
  Packet content contains only public policy data. No profile private-key
  access needed. Owned tables alone may be removed on successful explicit
  cleanup; quarantine removal requires verified no live path/namespace
  absence evidence and remains separate from ordinary shutdown.

Verification:

Offline meaningful tests for packet alignment/endian/nested attrs, malformed
netlink responses, ACK error/timeout/truncation/sequence/generation mismatches,
foreign ownership, mode/input rejection and scoped policy semantic assertions.
Use captured/synthetic UAPI fixtures with stated provenance, never secrets.
Provide one explicit ignored integration test or example executable designed
to run ONLY in a new disposable network namespace inside isolated lab. It
must check /proc/self/ns/net identity differs from PID1 netns and an explicit
root-owned lab marker before mutating, and refuse outside lab. No default
cargo test touches host kernel nft state.

Native lab check exercises install quarantine, exact dump verification,
atomic permit replacement, ownership/drift/extra-rule refusal, failed atomic
batch retaining old closed rules, one-scope cleanup and unrelated sentinel
table preservation. External nft CLI allowed in TEST harness only to compare
kernel rendering, inject faults and positive controls; native implementation
must execute no subprocess. Root controller owns guest execution and captures
evidence. Agent may prepare files/tests, not connect to or mutate production.

Run fmt/test/clippy -D warnings appropriate workspace. Commit explicit files
and force-add report. Report covering commands/results, unrun live cases and
limitations, exact commit, no runtime readiness/security release claims.
