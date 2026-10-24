# Task 4 — native scoped nftables policy/quarantine actuator

Status: IMPLEMENTED component; focused/covering offline checks PASS;
controller-reported isolated kernel integration PASS; independent review pending.
This is the first actuator component of work package3, not an active guard,
router runtime, migration release or client/leakage acceptance.

Base for task4: ab6a5973a412e5d3a0edc6bf503369490c8a5430.
Work paused for controller-requested task3b, separately committed and reviewed at
32e9e5f0614f46faa2769742fbb4ab01ec5ed683 / a107fa6.
Initial task4 implementation: f78e86d3dc40b2346793e94bf91554fa14b026f6.
Kernel-driven correction/hardening: 6f7255d508fb7ca59a80c3f1a8bce08693a91aac.
This report is committed separately so it can bind those exact code commits.

## Delivered scope

- New MIT vprouter-netfilter crate, workspace member/lockfile and
  docs/rust-v2/netfilter.md. Safe rustix=1.1.4 adds net/event features; direct
  dependencies remain exact pinned through workspace declarations. No new
  GPL-only dependency, libnftables/libnftnl, unsafe or production subprocess.
  UAPI codec encodes Linux headers/nested attrs using explicit byte operations.
- Strict Policy constructor validates entire AllocationRecord and exact exit
  membership, deployment/generation, Mullvad-only mode, public unicast IPv4
  endpoint/UDP port, WireGuard-kind input and explicit safe WAN interface.
  Core allocation names define all resources; no public arbitrary table/delete
  API, private key access, shell script rendering or direct-mode activation.
- Data, transport and host scopes each have separate persistent quarantine and
  permit tables. Exact table userdata binds deployment/exit/scope/allocation
  generation. Name alone never establishes ownership. All lifecycle mutations
  require native snapshots with ownership/semantic checks, plus kernel-global
  generation CAS in atomic nfnetlink batches. No global flush or foreign delete.
- Closed data IPv4 Tailscale/WireGuard-kind policy with exact source prefix,
  established/related reverse path and source/interface/kind-restricted NAT.
  IPv6 drops precede broad permits; lo/WireGuard-kind input/output are scoped.
  Tailscale DNS parity is narrowed to TCP/UDP53 at100.100.100.100.
- Transport contains only lo and one allocated veth-kind encrypted UDP flow:
  allocated transport address, public endpoint and configured port, with exact
  conntrack return. Forward stays closed. Host filters permit only that owned
  veth/source/WAN/endpoint flow; interface/subnet spoof paths, host input/output
  and IPv6 owned-veth traffic drop. Host NAT is only that exact UDP flow.
  Unrelated host traffic retains accept policy and has no unrelated verdict rules.
- Quarantine precedes permit installation/replacement. Release can only occur
  after an exact native permit dump with generation-CAS quarantine deletion.
  Permit cleanup first establishes quarantine. Drift/foreign/uncertain results
  refuse cleanup/release; quarantine remains. Final quarantine deletion has no
  standalone API until later native namespace/link absence proof exists.
- Bounded nonblocking socket/poll exchanges: five-second overall public-operation
  deadline,256KiB request/datagram cap,4MiB per exchange,2048 attr/256 expression
  caps, checked sequence allocation. Sender/sequence/embedded ACK sequence,
  all required mutation ACKs (data cannot substitute), error=0 ACK, negative and
  positive nonzero errors, interrupted/truncated multipart/DONE, ENOBUFS/overrun,
  generation changes and oversized framing fail closed. Uncertain exchanges
  poison their socket; callers reopen/reconcile rather than reuse stale ACKs.
  Errors/Debug/Serialize expose only authored codes, never kernel error payload.
- Exact native semantics check table flags/userdata, chain hook/type/priority/
  policy, rule order, expression grammar and every argument. Extra chain/rule/
  set/object/flowtable or unknown functional attribute fails. Only known kernel
  handles/use counts/padding/base-chain flags are accepted bookkeeping. No digest
  or user label substitutes for actual dump verification. Fixed reconciliation
  enum includes absent/owned/matching/drifted/foreign/unknown; full reconciliation
  only returns matching after complete verification, errors become unknown.

The CLI/Linux host/status files were unchanged and still guard_runtime:false.
No CLI command purports to launch a router or invoke this mutating library.

## Fresh local verification

Commands from /DATA/AppData/vprouter-rust-v2, pinned Rust1.97.0:

- cargo fmt --all -- --check: PASS, exit0.
- cargo test --locked --offline --all-targets: PASS,77 runtime tests
  (38 core,16 Linux,4 CLI,19 netfilter), zero failures;1 native kernel integration
  test ignored by default.
- cargo test --locked --offline --doc: PASS,1 existing core compile-fail doctest.
- cargo clippy --locked --offline --all-targets -- -D warnings: PASS, exit0.
- cargo build --locked --offline --release -p vprouter-netfilter: PASS, exit0;
  production library build excludes test-only CLI/diagnostics/harness.
- cargo test --locked --offline --release -p vprouter-netfilter --lib --no-run:
  PASS, produced explicit ignored native test executable.
- git diff --check and git diff --cached --check: PASS, exit0 before commits.

Meaningful offline coverage: independent synthetic nlmsghdr/nfgenmsg/nlattr layout,
endian/alignment/nesting, malformed lengths/duplicates, required ACKs, sender and
sequence mismatch, embedded ACK mismatch, positive/nonzero errno, generation
conflict, interrupted/incomplete/truncated/oversized multipart, elapsed deadline,
sequence overflow and poisoned socket; exact local table filtering when kernel
ignores dump filter; ownership marker/generation/table flag, extra chain/rule,
order/hook/priority/policy/expression drift; complete allocation/mode/membership/
input rejection. An independent supported-UAPI evaluator tests packet outcomes
for IPv6, source spoof, wrong endpoint/port/WAN, reused non-WireGuard name,
conntrack reverse, narrow DNS, host isolation and unrelated host preservation.
Fixtures are synthetic public policy/header fixtures, never live credentials.

One initial malformed-attribute fixture incorrectly assumed lengths29..31 could
not align into32 bytes; observed failure was corrected to admit valid padding.
Clippy initially flagged one collapsible-if; fixed before passing covering run.
The task3b pause and lockfile interruption are recorded separately in its report.

## Controller-reported isolated native kernel evidence

The agent did not access/mutate host networking or connect to the guest.
Root controller supplied results from its owned disposable Debian13 KVM guest,
kernel6.12.113+deb13-cloud-amd64, nft1.1.3. Root copied the release test executable
and ran it in a NEW netns with unshare --net. The ignored test first required
root, netns identity different from PID1, and the fixed no-symlink root:root0600
single-link regular marker under protected root0700 lab directory/safe ancestors.
No default cargo test opens a mutating netfilter socket.

Attempt1, f78e86d code: native_acceptance FAILED, exit101 in0.11s. Data quarantine
installation/exact native dump passed, then Err(Drifted) before permit case passed.
No claim of native acceptance was made from that result.

Attempt2, diagnostic/hardening binary SHA256
27a9a763ec9b52809700d835a20f3c0fe8bdf5fc4ac8821ea74e0787306c3e0d:
FAILED, exit101 in0.02s at install_permit Data with Drifted. Test-only bounded
public synthetic diagnostics showed GETCHAIN returned BOTH quarantine and permit
chains despite the requested table attribute. Expression diagnostics showed no
expression mismatch. The strict chain-count/table comparison correctly refused
that unfiltered input, but dump acquisition was incorrectly relying on kernel
request filtering.

Correction: always select the exact table attribute locally for chain/rule/set/
object/flowtable dumps, whether or not the kernel callback honors its request
filter. The entire underlying unfiltered exchange remains bounded and generation
checked. Added fixture covers quarantine,permit,prefix-lookalike/unrelated names
and malformed missing table identity. No semantic verification was relaxed.
Mutation ACK-specific handling and an actual stale-generation CAS fault were
added before the successful native run.

Attempt3, final corrected code6f7255d, test executable
/DATA/AppData/vprouter-rust-v2/target/release/deps/vprouter_netfilter-277cb42a2f751e29,
SHA25608d58097b3e26bcb1b15f27f1043ac005a9db295ff42779cdddc3f8c8127ccf1:
root reported native_acceptance PASS, exit0 in0.44s,1passed/0failed/19filtered.
Data,Transport,Host each passed all six case objects:

- quarantine_exact
- atomic_replace_and_foreign_refusal
- stale_generation_refused
- failed_batch_retains_policy
- actual_drift_extra_rule_refused
- scope_cleanup_and_sentinel_preserved

The harness also compares external nft rendering, releases quarantine only after
native verification, reinstalls it for cleanup, and emits the final native
acceptance object with guard_runtime:false. Native code performs all normal
mutation/verification; nft CLI is test-only rendering/extra-rule fault injection.
Injected late-invalid atomic batches retained the old policy and quarantine;
stale generation prevented deletion. Sentinel survived each scoped cleanup.
The disposable namespace was destroyed after each run, removing test resources.
No traffic was generated; these results prove native kernel codec/transaction/
dump behavior only. The controller owns separate evidence JSON artifacts; the
agent did not stage/edit lab-image.json, live-cli-smoke.json or
netfilter-lab-evidence.json.

## Limits and required next gates

- Native namespace admission, link ownership/kind observation, WireGuard peer/
  endpoint provenance, allocation-store locking coordination, complete guard,
  worker/watchdog/helper/container/client guards and migration activation are
  later packages. Policy strings/markers alone do not authenticate peers or
  establish a trustworthy namespace. Hostile host root can forge/change them.
- No final standalone quarantine cleanup API: it remains until later native
  namespace/link absence verification exists, separate from ordinary shutdown.
  Missing/foreign/drifted/ambiguous resources require investigation, not forced
  replacement. An uncertain ACK can mean commit: reopen and reconcile.
- One fixture exit across three scopes was tested in one disposable netns.
  No actual veth/WireGuard/Tailscale/Docker traffic, multi-exit runtime, endpoint
  transport connectivity, client IPv4/DNS/IPv6 capture/leakage, boot/reboot,
  migration fault matrix, real profile, performance or24h soak acceptance.
- Linux6.12 x86_64 native test only. Linux6.1, ARM64/big-endian kernel execution,
  target distro matrix and immutable release/SBOM/provenance remain unrun.
  No readiness/security-release claim follows from offline or synthetic lab PASS.
- Independent task4 review is pending. Component kernel PASS does not complete
  package3 or the binding IMPLEMENTATION.md mandatory acceptance gates.
