# Native scoped netfilter component

`vprouter-netfilter` is an actuator library for the first part of package3.
It does not implement the guard, namespace/link admission, WireGuard creation,
worker, watchdog, launch helper, migration activation or any router CLI command.
The existing CLI and Linux inspection retain `guard_runtime:false`.

All production operations use safe Rust `rustix =1.1.4` socket/poll APIs and a
bounded pure Rust Linux UAPI codec over `NETLINK_NETFILTER`. Rustix is licensed
Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT. There are no subprocesses,
FFI, libnftables/libnftnl dependencies or GPL-only packet libraries. The crate
forbids unsafe. The only `nft` invocations are in the test-only lab harness.
Direct workspace dependencies remain exact pinned; Cargo.lock is committed.

## Policy and transaction boundary

`Policy::new` validates the entire core AllocationRecord, exact caller exit
membership, deployment/generation, Mullvad mode, public unicast IPv4 UDP endpoint,
explicit WAN and WireGuard-kind input. Interface names use a small ASCII grammar;
all internal names derive from core allocations. No arbitrary table or deletion
API is public. No private profile key is read or held by this component.

The socket stays bound to the current network namespace at construction. The
later namespace manager must establish and verify that namespace, link ownership,
peer/profile and endpoint provenance before invoking this library. A supplied
`wireguard` kind string is not independent peer authentication. Packet policy
requires both the expected WireGuard name and `meta iifkind/oifkind wireguard`.
A reused name on a dummy/veth interface does not pass those rules.

Every deployment/exit has separate inet tables per data, transport and host
scope, derived as `{allocation.nft_table}_{d,t,h}{q,p}`. Table userdata is the
exact bounded byte format `vprouter-v2\0deployment\0exit\0scope\0` followed by
allocation generation as eight big endian bytes. Names alone never prove
ownership. These public markers detect accidental/foreign ownership; hostile
host root can forge them or change rules and is outside this evidence boundary.

Data input/output/forward default drop. IPv6 drops precede broad rules; loopback,
WireGuard-kind output, established/related WireGuard-kind input, IPv4 Tailscale
100.64.0.0/10 forward and established reverse paths are the only permits.
Masquerade is restricted to that IPv4 source, WireGuard name and kind. DNS parity
allows only TCP/UDP53 to 100.100.100.100 via tailscale0, narrower than legacy's
unrestricted destination rule.

Transport input/output/forward default drop. Apart from loopback, the sole flow
is the allocated /30's address+2 through its allocated veth name and veth kind,
IPv4 UDP to the public provider address/port, with established/related reverse
traffic from that address/port. Forwarding remains closed. There is no data-plane
transport interface or direct-mode reuse.

Host early filter chains use accept policy for unrelated traffic. Selected-veth
traffic permits only the exact transport source address, explicit WAN, public
endpoint and UDP port with a matching conntrack return path. Other traffic to or
from that veth or the selected /30 drops, including host input/output. Owned NAT
has that same forward-flow match; no general private-subnet NAT is installed.
Host quarantine blocks only selected veth/subnet. Namespace quarantine blocks
all external traffic/forwarding; only IPv4 loopback is allowed. Quarantine has
priority-310; permits have priority-150; owned postrouting NAT has priority100.

`install_permit` installs and verifies persistent quarantine first, then creates
or atomically deletes/recreates an already exactly matching permit table.
`replace_permit(next)` verifies the old policy exactly and allows a new endpoint
or WAN only under the identical allocation/generation/scope, under quarantine.
`release_quarantine` first dumps and verifies all expected permit semantics, then
performs quarantine deletion using the verified kernel generation CAS. No public
caller-created verification token can bypass that check. `cleanup_permit` first
establishes quarantine and removes only an exact owned permit. Drift/foreign
ownership is refused, preserving quarantine. There is intentionally no standalone
final-quarantine cleanup API until a later namespace manager can natively verify
namespace/link absence. Ordinary cleanup never removes quarantine.

Each mutation uses one atomic nft batch with `NFNL_BATCH_GENID`. Snapshots read
kernel generation before and after all relevant dumps. A generation change or
CAS conflict fails; a stale snapshot cannot authorize deletion/replacement.
All requested mutation ACKs must arrive. Sender/sequence/embedded ACK sequence,
positive success ACK (`error=0`), errors, interrupted multipart dumps, DONE status,
truncation, overflow and framing are checked. An uncertain exchange poisons its
socket to prevent reuse with unread ACKs. No raw kernel error content is logged.
An ambiguous ACK failure can mean a batch committed: quarantine remains for
permit changes, and callers must reopen/reconcile rather than assume rollback.

A public operation has a five-second total deadline including all sends, receives,
dumps and verification; EINTR/EAGAIN do not reset it. Requests/datagrams cap at
256KiB; each exchange caps at4MiB; attr lists cap at2048; expression lists at256.
Sequence overflow refuses further use. No unbounded raw payload is published.

Reconciliation codes are fixed: absent, owned, matching, drifted, foreign,
unknown. Full reconciliation returns matching only after semantic verification;
owned is reserved for ownership-only reporting, not a readiness result. A failed
or incomplete snapshot yields unknown. Table flags/userdata, exact chain hooks,
priorities/type/policy, expression grammar/arguments and rule order are checked.
Extra chains/rules/sets/objects/flowtables and unknown functional attributes fail.
Known kernel use counts, handles, alignment pads and base-chain flags are the only
bookkeeping accepted; rule positions are represented by the verified dump order.
Counters are not generated, and added counter expressions/chain attrs fail.
The expected policy digest or userdata alone never substitutes for rule checks.

## Verification and isolated harness

Default offline tests use synthetic UAPI fixtures derived from Linux headers
and an independent interpreter of the supported expression subset. They do not
open mutating netfilter sockets or change host nft state. No production fixture,
profile, private key or live table dump is used.

From the repository root:

```
cargo fmt --all -- --check
cargo test --locked --offline --all-targets
cargo test --locked --offline --doc
cargo clippy --locked --offline --all-targets -- -D warnings
cargo test --locked --offline --release -p vprouter-netfilter --lib --no-run
```

The last command prints the exact release test executable. Copy that executable
into the isolated guest. Controller must prepare a new disposable network
namespace there, then run its copied path (example `/root/native-netfilter-test`)
with exactly:

```
unshare --net /root/native-netfilter-test --ignored --exact isolated_kernel_integration::native_acceptance --nocapture
```

This command is for the isolated KVM guest only. The ignored test refuses before
opening any mutating socket unless euid0, `/proc/self/ns/net` differs from PID1,
and `/var/lib/vprouter-v2-lab/isolated-acceptance` is a regular root:root0600
single-link file opened without following symlinks, beneath root0700 lab directory
and root-owned ancestors without group/other write access. Marker content is not
used. A root-owned marker is an operator assertion of isolation, not proof of a
hypervisor boundary; the controller owns actual isolated-guest admission.

The harness needs test-only `nft` in PATH. It creates an unrelated sentinel and,
for each Data/Transport/Host scope, checks native quarantine exactness, foreign
userdata refusal, native atomic permit install/replacement, failed atomic batch
retention, external nft rendering, actual extra-rule drift/refusal, quarantine
release, permit cleanup and sentinel preservation. It leaves quarantine tables
and sentinel in the disposable netns; namespace destruction is the cleanup.
It never flushes any ruleset. Test-only fault resets delete only synthetic fault
tables. Every normal accepted case emits a JSON object with fixed `case`, `scope`
and `result:pass`; the final object has case
`native_netfilter_isolated_acceptance`, `result:pass`, `guard_runtime:false`.
Rust's test runner framing is separate from those JSON lines. Panic/failure or
missing final pass means native acceptance did not complete.

This harness proves kernel codec/transaction/dump behavior, not real traffic,
namespace isolation, WireGuard authentication, Tailscale/client leak protection,
Docker integration or runtime readiness. All larger binding acceptance gates in
IMPLEMENTATION.md remain required. ARM64/big endian kernel execution is unrun;
codec tests use native endian headers and big endian UAPI integer fields.
