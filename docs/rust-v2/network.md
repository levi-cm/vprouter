# Native route and WireGuard component

`vprouter-network` is a bounded WP3/4 library. It does not add a CLI capability,
guard, namespace owner/launch helper, watchdog, provider/server authentication,
Tailscale integration, migration, or activation. No library result means READY.

`Plan::new` validates the **entire** allocation record and exact caller exit
membership, rejects Direct, and takes peer key/endpoint/IPv4 only from the reviewed
Profile. Names derive solely from allocation. Alias format is
`vprouter-v2:{deployment}:{generation}:{exit}`. MTU is explicitly 1420. The plan
contains public facts only, including the X25519 device public identity derived
from the private scalar. Alias markers detect foreign/drifted cooperative state;
they are not authentication against privileged host writers.

## DOWN-only boundary and namespace trust

There is no sound retained netfilter quarantine handle across these crates yet.
Consequently this crate exposes **no activation, address installation, default or
endpoint route installation, arbitrary deletion, or quarantine release method**.
The plan exposes allocated host/transport IPv4 addresses (subnet +1/+2) for later
integration; computing them does not install an address or a route. WG and both
veth ends are created DOWN, MTU1420, with the exact ownership alias, unaddressed.
Linux may ignore IFLA_IFALIAS in NEWLINK. Only after this operation's successful
exclusive-create ACK, private initialization verifies newly created DOWN links,
exact kinds/hardware/MTU, empty-or-matching aliases and absence of addresses/routes;
veth ends must already be reciprocal. It then sets missing aliases by native
SETLINK and verifies them. This private path cannot adopt an existing unlabeled
link: pre-existing names are refused before the exclusive create. An ambiguous
initialization failure may leave an unlabeled DOWN link for operator reconciliation.
WG receives exactly one public IPv4 UDP peer endpoint and IPv4 allowedIP0/0 in a
native request. No key is sent to a command, file or log. Veth is created in the
caller-established host namespace with its peer directly in caller-supplied
transport namespace. WG is created/configured in caller-established transport,
then moved DOWN to caller-supplied data namespace with IFLA_NET_NS_FD. Linux
defines the WireGuard UDP socket's birth namespace to survive this move. The
harness verifies create/move ordering and link placement; it does not independently
verify UDP socket birth or packet-level transport isolation.

`NativeNetwork::open` captures `/proc/thread-self/ns/net` identity and opens two
reusable sockets there; they remain bound to that namespace. There is no setns,
async task, shared connection pool or namespace switch in production code.
**The caller must first prove** that this is the allocated host/transport/data
namespace. This component cannot prove PID/container/cgroup/namespace ownership.
The later trusted single-threaded launch helper must supply that authorization
and exclude concurrent lifecycle operations.

`NamespaceTarget::from_trusted_network_namespace` pins an owned duplicate FD,
checks nsfs magic and requires its proc-FD link to have direct `net:[inode]` form.
It does not mint proof of allocation/PID/container authorization. Persisted
`/run/netns/name` bind-mount FDs are deliberately unsupported in this constructor;
a trusted helper must validate/enter the namespace synchronously, then reopen
`/proc/thread-self/ns/net`. The target identity must match the supplied destination
socket handle and differ from the source. Plan identities must match exactly.
No caller boolean can manufacture quarantine evidence.

Handles have private fields. A veth pair retains its original host and transport
namespace identities together; endpoint getters only borrow, so callers cannot
recombine tokens from different pairs. Cleanup binds both caller namespaces to
that pair before any netlink request; reciprocal numeric ifindices alone cannot
identify a peer across namespaces. Before moving or cleaning up, the library checks
ifindex, exact name/kind/MTU/alias/DOWN state, absence of addresses and routes,
and expected device/peer identity and endpoint. Veth cleanup checks both endpoint
indices/names/aliases/kinds and reciprocal peer indices. It deletes only the
selected owned link; kernel veth deletion removes its verified peer. No route or
rule is flushed. Address/route/ownership drift refuses cleanup. Incomplete or
ambiguous mutation failures can leave a DOWN resource; reopening and reconciling
is required. `reconcile_wireguard_down` recovers a handle only for the complete
matching configuration, still DOWN and unaddressed.

These checks and rtnetlink mutations are **not an atomic alias/ifindex CAS**.
Cooperative lifecycle/allocation locking must exclude concurrent writers. Hostile
privileged writers can recreate interfaces, forge aliases, or bring links UP
between inspection and mutation; this library supplies no protection against
that race. Independent nft quarantine and the future guard are required before
any usable transport, address, route or activation is installed. DOWN-only
methods are not a replacement for that enforcement boundary.

## Observation and strict structural audit

`observe` dumps links, IPv4+IPv6 addresses, **all tables** of routes and all policy
rules in both families, then the selected WG device. It projects name/index/kind,
UP/MTU/alias, address/prefix/scope, complete supported route semantics, rules,
device and peer public identities, endpoint, allowedIPs and handshake timestamp.
Raw WG GET replies contain private/preshared keys: they never leave the private
codec boundary and are never serialized, formatted or logged. Public projections
contain no such fields and have no Serialize implementation. Extra peers and
split/multiple WG response chunks fail closed rather than lose continuation data.

Unknown functional attributes, multipath, nexthop IDs, encapsulation, via,
source-routing, marks, metrics/redirect attributes, nontrivial rules and rule
flags fail closed. Empty DEVLINK_PORT and DPLL_PIN nests, explicit XDP Attached
None, kernel counters/statistics/queue/AF statistics and route cache info are
accepted bookkeeping. Populated hardware associations, attached XDP or controller
links are refused. FRA_SUPPRESS_PREFIXLEN=u32::MAX is accepted only as the
kernel disabled-suppression sentinel; every functional threshold is refused.
Unknown kernel features can therefore make observation
unsupported; they do not become a partial valid snapshot.

Audit accepts only UP loopback of ARPHRD_LOOPBACK, the exact owned UP WG device
of ARPHRD_NONE/index/MTU1420, and optional UP tailscale0 of kind tun/ARPHRD_NONE.
No extra interfaces are accepted. The WG IPv4 source must be exactly the profile
/32; IPv6 is forbidden on WG. Loopback accepts only 127.0.0.1/8 and optional ::1/128.
Optional local Tailscale addresses must be 100.64/10 /32 or fd7a:115c:a1e0::/48 /128.
Duplicate entries and missing required source/default/local routes fail.

IPv4 policy rules must be exactly 0:local255,32766:main254,32767:default253;
IPv6 must be exactly 0:local255,32766:main254. Extra rules, including actual
Tailscale fwmark/table52 rules, are **unsupported** in this bounded component.
Real Tailscale integration remains unimplemented and must not expose traffic
based on these observations.

Expected IPv4 kernel local routes are local 127.0.0.0/8, local 127.0.0.1/32,
broadcast 127.255.255.255/32 on lo with preferred source 127.0.0.1; and local /32
routes for WG and any admitted Tailscale IPv4 address with the matching preferred
source. These have protocol kernel, table 255, metric 0 and no gateway. Local routes
have scope host; broadcast has scope link. A /32 does not create a main connected
route. The sole nonlocal IPv4 route is main 254 default, scope link, protocol static,
metric 0, exact WG index and profile preferred source, no gateway. Ordinary,
restored host defaults, endpoint exceptions, Docker routes and table52 escape
paths are refused. The later native activation component must deliberately
install this exact default protocol/source; legacy defaults are not assumed equal.

The restricted IPv6 kernel profile permits local ::1/128 on lo (table 255,
protocol kernel, metric 0), local Tailscale ULA/128 (same table/protocol/metric),
and that ULA's main 254 connected /128 route (kernel, metric 256). WG UP and an
IPv6-addressed tailscale0 each have the kernel ff00::/8 local-table multicast
route (metric 256). These routes have universe scope, no gateway/preferred source,
and no route flags. IPv6 destinations/prefixes beyond those local records fail.
This deliberately does not admit auto link-local FE80 addresses, anycast,
Tailscale table 52 routes, or forwarding-related IPv6 rules; ordinary real
Tailscale namespace state is therefore currently unsupported. The later guard
must resolve that integration contract under independent IPv6 nft drop.

The handshake must be present, finite and positive, not in the future, and its age
strictly below 180s against the caller's trusted realtime `now_unix` clock argument.
Invalid/nonfinite clocks fail. Missing snapshots are Unverified, missing WG is
Absent, errors/drift are Rejected. StructurallyValid is **observational only**:
these multiple kernel dumps are not atomic and supply no no-race enforcement
claim. Repetition does not substitute for closed nft policy.

## Transport, dependencies and secret handling

Maintained rust-netlink codecs are exact pinned: netlink-packet-core0.9.0,
route0.33.0, generic0.5.0, wireguard0.5.0 (MIT). Native sockets/poll use existing
rustix1.1.4. Async rtnetlink0.23.0 was investigated; background streams/pooling
were avoided in favor of a synchronous explicitly bounded socket wrapper using
the maintained payload codecs. X25519-dalek3.0.0 (BSD-3-Clause, MIT-compatible)
derives only the public identity; zeroize1.9.1 (Apache-2.0 OR MIT) scrubs owned raw
buffers and typed private/preshared key temporaries after projection/serialization.
All exact direct pins and transitive resolutions are committed in Cargo.lock.

Core adds only `Profile::with_private_key`, a minimal borrowed closure accessor
for trusted provisioning. It cannot sandbox malicious callers from copying the
borrow. Profile still has no Debug/Serialize. Existing ordinary fill-on-drop in
Profile is **not a guaranteed zeroization mechanism**. No claim is made about all
compiler/stack/OS copies or codec decode-failure temporaries being erased.

Every public native operation has one 5s total deadline shared across its sends,
dumps and checks. One datagram/request is at most 256 KiB, each exchange 4 MiB and
4096 messages; attribute framing caps 2048 attributes and nested depth 8 before
payload parsing. Unsupported NET_BYTEORDER flags fail closed. A snapshot needs
at most 9 exchanges (36 MiB aggregate); the largest create/verify operation needs
at most 21 exchanges (84 MiB aggregate), sharing the same total 5s deadline.
Sender, seq and embedded ACK request identity, positive ACK, multipart/DONE/error,
truncation, overflow and interruption are checked. Data cannot substitute for an
ACK. A failed exchange poisons its socket; no sequence wrap/reuse occurs. Fixed
redacted errors contain no raw kernel/codec errors or payloads.

Production crate forbids unsafe, has no direct FFI or subprocesses. Native syscall
dependencies contain their own unsafe/platform implementations; this is
not an assertion that transitive dependencies contain no unsafe. Only test code
uses external ip/wg and safe rustix synchronous namespace entry.

## Verification and guest-only harness

Default tests use deterministic synthetic keys/public facts and never open a
mutating socket. Unit tests exercise structural escape faults, exact membership,
mode/ownership/handshake rejection, secret redaction and bounded malformed frames.
Independent literal route expectations use the controller's disposable-kernel
route oracle rather than calling the expected-route implementation in fixtures.

Build the guest test executable without running it:

```
cargo test --locked --offline --release --target x86_64-unknown-linux-musl -p vprouter-network --lib --no-run
```

Controller copies that executable into the isolated disposable guest, then runs:

```
unshare --net /root/native-network-test --ignored --exact lab::native_acceptance --nocapture
```

Admission matches the netfilter lab: euid0, distinct self/PID1 network namespace,
root-owned non-writable ancestors, root0700 `/var/lib/vprouter-v2-lab`, and regular
root:root0600 single-link NOFOLLOW `isolated-acceptance` marker. That marker is an
operator assertion; actual guest isolation remains the controller's responsibility.
No kernel changes or subprocesses occur before admission.

The test creates only disposable named namespaces and a sentinel; test-only sync
threads enter them and open namespace-local sockets/direct proc FDs. Independent
ip/wg controls verify kind/alias/DOWN state/peer/endpoint/allowedIPs, move presence
and absence of any data veth, duplicate/foreign refusal and owned-only cleanup.
A test-only IPv4 address addition while WG remains DOWN proves native address
projection and cleanup refusal; it **does not test a production address mutator**.
Removing that control address permits exact cleanup. No real key/provider,
handshake, connectivity, packet delivery, Tailscale, fault or deployment proof is
provided. It leaves the unrelated sentinel until outer netns destruction. Final
pass JSON has case `native_network_isolated_acceptance`, guard_runtime:false and
activation:false; failed/missing final pass does not count as acceptance.
