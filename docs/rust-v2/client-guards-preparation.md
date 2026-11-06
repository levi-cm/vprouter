# Task 11 client guards: offline preparation

OFFLINE_PREPARATION_ONLY. Task8c runtime, ARM execution and real-client acceptance
remain OPEN. `release_ready=false` is unchanged. This library creates expected
policy, JSON preparation transactions and generated rules. It installs nothing,
opens no sockets, runs no service and has no activation/removal command or flag.
A synthetic `prepared` status means ordering of offline obligations only.

## Existing fleet and storage contracts

Task11 extends the same `ExitChange`, `PreparedFleet`, `FleetRecord` and
`FleetPolicy` from [multi-exit-preparation.md](multi-exit-preparation.md) and
[direct-exit-preparation.md](direct-exit-preparation.md). No second allocation or
identity store is introduced. Strict, bounded JSON intent examples:

```json
{"operation":"install_client","policy":{"id":"desktop","exit_id":"mullvad-1","selected_node_id":"node-primary","mode":"protected","dependency_adapters":[]}}
{"operation":"select_client","client_id":"desktop","exit_id":"residential","node_id":"node-direct","mode":"direct"}
```

Both use the existing generation increment and canonical-content CAS, with
revalidation of the entire fleet, disabled reservations, references and profiles.
Duplicate install, absent client/exit, empty identity, mode mismatch, duplicate or
unknown fields and fallback fields refuse. Existing root-owned private directory,
retained exclusive lock/inode checks, NOFOLLOW, single-link regular files,
O_EXCL temporary creation, file fsync/rename/directory fsync remain the only
preparation writer. Existing live allocations refuse preparation writes.
Interrupted/foreign/ambiguous evidence is retained, never reset or adopted.
No real profile/state is read by these tests; profiles are synthetic examples.
A desired disabled exit reference may persist but cannot yield a GuardPlan.

`FleetPolicy::configured_client_plan` requires the configured client ID, exact
stable node ID, enabled exit and explicit configured mode using existing
`select_client`/`client_plan`. Names never authorize selection. Protected mode
refuses direct; direct mode requires its exact authorized node and reports
`direct-exposed`. Route advertisements or a display-name match are insufficient.
Identities, enrollment, credentials and approvals are neither cloned nor edited.

## Guard configuration and daemon identification obligations

`client::GuardConfig::parse` accepts strict schema1 JSON, at most64KiB. This is
public expected metadata, not authenticated native evidence. Example kernel path:

```json
{
  "schema_version":1,
  "client_id":"desktop",
  "boot_id":"11111111-1111-1111-1111-111111111111",
  "namespace":{"device":4,"inode":123},
  "tailscale":{"name":"tailscale0","ifindex":7},
  "wan":{"name":"eth0","ifindex":2},
  "daemon":{"pid":25,"start_ticks":100,"executable_device":8,
    "executable_inode":900,"cgroup_id":500,"cgroup_level":3},
  "transport":[{"address":"185.65.134.88","port":41641,
    "source_port":41641,"protocol":"udp"}],
  "path":{"kind":"kernel"}
}
```

The namespace MUST be dedicated to the protected workloads and owned client
network stack. General host namespaces, unmanaged/non-Linux clients, inherited
host sockets, host resolver bridges, shared application/daemon cgroups and foreign
namespace FDs are unsupported. Supplying an inode is not proof of that scope.
Future admitted native code must authenticate namespace identity, boot identity,
links/ifindices/kinds, process pidfd/liveness/start ticks, pinned tailscaled
executable device/inode/origin, dedicated cgroup v2 membership and socket birth
in that cgroup/namespace. It must exclude application membership/descendants and
recheck retained authority on every reconciliation and before any mutation.
No executable path, root UID, process name, all-UDP or all-DNS assertion substitutes
for those checks. This increment contains no native daemon identity verifier.

At most32 exact IPv4 transport tuples are allowed. Nonzero source/destination
ports and public addresses are mandatory; ports53/853 refuse. Every tuple binds
protocol, endpoint, source port, WAN name+ifindex and socket cgroup v2 identity at
the expected hierarchy level. Return traffic additionally requires established
conntrack state. Empty/duplicate sets refuse; distinct source-port tuples are
disjoint. Order is canonical. IPv6 (including IPv4-mapped encodings), hostnames,
noncanonical address encodings, special-purpose/provider infrastructure ranges
and injection-shaped names/addresses/ports refuse. The conservative IPv4 range
snapshot lives in `address.rs` and is shared with direct plans, profiles and
netfilter endpoints. The profile public-address API delegates to that classifier.

## Generated netfilter policy

`vprouter_netfilter::client::ClientRuleset::prepare` reuses the existing private
Table/Chain model, expression helpers, bounded UAPI attribute codec and semantic
expression grammar. The renderer returns bounded JSON (at most1MiB) containing
ordered creation intents for separate quarantine and permit tables. It is NOT a
netlink batch, nft script, kernel dump, native policy handle or verification
receipt. There is no bridge to Actuator, native bootstrap or quarantine release.
`validate_rendered` checks the entire ordered expected content, including flags,
names, markers and rules; userdata/digests alone do not establish matching policy.
Offline tests also round-trip generated tables through the existing native
semantic verifier and independently interpret their packet outcomes.

Names are derived hashes of client ID and namespace identity; generation and
complete plan fingerprint are in the owned marker. A future native integration
must perform exact-owned generation-CAS atomic replacement under retained
quarantine and refuse foreign/drifted tables, sets, chains or rules. These
creation intents grant no authority to overwrite existing objects. No flush,
arbitrary deletion, Docker mutation or daemon restart is generated.

Dedicated namespace input/output/forward chains default drop. Quarantine uses
priority-310 and permits-150, as existing netfilter policy does. Explicit IPv6
drops precede permits, including loopback. Forwarding is always closed.
Kernel clients may send IPv4 TCP/UDP only through the exact Tailscale tun
name+ifindex+kind; reverse traffic must be established. DNS follows that same
selected exit path; there is no WAN/root/UDP/resolver exception. The narrow
daemon transport rules are the only WAN permits. Loopback remains namespace-local.
The Tailscale interface alone does not prove the selected exit: future native
reconciliation must bind the exact authorized node, approval, routes, DNS path,
prefs, namespace, generation and lifecycle to the same complete plan. Drift
requires independent quarantine before repair. Existing conntrack and socket
pools must be retired within the exact owned scope on generation/path change;
no prior flow is an authorization to bypass new selection.

## Userspace SOCKS and HTTP policy

Replace the example path with:

```json
{"kind":"userspace","socks_listener":"127.0.0.1:1080",
 "http_listener":"127.0.0.1:8080","cgroup_id":600,"cgroup_level":3,
 "upstream":"100.64.0.9:1080"}
```

Both listeners must be distinct nonzero IPv4 localhost endpoints inside the
same dedicated namespace. The gateway must have a cgroup distinct from the
daemon at the same hierarchy level; the upstream is one exact tailnet IPv4 TCP
socket. Applications can contact only the local listeners. Only gateway-owned
sockets may contact that upstream through the exact Tailscale interface. Direct
WAN, host resolver and application-to-overlay bypass paths are absent. Protection
cannot be promised if enclosure/cgroup custody cannot actually be enforced.

`GuardPlan::proxy_request` parses an already-negotiated SOCKS5 CONNECT request
or complete HTTP/1.1 CONNECT header into bounded target intent. No socket or
resolver is used. SOCKS BIND/UDP ASSOCIATE, IPv6, malformed/trailing data, HTTP
body framing, credentials, unknown/duplicate/conflicting headers and ambiguous
numeric hosts refuse. Exactly one matching Host is required for HTTP/1.1;
HTTP/1.0 and absolute-form requests refuse. Only SP/HTAB header-value padding
is allowed; other control bytes, folded headers, framing fields, pipelined data
and noncanonical ports refuse. This is a conservative CONNECT-only subset, not a complete
SOCKS handshake/authentication server or ordinary HTTP forwarding gateway.
Unsupported semantics refuse instead of being rewritten. Target parsing caps
at8192 bytes, domain/label lengths at253/63, and a total5s deadline from supplied
start time. Targets carry `selected_exit_only`, `ipv4_only` and the complete plan
fingerprint as pool partition. No fallback resolver, direct TCP connector, retry
or cross-exit socket pool exists. A future native gateway must use a bounded
namespace-local authorized-exit protocol, reject nonpublic/IPv6 resolved targets,
drop upstream failures and retire sockets on selection; parsed requests cannot
substitute for that implementation or prove DNS safety.

## Persistent ordering, clocks and restart

`ClientGuard` has quarantined/prepared/stopped/failed offline states and
instance+epoch callback tokens. Every constructor/reopen begins quarantined;
no caller can supply an installed/verified boolean. Each epoch must complete:

1. Exact owned persistent quarantine established before any usable traffic.
2. Capture operational for this boot before protected workload traffic.
3. Generation-bound client policy and installation record durably committed.
4. Exact nft, node, route, DNS, IPv6, socket/cgroup and ownership reconciliation.

`Step` completions and digests are public expected data, NOT native receipts.
Native integration must replace those assertions with authenticated retained
receipts and a locked/fsynced resumable installation journal. That journal and
workload launch are unimplemented here. `prepared` cannot activate anything.

Disappear/upstream loss/drift invalidates old tokens and requests quarantine.
Explicit restart repeats the complete ordering; selection requests quarantine
before checking new plan, requires same client/deployment/namespace/boot and a
strictly newer fleet generation, and never chooses another node on failure.
Ordinary stop retains the guard. STOPPED/FAILED are terminal; late callbacks,
reconciliation, restart, selection and repeated failures cannot revive or weaken
them. There is no administrative removal API: future exact ownership checked
removal must be a separate explicit operation.

All seven operational callbacks (complete, disappear, reconcile, restart, select,
stop, poll) check the same integer millisecond host high-water mark before input
or token checks. Negative/NaN cannot inhabit this type; >1e15ms, regression or a
5s enforcement-poll gap fails closed. Only poll renews that watchdog. Status is
observational, refuses regressing/out-of-range clocks, downgrades expired plans
to quarantined and reports unknown egress/DNS/
IPv6 as `not_tested`. It never turns planned rules into tested protection.
Recovery/selection is limited to1024 admissions per instance; exhaustion fails
terminally. Poll returns at most one coalesced quarantine obligation and skips
missed ticks. Invalid-clock and expired-watchdog polls drain that obligation
as `Ok([Quarantine])` even while time remains invalid. Repeated polls return an
empty action list after delivery. Neither invalid nor expired polls lower the
host high-water mark or renew the watchdog. Other operational callbacks return
an error while retaining the obligation for the next poll. `Ok` from poll means
action delivery, not healthy/prepared status. No native timer, task, process, pool, FD, syscall or subprocess is
added. Fresh process startup never interprets an old completion as usable.

Future systemd ordering must make persistent quarantine a required predecessor
of network/daemon/protected workload startup, with capture readiness required
before protected workloads; service stop must leave quarantine resident and
cannot remove policy in ExecStop. Future runit stages must establish quarantine
and capture in boot stage1 before stage2 protected services, with the same
readiness barriers and no cleanup-on-stop. `After=` or script order alone does
not prove readiness: missing capture/enforcement keeps workloads offline.
No unit, run script, boot setting, host service or native journal is installed
by this preparation increment.

## Review round 1: canonical input and clock boundaries

`address::parse` is the single reject-only host syntax parser for this client,
proxy and ruleset preparation path. `ipv4`, `authority`, `socket_v4` and `prefix`
compose it; `public_ipv4` holds the one conservative special-use snapshot and
`public_target` adds refusal of special local/internal domain suffixes. No input
is trimmed, case-folded, IDNA-decoded, numerically converted or resolved by this
parser. Only canonical dotted-decimal IPv4 or lowercase ASCII multi-label DNS
names are admitted. All numeric TLDs and labels starting with `0x` refuse, closing
mixed-radix numeric aliases without trying to reproduce a downstream resolver.
Leading-zero/octal/hex/integer/short/mixed IPv4, all IPv6 (including mapped and
compatible), zone IDs, brackets, trailing dots, uppercase spelling, userinfo,
embedded ports/paths, Unicode, punycode/IDNA labels, controls and host whitespace
refuse. Ports are canonical nonzero decimal u16; domains/labels cap at253/63.
HTTP header grammar permits only SP/HTAB around a matching Host value; profile
field whitespace remains part of the existing configuration grammar.

| Input boundary | Shared parser/classifier and context |
| --- | --- |
| HTTP CONNECT / SOCKS domain or binary IPv4 target | `public_target`; public IPv4 or restricted DNS only |
| Client transport JSON, including direct Serde deserialization | `deserialize_ipv4`; plan validation then requires `public_ipv4` |
| Userspace listeners/upstream JSON | `deserialize_socket`; only exact localhost listeners / tailnet upstream are admitted by plan validation |
| Direct host evidence address / connected and local prefixes | `deserialize_ipv4_vec` / `prefix`; canonical local/private evidence is allowed, and becomes denied destinations |
| Profile transport endpoint feeding existing native rulesets | `socket_v4` plus shared public classifier; no noncanonical port normalization |
| Netfilter `Policy` transport subnet | `prefix`, after allocation ownership/validation |
| Netfilter `Endpoint` and client ruleset | Endpoint receives typed IPv4 and the shared classifier through the compatibility profile API; client rulesets consume validated GuardPlan, no raw address input |
| Generated/rendered UAPI | Addresses are typed four-byte values; validation compares the entire generated intent and cannot introduce a string alias |

`tests/support/address_cases.rs` independently generates the five encodings of
each IPv4 component (decimal, leading zero, octal, lowercase hex, uppercase hex),
then their four-component cross-product, plus short/integer IPv4, IPv6 wrappers,
zone/bracket/trailing-dot/userinfo/port/Unicode/control/oversize shapes. Twenty-two
hand-selected special-use/provider representatives and a public positive control
exercise both proxy protocols, transport configuration, all three socket fields,
all three direct-host fields, direct packet policy and netfilter endpoints.
Canonical private/local values remain legal only in contexts which need them;
no test asserts that localhost listeners or private host evidence must be public.
Existing range-boundary tests cover the denied ranges' edges and allowed neighbors.

Host-time entry-point inventory and tested contract:

| Owner | Entry points | Invalid-time and queued-work behavior |
| --- | --- | --- |
| ClientGuard (`u64` milliseconds) | `new`; `complete`, `disappear`, `reconcile`, `restart`, `select`, `stop`, `poll`; `status` | Operational regression or >1e15 fails the whole guard; poll delivers the coalesced safety obligation. Status errors are observational and retain all work. Constructor refuses invalid time before creating state. |
| GuardPlan (immutable, `u64`) | `proxy_request(started, now)` | Rejects invalid/out-of-order/expired timestamps, returning no target authority; no lifecycle queue exists. |
| FleetPolicy (`f64` seconds) | `new`; `observe`, `observe_bytes`, `sample_finished`, `restart`, `reconcile_direct_host`, `poll`; `status` | Operational NaN/infinity/negative/regression/out-of-domain fails the entire mixed provider/direct fleet and retains or delivers EmergencyQuarantineAndStop for each exit. Status errors are observational and retain all work. Constructor refuses invalid time before creating state. |

The matrices run operational/query callbacks with and without queued quarantine,
valid and invalid times, and with pending or already-delivered terminal work.
Late callbacks cannot revive terminal state, weaken emergency actions or replay
a drained obligation. Client regression/out-of-domain cases use representable
u64 values; NaN, both infinities and negative values cannot inhabit those APIs.
The tests explicitly reject their serialized/type-boundary representations and
never cast f64 invalid values to u64 (which would silently manufacture time zero).
Constructor and immutable-parser queue dimensions are inapplicable. Queries grant
no usable status on invalid time and do not mutate state or operational clocks,
preserving the existing Task9/10 observational contract.

The HTTP table admits only HTTP/1.1 CONNECT authority-form with one exact matching
Host. It covers HTTP/1.0 refusal, both absolute-form versions, duplicate/conflicting
Host, header folding, whitespace before colons, controls, credentials, ambiguous
ports, framing/smuggling and pipeline shapes, truncation and exact8192/8193-byte
limits, plus exact253/254-domain and63/64-label boundaries. This remains an intent
parser; no HTTP server, resolver, connector, runtime capture or native quarantine
consumer was implemented or tested.

## Evidence and unimplemented gates

The Task11 report records exact sequential commands/results and RED evidence.
`tests/client_owned_guest.rs` contains four ignored, fail-if-forced acceptance
specifications. They are NOT_RUN: no native harness is implemented, Task8c is
OPEN and this delegate cannot use privileges/VMs/network or real identities.
Required evidence is continuous IPv4/DNS/IPv6/TCP/UDP marker traffic from real
disposable Tailscale clients, positive controls, captures at client WAN/host WAN/
transport/data, install/select/reboot ordering, route/DNS/nft drift, unknown/
changed/disappearing exits, daemon restart, absent/bypassed proxy settings and
upstream failure. Zero forbidden/cross-exit plaintext markers is mandatory.
Unknown/skipped checks are unverified. Offline tests cannot establish actual
nft enforcement, socket lookup behavior, process/cgroup exclusivity, Tailscale
routing/DNS, boot capture, filesystem power-loss/SIGKILL safety, ARM execution,
platform/service support, performance, migration, soak or release acceptance.
Independent review and controller-owned real-client gates precede integration.
