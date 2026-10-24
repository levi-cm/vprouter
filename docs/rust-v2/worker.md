# Native worker preparation

The worker is a compiled bounded monitoring engine and native protocol clients.
Production startup currently returns `StructuralGap` **before any runtime,
client, socket or writer thread is created**. There is no production placement
token constructor, feature flag, caller quarantine boolean, independent guard
server, production executable manifest or activation path. This preparation does
not enable a service, migrate state, enroll a node, or prove real exit traffic.

## Namespace and transport ownership

A private non-Send/non-Sync placement capability binds a worker thread to its
network namespace device/inode. Every client checks it before requests; HTTPS
and LocalAPI check it after requests too. The capability has only cfg(test)
synthetic constructors. Task8 must construct it from the reviewed helper's
actual selected namespace/allocation/placement proof, never just the observed
current namespace or caller-supplied inode. No setns or unsafe code exists here.

Provider and Unix client objects are created after placement and reused only by
that worker. Separate bounded Hyper connection drivers are aborted when their
owning client/session is dropped or cancelled. No global connection pool,
libc/getaddrinfo resolver, environment proxy, custom production certificate
store, certificate bypass, arbitrary production URL, or monitoring subprocess
exists. Fixed provider identity is `https://am.i.mullvad.net/json`; Rustls uses
pinned Mozilla roots, hostname verification and default safe TLS1.2/1.3 versions.
Native UDP DNS asks only A records for that exact hostname through an explicitly
supplied private tunnel resolver. Maintained Hickory parsing bounds packets to
4096bytes, exact transaction/question, no truncation or trailing bytes, bounded
CNAME chain and public IPv4 answers. TLS remains authoritative for server identity.
The resolver parameter currently has **no production authority source**: core
Profile validates DNS tokens but discards them. Task8 must retain/bind protected
approved resolver configuration and independently enforce WG-only DNS/HTTPS.

Each HTTP attempt has a12s timeout including DNS/connect/TLS/headers/body. Headers
are limited to32 and8192bytes; provider body16KiB, LocalAPI64KiB, control256bytes.
Responses do not follow redirects or decode compression. Chunked bodies use the
maintained parser and the same cumulative byte bound; trailers, non-identity
content encoding, malformed framing, duplicate JSON keys at any nesting level,
wrong JSON types and extra trailing JSON fail closed. Error bodies and external
error text are never emitted. Exact success fields are `mullvad_exit_ip:true`,
public IPv4 `ip` and `mullvad_exit_ip_hostname` equal the configured server, as
independently observed in `provider-response-oracle.json`. Friendly aliases are
not accepted.

## LocalAPI and health sequence

Fixed pinned1.102.5 endpoints are GET `/localapi/v0/status?peers=false`, GET and
PATCH `/localapi/v0/prefs`, using the namespace-local private Unix socket. The
peer-free status endpoint avoids expanding unrelated tailnet peers. Status must
be Running with self Online, exactly preserved stable node ID and exact self and
top-level Tailscale IP sets. Preferences must have WantRunning true, LoggedOut
false, RouteAll/CorpDNS false, NetfilterMode0, RunSSH false, NoSNAT true,
NoStatefulFiltering true, empty selected ExitNodeID/IP and either empty or exactly
`0.0.0.0/0,::/0` advertisements. Null AdvertiseRoutes is the pinned empty shape;
missing fields, duplicates and wrong types are refused. NoSNAT/SSH preference
writes have only synthetic request-validation evidence so far.

Initialization FIRST sends the narrow masked empty-advertisement PATCH and
reads it back, before any healthy sample. It then sets only NetfilterMode0,
RunSSH false and NoSNAT true with their corresponding Set bits, and verifies
safe empty preferences. No identity/auth key/hostname/reset/server rename occurs.
No enrollment operation or AuthURL output channel exists here; daemon AuthURL is
not projected, logged or persisted. Enrollment and explicit name reconciliation
remain separate reviewed lifecycle work.

Each sample audits all native interfaces, addresses, both-family all-table routes
and rules and the exact WireGuard device/peer/endpoint/allowed IP/handshake. The
independently assigned interface index is never inferred from the observed link.
Tailscale addresses additionally must exactly match preserved identity IPs.
Native Rule projection now retains action, flags, fwmark/mask, protocol,
suppression values, goto and realm. Unsupported other functional attributes
still fail. Exact guest raw fixtures prove the marked5210/5230/5250/5270 shapes
can be decoded, **not** that they are authorized. Strict Plan auditing still
rejects that Tailscale policy layout and unexpected link-local IPv6. No arbitrary
table52/default/LAN routes were admitted. Approved route/control witness and
exact active route metadata remain a task8 integration gate.

One eligible408/429/5xx, transport failure or attempt timeout retries once after
1s. A full fresh audit occurs immediately after failure, again after the delay,
after successful provider response and after LocalAPI observations/writes.
Permanent HTTP/TLS/malformed/oversize/negative/wrong-server/repeated failures and
any drift fail closed. Sample timeout34s leaves margin for the existing native
5s synchronous dump finishing after cancellation readiness: nominal sample bound
is below39s, strictly below45s. Native dump blocking can delay cancellation by up
to5s; this is not a hard realtime scheduler guarantee.

TLS negotiation and established HTTP I/O retain a bounded typed error-cause
classification: explicit reset/EOF/timeout and other allowlisted transient I/O
kinds may receive that single retry. Certificate/hostname/protocol failures,
non-allowlisted I/O and overlong cause chains remain permanent. No error-string
matching or external error logging is used.

Reviewed HealthMachine requires three independent fresh successes before
RECOVERING and actual advertised, online, approved stable identity before READY.
`ExitNodeOption` means offered AND approved in pinned Tailscale. False while
withdrawn is normal: three fresh samples may reach RECOVERING, then a narrow
advertisement request is permitted only behind task8's retained health-only
bootstrap capability. The next status/prefs observation must show exact offered
routes; initial admin approval can remain pending in RECOVERING. Revocation from
READY blocks and withdraws. Provider success alone never establishes readiness.
DNS/client IPv6 verification remains `not_tested` in health, never constant true.
Direct mode is explicitly unsupported.

One monotonic5s cadence drives sample starts and heartbeats while a slow provider
operation is polled concurrently. Core's deterministic bounded multi-exit offset
is used; one exit has zero offset and no extra exit timers. Overruns skip missed
cadence starts rather than create overlapping samples or retry bursts. Freshness
is strict45s; handshake ages must be nonfuture/known and strictly below180s.
The independent90s guard watchdog remains a task8 implementation requirement.
Cached evidence is explicitly expired before sampling, before any recovery
advertisement and before accepting replacement evidence. Expiry resets every
partial/recovery streak and returns through guard-first withdrawal, including
expired READY; a healthy replacement cannot hide that enforcement event.

## Failure, cancellation and protected status

Runner cancels clients, blocks the machine, notifies the independent guard FIRST,
then withdraws local advertisements and reads back emptiness. If LocalAPI cannot
confirm withdrawal within4s, a bounded fixed stop-tailscaled request goes to the
separate init role; this worker never becomes a reaper or selects arbitrary PIDs.
Guard and init requests have2s deadlines. Watch-channel shutdown cancels an
in-progress sample, then follows the same withdrawal/termination path and writes
STOPPING. Failed guard/init ACKs still attempt withdrawal and blocked status.

The private candidate notification protocol uses POST `/v1/worker/heartbeat` and
`/v1/worker/block` with version1/monotonic sequence/fixed reason and exact
version/sequence/`recorded:true` ACK. This ACK is observational only. Init has fixed
POST `/v1/init/stop-tailscaled`, version1 and `stopped:true` ACK. These transports
have only controlled Unix-server tests; **there is no actual cross-process guard
or init endpoint**. Task8 must replace/bind these to authenticated peer identity,
exact exit/allocation/generation, retained bootstrap enforcement, guard watchdog
and exact supervised daemon handles. There is no request to remove quarantine,
and no caller boolean or notification ACK grants readiness authority.

Health publication is descriptor-relative in private selected state, with mode
0700 directory, mode0600/single-link regular output, O_EXCL+NOFOLLOW pending file,
file fsync, rename and parent fsync. Symlink/hardlink/pending collisions refuse.
Only fixed redacted Status fields are serialized. One namespace-local writer
thread has a one-in-flight bounded channel and2s caller deadline; stalled disk
syscalls cannot hold the monitoring loop or build a queue. Linux cannot cancel
an in-progress disk syscall: one stale bounded write can complete later. Fresh
health timestamps must be checked observationally; files never authorize guard
release. Task8 must bind health to exit/generation and use the independent init
process deadline rather than join a stuck writer on shutdown. Kernel D-state
cannot be given a userspace kill-time guarantee.

## Evidence and remaining gates

Ordinary tests use controlled loopback TLS with a synthetic CA, actual Unix HTTP
servers, native loopback UDP DNS, boundary-injected clocks/faults and private temp
state. No production profiles, credentials, daemon/state, provider traffic,
privileged kernel mutation, or namespace entry is part of normal tests. TLS trust,
wrong-name/unknown-CA refusal, real slow headers/body deadlines, malformed/chunked/
oversize parsing, connection reuse, real retry timing/post-delay refusal, identity/
prefs refusal, approval recovery/revocation, heartbeat/cancellation and protected
publication have focused coverage. Synthetic health success proves engine logic,
not activated guard enforcement or real client isolation.

A custom `localapi_lab` test target skips unless explicitly `--ignored` and a
root:root0600/single-link isolated-acceptance marker exists. It performs only the
two fixed bounded GETs at `/run/tailscale/tailscaled.sock`, emits pinned-version,
Running/online, mode and advertisement count, and always reports guard/runtime
activation false. It never writes preferences, advertises, enrolls or prints
AuthURL/node/IP data. Controller alone may run the exact static artifact in an
owned isolated guest with a private mount view exposing the intended socket.

Task8 must supply the launch/guard/manifest/resolver/route witness and guarded
bootstrap integration, actual preference-write/withdraw/approved-offer tests,
control peer authentication and fixed-daemon termination, real independent DNS/
IPv6/client/traffic acceptance, kill/freeze/full-disk/reboot behavior, performance,
ARM64 kernel/runtime and additional release-platform certification. Until then
production startup remains unavailable. See task7 report for exact source and
command/artifact evidence; no performance or release/activation claim is made.
