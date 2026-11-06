# Task 11 independent re-review

Verdict: **PASS for OFFLINE_PREPARATION_ONLY — 0 Critical, 0 Important, 0 Minor defects reproduced.**

Reviewed 2026-11-06, `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD
`067069186f9106232fded16bb3707dcdd4dc891d`, including the uncommitted Task 11
cut and its report's Review round 1. The binding sources were task-11-brief.md
and docs/rust-v2/IMPLEMENTATION.md. The earlier FAIL review remains unchanged.
This verdict closes its three findings within the offline API contract. It
neither establishes native client protection nor changes runtime/release gates.

No child agents, sudo, network requests, VM operations, Git writes or process
termination were used. The only repository file written by this review is this
report. Source copies, reviewer tests, build output and logs are retained at:

`/tmp/vprouter-task11-rereview-_na1e2yc/`

All Cargo invocations were sequential, with `CARGO_BUILD_JOBS=4`,
`CARGO_TARGET_DIR=/tmp/vprouter-task11-rereview-_na1e2yc/target`, and build/test/
clippy flags `--offline --locked -j 4`. No ignored test was forced. The three
required checks ran on the unmodified source copy before adding reviewer tests.

## Original findings: independently reproduced scenarios, now fixed

The three original requirement tests were copied unchanged from the retained
previous review's `review_core.rs` into scratch `tests/original_review.rs`, using
the current synthetic fixture helpers. All three compiled and passed. These are
the same behavioral assertions that previously failed, not compilation probes.

| Prior finding | Current code | Fresh observation |
| --- | --- | --- |
| I1 Important: mixed hex IPv4 alias admitted as domain | `crates/vprouter-core/src/address.rs:18`, `crates/vprouter-core/src/client.rs:550` | The exact HTTP request `CONNECT 127.0.0.0x1:443 HTTP/1.1\r\nHost: 127.0.0.0x1:443\r\n\r\n` refuses. Additional checks of all five original aliases refuse in both HTTP and SOCKS domain form, including `169.254.0xa9.0xfe` and `0177.0.0.0x1`. |
| I2 Important: invalid-clock poll withholds quarantine | `crates/vprouter-core/src/client.rs:439` | Complete all four steps at 10ms, then `poll(9)` returns `Ok([Quarantine])`, status at 10 stays Failed, repeated `poll(9)` returns empty, and restart refuses. The same sequence with `u64::MAX` also delivers once without clock recovery. |
| M1 Minor: HTTP/1.1 CONNECT without Host admitted | `crates/vprouter-core/src/client.rs:538` | The exact complete input `CONNECT example.com:443 HTTP/1.1\r\n\r\n` refuses; matching-Host positive controls still succeed. |

Evidence: `adversarial-core.log`, scratch `tests/original_review.rs` and
`tests/rereview.rs::rr_original_three_scenarios`.

## Fresh adversarial address and HTTP sweep

Reviewer cases were authored separately from the implementer's cross-product
helper. The implementer's larger generated matrices also passed in the required
full touched-crate run. No additional target-validation bypass was reproduced.

- **287 host spellings** across HTTP, SOCKS domain, raw IPv4/socket/prefix APIs,
  GuardConfig parse and direct Serde construction, each userspace socket field,
  all three HostSnapshot fields, and synthetic profile endpoint parsing where
  its existing field grammar preserves the spelling. Added cases include signed
  components, much longer zero padding, mixed-case hex digits/prefixes, percent
  and double-percent encodings, NUL/control suffixes and prefixes, userinfo,
  query/path/fragment delimiters, Unicode separators/digits and bracketed zones.
  Raw/profile/JSON paths cannot introduce an address alias into a ruleset.
- Mapped/compatible IPv6 was tested as dotted tails, hexadecimal tails and full
  expanded notation, plus brackets, `%lo`/`%25lo`, NAT64 and 6to4-shaped inputs.
  HTTP/SOCKS text refuses; SOCKS ATYP=4 binary addresses refuse, including mapped
  public IPv4. Direct packet-policy checks also refuse typed mapped IPv6 and
  ordinary IPv6 while admitting the public IPv4 control.
- SOCKS domain and binary ATYP=1 representations of private/special addresses
  both refuse. Every other ATYP byte was substituted into an IPv4-shaped frame;
  version/command/reserved bytes were exhaustively mutated, and truncation and
  trailing-data cases refuse. Valid public ATYP=1 and domain controls succeed.
- **259 malformed HTTP shapes** refuse: authority and port ambiguity, absolute
  URI forms, absolute-form/Host disagreement, CONNECT/Host disagreement, missing
  ports, userinfo, bracketed IPv6/zones, duplicate Host, framing and folded-header
  shapes, and control bytes inserted around Host values or inside header names.
  Correct CONNECTs with case-insensitive Host names and SP/HTAB padding succeed.
  The supplied exact size/domain/label boundary tests also passed.
- Additional netfilter tests cover the existing standard-library typed socket
  path and `PublicProfile::parse_public`, rather than assuming every caller uses
  the new text helper. Noncanonical IP/mapped/zone aliases refuse there too.
  Canonical private and the six newly restricted provider/special endpoints
  refuse both public metadata validation and typed `Endpoint::new`.

Relevant code: `crates/vprouter-core/src/address.rs:18`, `:58`, `:85`, `:149`;
`crates/vprouter-core/src/client.rs:487`, `:514`;
`crates/vprouter-core/src/profile.rs:53`, `:258`;
`crates/vprouter-netfilter/src/policy.rs:36`, `:90`.
Evidence: `adversarial-core.log`, `adversarial-fleet-direct.log`,
`adversarial-metadata.log`; reviewer sources remain in the scratch source tree.

One initial reviewer assertion classified `127.1e0` as a numeric alias and
failed because it is admitted as a domain. An offline `socket.inet_aton` check
refused this spelling, while converting the original `127.0.0.0x1` to loopback.
No numeric conversion or local-target bypass was reproduced for `127.1e0`.
That overstrict reviewer expectation was removed, without editing product code;
the initial failing log is retained as `adversarial-core-initial.log`. This is
not evidence that DNS resolution of an admitted domain is safe.

## Fresh host-time and lifecycle sweep

No new action-loss, terminal revival or admission on invalid time was reproduced.

- **400 client cases** vary all five installation positions, pending versus
  drained initial work, all seven operational entry points plus status, and
  regression/out-of-domain/exact-watchdog/overdue time. Invalid time is processed
  even with a foreign callback token and wrong digest. Operational failures
  latch Failed and deliver exactly one quarantine action, including when no
  obligation existed before failure. Invalid status remains observational and
  consumes no pending work; expired status grants no Prepared result.
- Repeated invalid polls cannot rearm delivered work. Late complete/reconcile/
  restart/select/disappear/stop callbacks cannot revive Failed. Stop retains
  Stopped through invalid clocks and drains its existing obligation exactly once.
  Disappear followed by restart invalidates both old epochs. These sequences
  also run near and at the maximum valid integer time. Poll at 4,999ms renews;
  an exact 5,000ms gap fails and delivers quarantine.
- **112 mixed-fleet cases** exercise every timed FleetPolicy entry with/without
  queued work using both signed NaN payloads, infinities, a negative subnormal,
  one-ULP regression, one ULP beyond the domain maximum and `f64::MAX`.
  Operational failures deliver EmergencyQuarantineAndStop for both provider and
  direct exit. Late timed and untimed callbacks neither weaken nor replay that
  terminal work. Constructor invalid cases refuse; signed zero, positive
  subnormal and exact maximum are valid constructor controls.
- The supplied round-1 matrices additionally cover selection generation changes,
  stopped/failed queues, valid-time callbacks, immutable proxy parsing deadlines,
  constructors and unrepresentable u64 wire inputs. They passed unchanged.

Relevant code: `crates/vprouter-core/src/client.rs:278`, `:311`, `:398`, `:439`,
`:453`; `crates/vprouter-core/src/fleet.rs:300`, `:423`, `:490`.
Evidence: `adversarial-core.log`, `adversarial-fleet-direct.log`, `test.log`.

## Netfilter rendering and existing native behavior

No renderer injection, nondeterministic rule generation or broadened daemon
exception was reproduced within this offline model.

- Input/output/forward default drop, IPv6 drop precedes accepts, forwarding has
  no accept, and quarantine has no external permit. Namespace-local loopback
  admission remains scoped as documented. Userspace clients only reach intended
  listeners; the gateway's overlay exception binds its distinct cgroup, exact
  upstream, TCP and Tailscale interface identity. Existing bypass/DNS/IPv6 and
  unknown-socket-owner packet tests passed.
- **4,096 reviewer packet cases** cross userspace/kernel, TCP/UDP transports,
  input/output and simultaneous tuple mutations. WAN name/index, peer address,
  both ports, protocol, family and daemon socket cgroup must match; inbound
  transport additionally requires established/related state. The same packets
  are denied by quarantine and forwarding. No root/all-UDP/all-DNS permit exists.
  Separate decoding verifies exact socket cgroup hierarchy levels 1, 3 and 16.
- **290 reviewer mutations** remove each operation or alter its kind, flags,
  first/last attribute byte; every mutation refuses. Whole-content comparison
  also catches missing/extra/reordered/foreign/unknown input in the supplied
  tests. Equivalent independent plans render identical bytes; reversed maximum
  endpoint ordering remains deterministic in the supplied test.
- Names are derived hashes/fixed identifiers; address/port matching uses typed
  bytes and bounded attribute encoding. There is no executable script renderer.
  New allocation-subnet, table-name and WAN-name injection/overflow-shaped
  cases refuse through actual `Policy::new`, including record ownership checks.
- A scratch module containing the exact `policy.rs` from HEAD compares **30
  table operation sequences and three initial digests byte-for-byte** against
  the current renderer: Data/Transport/Host, quarantine/permit/emergency/bootstrap
  and all stage/permit-stage variants. All comparisons pass for existing valid
  fixtures; seven original packet-policy tests also pass in that module.
  This establishes fixture rendering parity, not universal kernel equivalence.
- Existing native actuator verifier changes are visibility/formatting only.
  Production native policy expressions, ownership, atomic mutation and semantic
  verification were not broadened. Subnet parsing now uses the canonical helper;
  allocation validation still precedes it. Endpoint admission is intentionally
  stricter for the six recorded special/provider addresses, so claiming literally
  unchanged admission for every old endpoint would be inaccurate. Existing valid
  native rendering/packet tests pass, including all **26 pre-client netfilter
  tests**, alongside the nine current client tests (35 passed, one ignored).

Relevant code: `crates/vprouter-netfilter/src/client.rs:29`, `:78`, `:89`, `:105`,
`:162`, `:189`; `crates/vprouter-netfilter/src/policy.rs:60`, `:582`;
`crates/vprouter-netfilter/src/actuator.rs:839`.
Evidence: `adversarial-netfilter.log`, `test.log`, `baseline-policy-head.rs`,
scratch `src/rr_baseline_policy.rs` and appended client tests.

## Minor notes, separated from defect findings

**Reproduced, nonblocking API qualification:**
`crates/vprouter-core/src/profile.rs:46`, `:57` retains the pre-existing typed
SocketAddrV4 metadata grammar: public `8.8.8.8:0443` is accepted and becomes
`8.8.8.8:443`. Private `127.0.0.1:0443` still refuses. This is not an address
classification bypass, and the new HTTP/profile text parsers correctly refuse
noncanonical ports. Do not extend their canonical spelling claim to all legacy
public-metadata deserialization. Evidence: `adversarial-metadata.log`.

**Unreproduced/unverified concerns, not blocking this preparation verdict:**
post-resolution DNS rebinding/private-address admission, actual nft socket/cgroup
lookup and exclusivity, namespace enclosure, and reliable native action delivery
remain integration obligations. No runtime bypass in these areas was reproduced
or tested here. The preparation guide already identifies these limitations;
this review does not convert them into new offline defects or proven protection.

## Verification ledger

All commands below ran from the scratch `source/` directory. Every command exited
0; build/test/clippy used the offline/locked/job flags shown and the common temp
CARGO_TARGET_DIR above. Logs and structured command/results/hashes are in
`verification.json`.

| Exact command | Fresh result | Log |
| --- | --- | --- |
| `cargo test --offline --locked -j 4 -p vprouter-core -p vprouter-netfilter --all-targets` | 163 passed, 0 failed, 13 ignored | `test.log` |
| `cargo fmt --all -- --check` | clean, empty output | `fmt.log` |
| `cargo clippy --offline --locked -j 4 -p vprouter-core -p vprouter-netfilter --all-targets -- -D warnings` | no warnings/errors | `clippy.log` |
| `cargo test --offline --locked -j 4 -p vprouter-core --test original_review --test rereview -- --nocapture --test-threads=1` | 3 unchanged original requirement tests + 6 reviewer tests passed | `adversarial-core.log` |
| `cargo test --offline --locked -j 4 -p vprouter-netfilter --lib rr_ -- --nocapture --test-threads=1` | 5 new reviewer tests + 7 base-policy tests passed | `adversarial-netfilter.log` |
| `cargo test --offline --locked -j 4 -p vprouter-core --test rereview_fleet --test rereview_direct -- rr_ --nocapture --test-threads=1` | 2 reviewer tests passed | `adversarial-fleet-direct.log` |
| `cargo test --offline --locked -j 4 -p vprouter-netfilter --lib rr_typed_and_public -- --nocapture --test-threads=1` | 1 reviewer test passed | `adversarial-metadata.log` |
| `git diff --check`; `git diff --cached --quiet` | both exit 0 | preservation checks |
| Baseline SHA256 comparison | 202 source/manifest/report files unchanged; all 19 Task 11 source/doc paths separately bound | `baseline-hashes.json`, `reviewed-source-hashes.json`, `preservation.json` |

Harness-only caveats: the initial overstrict domain assertion described above
exited 101 after compilation and was corrected. One preliminary `rr_` netfilter
invocation used the original repository cwd and selected zero tests; it is not
counted as evidence and was rerun from scratch with the 12 passing results above.
Scratch-only fixture imports emitted unused-import warnings; strict clippy on
the unmodified reviewed source was clean. No product source was changed to pass
reviewer tests.

Workspace-wide, musl/ARM checks and historical REDs were NOT_RERUN by this review.
Real Tailscale clients/captures and positive controls, native guard installation/
reconciliation/daemon identity/socket custody, actual proxy/resolver behavior,
boot ordering, persistent-journal interruption, migration, ARM execution,
performance and soak remain **NOT_RUN**. All 13 ignored tests remain unverified.
No native consumer or activation bridge was added or exercised. Task8c and all
runtime/release acceptance gates remain OPEN.
