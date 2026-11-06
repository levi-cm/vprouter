# Task 11 independent review

Verdict: **FAIL — 0 Critical, 2 Important, 1 Minor finding.**

Reviewed 2026-11-06, branch `rust/v2`, HEAD
`067069186f9106232fded16bb3707dcdd4dc891d`, including the supplied uncommitted
Task 11 files. Binding inputs: `.superpowers/sdd/rust-v2/task-11-brief.md`,
`docs/rust-v2/IMPLEMENTATION.md` (work package 8 and mandatory acceptance), and
the user's review instructions. The implementation report was unverified input.
All 14 source/doc SHA256 values in that report match the reviewed files.

This verdict covers the authorized offline preparation layer. It does not
require native activation from this increment or infer runtime failure from
unimplemented native integration. Findings below are reproduced policy/parser
behaviors; no actual packet leak or privileged kernel behavior was tested.

No sub-agents, source fixes, sudo, network operations, VMs, Git mutation commands
or process termination. Only this review file was written inside the repository.
Scratch source, executables, build output and logs are under
`/tmp/vprouter-task11-review-AYJ9hp/`.

## Findings

### I1 — Important: mixed hexadecimal IPv4 aliases bypass proxy target validation

Location: `crates/vprouter-core/src/client.rs:541`, especially lines 551–553.
Documentation claim: `docs/rust-v2/client-guards-preparation.md:136`–140.

When strict `Ipv4Addr` parsing fails, `validate_target` rejects strings beginning
with `0x` and strings made entirely of decimal digits/dots, then treats the
remaining valid labels as a domain. Hexadecimal components after the first
component pass that filter. Both HTTP CONNECT and SOCKS5 domain requests accept:

| Accepted target | Local numeric conversion (`inet_aton`, no DNS/network) |
| --- | --- |
| `127.0.0.0x1` | `127.0.0.1` |
| `127.0.0X1` | `127.0.0.1` |
| `0177.0.0.0x1` | `127.0.0.1` |
| `169.254.0xa9.0xfe` | `169.254.169.254` |
| `10.0.0.0x1` | `10.0.0.1` |

For example, `proxy_request(HttpConnect,
b"CONNECT 127.0.0.0x1:443 HTTP/1.1\r\nHost: 127.0.0.0x1:443\r\n\r\n", 0, 1)`
returns `Ok(ProxyRequest)` rather than refusing the numeric alias. The equivalent
SOCKS5 ATYP=3 request also succeeds. The resulting intent labels the request
`selected_exit_only`/`ipv4_only` without applying the nonpublic-address check to
its numeric meaning.

This violates the claimed rejection of ambiguous numeric hosts. A downstream
numeric-aware resolver/connector can interpret these as loopback, link-local or
private addresses. The future requirement to validate resolved addresses remains
necessary, but does not make the current parser's refusal claim true. No
downstream connection was attempted in this review.

Reject numeric-address aliases across the whole host before admitting a domain;
keep canonical dotted-decimal public IPv4 as the only admitted numeric form.
Cover mixed decimal/octal/hex components and both proxy protocols.

Reproduction: `review_numeric_ipv4_aliases` prints all five accepted targets and
asserts acceptance in both protocols. Requirement test
`review_expected_reject_mixed_ipv4_alias` **FAILS**, exit101.
Evidence: `scratch-core.log`, `scratch-red.log`, `numeric-conversion.txt`,
`review_core.rs:691`.

### I2 — Important: invalid-clock polls cannot deliver the queued quarantine obligation

Location: `crates/vprouter-core/src/client.rs:435`–440; failure queuing at
lines 303–309 and invalid-clock detection at lines 311–315.

`clock` correctly changes a nonterminal guard to `Failed` and sets
`pending=true` on regression/out-of-domain time. However, `poll` immediately
returns `Err` for `InvalidEvidence`, before draining `pending` into the only
action type this policy exposes. It handles watchdog expiry differently:
`StaleEvidence` proceeds to deliver `Step::Quarantine`.

Reproduced sequence using a valid plan:

1. Construct at10ms and complete Quarantine, Capture, Commit and Reconcile at10ms,
   reaching `Prepared`. No quarantine obligation remains pending.
2. `poll(9)` returns `Err(InvalidEvidence)`. `status(10)` confirms `Failed`.
3. A second `poll(9)` again returns `Err`, with no action. As long as the clock
   stays regressed, the caller cannot obtain the queued quarantine obligation.
4. Only `poll(10)` finally returns `[Quarantine]`. The same early-return behavior
   occurs for an out-of-domain time such as `u64::MAX`.

The internal terminal state is preserved, but it is not the persistent nft
quarantine. An action consumer cannot execute a quarantine action that this
poll interface withholds. There is no supplied native consumer or documented
mandatory error-to-quarantine bridge that establishes an alternative here.
Thus the offline action contract is weaker for a broken clock than for an
expired watchdog, precisely when fail-closed work must remain deliverable.
This finding does not assert a deployed leak: native enforcement is NOT_RUN.

Deliver the one coalesced quarantine obligation independently of clock recovery,
while retaining Failed and refusing further preparation. This can use an
error-plus-actions result or the existing terminal-drain behavior used for
watchdog expiry; do not reset the time high-water mark to recover admission.

Reproduction: `review_poll_invalid_clock_omits_quarantine_action` checks the
sequence and valid-clock drain. Requirement test
`review_expected_deliver_quarantine_despite_clock_regression` **FAILS**,
exit101 (`None` rather than `Some([Quarantine])`).
Evidence: `scratch-core.log`, `scratch-red.log`, `review_core.rs:697`.

### M1 — Minor: HTTP/1.1 CONNECT accepts a missing Host header

Location: `crates/vprouter-core/src/client.rs:522`–535, especially the end of the
header loop at line530. Documentation: client preparation guide lines 134–140.

`seen` detects duplicate Host headers, but is never required to become true.
Consequently the complete input
`b"CONNECT example.com:443 HTTP/1.1\r\n\r\n"` is accepted and produces target
intent. HTTP/1.1 requires a Host field; the conservative parser claims malformed
requests refuse and unsupported semantics are not rewritten. Require exactly
one matching Host header for this admitted HTTP/1.1 subset.

This is a request-validation/compliance defect; no request smuggling, native
activation or network fallback was demonstrated.

Reproduction: `review_missing_host_header` confirms acceptance. Requirement test
`review_expected_reject_http11_missing_host` **FAILS**, exit101.
Evidence: `scratch-core.log`, `scratch-red.log`, `review_core.rs:704`.

## Netfilter review

No additional concrete defect was established in generated rules or existing
non-client native behavior within the offline boundary:

- `actuator.rs` changes only `verify` visibility to crate-private; its body is
  unchanged. `policy.rs` changes helper/test visibility and adds ifindex support
  to the test interpreter. Existing production validation, ownership checks,
  expression encoding, semantic verification and atomic-update logic are not
  edited. `lib.rs` exports the new offline module and retains unsafe prohibition.
- Client table names are generated hash identifiers, chain names are fixed,
  interface names are restricted to bounded ASCII and matched as fixed-width
  bytes, and addresses/ports are encoded typed values. No nft script or shell
  text is rendered. Strict transport IPv4 parsing rejects mapped IPv6, zone IDs,
  leading-zero/hex encodings and injection strings. I1 affects proxy target
  intent, not the transport-address parser or UAPI encoding.
- Transport lists must contain1–32 exact, nonduplicate tuples. No ranges,
  wildcard sets or prefix overlap exist. Different source-port tuples are
  disjoint; sorted tuple order produces deterministic fingerprint/rendered
  operations. Maximum32 tuple rendering and rule-positive/negative controls pass.
  Config input is bounded at64KiB, rendered JSON at1MiB; altered or oversized
  rendered input refuses. No arbitrary set/deletion/flush operation is emitted.
- Input/output/forward chains default drop. Explicit IPv6 drop precedes every
  permit; forwarding has no accept rule. Kernel loopback acceptance is restricted
  to the dedicated namespace's `lo` name/index. Userspace loopback rules admit
  only the two intended TCP listeners and established replies. General WAN
  application TCP/UDP, DNS53, TLS-DNS853 and ordinary application HTTPS/DoH do
  not match a permit. The permitted kernel application path uses exact Tailscale
  name/index/tun-kind; that interface alone is explicitly not selected-exit proof.
- The WAN exception matches protocol, exact remote IPv4/port, local source port,
  WAN name/index and socket cgroup identity at an explicit hierarchy level;
  reverse traffic also requires conntrack state. No root-UID/name-only/all-UDP/
  all-DNS exemption was added. Userspace upstream traffic also requires the
  distinct gateway cgroup and exact tailnet TCP destination. Actual executable,
  pidfd, cgroup exclusivity, socket birth and namespace authority are unverified
  integration obligations, explicitly documented as such. Offline matching
  tests do not establish those runtime facts or encrypted-payload provenance.
- All existing netfilter tests were rerun: **26 existing tests passed**, together
  with **7 new client tests**; the existing privileged native test stayed ignored.
  This includes ownership/marker/generation/flags, extra/missing/reordered rules,
  semantic dumps, bootstrap exclusive creation, replacement compatibility,
  packet-path and deadline regressions. No native policy was activated.

## Core, storage and evidence boundaries

- All seven operational client callbacks validate the integer host clock before
  token/input checks. Negative/NaN cannot inhabit `u64`; regression, >1e15ms and
  watchdog-expiry controls pass for all seven, subject to I2's action-delivery
  issue. Scope/instance/epoch rejection, terminal preservation, ordered startup,
  selection generation checks and repeated-poll coalescing are covered by the
  supplied tests and extra scratch controls. A failure/stop on one guard leaves
  another instance prepared. The supplied restart exhaustion test passes; state
  consists of bounded counters/options rather than growing event histories.
- Status checks reject time below the last operational high-water mark and stay
  observational, matching the prior Task9/10 distinction. A scratch probe also
  confirmed status calls do not advance that mark: a future expired status query
  followed by an earlier query above the operational mark can display Prepared
  again. This is not reported as a new operational clock failure or terminal
  revival; it is the existing observational-query contract. DNS/IPv6/observed
  egress remain `not_tested` and Prepared is explicitly offline.
- New install/select variants mutate a cloned configuration, then enter the
  existing full validation/build and generation/content CAS preparation writer.
  No new filesystem API, native client installation journal or store is added.
  Existing retained-lock/inode, ownership/private-mode, NOFOLLOW, single-link,
  exclusive-temp, file/directory-fsync and symlink/hardlink/CAS regression tests
  pass. No new TOCTOU was established within the existing private-store and
  cooperating-writer boundary. This does not prove native installation or
  power-loss recovery, which remain unimplemented/NOT_RUN.
- No new unsafe block, privileged test execution, network socket, subprocess,
  CLI activation flag or optional verification boolean was found. Call-site
  search found no production native consumer of ClientGuard/GuardPlan/ClientRuleset.
  The new ignored guest specifications only panic if forced; none was forced.
- Documentation and report clearly distinguish offline intent from authenticated
  native authority, proxy parsing from an operational gateway, and ignored
  specifications from runtime evidence. Apart from the concrete claims qualified
  above, no runtime acceptance or release-readiness overclaim was established.
  No acceptance ledger, identity, credential, service or CLI was changed.

## Verification ledger

Cargo commands were executed **sequentially**, using Rust1.97.0, with
`CARGO_TARGET_DIR=/tmp/vprouter-task11-review-AYJ9hp/target` and
`CARGO_BUILD_JOBS=4`. Every Cargo build/test/clippy invocation used
`--offline --locked -j 4`. Fmt does not accept those build flags.

| Exact command | Exit | Fresh result | Evidence under scratch directory |
| --- | --- | --- | --- |
| `cargo test --offline --locked -j 4 -p vprouter-core -p vprouter-netfilter --all-targets` | 0 | 150 passed,0 failed,13 ignored | `test.log` |
| `cargo fmt --all -- --check` | 0 | clean, empty output | `fmt.log` |
| `cargo clippy --offline --locked -j 4 -p vprouter-core -p vprouter-netfilter --all-targets -- -D warnings` | 0 | no warnings/errors | `clippy.log` |
| `git diff --check` | 0 | clean | tool result |
| `review_core review_ --nocapture --test-threads=1` (initial diagnostic build) | 0 | 4 reproduced observations, including observational-status control | `scratch-core.log` |
| `review_core review_control --nocapture --test-threads=1` (final scratch build) | 0 | 3 additional controls passed | `scratch-controls.log` |
| `review_core review_expected --nocapture --test-threads=1` (final scratch build) | 101 | 3 requirement assertions failed: I1,I2,M1 | `scratch-red.log` |
| SHA256 comparison of all14 report-listed source/doc files | 0 | 14/14 match | `source-hashes.json` |

Scratch tests were compiled directly with `rustc --edition=2024 --test`, linking
the fresh Cargo-built core/serde_json rlibs; the exact compiler command is in
`scratch-compile-command.txt`. The scratch test source copies the supplied core
fixture/test module and adds reviewer cases; its support-module path points to
the unchanged synthetic fixtures. No test was injected into the repository.
The three failing cases are behavioral assertions after successful compilation.
`verification.json` records commands/results.

The report's three requested validation claims are confirmed by fresh checks.
Its additional workspace test, x86_64-musl tests, ARM64 compile and historical
RED/artifact claims were **NOT_RERUN** in this bounded review, and are not
promoted to independently verified evidence here.

Real-client IPv4/DNS/IPv6/TCP/UDP capture and positive controls, native nft/socket/
cgroup authority and reconciliation, client install/select/restart/disappearance,
proxy failure/bypass under real traffic, boot capture before workloads, durable
installation interruption, systemd/runit behavior, ARM execution, migration,
performance and soak: **NOT_RUN**. All13 ignored tests remain unverified, including
the four new client acceptance specifications. No runtime or release acceptance.

Evidence SHA256:

```text
2bcda64c1d5f4b62ab5cc91143d0682e90cc298362f26ba37ed4930f51603087  review_core.rs
c2b72ca33881ba971f92079eff1c6620dfcc20a46415b3cefc4ed6366042170d  test.log
8724f50e1cd65ce7fa74cb9c896680fd056cf2e7166ea5b768eb76f57b117ede  clippy.log
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  fmt.log
661a39e3f595ab9619ce0cf6c54b9832b1404d9d09a6835d5ee3c3ef80ff94c3  scratch-controls.log
ee21da4e824fbec465848ce36478855c29a338738733da6ffddf1099afd1db7b  scratch-red.log
```
