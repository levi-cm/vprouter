# Native worker monitoring and provider confirmation engine

Preparation only; dispatch after launch-helper task6 approval. Workdir
/DATA/AppData/vprouter-rust-v2, rust/v2. No subagents, no production access, no
real credentials, no network/kernel mutations during normal tests.

This package provides native namespace-local Tailscale LocalAPI and reusable
bounded certificate-verified HTTPS provider checking plus worker health decisions.
Read this brief first, binding docs/rust-v2/IMPLEMENTATION.md, reviewed state types,
network audit API and task6 launch manifest contract. Do not silently loosen strict
network auditing to accept real Tailscale; enumerate exact required pinned-version
route/rule/address metadata with independent kernel oracles and negative tests.
No readiness or activation from test stubs. No shell/CLI monitoring subprocesses.

Own worker crate and minimal shared API fixes justified for integration, tests,
docs/rust-v2/worker.md and task7-report.md. Dependencies exact pinned and locked.
No cross-exit connections: construct sockets/clients only after dedicated helper
placement and pin ownership to namespace identity. No client construction before
setns and no async setns. The one-exit worker must have one cadence without
placeholder exit timers. Keep a separate init/reaper boundary from worker.

Provider URL is fixed https://am.i.mullvad.net/json with certificate and hostname
validation, bounded headers/body/redirects/compression and complete deadline
strictly below45s. Do not follow redirects or trust proxy environment variables.
Retain12s-or-less HTTP attempt deadline, one retry after1s for408/429/5xx and
eligible transient transport failures. Recheck interfaces, ALL routes/rules and
fresh handshake before retry including after delay, and after success. Permanent
HTTP, TLS verification, malformed/oversize/negative JSON, wrong server identity,
structural drift and repeated failures block. Fixed errors, no external body,
URLs, peer keys or secret-bearing errors in logs. Reject duplicate relevant JSON
keys and invalid types. Require mullvad_exit_ip true, public IPv4 egress and exact
mullvad_exit_ip_hostname equal configured verified server (check real provider
API fixture shape rather than assume a friendly alias). Provider success alone
never establishes Tailscale readiness. Native DNS must stay inside data namespace
and WG-only policy; no host resolver sockets carried across namespaces.

Tailscale LocalAPI uses private Unix socket, bounded HTTP and exact pinned1.102.5
endpoints. Project status/prefs: Running, self.Online true, approved exit option,
expected stable node ID/IPs, exact advertised routes, NetfilterMode0, no unexpected
selected exit or route acceptance. New identity enrollment never clones state;
interactive AuthURL returned only to operator through protected channel, not
persisted in reports/journals. Preference writes must be narrow and explicit;
no resets that discard identity or approvals. Initial stale advertisement must
be withdrawn before healthy observation. Server/name reconciliation is separate
explicit lifecycle action. Direct mode rejected until its policies exist.

Use reviewed HealthMachine STARTING/BLOCKED/RECOVERING/READY/STOPPING/FAILED;
three independent successes plus actual approved/online identity evidence before
READY. Monotonic cadence5s, bounded deterministic multi-exit offset; handshake
strictly<180s, no future/unknown timestamps, freshness<45s, independent guard
watchdog90s. A whole provider operation cannot starve heartbeats/withdrawal.
Support bounded cancellation/shutdown; failure must notify independent guard and
withdraw local exit or terminate tailscaled if API is unavailable. Guard owns
quarantine; worker status requests remain observational. No claim of an active
guard until actual cross-process protocol exists and is tested. No bool-based
quarantine bypass. Health JSON protected/atomic and redacted, DNS/IPv6 verified
independently or not_tested, never constant true.

Meaningful offline tests: local controlled TLS server with trusted synthetic CA,
unknown CA/name mismatch rejected; real bounded HTTP parser malformed/chunked/
slow/oversize/deadline; real LocalAPI mock Unix server validates request method/
path/body, withdrawal/preferences and identity refusal. Clock/fault injection at
external boundary tests one eligible retry, post-delay drift,180s expiry, wrong
server, negative provider, permanent errors and repeated transport failure.
Normal tests use only loopback/Unix sockets, no external provider/profile/state.
Provide ignored owned-guest harness for actual pinned tailscaled LocalAPI without
advertising routes unless root authorizes under full quarantine. Root runs any
kernel/integration acceptance, with evidence preserving failures. No real-client
leakage claim from synthetic tests. Run focused checks, commit explicit files,
report exact code hashes/commands/results/dependencies and remaining gaps. Return
status/commits/short tests/concerns; report file carries detail.

Controller independent read-only pinned LocalAPI oracle is in docs/rust-v2/localapi-lab-evidence.json: actual GET /localapi/v0/status and /localapi/v0/prefs both200 over Unix socket; actual1.102.5 version and nullable empty AdvertiseRoutes/empty ExitNodeID+IP shapes retained. Enrollment-only default NetfilterMode2 is explicitly unready; worker must establish reviewed mode0 before readiness. No write/withdraw/healthy advertised exit tested by this oracle.

Controller public-source oracle docs/rust-v2/tailscale-routing-source-oracle.json binds the peeled v1.102.5 commit to the actual lab version prefix. Upstream Linux route code moved under wgengine/router/osrouter. It documents exact rule intent (5210/5230/5250/5270, marks/mask, disabled sentinel values) and route constructor, but does NOT prove installed kernel metadata. Native Rule projection currently lacks mark/action fields; retain and audit every functional attribute rather than silently ignoring them. Independent kernel shapes and appropriate identity/control witness remain necessary; never allow arbitrary observed table52/default/LAN routes.
