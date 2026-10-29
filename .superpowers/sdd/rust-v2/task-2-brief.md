# Task 2 — strict Rust configuration, health machine and allocation storage

Implement offline foundation only. Workdir /DATA/AppData/vprouter-rust-v2.
Read docs/rust-v2/IMPLEMENTATION.md first; user handoff there is binding.
No subagents. No live namespace, firewall, Docker or service mutation. No deploy.
Own Cargo.toml/Cargo.lock/rust-toolchain.toml, crates/vprouter-core/**, .gitignore,
docs/rust-v2/configuration.md and examples/v2/**. Other crates come later.

Workspace Rust edition 2024, pin installed 1.97.0 minimal rustfmt/clippy; Cargo.lock
tracked. Minimal dependencies with exact resolved lock. Shared library
vprouter-core, modules config, profile, state, allocation, reason. Rust unsafe
limited to Linux crate later; core should forbid unsafe. No shell calls.

Strict serde schema (deny unknown including enum mode-specific fields):
Configuration {schema_version:2,deployment_id,site,gateway_image,exits,
 dependency_adapters:[],client_policies:[]}. Reject unknown versions, blank fleet,
>bounded number 128, duplicate IDs. Labels lowercase DNS labels <=63; deployment
and exit IDs <=32 practical; site explicit. Exits {id,enabled,state_dir,
 enrollment_key_file?:path, mode: tagged configuration}. Prefer mode enum flat
internally tagged with mullvad {profile,expected_server} and direct {} nested
field `mode: {kind:"mullvad",profile:"...",expected_server:"..."}` so strict
mode separation is straightforward. All paths absolute lexical canonical (no
.. or .), state directories distinct and non-overlapping including disabled
exits; identities reserved for disabled exits too. Client policy defines selected
stable node ID and explicit protected/direct mode, reference IDs unique. Adapter
absolute executable+argv action arrays for drain/stop/rebind/start/health_check,
bounded timeout 1..300s, declarations idempotent=true; no shell strings. Policy
references must resolve. Avoid accepting uninterpreted Json Value.

Pinned image accepts sha256:<64 lowercase hex> or repo@sha256:<64 lowercase hex>;
reject tags and malformed repository/empty repo. No auto fallback field.
Hostname generation exact mullvad-{site}-exit-{expected_server} and
unsafe-direct-host-ip-{site}-exit. expected_server syntax real Mullvad server
(e.g de-fra-wg-404), preserve pinned server. On name collision suffix BOTH names
with -{id}; validate final <=63 and all final names unique (colliding suffixed
and original name must be rejected). Disabled names still reserved.
Never derive identity or state paths from hostname.

Profile parser strict WG Interface/Peer one each. Bound 64KiB. Parse private/public
base64 exactly32 bytes, IPv4 /32 address (allow profile's IPv6 address entries but
ignore forwarding; retain original file), literal public IPv4 endpoint:port,
AllowedIPs includes IPv4 default. Reject duplicate sections/fields, commands
Pre/PostUp/Down, unknown dangerous directives, empty/repeated peer. Mullvad
server identity supplied explicitly and cross-checked against a profile server
comment/filename if verifiable; document anything profile cannot authenticate.
Secret types: no Serialize or Debug revealing keys. Error messages authored,
no raw paths/content/serde input values or external errors. Shared config validate
uses injected profile reader so tests need no privileged production paths.
Fleet duplicate private key detection including disabled exits, never report key
or digest. Protected file validation on real host deferred Linux crate but
parse/load must not follow secret symlinks; avoid logging raw serde errors.

Health explicit STARTING/BLOCKED/RECOVERING/READY/STOPPING/FAILED transitions:
no STARTING->READY; three consecutive fresh provider+structural checks before
recovering, approved online exact server and policy before READY. Failure resets
successes and immediately BLOCKED/FAILED; no mode transition except explicit
stop/reconfigure. Stale/future heartbeat/verification age, invalid floats/time,
READY missing server/node/egress/verification evidence rejected. IPv6/DNS fields
Verified/Failed/NotTested; never infer positive DNS verification from readiness.
Direct reports exposure `direct-exposed`; Mullvad protected status only when
READY with evidence. Define stable serializable reason codes, no external text.
Constants 180s handshake,45s staleness,90s watchdog,5s provider cadence,1s retry.
Deterministic bounded per-exit staggering (no single-exit extra timers).

Allocation records: schema version/deployment/generation; deterministic scoped
namespace/table/interface names (Linux IFNAMSIZ=15), per-exit distinct /30 or
/29 transport subnet avoiding conflicts and overlapping state; include stable
exit ID and mode. Stable allocation derived from deployment+ID rather than
position/name. Validate foreign/duplicate resources before accepting record.
Atomic file storage needs exclusive nonblocking flock, generation compare-and-
swap, temp create_new 0600, write+fsync, rename+parent fsync, no symlink path
components, private owned dir. Use safe rustix/nix helpers or place persistence
in small safe module using fs2 locking; do not add unsafe to core. Parent dirs
and owner checks production root; allow current user temp root explicitly in
unit tests via constructor restricted to cfg(test). No silent race/stale writes;
interruption leaves last committed record readable, unknown temp retained safely.
Tests must exercise real concurrent lock/generation, symlinks, incomplete writes,
collision/malformed schemas, duplicate keys/states, mode/name changes and health
boundaries. No implementation mirror tests.

Add synthetic one/five/mixed examples with documentation 'schema examples,
not deployable credentials/artifact' and valid digest placeholder clearly marked;
configuration reference field details, strict validation and stable ID policy.
Run cargo fmt/check/test/clippy --all-targets -- -D warnings. Existing Python
baseline stays preserved. Commit explicit owned files. Full report to
.superpowers/sdd/rust-v2/task-2-report.md; return status, commits, tests, concerns.
