# Native read-only host interface, CLI and migration planning

Workdir /DATA/AppData/vprouter-rust-v2. No subagents. Read IMPLEMENTATION.md and
Task2 report/types first. Own crates/vprouter-linux/**, crates/vprouter/**,
Cargo.toml lock additions, tests CLI integration and docs/rust-v2/agent-guide.md.
Do not touch legacy runtime/services or deploy. This is independently useful
read-only preparation for packages3/9, NOT completion of their guard/apply runtime.

Add Cargo workspace members vprouter-linux and vprouter CLI binary. Linux read-only
integration MUST use native APIs/files/Unix socket, never shell subprocesses.
Native-only safe Rust initially, forbid unsafe. Any inability to prove kernel
feature gets NOT_TESTED, never 'true'. No shells/wildcards or external programs
in implementation. CLI JSON to stdout on success AND failure, nonzero on failed
checks; errors authored reason codes no external error text/path/JSON data leak.
Use clap for implemented subcommands only: validate --config; status/probe
--config; migrate inspect --legacy-config; migrate plan --legacy-config --site
--expected-server --deployment-id [--output]; diagnose --config. Global --help.
Do not expose unimplemented mutating commands as if real. Report exact missing
commands in docs and machine-readable capabilities. Read-only commands must not
quarantine/write runtime state/stop/rebind. --output only explicit plan artifact,
not runtime mutation. Exit ID/container/service preserve legacy name.

Preflight validate Linux>=6.1 arch x86_64/aarch64, supported os-release/manager
Debian13 systemd, Arch/CachyOS systemd, Void glibc runit; cgroup2; /dev/net/tun
character device; nftables and WG feature availability verifiable (module files
not proof loaded usability; report required active probing as NOT_TESTED until
lab). Docker Unix API bounded+deadline+no redirects over Unix socket, version
>=supported chosen minimum, no daemon mutations. All root-sensitive paths and
secret files must be root-owned not writable by group/other, no symlink ANY
component. Key files mode<=0600; state<=0700 and directories type; release
root-owned no group/other writes real directory. Distinguish schema_valid vs
host_supported vs activation_ready; unknown prerequisites prevent ready.
Profile validation native reader uses core redacted errors; never emit keys.

Docker inspect read only via /var/run/docker.sock, bounded request/response
(max 1MiB), full HTTP parsing via hyper or equivalent (incl chunked); connect,
header+body deadline (e.g3s each,total<10); API version explicit /v1.45 etc and
verify API compatibility. Parse ONLY relevant fields into deny? Docker may add
fields so ignore unknown response fields. Inventory container ID, Name, image,
PID/start time, labels ownership, mounts references, NetworkMode dependents,
state/restarts/OOM. Never serialize env, full config, state content, label values
other than scoped ownership. Names may be hostile: redact/validate instead of
using as reason text. Never Docker exec (query must be observational).
Status reads root-owned per-exit health under /run/vprouter-v2/<deployment>/<id>
if present; validate content/freshness and config binding before reporting.
Missing health -> not_running or NOT_TESTED, never READY. No inventing egress,
node IDs, DNS or IPv6 success. Disabled exits show disabled. Direct always
`direct-exposed` even not ready; distinguish exposure mode from verification.
Validate mode/display/server/exit/deployment match configuration to avoid stale
health reuse. Reuse core state machine/evidence validation. Probe observational
can report cached verified age; must state source cached, not actively verified.
Do not read legacy tailscale.state to extract secrets. Legacy status health may
only be inventoried as snapshot, never Rust readiness evidence.

Migration inspect strict legacy config exactly name/profile/state_dir/image_ref/
compose_dir plus optional tailscale_hostname (type+name validate). Detect v2,
unsupported fields/unknown ownership safely. Inventory real releases hashes,
unit manager/unit files ownership, hooks collector declared files (safe fields),
primary/uplink identities via container metadata only. Cannot infer nodeID from
state -> explicit NOT_TESTED, unknown hostname dependencies require declaration.
Create schema2 candidate preserving actual profile/state/image/container/service
name under stable primary id; explicit site+expected server provided by operator;
new hostname formula verified. Preserve old_hostname and new_hostname separately.
Never mutate or copy identity; no implicit enable direct, no credentials in plans.

Plan schema strict and deterministic: version, deployment/site/exit identity,
source/config/profile(restricted fingerprint only not key)/release/unit hashes,
container ID+PID start time if observed, existing and proposed names, exact ordered
steps and quarantine/backup/adapter/rollback preconditions. Opaque secret file
hash not serialized (avoid offline secret fingerprints); expected endpoint/public
server allowed. Config precondition hashed, identities represented by path+metadata
(no secret bytes). Emit sha256 canonical plan content fingerprint for future
unchanged plan validation, but state apply unavailable and verification incomplete.
--output uses create_new0600+sync; refuse overwrite/symlink parents; stdout no
secret contents even on parse errors. If missing adapters/client coverage/node ID/
checksums/rollback compatibility, blockers listed; can still create non-applicable
review plan, `applicable:false`, command nonzero (choose2) and clearly documented.
Never claim a plan can be applied when runtime not implemented.

Diagnose JSON support bundle only authored/static sanitized statuses with
capabilities, preflight and `NOT_RUN` acceptance manifest; no system env/config
or external response dump. No broad journal reads. Clearly lists unperformed
single/five/mixed real clients, reboot, soak, performance, second host, unsafe
launcher review, artifacts. No performance claims from sample.

Tests meaningful: mock Docker Unix server for HTTP body cap/deadlines/chunked/
malformed JSON/403/no env leakage; unsupported platform fixtures; temp path
symlink/type/mode ownership checks; CLI parse/invalid config redaction (inject a
fake secret as invalid input), strict legacy -> v2 path preservation, deterministic
fingerprint and no plaintext secrets, stale/mismatched health never READY,
output file refuses replacement. For host integration tests no root mutation.
Document exact offline build/validate/inspect/plan/status commands and unsupported
operations, no fictional deployment/apply/rollback procedures.
Run cargo fmt/test/clippy all-targets -D warnings, Python tests only if legacy
changed. Commit explicit owned files. Report
.superpowers/sdd/rust-v2/task-3-report.md status/commits/tests/known unimplemented
required gates. Return only status/commits/testsummary/concerns.

Additional integration details: exact current public server observation is
recorded docs/rust-v2/current-server-observation.json (de-fra-wg-404). A schema2
candidate is NOT a new runtime release. Status must require actual native guard
liveness/ownership proof in addition to valid health; since the guard is not
implemented, no status may report Rust protected/READY merely from a health file.
It may validate/report a snapshot separately but runtime readiness must remain
unverified. Emit explicit capability guard_runtime=false. Never report v2 live
readiness for a legacy Python guard. Use clap try_parse and emit sanitized JSON
invalid_arguments on parser errors rather than printing supplied raw argv; help
and version remain ordinary nonsecret user-requested text. Diagnostic paths via
public defaults only; no parameter that enables bypassing root ownership in
production (test helper injection may be cfg(test)).
Read-only status/inspect must not call AllocationStore::open/lock if that creates
lock files/directories. Ownership validation is read-only; create no paths unless
--output was explicitly supplied. There is now one staged disposable userspace
client, recorded enrollment-evidence.json; do not mutate it from this package.
User supplied root0600 /DATA/AppData/vprouter/wiregurad-auth.zip with five distinct
keys/addresses, endpoint/server catalog mappings verified. Do not extract or
read real profiles during implementation tests. Root is preparing isolated KVM
lab tools under ignored target/ separately, not using this crate to start VM.
