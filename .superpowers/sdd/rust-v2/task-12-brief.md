# Transactional migration, dependency adapters and legacy compatibility

PREPARATION ONLY. Dispatch after reviewed actual runtime and client-guard tasks.
Workdir /DATA/AppData/vprouter-rust-v2, rust/v2, no subagents. Binding
IMPLEMENTATION.md and original handoff. Root alone performs external/privileged
lab tests; this task cannot migrate production or reset credentials/identities.
Read observational migration artifacts and all runtime/ownership/client contracts.

Implement inspect/plan/apply/resume/rollback JSON commands and declared dependency
adapters using a durable locked journal with generation-bound atomic fsync state.
Plan records exact changes and unchanged precondition fingerprints. Apply only an
unchanged staged plan under the deployment lock; idempotent resume/reversal after
any boundary. Validate supported host BEFORE altering existing installation.
Unpinned/missing provenance, uncertain ownership, incomplete required adapters or
unknown hostname dependencies block unattended cutover. Client coverage can be
explicitly unverified but never represented as protection; release acceptance
still requires actual client no-fallback verification.

Required ordered transaction: inspect versions/images/service/config/identity/
state/firewall/Docker dependents/hooks; stage immutable release/image/checksums
and verify config/names/allocations; plan exact changes; establish quarantine
independently of old supervisor; drain/stop adapters and old service; verify ALL
old identity users stopped; take root-only stopped-state backups of identity,
config, service/hooks, release metadata and allocations; activate transactionally
into a root-owned REAL release directory; restore same nodeIDs/IPs/approvals;
verify exact provider server then rename existing nodes; actual protected-client,
mode/isolation and dependency verification; commit and resume workloads. Failure
quarantines FIRST, restores last verified compatible release AND configuration/
Tailscale state, or keeps affected exits offline if safe restoration unproved.

Preserve primary service instance and container names, original WG profiles and
state paths, Tailscale identities/addresses/approval. Stable exitID primary for
legacy input; preserve deployment names separately. Never run two copies of one
identity concurrently, delete/recreate credentials, clone enrollment, or change
Mullvad server implicitly. Avoid symlink activation incompatible with old rollback
checks. Backup creation/restore must not expose secrets or follow attacker paths.
An old image alone is insufficient rollback compatibility proof; record format/
state-version compatibility and stopped-state metadata. Unknown/ambiguous cleanup
retains quarantine and ownership records rather than guessing what to remove.

Adapters declare absolute executable argv arrays, bounded idempotent drain, stop,
rebind, start and health-check operations. No shell strings, implicit eval, broad
service restart or Docker/containerd restart. Inventory auto-detection is evidence,
not authority to execute unknown custom hooks. Retain existing collector ordering:
pre-start stop, post-start start, post-stop stop. Known hostname references may be
updated by declared adapters; unknown external hostname users must be declared
before unattended rename. Prefer stable nodeID selection. Fixed audited adapter
subprocesses are lifecycle actions, never steady-state monitoring.

Provide lightweight legacy router-runtime --status/--probe and host status/
validate compatibility wrappers invoking the Rust CLI, without persistent Python.
Preserve expected primary-exit JSON semantics while replacing falsely constant
DNS/IPv6 assertions with verified fields or not_tested. Queries observational;
no quarantine mutation from status/probe. Ordinary protected shutdown preserves
guards; explicit ownership-checked uninstall is a separate operation.

Offline tests use meaningful synthetic stopped-state fixtures from current main
and retained local retry variant528fece/84fb353, not secret copies. Kill/resume at
every transaction boundary; change preconditions; interrupted writes/full disk;
missing adapters/ownership; renamed nodes; custom hooks; backup/state mismatch;
rollback failure. Prove no duplicate identity process and correct quarantine-first
ordering. Ignored owned-guest test migrates a NEW disposable legacy installation
with its own fresh identity, stopped-state backups and declared fake dependents;
validate real identity retention/name reconciliation and compatible rollback.
Root may perform authorized final debdev canary only after release gates; second
existing host remains inaccessible until administrative access is supplied.

Own migration/adapter/wrapper integration plus exact agent instructions for
preflight, inspect, plan, apply/resume, validation, recovery and rollback. Document
systemd/runit procedures and compatibility/unsupported matrix. Focused tests,
fmt/clippy, x86_64/ARM64 checks, explicit owned-file commits and self-review;
task-12-report.md records exact source/artifact hashes, commands/results, redacted
transaction evidence and unperformed gates. Independent review before packaging
or production migration claims; synthetic tests do not certify final acceptance.
