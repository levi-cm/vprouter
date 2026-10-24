# Service managers, immutable artifacts and release integration

PREPARATION ONLY. Dispatch after reviewed runtime/client/migration components.
Workdir /DATA/AppData/vprouter-rust-v2, rust/v2, no subagents. Root alone performs
privileged owned-guest acceptance. No production cutover, shared-branch push,
publication, Docker/containerd restart or unrelated service changes in this task.
Binding IMPLEMENTATION.md and original user handoff.

Deliver install/update/recovery/rollback/uninstall procedures and systemd/runit
supervision for supported Linux6.1+/cgroupv2/nft/kernelWG/TUN, Debian13,
CachyOS/Arch and Voidglibc; static x86_64 and ARM64 artifacts. Unsupported hosts
fail preflight before installation changes. Static musl artifact does not imply
Voidmusl host support. Preserve existing service instance names, primary container
names, real release-directory rollback semantics, root-owned private identities,
profiles and backups. Do not delete credentials/state on ordinary uninstall.

Pin exact Rust toolchain/Cargo.lock/Tailscale1.102.5/baseOCI digests and include
checksums, dependency inventory/SBOM, source bindings, image/artifact immutable
identifiers and verifiable provenance. No mutable tags as release configuration.
No Python persistent/runtime image, privileged Docker, host network, Docker socket
inside gateway or persistent SYS_ADMIN. Review actual manifest seccomp/LSM/caps
rather than assuming container inspect is applied to host-launched children.
Secrets and provider archives must never enter build context, artifacts, reports
or command arguments. Fixed audited installation/diagnostic subprocesses only;
steady-state guard/worker uses native APIs.

Service ordering must establish independent host quarantine and client guards
before protected workloads/usable paths and retain protection on ordinary stop.
Host guard watchdog90s independent of worker health45s, bounded startup/shutdown
and cgroup kill/accounting. Runit must have actual equivalent enforcement/failure
behavior rather than copied unit text or an unsupported guarantee. Persistent
allocation/namespace ownership reconciles after crash/reboot; ambiguous foreign
resources remain quarantined. Uninstall removes only exact verified owned
resources, separate explicit client-policy removal. No foreign nft flushes.

Owned-guest tests: clean install, interrupted update, reboot, startup failure,
watchdog, guard freeze/crash/OOM, Docker restart, quarantine ownership recovery,
compatible release+state rollback and ownership-scoped uninstall. Capture must be
operational on an actual observation interface BEFORE protected traffic starts
for boot claims. Ordinary service enablement is insufficient proof. Preserve
failed attempts/source and artifacts. ARM64 compile is not ARM64 runtime; mark
unavailable platform acceptance NOT_RUN and block corresponding certification.

Produce exact agent preflight/migration/validation/recovery/rollback instructions,
explicit systemd and runit procedures, config reference and one/five/mixed
examples, compatibility matrix, redacted migration/validation evidence and
unsupported/unverified environments. Commands must match actually implemented
CLI; incomplete checks cannot imply applicability/readiness. Do not publish the
release/migration guide as supported until mandatory traffic/performance/canary
gates pass. Candidate docs and artifacts can be prepared locally and clearly
labeled unreleased/unverified.

Focused tests/fmt/clippy/static architecture builds, explicit owned-file commits,
self-review and task-13-report.md with exact commands/results/artifact hashes,
unsafe/capability/subprocess inventory, platform limits and unperformed gates.
Independent review before performance/canary gate reliance.
