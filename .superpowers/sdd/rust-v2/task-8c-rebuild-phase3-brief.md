# Task 8c rebuild phase 3 brief — fresh baseline, gaps, run409 reservation, preflight

Date: 2026-11-04. Workspace `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD `6ca0073` (pushed to `fork/rust/v2`).

## Context you must read first

- `.superpowers/sdd/rust-v2/task-8c-lab-rebuild-assessment.md` — sections 3, 5 (steps 7–10). This phase is steps 7 and 8 only.
- `.superpowers/sdd/rust-v2/task-8c-rebuild-phase2-report.md`, `-phase2-fixes2-report.md`, `-phase2-fixes2-review.md` (PASS; I1 BLOCKED_BY_HOST — now resolved, see below).
- `.superpowers/sdd/rust-v2/task-8c-driver-cost-brief.md` (what run 409 measures) and `task-8c-bootstrap408-diagnosis.md`.
- `.superpowers/sdd/rust-v2/progress.md` tail.
- Controllers: `target/platform-lab/run-frozen-host-projection.py`, `target/author-host-baseline-after-bootstrap-v2.py`, `target/platform-lab/run-frozen-secret-bootstrap.py`, `target/verify-continuation-candidate.py`, `target/copy-frozen-contexts.py`, `target/inspect-secret-bootstrap-failure.py`, and whatever they import or read. Prior baseline reviews: `task-8c-diagnostic-baseline-review.md`, `task-8c-next-baseline-helper-review.md`, `task-8c-next-baseline-v2-review.md`.

## Host status (new since phase 2)

debdev crashes were diagnosed: earlier ones were L0-host OOM kills; the 2026-11-04 ones were debdev kernel panics "Host injected async #PF in kernel mode". The user added `no-kvmapf` to debdev's kernel cmdline. The lab guest was restarted at 2026-11-04 14:43:10Z with `tools/rust-v2-lab/restart-clean-debian.py` (record `target/platform-lab/debian-clean-x86_64/process-restart-20261104T144310.427977Z.json`, QEMU PID 2147340, `-accel kvm -cpu host`), guest boot_id `e14efc10-050b-41b0-89d8-1e946725098c`, `systemd-detect-virt`=kvm, and passed a 15-minute soak (30/30 strict-SSH checks, no debdev reboot). The guest is live now. Do not stop or restart it unless it is dead; if it dies, use only `tools/rust-v2-lab/restart-clean-debian.py` and record it.

## Decisions already made by the user (do not re-ask)

- Original continuity is lost (target/ deleted 2026-11-03; runs 398–408 raw records and original guest identities are gone). Use the **fresh-lab route**: a documented, independently reviewable fresh baseline for the new guest. Never fabricate or "recreate" historical evidence, run files, IDs or resources.
- Autonomous execution; no approval stops. Run 409 itself is NOT part of this phase — stop after the preflight gates.

## Tasks

A. **Guest admission (read-only checks, record evidence).** Strict pinned SSH handshake; boot_id; `systemctl --failed`; root mount; Docker service health; the phase-2 pinned images present with the expected digests; marker/permissions; kernel/cgroup2/systemd/NIC shape and RAM/disk headroom as the assessment step 3 lists. Record into a fresh evidence directory under `target/rebuild-phase3/`.

B. **Historical-evidence-gap disposition.** Write `.superpowers/sdd/rust-v2/task-8c-historical-gap-disposition.md`: each historical gate the old flow required (raw-reader replay over 398–408, recovered408 preservation, original live-resource/selector checks, original identities) → status (NOT_RUN / UNRECOVERABLE / replaced-by X) with the exact reason and what replaces it. No gate is silently dropped.

C. **Fresh baseline.** Design and author a new independently reviewable baseline + provenance record for the new guest, following assessment step 7's fresh-lab route: keep namespace identity, all structural fields and the original custody/deadline checks; do not substitute live-observed fields into an old template; do not create extra links to hit an old count; label old-vs-new environment differences explicitly. Then run the read-only `python3 target/platform-lab/run-frozen-host-projection.py CANDIDATE debian-clean-x86_64` (CANDIDATE = `target/candidates/rebuild-20261103T231415Z`) and compare against the new baseline. If the existing authoring helper cannot serve the fresh route, add a narrow new helper (versioned under `tools/rust-v2-lab/`), don't edit historical controller bytes in place without updating `tools/rust-v2-lab/source-manifest.json` consistently.

D. **Run 409 numbering/reservation.** Determine how `run-frozen-secret-bootstrap.py` derives the run number and what it requires of prior runs. Add an explicit, exclusive, auditable run-409 reservation (no fake placeholder run files for 398–408). Keep the label `bootstrap409-driver-cost`.

E. **Preflight gates.** `python3 target/copy-frozen-contexts.py CANDIDATE`, `python3 target/verify-continuation-candidate.py CANDIDATE`, the frozen inspection/clock/filter preflights, selector absence, retained file permissions, one-shot budget. Determine and record the exact command for run 409 and confirm every gate it checks will pass — but **do not execute run 409** or any command that mutates guest network/namespaces/nft/containers.

## Constraints

- No production changes; no real Mullvad/Tailscale credentials or enrollment; no sudo on debdev; no network/firewall/Docker/Tailscale changes on debdev itself. Guest-side read-only inspection is fine; guest mutations only where a preflight controller inherently needs them and they are non-destructive (record them).
- Never weaken strict SSH: keep `-F /dev/null`, `GlobalKnownHostsFile=/dev/null`, `IdentitiesOnly=yes`, `IdentityAgent=none`, dedicated key `target/lab-state/id_ed25519`, pinned `UserKnownHostsFile`, `StrictHostKeyChecking=yes` on every new SSH/SCP call.
- Cargo only if Rust source changes (it should not); if needed use `-j 4`. Musl cross env is in memory note `musl-cross-toolchain` (zig wrappers in `~/.local/share/zig-cross/bin`).
- No git commit/push; the orchestrator commits. Leave tracked changes unstaged. Reports in `.superpowers/sdd/rust-v2/` are gitignored (the orchestrator force-adds).
- Keep secrets/private keys out of reports and Git.

## Deliverable

`.superpowers/sdd/rust-v2/task-8c-rebuild-phase3-report.md`: what was done per task A–E, exact commands with exit codes, evidence paths, files changed (tracked and ignored), anything NOT_RUN and why, open risks, and the exact run-409 command plus the gates confirmed for it. Be factual; no claim without evidence.
