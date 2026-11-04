# Task 8c rebuild phase 2 independent re-review

Overall: **FAIL for the complete current handoff.** The preserved phase 2 process/disk binding was observable initially, but another outer-host boot discontinuity occurred during this review and the guest is now absent. The trust-path alias is repaired; phase 3 SSH isolation is still incomplete. Candidate/static checks, optimized-Python refusal and bounded Rust checks pass. No phase 3 execution or release readiness is approved.

Reviewed 2026-11-04 CET, branch `rust/v2`, HEAD `d62ab24e172badb9245fa5f20d71f15930731839`. Read the prior review, both staged reports, full staged tool diff, original/restart process records, preserved restart evidence, verifier sources and restored controller trust inventories. Evidence and exact helper sources: `target/rebuild-phase2-rereview/`. No tracked/staged files were edited, no Git writes/subagents/outer-host sudo occurred. The requested report is the only documentation output. Scratch files and Cargo outputs are ignored. No guest restart/stop/reboot, QMP connection, offline disk repair, inventory acquisition, projection, baseline authoring, Bootstrap or experiment was performed. The sole SSH attempt used the dedicated key/pin and strict checking; it failed before any guest command executed.

## Per-finding disposition

| Finding | Disposition | Evidence and limit |
| --- | --- | --- |
| I1 | **Not closed for current handoff; restart provenance checks pass initially** | PID91972/start45353, exact original argv, preserved process record/archive, base SHA512 and two-image backing chain passed before the next host reboot. Current process/listener absent; strict SSH exit255. Fresh guest identity, health and Docker checks are NOT_RUN. |
| I2 | **Path defect fixed; full isolation requirement remains open** | Clean-Debian alias resolves to the sole pin and controllers select port22036/dedicated key. Unchanged controller options still consult SSH configuration/global trust; Bootstrap/scp allow agent identities. |
| M1 | **Mitigated and honestly documented; historical proof unavailable** | Post-hoc snapshot exists and explicitly disclaims retrospective equality. No matching pre-phase snapshot or firewall dump; historical host preservation remains unproven. |
| M2 | **Closed** | Both changed tools reject `-O`, `-OO` and `PYTHONOPTIMIZE=1` with exit1 before argument handling/state reads/subprocess work. Normal inventory invocation without SSH options exits2. |

## Important findings

**I1 — Guest availability was lost again across an outer-host reboot.** `.superpowers/sdd/rust-v2/task-8c-rebuild-phase2-fixes-report.md:3` and its final handoff describe the guest as running. At approximately **2026-11-03 23:38:14 UTC**, `check.py` verified live PID91972, start45353, controller boot `256891be-cd7c-4f1e-8531-8c1d334d6bf5`, and byte-exact argv equality with original `process.json`. The base hash/backing chain, archive equality and controller checks completed, and receipts survived. The initial execution session subsequently became unavailable. At **23:40:53 UTC**, strict SSH exited255 with `Connection refused`. Fresh `/proc/sys/kernel/random/boot_id` is **4655f8b2-34c3-4889-b664-59bad073355f**; `ps -p 91972` exits1 and loopback22036 has no listener. `journalctl --list-boots` shows the former host boot's last visible entry at **00:38:31 CET**, followed by the new boot beginning **00:39:48 CET**. These are visible journal boundaries, not the exact crash instant or root-cause diagnosis. This is another outer-host discontinuity, not evidence of an autonomous guest failure. No reboot or lifecycle command was sent by this reviewer; the transition preceded the Cargo checks launched at about23:40:53 UTC. The review did perform lightweight reads/hash checks before the transition; the crash mechanism is unknown.

Failure scenario: phase 3 cannot freshly admit or inspect this guest. Its previous SSH/boot/Docker/health observations cannot be treated as current after this additional abrupt loss. Do not silently relaunch or reuse old boot/namespace identities. Recovery requires the appropriate lifecycle authority and preservation of the disk and accumulated records. This report does not authorize it.

**I2 — The alias fixes missing trust input, but controller SSH is not confined to the single pin/key.** `target/platform-lab/run-frozen-host-projection.py:180-183` supplies the dedicated key, explicit pin, strict checking and IdentitiesOnly, but no `-F /dev/null` or `GlobalKnownHostsFile=/dev/null`. `target/platform-lab/run-frozen-secret-bootstrap.py:36` and `:44` similarly omit configuration/global-trust isolation, and also omit `IdentitiesOnly=yes` for SSH and SCP. Fresh `ssh -G` using each controller's exact options confirms:

- Projection: `identitiesonly yes`; Bootstrap: **`identitiesonly no`**.
- Both: dedicated `identityfile`, explicit clean-Debian `userknownhostsfile`, port22036 and `stricthostkeychecking true`.
- Both: **`globalknownhostsfile /etc/ssh/ssh_known_hosts /etc/ssh/ssh_known_hosts2`**. No effective ProxyCommand/ProxyJump/HostKeyAlias was observed.

The explicit UserKnownHostsFile excludes default personal `~/.ssh/known_hosts` in these observed configurations. That narrower requirement passes. However, configuration is still read, global trust remains eligible, and Bootstrap can offer unrelated agent identities. Failure scenario: ambient configuration/global pins or agent authentication influence a controller connection, so the supplied lab pin and dedicated key are not its exclusive authority. This is inherited controller behavior, not weakened logic introduced by the symlink fix; the fixes report acknowledges the global-default caveat at its I2 discussion. Its unqualified opening claim that I2 is resolved is therefore too broad for this review's single-pin/key requirement and the prior review's “inherit no unrelated SSH configuration” prerequisite. Before phase 3, review a confined invocation for both SSH and SCP, or a fully bound equivalent isolation mechanism; do not execute historical controllers simply to test wiring.

## Critical and new findings

**Critical: none found. New standalone Important/Minor defects introduced by the fixes: none found.** I1 is a recurrence across another outer-host boot; I2 is an incompletely resolved inherited integration requirement. M1 remains an explicitly retained evidence limitation. The maintained restart helper's cooperative-lock and narrow fixed-state scope are documented, not generalized lifecycle qualification.

## I1 provenance and restart-helper safety

Fresh initial observations establish the preserved phase 2 disk/process binding:

- Original `process.json` SHA256 **2f8c1d8107eea43ea4d36f5bfbb99b12825a5ac807e1438586dc346c72c95200**, equal to the archived original and restart record binding. Original PID3289270 is historical; new PID91972/start45353 was checked directly, with exact original argv and controller boot binding.
- Base SHA512 **16e0965312c56feb331049d45d2b1b5778f3f942a33d4300eedbb97527707f2bea87c0006f3e4cc7a25fadbff739c4e235a51fb9bcd1b66fd554f7f8e80ba45c**, freshly hashed twice and matched against original process metadata/checksum manifest.
- Read-only `qemu-img info -U --output=json --backing-chain` returned exactly the existing qcow2 overlay and this base, with no further backing image. `-U` permits shared read-only metadata access while QEMU held the disk; no check/repair/convert operation ran. This is chain metadata verification, not an exhaustive consistency check of a live image.
- Verified pin SHA256 **38b48e872f7876cb68b02b9c823107ccc2969c5d63642b9b74561803688e139e**, host fingerprint **SHA256:rk1TQu4ncW/fxBUmvcFu/M3BbOKpqofLaf5glJ86WvA**. Static serial-console provenance and pin bytes were independently rechecked. This is fresh verification of the retained pin, **not** a successful current guest handshake.
- Dedicated public-key fingerprint **SHA256:oA3DjOssKJEmB7MTEn2s8GyySbx6sS3HG04Ns736nXg**, matching retained generation/provisioning evidence. Private key and pin modes0600. Private key bytes and personal SSH files were not read.

`tools/rust-v2-lab/restart-clean-debian.py:19-107` refuses optimized Python before opening its lock, requires existing state and the recorded fixed endpoint/paths, takes nonblocking exclusive flock, scans process cmdlines and fails closed on PermissionError, and probes bindability of loopback22036. It verifies the full immutable base hash, checksum entry and exact backing chain before archiving/launch. It repeats its live-process/port checks immediately before archive creation. It copies original process/serial/QEMU logs and moves stale PID/socket files aside before launching exact recorded argv; a separate exclusive restart record retains old-record hash/archive/boot bindings. It never creates a disk, seed or key, and does not overwrite original `process.json`.

Pure extraction of `refuse_live` with synthetic process/socket inputs independently confirmed duplicate-state and EADDRINUSE refusal without executing helper top-level code, creating restart locks, or launching QEMU. Static review confirms fail-closed unreadable-process handling. These extracted gate checks do not prove arbitrary concurrent launcher safety: a noncooperating process can race the cooperative lock/port probe, as already documented in the fixes report. The helper was not rerun, including after the guest became absent.

Retained fixes evidence reports guest machine-id `6efc72f8c01340cc91fec545d32e0082`, boot `ba98deeb-881c-44b4-b6a7-1d0cc8cff4a8`, root ext4 journal recovery/clean fsck, root mounted read/write, zero failed units and both phase 2 Docker images. It also preserves FAT dirty-bit repair, unclean journal replacement and the systemd-ssh-generator error. These are historical post-first-crash observations, not exhaustive storage health and not current health after the second abrupt loss. **Fresh strict SSH, current guest fingerprint/machine identity, guest filesystem health, marker and Docker image presence remain NOT_RUN.** The prepared `guest.py` contains only reads and was never executed remotely.

## Trust wiring and unchanged controllers

`target/platform-lab/debian-clean-x86_64/known_hosts -> ../../lab-state/known_hosts` resolves to `/DATA/vprouter-lab/lab-state/known_hosts`; no independent pin copy exists at that alias. `target/lab-state/id_ed25519` resolves to the dedicated durable lab key. The clean-Debian choices in projection and Bootstrap select22036 and the alias; original22032 and other platform22033–22035 mappings were not retargeted. Those inactive historical endpoints are not admitted for execution by this repair.

Re-ran both trust-reference inventories across runtime platform controllers and the restored archive sources; raw matches are `restored-trust-inventory.stdout` and `all-restored-trust-inventory.stdout`. The fixes' retained 115-file platform-controller input-hash map was independently rehashed unchanged. No controller logic was weakened. The broader inventory contains historical endpoints, launchers, fixtures and unrelated platform trust files; its presence is not proof that all historical controllers are safe or aimed at this new guest. The single-pin alias conclusion applies to controllers choosing the clean-Debian alias/shared lab pin, with the SSH isolation caveat above.

## M1 and M2

`target/lab-state/host-snapshot-20261103T233034Z.txt:1` explicitly says **“POST-HOC current outer-host reference; not historical phase 2 preservation proof.”** It retains command arguments/output/exits for address/routes, Docker inventory, failed services, boot history and memory. The fixes report accurately says it was taken before the restart and supplies no retrospective before/after equality or firewall dump. This satisfies the requested honest post-hoc reference; M1's historical limitation cannot be repaired retrospectively. It is also no longer a snapshot of the present host boot.

`tools/pinned-tailscale-program-inventory.py:18-19` refuses optimized execution before argparse/index/SSH work. The same early guard exists in restart helper:19-20. Fresh `-O`, `-OO`, and environment-driven optimization all exit1 with `optimized_python_refused`; inventory's ordinary incomplete invocation exits2. AST comparison confirms that removing only this guard from the current inventory tool restores the exact previously executed/candidate tool. Thus M2 is fixed without rewriting historical receipt hashes or frozen candidate provenance. No acquisition was rerun.

## Candidate verification and exact commands/results

The stock verifier sources were reviewed before execution. `target/verify-continuation-candidate.py:80-84` exclusively writes/chmods `root-verification.json` and may create retained contexts at58-62. `target/verify-frozen-inspection-preflight.py:23-24,51-54,77-81,93-96` creates output/executable/validator/result files and executes the payload. They have no read-only mode and their result destinations already exist. **Both requested stock reruns are NOT_RUN under the conditional read-only instruction.** No evidence was renamed, overwritten, or bypassed to force them through.

Instead, `static-check.py` independently re-executed their static source/payload/context assertions and validated retained execution evidence, without executing the payload. It verified203 archived/current build inputs, source binding, both static ELF payloads, both seven-file contexts, six candidate Rust program copies, all18 candidate report-table file sizes/hashes, six pinned public inventory files, exact pin/serial/key provenance and retained mechanics results. Candidate `1b65709a1189a5fff0fb62c47877e349d4f4f0c4` still has parent HEAD d62ab24; only the historical inventory implementation differs from HEAD. Its tool matches acquisition bytes; current staged inventory differs only by the optimization guard. Source/archive/payload/context hashes remain those in the prior review and candidate metadata. This is retained-evidence/static proof, not fresh payload/guest/runtime acceptance.

Commands ran from `/DATA/AppData/vprouter-rust-v2`; stdout/stderr and ledger are under `target/rebuild-phase2-rereview/`.

| Exact command or retained nested command source | Result |
| --- | --- |
| `git status --short`; `git rev-parse HEAD`; `git diff --cached --binary`; `git diff --cached --check` | HEAD as above; original four staged paths preserved; whitespace exit0 |
| `python3 target/rebuild-phase2-rereview/check.py` | Completed assertions and identity.json before reboot; outer execution session completion unavailable after host reboot. Each nested command exit retained in commands.jsonl. |
| `target/lab-tools/root/usr/bin/qemu-img info -U --output=json --backing-chain /DATA/AppData/vprouter-rust-v2/target/platform-lab/debian-clean-x86_64/guest.qcow2` with recorded QEMU library/module environment | exit0; two-image chain, base binding passed; exact absolute executable/env in check.py |
| `ssh-keygen -lf /DATA/AppData/vprouter-rust-v2/target/platform-lab/debian-clean-x86_64/known_hosts`; corresponding lab public-key command | exit0, fingerprints above |
| `ssh -G` with projection/Bootstrap exact options | exit0; effective configs retained, I2 above |
| `python3 -O <tool>`; `python3 -OO <tool>`; `PYTHONOPTIMIZE=1 python3 <tool>` for both changed tools | each exit1, early optimized refusal |
| `python3 tools/pinned-tailscale-program-inventory.py amd64` | exit2, all three explicit SSH options required |
| `python3 target/rebuild-phase2-rereview/run-guest.py` | exit1 after SSH255, connection refused; remote payload never ran |
| `python3 target/rebuild-phase2-rereview/static-check.py > target/rebuild-phase2-rereview/static-check.stdout 2> target/rebuild-phase2-rereview/static-check.stderr` | exit0 on final synchronous rerun to resolve missing initial wrapper status; all assertions passed, static-verification.json retained, stderr empty |
| `python3 tools/verify-frozen-build-inputs.py <candidate source> 1b65709a1189a5fff0fb62c47877e349d4f4f0c4` | nested static-check call exit0;203 inputs, exact candidate binding |
| `python3 target/rebuild-phase2-rereview/cargo-checks.py` | sequential commands below; explicit exit receipts retained |
| `cargo test --workspace --locked -j 8` | exit0;425 passed,2 ignored,0 failed across27 result groups |
| `cargo fmt --all --check` | exit0 |
| `cargo clippy --workspace --all-targets --locked -j 8 -- -D warnings` | exit0 |
| `python3 target/rebuild-phase2-rereview/final-check.py` | exit0; optimization/env/default-option checks, extracted refusal gates, fresh base rehash, inventories and tracked/index/HEAD equality |
| `journalctl --list-boots --no-pager -q`; `ps -p 91972 -o pid,stat,lstart,comm`; `ss -ltnp 'sport = :22036'` | journal exit0 confirms additional host boot; ps exit1; ss exit0 with no listener |

The exact attempted SSH argv is retained in `commands.jsonl` and constructed in `run-guest.py`: `ssh -F /dev/null -i /DATA/vprouter-lab/lab-state/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o UserKnownHostsFile=/DATA/vprouter-lab/lab-state/known_hosts -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o UpdateHostKeys=no -o ConnectTimeout=5 -p 22036 vprouterlab@127.0.0.1 'sudo -n python3 -I -'`. Guest sudo was part of the prepared read-only command; it never executed. No outer-host sudo was used.

Scratch receipt correction: check.py initially reused the variable `digest` in its final controller loop, causing identity.json's base_sha512 field to contain the final controller digest despite the earlier correct base assertion. final-check.py independently rehashed the base and corrected this scratch field with an explicit note. Raw script/ledger evidence is retained; no phase artifact or source claim was changed.

## Phase 3 must provide

1. Resolve repeated outer-host instability sufficiently to retain the next admitted guest/evidence session. Under separately appropriate lifecycle authority, recover the preserved phase2 disk without recreating identities or discarding prior records. Bind the actual new process/start/argv/controller boot, strict pin, guest boot/machine identity, current filesystem recovery, Docker images/cgroup/kernel/WAN and protected marker. Do not reuse this now-dead process/boot binding or infer crash cause from journal boundaries.
2. Complete I2 for every SSH/SCP invocation selected for phase3: fixed clean-Debian endpoint, dedicated identity only, sole verified pin and no inherited unrelated configuration/global trust. Preserve controller originals and bind reviewed new controller/wrapper bytes. Refresh effective config and a strict read-only connection immediately before any authorized mutation. Do not retarget historical platform endpoints.
3. Independently review a fresh baseline provenance/authoring procedure. The restored `target/author-host-baseline-after-bootstrap-v2.py` expects lost original408 evidence; it cannot be used as a fresh-baseline constructor by fabricating inputs. Independently declare intended guest structure, then reconcile exact candidate-bound frozen projection with full namespace/link/address/route/rule equality and original deadlines/custody. Projection itself writes retained guest/controller files and requires that scope.
4. Retain a reviewed current baseline/template/reconciliation chain with protected modes and honest historical discontinuity. Explicitly dispose of unavailable raw405/407/408 reader replay and original-resource continuity. Projection cannot authorize its own baseline; synthetic checks do not establish a causal speedup over408.
5. Implement and independently review exclusive **pre-execution run409 reservation/high-water mark**, collision prevention and discontinuity metadata. Bootstrap still chooses the first missing number after execution at53-56. Do not manufacture dummy historical records or relabel runs afterward.
6. Immediately before mutation, freshly verify root-owned0700 lab directory/root0600 single-link marker, all eight fixed selectors absent, initial namespaces/WAN, candidate/source/payload/static contexts and required capacity/kernel/cgroup/systemd/Docker capabilities. Requalify exact clock/filter/privileged instrumentation prerequisites; retained unprivileged mechanics are insufficient.
7. Complete independent current source/candidate/reader/baseline review, evidence-gap disposition and any historical workflow checkpoint/publication verification under its own authorization, then obtain the separately required one-shot synthetic experiment scope/budget. Preserve original2s windows, negatives and identity/custody checks; no timing/policy relaxation or unchanged retry.
8. Establish durable raw-result/directory-binding/private-resource/failure custody before execution. Preserve and inspect any failure before identity-bound selector archival under its own reviewed authority. No enrollment/provider profiles, ARM runtime, operational acceptance or release-readiness claim follows from this review; `release_ready=false` remains.

Overall: FAIL for current phase2 handoff; no new standalone fix defect found.
I1: initially bound preserved guest, then lost across another outer-host reboot; fresh guest checks blocked.
I2: alias fixed; exclusive SSH/SCP pin/key/config isolation still required.
M1: honest post-hoc reference only; M2 closed; candidate/static checks and 425 tests/fmt/strict Clippy pass.
Next: stabilize host and recover/admit guest, isolate controllers, review fresh baseline and reserve409 before any one shot.
