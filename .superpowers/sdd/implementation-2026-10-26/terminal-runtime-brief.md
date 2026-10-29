# Continue all nine findings: terminal expiry and operational runtime

The user explicitly requested an implementation subagent for all nine findings,
then testing and an independent verification subagent. This is a sequential fresh
context handoff, not a new task or scope reduction. You are the sole implementation
writer. Do not spawn agents. Work only in existing /DATA/AppData/vprouter-rust-v2,
branch rust/v2, preserving all unfinished changes. Do not reset/clean or mutate the
real Git index/HEAD, publish, or touch production Python/runtime/credentials.
Root exclusively runs privileged or credential-bearing local VM actions; you run
ordinary tests, static builds, self-review and prepare exact frozen artifacts.

Read constraints.md and docs/rust-v2/implementation-2026-10-26.md for all nine
requirements; docs/rust-v2/IMPLEMENTATION.md is binding. Read the FINAL section
'Handoff checkpoint 2752df5894' in runtime-bridge-report.md first (it supersedes
old pending/unfrozen text). Original task-8c through task-15 briefs describe later
runtime/client/migration/service/performance requirements. Do not substitute
schemas, mocks, stage-only APIs or component proofs for operational functionality.

## Exact handoff and controller results

Previous sole writer implement_runtime_bridge completed NEEDS_CONTEXT and paused.
Current source2752df5894c57d24e24dddac014920f127164dae, candidate
 target/continuation-20261026T143406Z/candidate.json,108 verified inputs.
217 ordinary tests, clippy-Dwarnings, static musl x86/ARM and exact four-role
context/init consistency PASS. Both immutable contexts copied candidate-local.
No public runtime start enabled. Runtime is Starting-only, no periodic Engine or
independent executor integration yet. Original zeroization/shared-host/health
foundation remains; all remaining nine-area work stays active.

Fresh controller results AFTER previous report handoff:
- Frozen native netfilter kernel acceptance PASS:22 emitted cases including
  terminal deny stale-generation refusal and preservation through fresh ordinary
  release in Data/Transport/Host. Evidence candidate/netfilter-native/native-run.json.
- Debian actual50 PASS all17 component cases on2752df; exact new directory
  task8b2-59296, candidate/debian-x86_64-actual/{controller,directory-binding}.json.
- ARM actual49 now passes all14 pre-monitor cases. Moving both daemon audits to
  the existing5s placement gate fixed the initial2s exchange: audits1247/1255ms
  occur BEFORE worker executes. No hashes/checks/timeouts removed.
- ARM monitor authenticates, publishes Starting, then dies before final stopACK:
  LAB_SENDER_FAILURE verify_initial_pidfd_alive / placement_failed. Predicted
  two full daemon audits around Offline/publisher completion each~1.2s exceed
  the monitor frame's existing2s ACK. Do not silently extend2s, remove audits or
  treat heartbeat as new verification. Diagnose/fix through valid protocol
  scheduling or independently proved immutable executable authority.
- Root bounded read-only witness proves ARM49 exact root-owned cache exists:
  /run/vprouter-v2/transportlab5322/one/health.json, snapshotv2 seq1 STARTING,
  no evidence, exact synthetic binding. Thus publication completed before sender
  death. Witness candidate/debian-arm64-actual/host-cache-witness.json. Do not read
  actual daemon state/credentials or invent a full monitor PASS.
- Prior66d8 checkpoint Debian45 and Arch46 PASS17 each,6captures/112records each,
  0forbidden markers/0kernel drops. Four live post-pin drift tests prove immediate
  observational Offline before repair. Actual Starting bridge and publisher
  confinement/freeze proven, not operational Ready/client/release acceptance.
- Independent reviewer PASS/no findings for66d8 proc-superblock fix, forced-order
  regression, exact Arch attrs and retained Session earliest handshake expiry.
- Root reproduced old proc race deterministically: ordinary readonly remount in
  child changes shared proc superblock and parent attr/current write-open EROFS;
  per-mount bind remount preserves parent write-open and child readonly. Fix
  retains private mount+MS_BIND|MS_REMOUNT|RO|NOSUID|NODEV|NOEXEC. Test pipe forces
  child readonly BEFORE PID1 LSM transition. Historical36 precise errno unknown.
- Void actual48 NOT_RUN product: VM default iptables-legacy lacks required nft
  ip/filter/FORWARD. Root is preparing only that new identity-free guest's nft
  backend; cgroupfs/runit adapter remains OPEN. Exact real cgroup shape is
  target/platform-lab/void-x86_64/cgroup-shape.json:0::/docker/<id>,root cgroup2,
  root:root0755, exact PID membership, PID1runit. Do not widen systemd path match.

## Next concrete implementation

Follow the ordered six steps in final runtime-bridge-report.md. First resolve or
precisely contain ARM publication ACK timing with focused RED/GREEN regressions.
Then build three fixed native terminal-expiry executors, durable ownership and
surviving-child lock barriers, authenticated original-evidence/sequence leases,
independent earliest BOOTTIME expiry and separate90s liveness watchdog. Ready
requires all three actual executor registrations/ACKs and sufficient remaining
lease; no generic callback/bool may mint authority. Terminal deny survives
ordinary release and must fence stale in-flight work. SIGSTOP delivery is not
proof an in-kernel transaction drained. Existing BOOTTIME timerfd component is
not suspend/blocked-kernel containment certification. Retain deadline failures
and no positive claim without actual exact deny verification.

New native APIs: netfilter::BootDeadline, TerminalQuarantine and Socket terminal
mode. They open separate socket/timer in exact namespace, bind one absolute
BOOTTIME deadline, one-shot CAS+exact table verify, no deletion API. No executor
process or lifecycle journal exists yet. Do not duplicate a guard's active socket
or construct ordinary Actuator with assumed phase. Retain deployment flock in
surviving child or equivalent proved barrier; Rc alone is not a durable lease.
No generation reuse while surviving writers can mutate. Add bounded recovery
without deleting foreign resources or generic prefix cleanup.

Then integrate actual periodic monitor Engine/provider/structural channel,
quarantine-first recovery, advertisement/approval and CLI lifecycle. Root alone
runs fixed source-bound isolated actual guard/worker/crash/freeze/provider/native
stall tests and coordinates existing approved gateway/client state. Preserve
cadence5s, eligible retry1s with fresh checks, handshake<180, health<45 and separate
90s watchdog. Continue multi/direct/client/migration/platform/release/performance
requirements after the real single-exit gate; they are not dropped. No production
activation, remote installation SSH, identity cloning or new provider devices.

## Artifacts and continuation contract

Write your report as terminal-runtime-report.md in this plan directory, update
nine-area status and send useful milestone/test requests to root. Root's ledger
is progress.md. Preserve every failure and source/artifact binding. Use existing
alternate-index target/implementation-20261026-build.py (includes new crate files
and four fixed program roles); do not use old driver that only stages tracked
files. Notify root before refresh/copy contexts; root copies immutable contexts.
Ordinary checks as appropriate, fmt, clippy, staticboth. You cannot report native
PASS without root results. Do not settle for another preparatory API milestone:
continue operational integration until context actually requires handoff; then
persist exact APIs/next steps and return NEEDS_CONTEXT, never overall DONE.
