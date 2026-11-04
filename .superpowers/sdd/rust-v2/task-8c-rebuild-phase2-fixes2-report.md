# Task 8c rebuild phase 2 second fixes report

**I2 fixed and statically verified; I1 remains blocked by another outer-host boot discontinuity. The guest is down at handoff.** The requested restart launched the same preserved guest, but debdev rebooted again before a fresh authenticated health check. No further launch was attempted after observing the new discontinuity. No claim of a running guest or fresh Docker/filesystem qualification is made.

Workspace `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD `d62ab24e172badb9245fa5f20d71f15930731839`. Work date 2026-11-04 CET. Read the complete phase2 re-review (I1/I2), preceding fixes report and maintained restart helper. Applied verification-before-completion. Memory lookup supplied preservation/evidence conventions only; findings below use current files and observations. No subagents, Cargo, Rust changes, outer-host sudo, Git commit/push/ref-write command, host network/firewall/Docker/Tailscale changes, Bootstrap/run409, baseline authoring or projection execution.

## I2: SSH/SCP confinement and archive integrity

Added only missing connection options, identically before the existing `-i` in each direct or shared option list: `-F /dev/null`, `-o GlobalKnownHostsFile=/dev/null`, `-o IdentitiesOnly=yes`, `-o IdentityAgent=none`. Existing `-i`, port, `UserKnownHostsFile`, `StrictHostKeyChecking=yes`, timeouts, endpoint and remote operations remain unchanged. Existing matching options were retained without duplication. AST comparison after removing only these confinement option pairs proves no other controller logic changed.

Changed 159 existing controllers: 147 restored controllers and 12 maintained `tools/*.py` implementations. All 147 restored controllers have byte-identical updated copies at their existing `tools/rust-v2-lab/target/...` archive paths and updated size/SHA256 manifest entries. The 12 maintained tools have no pre-existing copy in this historical target-only archive; they remain maintained at their original tracked paths. The new maintained status helper is also outside that archive, like the restart helper. All **293** manifest entries were checked for source/archive equality, length and SHA256, including unchanged entries. No candidate source tarball, frozen input manifest, historical acquisition receipt or program inventory bytes were rewritten. Future phase-3 bindings must record the new controller hashes.

All clean-Debian configurations still select port22036 and the original dedicated key. Clean-Debian pin aliases resolve to `/DATA/vprouter-lab/lab-state/known_hosts`; its SHA256 is `38b48e872f7876cb68b02b9c823107ccc2969c5d63642b9b74561803688e139e`. `ssh-keygen -lf` freshly verifies retained pin fingerprint **SHA256:rk1TQu4ncW/fxBUmvcFu/M3BbOKpqofLaf5glJ86WvA**. This verifies stored trust bytes; successful current guest handshake is unavailable. Historical22032–22035 ports and their explicit trust files are preserved, not retargeted or admitted for execution.

### Exact argv / effective configuration proof

`python3 target/rebuild-phase2-fixes2/prove.py` passed: **457 connection-option proofs across 160 controllers**, zero remaining failures, including both SCP transfers in secret Bootstrap and the new status helper. It parses AST option expressions without importing/executing controllers and runs only `ssh -G`. Each source site/platform variant, exact connection argv passed to `ssh -G`, complete stdout/stderr and effective configuration is retained in `target/rebuild-phase2-fixes2/ssh-G-proofs.json`; the evaluator and assumptions are in `prove.py`. Remote command/payload expressions and transfer operands are deliberately excluded because they do not affect SSH configuration. For SCP, its exact connection options are translated to SSH spelling (`-P` to `-p`, transfer-only `-q` omitted); SCP has no `-G` option. No SCP transfer was made. Historical cloud-probe row-driven ports are instantiated as the documented arch22033/arm22034 options; no historical guest process is claimed current.

Every proof has `-F /dev/null` in argv, effective `globalknownhostsfile /dev/null`, `identitiesonly yes`, `identityagent none`, `stricthostkeychecking true`, exactly one dedicated `identityfile`, exactly one explicit `userknownhostsfile`, and no ProxyCommand/ProxyJump. Thus user/system SSH config, default/global trust and agent identities cannot influence these connections. `ssh -G` does not prove reachability or host authenticity.

Representative exact connection argv for the phase-3 projection (remote payload omitted):

```text
ssh -G -F /dev/null -o GlobalKnownHostsFile=/dev/null -o IdentityAgent=none -i target/lab-state/id_ed25519 -p22036 -o IdentitiesOnly=yes -o UserKnownHostsFile=target/platform-lab/debian-clean-x86_64/known_hosts -o StrictHostKeyChecking=yes -o ConnectTimeout=5 vprouterlab@127.0.0.1
```

For Bootstrap SSH and SCP the same four confinement options precede the retained key; SSH retains `-p22036` and ConnectTimeout5, SCP retains `-P22036`. Exact per-site proof argv, including existing option ordering, is in the JSON above. Inventory uses its explicit resolved `--ssh-key`/`--ssh-known-hosts` arguments and22036; its previous optimization refusal and remote behavior remain intact.

### Controller invocation inventory

`rg --no-ignore -n '\b(ssh|scp)\b' target tools -g '*.py' -g '*.sh'` was narrowed to source/controllers rather than binary/private state and evidence; raw results are `target/rebuild-phase2-fixes2/rg-ssh-scp.txt`. Manifest enumeration separately covers all293 restored Python sources. The table lists every actual SSH/SCP argv site found in restored controllers and maintained tools; counts include transfer sites sharing `opts`. All listed existing sites were confined, including historical ones, so a later wrapper cannot reintroduce ambient SSH authority.

Path labels: **YES** = identified phase-3/run409 core or its Bootstrap failure/custody helpers; **support** = new optional liveness gate; **other** = other/historical procedure, not required to execute the requested projection/secret-Bootstrap path. Clean-capable marks scripts that also offer22036; it is not permission to run them. Full original expressions/line numbers are in `controller-inventory.json`; current lines and proof variants are in `ssh-G-proofs.json`.

| Controller | Phase3/run409 | Clean-capable | SSH/SCP sites; effective ports |
| --- | --- | --- | --- |
| `target/actual-program-inspect-monitor.py` | other | no | 65; 22032 |
| `target/archive-failed-owner-nonce.py` | other | yes | 37; 22032,22033,22034,22036 |
| `target/archive-secret-assembly-selectors.py` | other | yes | 39; 22032,22033,22034,22036 |
| `target/archive-secret-attachment-selectors.py` | other | yes | 22; 22032,22033,22034,22036 |
| `target/archive-secret-bootstrap-selectors.py` | YES | yes | 39; 22032,22033,22034,22036 |
| `target/archive-secret-host-addition-selectors.py` | other | yes | 39; 22032,22033,22034,22036 |
| `target/archive-secret-movement-selectors.py` | other | yes | 22; 22032,22033,22034,22036 |
| `target/archive-secret-preparation-selectors.py` | other | yes | 32; 22032,22033,22034,22036 |
| `target/archive-secret-producer-binding-selectors.py` | other | yes | 39; 22032,22033,22034,22036 |
| `target/archive-secret-provision-selectors.py` | other | yes | 22; 22032,22033,22034,22036 |
| `target/archive-secret-quarantine-selectors.py` | other | yes | 39; 22032,22033,22034,22036 |
| `target/collect-terminal-witness.py` | other | yes | 18; 22032,22034,22036 |
| `target/drain-exact-terminal-guard.py` | other | yes | 23; 22032,22034,22036 |
| `target/drain-expiry-drop-failure-guards.py` | other | yes | 43; 22032,22033,22034,22036 |
| `target/drain-retirement-failure-guard.py` | other | yes | 47; 22032,22033,22034,22036 |
| `target/drain-stopped-owner-guards.py` | other | yes | 31; 22032,22033,22034,22036 |
| `target/inspect-bootstrap-route-failure.py` | other | yes | 26; 22034,22036 |
| `target/inspect-expiry-drop-deny.py` | other | yes | 20; 22032,22034,22036 |
| `target/inspect-expiry-drop-failure.py` | other | yes | 61; 22032,22033,22034,22036 |
| `target/inspect-failed-owner-terminal.py` | other | yes | 31; 22032,22034,22036 |
| `target/inspect-secret-assembly-failure.py` | other | yes | 49; 22032,22033,22034,22036 |
| `target/inspect-secret-attachment-failure.py` | other | yes | 43; 22032,22033,22034,22036 |
| `target/inspect-secret-bootstrap-failure.py` | YES | yes | 52; 22032,22033,22034,22036 |
| `target/inspect-secret-host-addition-failure.py` | other | yes | 52; 22032,22033,22034,22036 |
| `target/inspect-secret-movement-failure.py` | other | yes | 43; 22032,22033,22034,22036 |
| `target/inspect-secret-preparation-failure.py` | other | yes | 39; 22032,22033,22034,22036 |
| `target/inspect-secret-producer-binding-failure.py` | other | yes | 49; 22032,22033,22034,22036 |
| `target/inspect-secret-provision-failure.py` | other | yes | 43; 22032,22033,22034,22036 |
| `target/inspect-secret-quarantine-failure.py` | other | yes | 49; 22032,22033,22034,22036 |
| `target/inspect-stopped-owner-guards.py` | other | yes | 17; 22032,22033,22034,22036 |
| `target/inspect-terminal-deny.py` | other | yes | 20; 22032,22034,22036 |
| `target/platform-lab/arm-trace-summary.py` | other | no | 39; 22034 |
| `target/platform-lab/capture-approved-kernel.py` | other | no | 3; 22032 |
| `target/platform-lab/capture-void-cgroup.py` | other | no | 3,4; 22035 |
| `target/platform-lab/probe-cloud-guests.py` | other | no | 26; 22033,22034 |
| `target/platform-lab/probe-original-scope-pin-order.py` | other | yes | 173; 22032,22033,22034,22036 |
| `target/platform-lab/probe-original-scope-pin.py` | other | yes | 165; 22032,22033,22034,22036 |
| `target/platform-lab/probe-proc-remount.py` | other | no | 19; 22032 |
| `target/platform-lab/reboot-void-after-backend.py` | other | no | 3; 22035 |
| `target/platform-lab/run-actual-arch-x86_64.py` | other | no | 247,251; 22033 |
| `target/platform-lab/run-actual-debian-arm64.py` | other | no | 247,251; 22034 |
| `target/platform-lab/run-actual-monitor-arch-x86_64.py` | other | no | 258,262; 22033 |
| `target/platform-lab/run-actual-monitor-debian-arm64-tcg120.py` | other | no | 258,262; 22034 |
| `target/platform-lab/run-actual-monitor-debian-arm64.py` | other | no | 258,262; 22034 |
| `target/platform-lab/run-actual-monitor-debian-clean-x86_64.py` | other | yes | 258,262; 22036 |
| `target/platform-lab/run-actual-monitor-debian-x86_64.py` | other | no | 258,262; 22032 |
| `target/platform-lab/run-actual-monitor-void-x86_64.py` | other | no | 258,262; 22035 |
| `target/platform-lab/run-actual-void-x86_64.py` | other | no | 247,251; 22035 |
| `target/platform-lab/run-explicit-ifindex-probe.py` | other | yes | 7; 22033,22034,22036 |
| `target/platform-lab/run-frozen-host-projection.py` | YES | yes | 180; 22032,22033,22034,22036 |
| `target/platform-lab/run-frozen-platform-actual.py` | other | yes | 20; 22032,22033,22034,22035,22036 |
| `target/platform-lab/run-frozen-secret-assembly.py` | other | yes | 23,32,33; 22032,22033,22034,22036 |
| `target/platform-lab/run-frozen-secret-attachment.py` | other | yes | 22,31,32; 22032,22033,22034,22036 |
| `target/platform-lab/run-frozen-secret-bootstrap.py` | YES | yes | 36,45,46; 22032,22033,22034,22036 |
| `target/platform-lab/run-frozen-secret-host-addition.py` | other | yes | 36,45,46; 22032,22033,22034,22036 |
| `target/platform-lab/run-frozen-secret-movement.py` | other | yes | 22,31,32; 22032,22033,22034,22036 |
| `target/platform-lab/run-frozen-secret-preparation.py` | other | yes | 19,28; 22032,22033,22034,22036 |
| `target/platform-lab/run-frozen-secret-producer-binding.py` | other | yes | 23,32,33; 22032,22033,22034,22036 |
| `target/platform-lab/run-frozen-secret-provision.py` | other | yes | 22,31,32; 22032,22033,22034,22036 |
| `target/platform-lab/run-frozen-secret-quarantine.py` | other | yes | 23,32,33; 22032,22033,22034,22036 |
| `target/platform-lab/run-native-inspection-preflight.py` | other | no | 87; 22032,22033,22034,22035 |
| `target/platform-lab/run-nsfs-fd-mount-probe.py` | other | yes | 5; 22033,22034,22036 |
| `target/platform-lab/run-operational-profile-debian-arm64.py` | other | no | 249,253; 22034 |
| `target/platform-lab/run-operational-profile-debian.py` | other | no | 249,253; 22032 |
| `target/platform-lab/run-owner-admission-birth-failure-debian-arm64.py` | other | no | 289,293; 22034 |
| `target/platform-lab/run-owner-admission-birth-failure-debian-clean.py` | other | yes | 289,293; 22036 |
| `target/platform-lab/run-owner-admission-birth-failure-debian.py` | other | no | 289,293; 22032 |
| `target/platform-lab/run-owner-admission-stop-arch.py` | other | no | 288,292; 22033 |
| `target/platform-lab/run-owner-admission-stop-debian-arm64.py` | other | no | 288,292; 22034 |
| `target/platform-lab/run-owner-admission-stop-debian-clean.py` | other | yes | 288,292; 22036 |
| `target/platform-lab/run-owner-admission-stop-debian.py` | other | no | 288,292; 22032 |
| `target/platform-lab/run-owner-bootstrap-debian-arm64.py` | other | no | 279,283; 22034 |
| `target/platform-lab/run-owner-bootstrap-debian-clean.py` | other | yes | 279,283; 22036 |
| `target/platform-lab/run-owner-bootstrap-debian.py` | other | no | 279,283; 22032 |
| `target/platform-lab/run-owner-deployment-debian-arm64.py` | other | no | 278,282; 22034 |
| `target/platform-lab/run-owner-deployment-debian-clean.py` | other | yes | 278,282; 22036 |
| `target/platform-lab/run-owner-deployment-debian.py` | other | no | 278,282; 22032 |
| `target/platform-lab/run-owner-domains-arch.py` | other | no | 278,282; 22033 |
| `target/platform-lab/run-owner-domains-debian-arm64.py` | other | no | 278,282; 22034 |
| `target/platform-lab/run-owner-domains-debian-clean.py` | other | yes | 278,282; 22036 |
| `target/platform-lab/run-owner-domains-debian.py` | other | no | 278,282; 22032 |
| `target/platform-lab/run-owner-expiry-drop-arch.py` | other | no | 289,293; 22033 |
| `target/platform-lab/run-owner-expiry-drop-debian-arm64.py` | other | no | 289,293; 22034 |
| `target/platform-lab/run-owner-expiry-drop-debian-clean.py` | other | yes | 289,293; 22036 |
| `target/platform-lab/run-owner-expiry-drop-debian.py` | other | no | 289,293; 22032 |
| `target/platform-lab/run-owner-expiry-partial-drop-arch.py` | other | no | 289,293; 22033 |
| `target/platform-lab/run-owner-expiry-partial-drop-debian-arm64.py` | other | no | 289,293; 22034 |
| `target/platform-lab/run-owner-expiry-partial-drop-debian-clean.py` | other | yes | 289,293; 22036 |
| `target/platform-lab/run-owner-expiry-partial-drop-debian.py` | other | no | 289,293; 22032 |
| `target/platform-lab/run-owner-expiry-placement-debian-arm64.py` | other | no | 288,292; 22034 |
| `target/platform-lab/run-owner-expiry-placement-debian-clean.py` | other | yes | 288,292; 22036 |
| `target/platform-lab/run-owner-expiry-placement-debian.py` | other | no | 288,292; 22032 |
| `target/platform-lab/run-owner-host-audit-debian-arm64.py` | other | no | 279,283; 22034 |
| `target/platform-lab/run-owner-host-audit-debian-clean.py` | other | yes | 279,283; 22036 |
| `target/platform-lab/run-owner-host-audit-debian.py` | other | no | 279,283; 22032 |
| `target/platform-lab/run-owner-inspection-held-arch.py` | other | no | 288,292; 22033 |
| `target/platform-lab/run-owner-inspection-held-debian-arm64.py` | other | no | 288,292; 22034 |
| `target/platform-lab/run-owner-inspection-held-debian-clean.py` | other | yes | 288,292; 22036 |
| `target/platform-lab/run-owner-inspection-held-debian.py` | other | no | 288,292; 22032 |
| `target/platform-lab/run-owner-inspection-setup-debian-arm64.py` | other | no | 288,292; 22034 |
| `target/platform-lab/run-owner-inspection-setup-debian-clean.py` | other | yes | 288,292; 22036 |
| `target/platform-lab/run-owner-inspection-setup-debian.py` | other | no | 288,292; 22032 |
| `target/platform-lab/run-owner-journal-debian-arm64.py` | other | no | 278,282; 22034 |
| `target/platform-lab/run-owner-journal-debian-clean.py` | other | yes | 278,282; 22036 |
| `target/platform-lab/run-owner-journal-debian.py` | other | no | 278,282; 22032 |
| `target/platform-lab/run-owner-process-inspection-debian-arm64.py` | other | no | 288,292; 22034 |
| `target/platform-lab/run-owner-process-inspection-debian-clean.py` | other | yes | 288,292; 22036 |
| `target/platform-lab/run-owner-process-inspection-debian.py` | other | no | 288,292; 22032 |
| `target/platform-lab/run-owner-retained-drop-debian-arm64.py` | other | no | 289,293; 22034 |
| `target/platform-lab/run-owner-retained-drop-debian-clean.py` | other | yes | 289,293; 22036 |
| `target/platform-lab/run-owner-retained-drop-debian.py` | other | no | 289,293; 22032 |
| `target/platform-lab/run-owner-retirement-arch.py` | other | no | 325,329; 22033 |
| `target/platform-lab/run-owner-retirement-debian-arm64.py` | other | no | 325,329; 22034 |
| `target/platform-lab/run-owner-retirement-debian-clean.py` | other | yes | 325,329; 22036 |
| `target/platform-lab/run-owner-retirement-debian.py` | other | no | 325,329; 22032 |
| `target/platform-lab/run-owner-retirement-global-stop-arch.py` | other | no | 325,329; 22033 |
| `target/platform-lab/run-owner-retirement-global-stop-debian-arm64.py` | other | no | 325,329; 22034 |
| `target/platform-lab/run-owner-retirement-global-stop-debian-clean.py` | other | yes | 325,329; 22036 |
| `target/platform-lab/run-owner-retirement-global-stop-debian.py` | other | no | 325,329; 22032 |
| `target/platform-lab/run-owner-retirement-host-span-arch.py` | other | no | 325,329; 22033 |
| `target/platform-lab/run-owner-retirement-host-span-debian-arm64.py` | other | no | 325,329; 22034 |
| `target/platform-lab/run-owner-retirement-host-span-debian-clean.py` | other | yes | 325,329; 22036 |
| `target/platform-lab/run-owner-retirement-host-span-debian.py` | other | no | 325,329; 22032 |
| `target/platform-lab/run-owner-retirement-queued-failure-arch.py` | other | no | 325,329; 22033 |
| `target/platform-lab/run-owner-retirement-queued-failure-debian-arm64.py` | other | no | 325,329; 22034 |
| `target/platform-lab/run-owner-retirement-queued-failure-debian-clean.py` | other | yes | 325,329; 22036 |
| `target/platform-lab/run-owner-retirement-queued-failure-debian.py` | other | no | 325,329; 22032 |
| `target/platform-lab/run-owner-retirement-writer-failure-arch.py` | other | no | 325,329; 22033 |
| `target/platform-lab/run-owner-retirement-writer-failure-debian-arm64.py` | other | no | 325,329; 22034 |
| `target/platform-lab/run-owner-retirement-writer-failure-debian-clean.py` | other | yes | 325,329; 22036 |
| `target/platform-lab/run-owner-retirement-writer-failure-debian.py` | other | no | 325,329; 22032 |
| `target/platform-lab/run-owner-terminal-death-debian-clean.py` | other | yes | 288,292; 22036 |
| `target/platform-lab/run-owner-terminal-death-debian.py` | other | no | 288,292; 22032 |
| `target/platform-lab/run-owner-terminal-debian-clean.py` | other | yes | 288,292; 22036 |
| `target/platform-lab/run-owner-terminal-debian.py` | other | no | 288,292; 22032 |
| `target/platform-lab/run-owner-watchdog-debian-clean.py` | other | yes | 278,282; 22036 |
| `target/platform-lab/run-owner-watchdog-debian.py` | other | no | 278,282; 22032 |
| `target/platform-lab/run-peerpidfd-probe.py` | other | yes | 5; 22033,22034,22036 |
| `target/platform-lab/run-terminal-death-debian.py` | other | no | 249,253; 22032 |
| `target/platform-lab/run-terminal-executor-debian.py` | other | no | 249,253; 22032 |
| `target/platform-lab/smoke-readonly-accounting.py` | other | no | 211; 22032 |
| `target/platform-lab/switch-void-nft-backend.py` | other | no | 2; 22035 |
| `target/run-netfilter-native-frozen.py` | other | no | 8,9; 22032 |
| `target/run-shared-lease-regression-frozen.py` | other | no | 16,18; 22032 |
| `target/run-transport-regression-frozen-original.py` | other | no | 19; 22032 |
| `target/run-transport-regression-frozen.py` | other | no | 31,25,26,27; 22032 |
| `target/run-transport-regression.py` | other | no | 17; 22032 |
| `tools/actual-program-inspect.py` | other | no | 65; 22032 |
| `tools/actual-program-oracle.py` | other | no | 258,262; 22032 |
| `tools/actual-program-path-trace-summary.py` | other | no | 45; 22032 |
| `tools/actual-program-peer-trace-summary.py` | other | no | 46; 22032 |
| `tools/actual-program-stderr-classify.py` | other | no | 64; 22032 |
| `tools/actual-program-trace-summary.py` | other | no | 39; 22032 |
| `tools/guarded-transport-capture-oracle.py` | other | no | 86; 22032 |
| `tools/guarded-transport-cleanup-wan.py` | other | no | 48; 22032 |
| `tools/guarded-transport-oracle.py` | other | no | 41,44; 22032 |
| `tools/pinned-tailscale-program-inventory.py` | YES | no | 42; 22036 |
| `tools/producer-placement-oracle.py` | other | no | 36,74; 22032 |
| `tools/rust-v2-lab/lab-guest-status.py` | support | yes | 40; 22036 |
| `tools/worker-localapi-parser-oracle.py` | other | no | 8,10; 22032 |

Additional grep matches are indirect wrappers (`collect-component-evidence.py`, which rewrites dedicated maintained collectors for its selected lab port/pin, and controller-generation/orchestration helpers), guest payload text, provisioning `ssh-keyscan`, archived duplicates and retained review/evidence scripts. Wrappers are covered through their now-confined source controllers. Provisioning/scan tools were not run or changed; scans do not replace the single verified clean-guest pin. Earlier review/evidence scripts remain historical receipts and are not on the phase-3/run409 execution path. None was used to bypass strict trust.

### Old/new hashes and archive updates

Manifest SHA256: `9a30c580290ce3fad2c142c335675283a4f5c25f749b33c2c42a2f0e6f5053e9` → `995f054229cf4f59f04746398f10297e32fad574031d9350e606948d9b00d93b`. Unchanged entry order/paths and293-entry coverage retained. For every `target/...` row below, the matching updated archive path is `tools/rust-v2-lab/` followed by that exact source path. Maintained `tools/...` rows have no historical archive counterpart. Exact old/new sizes/hashes and archive paths are also in `changes.json`.

| Source | Bytes old → new | SHA256 old → new |
| --- | --- | --- |
| `target/actual-program-inspect-monitor.py` | 5148 → 5235 | `ef0fbff5ed39d047f0c58836650e9e4d7e26192ae431c06b46df7a6490e79c61` → `f58375240d9801b3f52750656d49bb714b6b62b1de872150ee7ceff65971babf` |
| `target/archive-failed-owner-nonce.py` | 3526 → 3641 | `dce2021197569b1e5017d9569b23ed1297273e497a5ad8db3433794b8e417733` → `8680a9185be299ead372b134d9b339508a88e60fb3a0774665df8280866af2d3` |
| `target/archive-secret-assembly-selectors.py` | 5107 → 5222 | `2fe99f5315e658ce74e852de038a51084bc19b3f4cf55c720a1efd76cfbebc75` → `34ac4ce71be019b7f480e4448dc8d1e1a97f2bdfd1e052dbbe78bbbff515897f` |
| `target/archive-secret-attachment-selectors.py` | 3693 → 3808 | `d37ea8faa4a14442ca333adb222e2eb2655df02def3758aa2acd764088a3f2ad` → `fdaec2cd72bc83c264680bc5bb0175e5c7e56273f9e5381b503c9be29de4156d` |
| `target/archive-secret-bootstrap-selectors.py` | 5242 → 5357 | `e36a8e8c122663d9adc36ab8827f2923bd01147601efd248823f9cff0c62b9c0` → `e43e8cef7fa3f16347056ec61cb141cd62d7c105659ed699b8c5fc58771117a1` |
| `target/archive-secret-host-addition-selectors.py` | 5155 → 5270 | `f473caab188be2d3a026168ea0fafcba2b965863eb4947c640d56fcef9a6aa4e` → `8ea1df30aed81a1d90e1762e1bf4f727fb27eaee83dd8149cfaf0ebe5f7b9424` |
| `target/archive-secret-movement-selectors.py` | 3795 → 3910 | `2ae64029e16384693979607de30ec6bc24a9b06bc8d6f33d96fdd13c132ea7f3` → `e16595a2fc552f54e0ede9492fb34eab264c26410ad24d06989ba95276a905ee` |
| `target/archive-secret-preparation-selectors.py` | 3765 → 3880 | `05a4a773acc8e0a5a913d844e231b73140e151a6f6fc07cb617bf95a7f0c57a7` → `06acaed9a4f31aa5c7f12412ef84a8353f6ecbc8e5e0b799610497c39ed88c3d` |
| `target/archive-secret-producer-binding-selectors.py` | 5145 → 5260 | `39503c1f6bfe6794ca42df0994c83df32c47a17f96e0297d6dcd26137a068feb` → `a0563722d8d52e0ec5957de2323b0c08b3dba4c1d0d7305642d2e631bd4db3df` |
| `target/archive-secret-provision-selectors.py` | 3801 → 3916 | `b94890a4b08224499d5e757cacdc6e33f1a4b51840519d65132d9b01cab69b19` → `eaef300ea28e039bad251a7eb25eef362acb08ac13fcab2f6d1075dfcc9f60cc` |
| `target/archive-secret-quarantine-selectors.py` | 5109 → 5224 | `b45724f3693ba2830d9762c599f446dec137890b67092b6da2329ff7f2f0186f` → `b036af8126eb405295f596e0a3c649faa265062d1a2ba6e9316edf126281a52a` |
| `target/collect-terminal-witness.py` | 2804 → 2919 | `7da567bdac277fab84dbb43f205c6e1d61bc4922c1a696b2ea6e8e65694c4a0a` → `ca20b3132965d49073956acd256b838e466833eb46ff0b1e7014759048be7d3c` |
| `target/drain-exact-terminal-guard.py` | 3629 → 3744 | `dcf5bc63d75784348640ed8b630a1dadfc321c7b5a5c06d68561a1bae4104091` → `e9f90376929897995e2534e485a6050fb1b4356036561f9740efa6b128c6ae73` |
| `target/drain-expiry-drop-failure-guards.py` | 4627 → 4742 | `3c831fc881dd5815f79f9546a2e9955c5a99b0a036697e4987fdcfc4ef10c11f` → `5578cd28deabc63babf1af618443438ddf9905226ff1015a3cfa3998d121d8f3` |
| `target/drain-retirement-failure-guard.py` | 5097 → 5212 | `b78dc76293f9e62f43605bad3f4b7a62f5a8295e55ae13dc21ae2b94664aceb4` → `6247470e57379ad80478b7f70f197b2816add4f5625ee31995c9f3928dcdc855` |
| `target/drain-stopped-owner-guards.py` | 3203 → 3318 | `f8aa8ac4ac9c6f035bafeb3798b419dd0da6fcd8c0fbf4787bec292b479821db` → `b57114b5f2c924f5d0b59cd7dc36c6baa41b77b9bde2e8778a93bd8e7607f882` |
| `target/inspect-bootstrap-route-failure.py` | 2683 → 2798 | `af1c575e91bcfb050fd3de1a8d33d355337993fbb293bbbb403d3bf6a22b9a94` → `225065f356aa766cf69ff35a7abe94a9dc13c3e75eacaec78a80124183921291` |
| `target/inspect-expiry-drop-deny.py` | 2837 → 2952 | `d3ef148ef3f91236297ed0cc469f9df05b4b6941ef9c46b2a4c6416f0cda68b1` → `5b246f9952b4fd49ad18fd29e24eb9f04f3161cfe8019f3bae8e398a0275ea51` |
| `target/inspect-expiry-drop-failure.py` | 4522 → 4637 | `49e9306f9db66034a84af9750e655924e40856fcaf50f347675b85d3defed9e5` → `d3edf741537f320aa2af5f65e3ab00105806c6552d5e0ce9955401e93f5310f7` |
| `target/inspect-failed-owner-terminal.py` | 3673 → 3788 | `f4349a2bdede51e740bc7a8c02f5483716d9d38775f1182b136fd048180cc092` → `084e2ad039dea50fe14cfeb20a4c7b5ad346d623b047b625d316f836d91ef8ce` |
| `target/inspect-secret-assembly-failure.py` | 6166 → 6281 | `45d3c92d85954fb188213b8bdd8d19bcd30c449563c206ebda06259554a40cef` → `90f6a586fe81dab75176a740a0d9f0d6de9f3bb02821d3a16402c4474837d8e4` |
| `target/inspect-secret-attachment-failure.py` | 5174 → 5289 | `7e08d1d241bac87e40c129b25b9cd53b892ec6f5349f214c0d63623336cfddd5` → `d57fe8a1d5286c0b66d8b2be5edf4acc431b7e051eb6929ded027e93564baa1d` |
| `target/inspect-secret-bootstrap-failure.py` | 6736 → 6851 | `64537a9d291d7e4df754e7cd194ac3bd6375f61ed538da0b1d8023e0cd879411` → `9a79e98c0e606566db6107538572afc77eee37eeafc8f547dae8f5c343b24608` |
| `target/inspect-secret-host-addition-failure.py` | 6645 → 6760 | `73f7080c4074417dd2d5b39367656d905f6a56a745c651b1cc817fa37a6f190b` → `0bfd84e00853c8f94083e8a60fb56261b5b4f434109ba38f7927d0a430ae95e5` |
| `target/inspect-secret-movement-failure.py` | 5278 → 5393 | `799177dddaa016099335a3279417d9932ff68aeed6a509f97f0e6c6b9e5b8859` → `147d1f1cd81453c5af57f6004d10b754c24978eb2111926499302c6855f7b507` |
| `target/inspect-secret-preparation-failure.py` | 4079 → 4194 | `c24f5a1551c0085065ef17b8faba409d6f213086e08a5523c7bc784e675e05d3` → `e0f09a58fb827fc41cc1a6a2a19971d926c05996d412b100286eec11f02ba901` |
| `target/inspect-secret-producer-binding-failure.py` | 6196 → 6311 | `197f929fad3245eb9fc5473fab59f30c30dc45e1ce7ccd9f6ab3e1f2e4a47775` → `25d569efef36bc7974a3695c8f14b64ec212016275be1b3c6335bb11079a5574` |
| `target/inspect-secret-provision-failure.py` | 5283 → 5398 | `7e6e5aef3fd3e0a4573cbbda5b124c426c39a1dedcf2a791eb69831a26420eb1` → `0c863cd739a000c0b17f47118fc7a7d043cb4104855ec4e1a002968f2afaf4fb` |
| `target/inspect-secret-quarantine-failure.py` | 6166 → 6281 | `653881a070ef5f407d39696fc68f12ce98e785b614403a8df4732b61fc132a28` → `7c2b5c7f7e5048fa5e60e94979e93aed6d76496b2c41c3c42868701ba28e3853` |
| `target/inspect-stopped-owner-guards.py` | 1832 → 1947 | `ecf472ebcad27bf7f735f5d906adb48b129229d906ff3318ecc3745e10c562b6` → `4b84e617db1de3778b3a629cf73eb912b4a2e8f21c384d3ae2c9435624d6cbaa` |
| `target/inspect-terminal-deny.py` | 2756 → 2871 | `3d39d76c7492f2150d465dc722ab3a54122cc03fdf464c9519f16e94945f2692` → `2a96f056f689fd0654adc4924e587683e3a809956b6604dfa5d7218ff1bb94a4` |
| `target/platform-lab/arm-trace-summary.py` | 2787 → 2874 | `c9e9459198c152e5214e1d1c778ce0b9970a48184e7bf629a136379dd8ef8a1b` → `033a8bdfc34b1b92a7cccd628b9fd341bb20105d36b1581fe831c60fdc09db62` |
| `target/platform-lab/capture-approved-kernel.py` | 6532 → 6619 | `78cf6ef75573b537e9d4653276969c4240459cb750626e57b31e217f84bc599d` → `92f6414fb34ae430d24bc0596f785043481abc1a0924c7534ade14f74cf5ddd0` |
| `target/platform-lab/capture-void-cgroup.py` | 3543 → 3658 | `fd304d77e308e593d963a223f4a005e4700ae654e30254f1ac4f61bf46a45334` → `6014fe7ac2c1a25d344b47ed51462486ab4939cfc52889de7e6b6034f80cf60d` |
| `target/platform-lab/probe-cloud-guests.py` | 2310 → 2397 | `901daaa5a245f6803937c876d18a5abdd308bfaf6c6d11f1ed0722d46764f181` → `58bfd75a79e1ff8c3a0f0b27e117517058363fb20f8f7a72608f09d01f37cd90` |
| `target/platform-lab/probe-original-scope-pin-order.py` | 15180 → 15267 | `7ce33e7572f4cc1e337037b1dea9bba704fc907d299e785f2b5a64607eb54641` → `2b7138e32511a38784f87095a536897609f892b164e3354fc4ec2476d656beba` |
| `target/platform-lab/probe-original-scope-pin.py` | 13913 → 14000 | `37471b05df2ef9ea0d830375f3c41b4d0549f1443f98ef0fe7c497bf3d0e9984` → `808caa45d2cff809b1346e8c17985348942c347bb96da0eeae8ac6d6ea52c3de` |
| `target/platform-lab/probe-proc-remount.py` | 2087 → 2202 | `9bbf0e5d1d2bec9f6aeef38af3b579f0291484e9807ce074282854530b49b63e` → `419e935fa49a68d810b7d4884b9c3cd6399a079bf4d73cb2bbb0ad0ab00a40bc` |
| `target/platform-lab/reboot-void-after-backend.py` | 2460 → 2575 | `cb411ec9b815722301b11130ae413c71fd4702b052df68e7d0dd497992e23df1` → `0d463b4346036c2ab2af5c180adf24d05a22accc5221ea5cead06caee1225a3d` |
| `target/platform-lab/run-actual-arch-x86_64.py` | 17842 → 17929 | `e70e7ef71d1ed756f0fe3a1ed391763f5c016a5adc17273adf61972f7e54358d` → `353b87508e24183e1c0098d55ce718c974fb97fd5ade68acb194d60b90b7215c` |
| `target/platform-lab/run-actual-debian-arm64.py` | 17844 → 17931 | `d6ecdfa1df4cf44d3ce7d182702dc7e26ee6d85e895a73ecbe35b1be3b6f14f0` → `ed9a88e9bb4bdd5893db85158bf52c39c4c70cfbaf5530b606b64da15c52eafb` |
| `target/platform-lab/run-actual-monitor-arch-x86_64.py` | 18926 → 19013 | `919d2ac3fa2c06a0501b80e902009e1e7f4ba6273e27abda9e820440010faee7` → `31f40aeda54b9fe1c3277aa13104a1831df3429fc8c65e27f4824a8ccfb2dcdd` |
| `target/platform-lab/run-actual-monitor-debian-arm64-tcg120.py` | 19011 → 19098 | `0ede5e1648bbf54b42f12cd3480cb8180612c6fd667efa6a5008f94245ea0dc7` → `948d98f4cdd8d47a1989fc0bbeb9c48a55abb571de0a53a6181616816086d162` |
| `target/platform-lab/run-actual-monitor-debian-arm64.py` | 18928 → 19015 | `12504704b82b56a354a069d90388a39f06fc4ccbdf88505eb8982ff8373c1a62` → `7aeedbff5894dff892db758edcbda19e69b6ea0f686d4cbbb7b0edea3efc7135` |
| `target/platform-lab/run-actual-monitor-debian-clean-x86_64.py` | 18817 → 18904 | `dd8a9d456770208f0ca7d7f0b25158311426fb198df669d88740088866ce7f97` → `df51e2448bd59f2cf56d33d7ac19d32f91d896b5c04a29780beb5718a7d0cff1` |
| `target/platform-lab/run-actual-monitor-debian-x86_64.py` | 18770 → 18857 | `979556480909e7b2fdad76febefa41627a1a43436d78736cc5afb7f3e1cbce3c` → `255b4abb95240b024c409ce6ffa63a77fce7bd9bd6e9f2f3dc41d312c9fcd0fb` |
| `target/platform-lab/run-actual-monitor-void-x86_64.py` | 18926 → 19013 | `bea11b07c1d38a4d5927ec7104dc23eef787340ca79ccee0832993bf798e88f5` → `0d156f386d542024d0daacedcb8c70f3b9b64098b0af9db19e4c8fc42a7b9a08` |
| `target/platform-lab/run-actual-void-x86_64.py` | 17842 → 17929 | `07b8a8b536e72c224c3e3709a3cf5d29e350454f5d445bc4f05e587ccf6f54e3` → `e8d8412798b65eb80a634077b7c9f7abf94081b538fdd153e246c8c47427fa27` |
| `target/platform-lab/run-explicit-ifindex-probe.py` | 1906 → 2021 | `c2f0755ea1aaa508315011bf4cc0e875964aa145116f97b448d4f1df42f320f9` → `bac5a40573018bda227dda9654dc95a5c252296d133534856c5f1d40fce9767d` |
| `target/platform-lab/run-frozen-host-projection.py` | 12332 → 12419 | `687ed1627b0a5f1efac5d1a90be283ac185d8e5710b46646c57e2e7b6a9e08af` → `e6720caed0fa2918c1479a35753dea9c51c0997a84e38ce123142f028e3500ea` |
| `target/platform-lab/run-frozen-platform-actual.py` | 6537 → 6652 | `ddda15eef0e164bdbbed9ba366d0a2e5433c504ddfab2eeb42bbd7a0ecf7945d` → `bdc4c962155003db3488fc5ec0c88c58d9d06ea00645e1606deaa1679bfe3683` |
| `target/platform-lab/run-frozen-secret-assembly.py` | 7601 → 7831 | `de9804a89b5ee019c2602c1274410cf88f1cf3ddf7a13330ddd29511a8420b23` → `0cd53a6621f82a643832f94c7695dbc7d4f2c245efea1913069d21e706ba07e2` |
| `target/platform-lab/run-frozen-secret-attachment.py` | 7052 → 7282 | `a3bfcc1d102fc6c9611819cd83a86e63aaa7998d29508f3bf03b9a2e8ee1810e` → `b63f50498e0a633679f09c1c01d601a901ba3fafa3704cd57694540d2844a944` |
| `target/platform-lab/run-frozen-secret-bootstrap.py` | 10050 → 10280 | `565ecefd0472be62e53c927bb6875519440fb95b4516749386501c11cc52eb8c` → `6ac51a1879688d1df7d7a1486cd4e51a0b9c8974284958acf82d59f97f9c0ea2` |
| `target/platform-lab/run-frozen-secret-host-addition.py` | 10007 → 10237 | `3472f7a7ed760aa589871daa7ad5faffb64428380eebd7cd1737fb501be9fdfb` → `026587ccf1a91ca494eecc6ba825d2edfccdfd90616bd6841878ddd6967d335c` |
| `target/platform-lab/run-frozen-secret-movement.py` | 7151 → 7381 | `b534ef84893e7d68c6a61360f4e5db09981544108939cb484d409682799b9c61` → `7683fb0cc9de7f4132a493ccfed45ee9e332f8dff56838cb39d71db0175da165` |
| `target/platform-lab/run-frozen-secret-preparation.py` | 6290 → 6520 | `f0c23807c204bef28058f903593c7078b64d1a1f3d1e0ef691775d81d3f5a7af` → `a8d7c60b56ee2709bc3d617f25e15861458a3b343caf2edbe512af0b62678b4d` |
| `target/platform-lab/run-frozen-secret-producer-binding.py` | 7686 → 7916 | `61088600f7e1b405e26608a2b89423875c1f60b8a4408bc743424160741f50c0` → `27e2ed03e3992967cf2d0e2807979a8583b7bd5b96c261d95495563fa3dc3832` |
| `target/platform-lab/run-frozen-secret-provision.py` | 7166 → 7396 | `b68f317831e273324724cb23361f97d2c0a6a6cdbb93ac19d2b8cc9438f76bff` → `a239c8d5e445a542323f60d2761361d811157eb9871400dddf25c57c35380cce` |
| `target/platform-lab/run-frozen-secret-quarantine.py` | 7615 → 7845 | `d2e616ea1dfdc90766bfa66c614ef2fb9542694b64ecf4ddbd2a5cdb5b97926b` → `acf898746f057a101a30154eac2155d46bf999f56a7318f6331cc590786dac44` |
| `target/platform-lab/run-native-inspection-preflight.py` | 6382 → 6497 | `d56d5e11aabd1883aad4b1e58a62bbdc74f8f87e8fec4e9937f048b4770eaf1f` → `3297bd13525ebdb1f0d49f515695f1e282816862e4aef23f8bd8fc0a621c8184` |
| `target/platform-lab/run-nsfs-fd-mount-probe.py` | 1854 → 1969 | `31036fdd1dddf63943cdc68e7027cc4fe8930c16e17a2dd087ddd21ef34838a1` → `0b9199fe2cbe413c8fa9abe33b32ae2c035e92795f0dfc740789ce1eaa6b4bfe` |
| `target/platform-lab/run-operational-profile-debian-arm64.py` | 18187 → 18274 | `b8c6d77f9fe40bd3be498708613d7f1f788bc886aabf7fecad476f1eea9edcea` → `6bd655162a5253a7eb6edd30cfea621dd64511daa5d90755d092836dd2c82e28` |
| `target/platform-lab/run-operational-profile-debian.py` | 17938 → 18025 | `93545db2cdc3534c3e4180928399a96fde85efa13becfa9f33b9da16c8a0a59c` → `1e799c08c8bef8e90ea45f067d9e20b98ccbdb5826c858d415f706a8ecde278a` |
| `target/platform-lab/run-owner-admission-birth-failure-debian-arm64.py` | 20928 → 21015 | `87c90b7800ba3a3280104823327250bd6461d3bde5820f5e22d9c8f964f98bc2` → `3551393f90c906d0b6605acbf9936c43c7bf0f3c081c48593a5964b6cbc38199` |
| `target/platform-lab/run-owner-admission-birth-failure-debian-clean.py` | 20944 → 21031 | `532e687dabeda61bef3e7fc7e2e0b3e2522c2f461a459826701c71107af52645` → `26ad93736f8d6ce4dad96b5edd67ed7e91a9ab02e184bdee900d5162af70fa91` |
| `target/platform-lab/run-owner-admission-birth-failure-debian.py` | 20897 → 20984 | `7737de67ccfcfa7714e733e7bb5fef6a08ab1cafcff087fdf0ab6bcaebe95a5a` → `bb12c910dc1ac677951032f64a61ded480f796f35af928109b702f3351c456db` |
| `target/platform-lab/run-owner-admission-stop-arch.py` | 20703 → 20790 | `6df2a4a2a4a6d2f20c1de42f445a0b84bfd7b10ebf015a076ac10095a9808497` → `27c962bc299086060d1c6ec65056caacbe84576544da306ffa0de34592b3495f` |
| `target/platform-lab/run-owner-admission-stop-debian-arm64.py` | 20716 → 20803 | `46b09f1a65c722a7cbc73c908f9fce99fd850ed60f4382a2c4d13a938ac0d317` → `e0cd32773bd7e1d5ab038b9f937d78ce5733b71cfd6bae978afe3e75d6685c73` |
| `target/platform-lab/run-owner-admission-stop-debian-clean.py` | 20732 → 20819 | `f280e3994a140e3b15b98a87ea5124576408a65a0ad731c129a0d7d207a8e4df` → `077ec8670063f628cb36653609be6fad41bc9d7dc7877493c552f236d7a557fd` |
| `target/platform-lab/run-owner-admission-stop-debian.py` | 20685 → 20772 | `f5c3bc577d5834354ff34ea5d683507a43290d7e052df5918254261e139c9964` → `8d2247821c81d63ce85e662ac986099557732c6d2854d45bb6a28a3563a1e819` |
| `target/platform-lab/run-owner-bootstrap-debian-arm64.py` | 20002 → 20089 | `a59df77c727f88f3ef1d73bbd201e6cca3e2edae644b90085731eeedd82e1860` → `73686e67e2c295d6be5c095c6bb04425c029d1415e159408782da863b99db934` |
| `target/platform-lab/run-owner-bootstrap-debian-clean.py` | 20018 → 20105 | `d9e8d7b94fb94934a5114bdf13969c89abe909226ecfa483d47ac7713319e489` → `dcf35749e53138b8f028dca781d22b646b990f5181300ec56fbd9ecfa2de30a1` |
| `target/platform-lab/run-owner-bootstrap-debian.py` | 19971 → 20058 | `56b3f4c488eec36936a343046023dbe20aec34f044d456036709d285b9fc25ac` → `1a117b6215a930f1a05806bc1c5a3b810f8ada77becf9c9b766db901cf759b99` |
| `target/platform-lab/run-owner-deployment-debian-arm64.py` | 19911 → 19998 | `d9a41007214522e61022a4010707d487885d6801d072a8d6e534637cece03024` → `9c2940f94b6183aac604af351ca9ccc7b96caae4d3ac72408627a956701c19aa` |
| `target/platform-lab/run-owner-deployment-debian-clean.py` | 19927 → 20014 | `9a93285b0932d5cc01f803ae8024e8f6cc8c08b4058081ec9b7606ed84e3293f` → `124255e5e95c227c62160393f44dfc9c98d1356f4c9f91aa5f97431eeb6bca1a` |
| `target/platform-lab/run-owner-deployment-debian.py` | 19880 → 19967 | `824f1d02f963ef3b18dee264c5a5e997029c988071d4550c66d9d76c7a1b67e7` → `549e51337fa32bbae319a82ba94bbfd0b1dd77a5603ddb893edcf113cefb3871` |
| `target/platform-lab/run-owner-domains-arch.py` | 19884 → 19971 | `26e58b85caa351723b3092a69738f656d01bc5a2f3afb8e06918077dcb15efdc` → `0669a0e2a7aa5e589ed28f16222eaeb029352df2cbae686060bfd7915898fa8d` |
| `target/platform-lab/run-owner-domains-debian-arm64.py` | 19902 → 19989 | `51fc63cc85143caa46dba9c41f25c3be6b03cd8c418df96f0d34dea0642f013a` → `fff9bc79aa999d52dac5f4b905a485412a80ed9a4f7238cce9db9f5a99e1cc0b` |
| `target/platform-lab/run-owner-domains-debian-clean.py` | 19918 → 20005 | `40f349dbd215abdf3509cd7337b48854c2effd77f4ec52ad0db2eeef950d9a47` → `0eda6356dac3c02f28cc2a35dfeb9d0141bd6a7bbbab10462267b26f73c4daeb` |
| `target/platform-lab/run-owner-domains-debian.py` | 19871 → 19958 | `97dbb9513e3abe02d264b678319b1791a72d63548149f2b4b5d01648329ae775` → `368bcdd3175415d5281f7f1d3edcf25984334b941387dea3ded262705bdcd1fc` |
| `target/platform-lab/run-owner-expiry-drop-arch.py` | 20867 → 20954 | `62f0f3fddcaf17c217ed7ba32032e4d55064ff37a82037c24254d7085288c6f9` → `58aafd2d4d027bb975709edca3442113b1aba24b511d9397c23f806899fbac7e` |
| `target/platform-lab/run-owner-expiry-drop-debian-arm64.py` | 20880 → 20967 | `3570e3c4d9623442e9a72118ea12a5a493b814e58f0efbcc410ba54a2934fb23` → `1e90d117ebde58a0cdb7cb9830eb9e3d043e1745993db0eda3fd4b729e26e64b` |
| `target/platform-lab/run-owner-expiry-drop-debian-clean.py` | 20896 → 20983 | `f3fa87abefcdcf8033f0cc252960e365393637fac1fcabfcb60e00c98084616c` → `3ca02122bbeba336fd058eb13134813c91c9513c34c4c5ee25accfa13afd8eea` |
| `target/platform-lab/run-owner-expiry-drop-debian.py` | 20849 → 20936 | `6cc9eb23f92a94694f57aca2d8c96b96dad5b46264110fd9db507789a9aa46fe` → `56eb3c40e7b9def044b13f178e305cc147a435ef1dcad5e0ef808ab7666dc032` |
| `target/platform-lab/run-owner-expiry-partial-drop-arch.py` | 20899 → 20986 | `c09fc47bc53a7578f8a952089ca1ebdb79bfbf91556ba1c62cc9c6fbb4f52235` → `7da8df813cec68386f54e62252637344bc1d30f8b7dd255d858309c459fe1879` |
| `target/platform-lab/run-owner-expiry-partial-drop-debian-arm64.py` | 20912 → 20999 | `dbc09efa43e2be4adf6986691045d46b47f354287372831a16e62f1bea0c4463` → `8bfa1f5024739c4cecee74a1b8b42a38624f906043498d482ffdc00e06d22fad` |
| `target/platform-lab/run-owner-expiry-partial-drop-debian-clean.py` | 20928 → 21015 | `e12185bf6189cb094b6dda23f10c6938dcd1aeebb5fc3ff7e86305c1e8ffb9fa` → `db9ae821c544dfcb7fcb4e2512823bd3c0755214778f111eeea5efa65a07e1a8` |
| `target/platform-lab/run-owner-expiry-partial-drop-debian.py` | 20881 → 20968 | `86175633cee5610f46cb9a6e962bc484e520ac18417f6e42ebbfaa6727286089` → `396cf20cd587ac31d5f909be03b1d3824dd2d511e0da31cbef681246bd41fd10` |
| `target/platform-lab/run-owner-expiry-placement-debian-arm64.py` | 20722 → 20809 | `fecf1a6471bf26f34bc460e2aab2d9c00abf966ad34c26f4042102f78cd8f849` → `be7876383113ba8501643e249efa8b505e0d80b07a2abac09c429c1a879d06ea` |
| `target/platform-lab/run-owner-expiry-placement-debian-clean.py` | 20738 → 20825 | `a8b0b69445a60be1ccade4306e8e9c8fe3fdd4228678ddd4c349281eede2dac3` → `f79f237961e82c1ba1bf05a33787390f8bd3fb7d57bee732b59cd2e77fd6a353` |
| `target/platform-lab/run-owner-expiry-placement-debian.py` | 20691 → 20778 | `34a6dc2140d30309d8b9190b9a790b4a330a06c5abff925a1e62b6d119df6481` → `714f7662189e75b95fc2ac22632696a3991e8b116eb878b1c4f19e07b71f103e` |
| `target/platform-lab/run-owner-host-audit-debian-arm64.py` | 20005 → 20092 | `3be07edf971b50d7ad504130a9c250df81466507c29a3721794a5573676989dc` → `0c5369fa08aaa3dd8d81773b0ea848c5f54afb16143e277ef7ec0dac2157a6d2` |
| `target/platform-lab/run-owner-host-audit-debian-clean.py` | 20021 → 20108 | `3abb588e5e83c182877911c4f1a77e859eaf0a68072214aab327abd798524968` → `e87d88308acaea3de2f01c69ebff6d84cb032e216e0d6631499879e124d271c2` |
| `target/platform-lab/run-owner-host-audit-debian.py` | 19974 → 20061 | `b99b04963e46efc590d1bfd84a752f1acd9d6bdff451077ec2d45980c15d4a00` → `cf475fdb5ae725f9de4a338eb144d320a76c88ba7e952d153f3e8dd9a31ffd44` |
| `target/platform-lab/run-owner-inspection-held-arch.py` | 20706 → 20793 | `cbf6ebfaca00d15717ac227a6b50cfb0f6486c72356d756fdd470a804a1de4ce` → `fc39ea769ee3d64ef4d6345211518f57cdce124bb689040a83595f975a372439` |
| `target/platform-lab/run-owner-inspection-held-debian-arm64.py` | 20719 → 20806 | `2dd14c9bccca2d55b378c76aff61106b230c364cf13a307b557518cbdfb46c09` → `19d515990097cedb883582a7c90ca233fcdede95ebd9c67bd41c7bd4edbd0181` |
| `target/platform-lab/run-owner-inspection-held-debian-clean.py` | 20735 → 20822 | `15904637465e2a502d5ae4616d578c59d47e9b586d69f226428d7011fc5ddeb4` → `4d4a192c9ea65348a860d7674de6cff6acf7b76987a3e2d542257eb78d255bbe` |
| `target/platform-lab/run-owner-inspection-held-debian.py` | 20688 → 20775 | `9a8eaecdb36479513421ac8c5a9315b95dbc6afddc6c497063c0fc15786c2248` → `526d8fdd9c1ff36dc09acbd2558c744560b59ec7389c7db36a3060765bf7ea4b` |
| `target/platform-lab/run-owner-inspection-setup-debian-arm64.py` | 20722 → 20809 | `1de03e33a5487ee86dcbf88c2431363425c7a248bbf658bf0e83434183307e12` → `0409e203d847be9253f644c13d19fffbcdf9b2970707c524ef1019dfdc846372` |
| `target/platform-lab/run-owner-inspection-setup-debian-clean.py` | 20738 → 20825 | `5330ef5ebd88ea160a4aa04a7998f01c1a6a41521fdd0b61dc5b83475120e955` → `7c67959c39cf8f0dedc8ddf3ee1dfd3d0b311c3b058fc9978d20a1faf2821f02` |
| `target/platform-lab/run-owner-inspection-setup-debian.py` | 20691 → 20778 | `6e1451805d4623394126842018e25465ab143793283e7ea7653fb55f79a22ef7` → `fa66603a7cd3a8b9ca1c3cc42024f0dda37ec4e7688544ba6efcf351d3e66252` |
| `target/platform-lab/run-owner-journal-debian-arm64.py` | 19902 → 19989 | `3d9f96434ff3e7ee9ae341b263ec8504bc3c2e31bb80212949ff6c33af5d0c58` → `9905df47ff5fcf284c1b27d3a325494df3067ea0f4fa454c2a48e6b98cddabcd` |
| `target/platform-lab/run-owner-journal-debian-clean.py` | 19918 → 20005 | `2cc9eb99686f11421b5c1be42d3aec4a81a640ed23de21233f3bd41d46cffcff` → `5bbbf605030377b9412f95ac87cb2bfae60319e1dbac6cd35f22797a156ba16a` |
| `target/platform-lab/run-owner-journal-debian.py` | 19871 → 19958 | `0d28c86839d703f8fcdcb45fb7e0598261cc30039ce8feaf92a3542f0d46f27a` → `9913e137f50faded428a60dba2bf5b1113412dedd51c155e4208dc49bb7099b7` |
| `target/platform-lab/run-owner-process-inspection-debian-arm64.py` | 20734 → 20821 | `32fe268b3de9a1e94c8fba53f839cb4a8e968a639670b6fc289a35b5a34d5dad` → `c1587e3ef37fc40d5846e4201ce50d9ebe3cd231bdbc5ed12b1e162b74d9c057` |
| `target/platform-lab/run-owner-process-inspection-debian-clean.py` | 20750 → 20837 | `a5e392427790ffc323d2d6603fecc8dc4f6836a406f8af77aa8b8456ebe63f77` → `fac9666ab24f2817ffc20a4c3a4dcd02be5594063c85f52749087382f20f2c96` |
| `target/platform-lab/run-owner-process-inspection-debian.py` | 20703 → 20790 | `de001d4eed85b6207bdb8cc628a80be3fe9d8739e9d4194419772f619a52d696` → `0376ecc637045825b79dcc01af5795ca9f23ae6f0d6e0a4bca487b15075fe862` |
| `target/platform-lab/run-owner-retained-drop-debian-arm64.py` | 20888 → 20975 | `84526276f65576fb53942da5a576a05699517b8b23a609125b52eb3de6f35d4c` → `267dcbb84c53eae8013a776975accf8315925375c8b1eb9577167a1e931ef585` |
| `target/platform-lab/run-owner-retained-drop-debian-clean.py` | 20904 → 20991 | `0dc0599e3ef6a811bfeefaa7078bf737880efb41ab1f27dffaa1f012ddd184ae` → `53827439cb6b619bc12937faebb8e97f6e2d0e47bd5686cfcf7dcfcfe19841b6` |
| `target/platform-lab/run-owner-retained-drop-debian.py` | 20857 → 20944 | `4de03f6769ac16f107a8bbf5189af2df7e85f12cb552fa20dbc85ed0837b0727` → `060334bc46accf2caf155605f87d87996e9e145df249d6639e47f5ce461b790f` |
| `target/platform-lab/run-owner-retirement-arch.py` | 23701 → 23788 | `0cecd7f2f1740388b2a417f9040b90c966a3863faae91adcf57e722d030dc5b9` → `910c2cd01b94fff08d29cc2f35d690583d0c0cf518cf51556f5ed16dcac83b25` |
| `target/platform-lab/run-owner-retirement-debian-arm64.py` | 23714 → 23801 | `2edc71165a50d6998425d39e1fcc3d068a90893d27d29b7c1afc365b50383224` → `7c6f4db63305beda6090e6516ecbe41b382699fd6d53aef5f6490cb196927cfc` |
| `target/platform-lab/run-owner-retirement-debian-clean.py` | 23730 → 23817 | `32b552a3da81261b708a8cec4b271a62187bfa6624cd02b26445488afbc7d65d` → `00b909412f84b932b7eae6682ee029fa2ec7f8681a3e6dc14aefcec080d34950` |
| `target/platform-lab/run-owner-retirement-debian.py` | 23683 → 23770 | `471439b63019944eb20d4128a8b2fb30a889d3f8930a87f04430d72ef0fcdd6e` → `4ae7f848117a40b00d2b5edc2aa30c9d32226b2f2962c6f4a1c8403d370db956` |
| `target/platform-lab/run-owner-retirement-global-stop-arch.py` | 23749 → 23836 | `879925d7ddd7f84e15652471db2a74e15bec1781bb8ddd46455e6ed87f28b5e1` → `b17ab0b9faee41cf8f3250f6336c9dd7645aa5085a5cd433fa654fd0d2ed4326` |
| `target/platform-lab/run-owner-retirement-global-stop-debian-arm64.py` | 23762 → 23849 | `bff64736f0a272c5f4937569cc2a5d16743ec8c740ef4ca9323d7215fb0c1e70` → `7d72c7b81a74c8111c675ca57a5154fef0d7e856682a4e2760a50a37f4744cd4` |
| `target/platform-lab/run-owner-retirement-global-stop-debian-clean.py` | 23778 → 23865 | `8753d2a7fbd09fd70ea4f14b709061ffc0253ee7c79f0559994289b36ce7dadb` → `f6e6fb298ba41f0541a555408fa5c359c37c39338fbf8048a8e7b64ecfd2fc7e` |
| `target/platform-lab/run-owner-retirement-global-stop-debian.py` | 23731 → 23818 | `46d62040e381aef60385a6614ff653642a580ac71d6545cf6a09656eb86284b4` → `63143061032e87251d4e19d4ea35245d1bc2290ef087b53b37759ab2be2473bb` |
| `target/platform-lab/run-owner-retirement-host-span-arch.py` | 23741 → 23828 | `32d266077caa5b873a6358d6ca2d303935e0687769898b8415ad532c0eb01dfb` → `a28d14fdb7afb7c75dec132901476d07f6a92be25387cc3d1a6833b5c9722d57` |
| `target/platform-lab/run-owner-retirement-host-span-debian-arm64.py` | 23754 → 23841 | `05579c539069b4aa0359be7f4307a35c9d5a0c73fa73d1831e0a22e30877f1b7` → `aea1669ca73ec2d648a5c28800b59e351d68a8d58b97fe47a40cc09bbd437316` |
| `target/platform-lab/run-owner-retirement-host-span-debian-clean.py` | 23770 → 23857 | `7813c201376aacc6d3c9e2888ff8b8891c1246ff3de636869590cad921f2b902` → `1eb249367d673fa8fefc487e2058ca54c8c739ee4d6203b8220f54a4c6cbf4b2` |
| `target/platform-lab/run-owner-retirement-host-span-debian.py` | 23723 → 23810 | `2aacc54e5f2c9550912e109a2cea9eb49932697efdcc0256c4f944b9a69ee55c` → `6d8192e46f7f733449fe08c99b695c2f047a2190200faefce30e697affd0a347` |
| `target/platform-lab/run-owner-retirement-queued-failure-arch.py` | 23761 → 23848 | `cc0557c634cef9ef6d568ca3f55f1256bcb28f45d038c7b6619e6007b95873b5` → `b7a803785d4b37cbaadb13b5f6a8f634febfba3f6cd2ab2c6b6a64e2b8097537` |
| `target/platform-lab/run-owner-retirement-queued-failure-debian-arm64.py` | 23774 → 23861 | `2eeddf84b6261082dcfb9aad4f059167630cf470ef8bb71c516a14d4d4fb685a` → `0d220f0dca9ea767b4002a8fd8f5c57e678a111a3530a9c23188a7f15cd5d575` |
| `target/platform-lab/run-owner-retirement-queued-failure-debian-clean.py` | 23790 → 23877 | `76829af7a945b9f03ad45a9d9dbaf0eda0bf4c0b087a2cd7fd0f192e791797e1` → `0ca9708164b903c08e0b94c41f92b048c9df22bc930ce84a1eafd64af1de5bd2` |
| `target/platform-lab/run-owner-retirement-queued-failure-debian.py` | 23743 → 23830 | `a28cc751c49ca8a935aef62f2c9290d044d2ce3335a3350c7db6dad489249837` → `3d40e1da04ae33f7600d9f80a41739086ebc29a2e5ac2b0d2aece2b9cdce0ef0` |
| `target/platform-lab/run-owner-retirement-writer-failure-arch.py` | 23761 → 23848 | `8be0eb40d679f6777db097ebf5e7540f33524fe7a95b26aeb0279d6328e093d3` → `16d04423392944fca31e70cd01476db2e4a099f9b545cf7c6bf22a230f0eefbc` |
| `target/platform-lab/run-owner-retirement-writer-failure-debian-arm64.py` | 23774 → 23861 | `ec529e38b0ff226c4649939416b32b24d469bbd7436e971a5a973f7319b893f0` → `6a36f209c9200f5ffdd659fdca3c90bdb07d9a89e258c709d1ad058c65b7e74e` |
| `target/platform-lab/run-owner-retirement-writer-failure-debian-clean.py` | 23790 → 23877 | `ec0583d34afa83527ebcbb752acc0c34bd3cf50e814efebc60dd43d02cd0390e` → `ab043a86ab4bc00ee5b4a8867b9189d2ac7ecea3b5c24c1b2a6d45dbd02aeacb` |
| `target/platform-lab/run-owner-retirement-writer-failure-debian.py` | 23743 → 23830 | `5804f58a6bb7f0fca72c741ab8ccf19891bdc434c244eb519fe8e186d507104d` → `2a257972812c91bea2e2f67c448219dc04e89c6a3a0914008892c842dc6849e0` |
| `target/platform-lab/run-owner-terminal-death-debian-clean.py` | 20732 → 20819 | `5dd6ed2538231efc27c2a4880e32b7a172b9c09fc73bfcd1f489e726039ef4bb` → `09251fed1b4dee06d018e314cf44c3035e680e248ff9ded717c9f0dfb7d4495d` |
| `target/platform-lab/run-owner-terminal-death-debian.py` | 20685 → 20772 | `8064fac3bf09ca69bfb74cb371413c275d3e623f0ef0029085236e05ce81489a` → `b641521480d6f5d9194345843848f137e01e31c5ed8556278cad248263d0ec6a` |
| `target/platform-lab/run-owner-terminal-debian-clean.py` | 20714 → 20801 | `1ea90e983b1b1bcaaeac879bd82ce9c9c3d40b2b6731704124d673eea1d52993` → `44f0c95e8b9f2d9ab49d8ac7dd264eb01dbba667235f06ebc1c0207485ef1a1c` |
| `target/platform-lab/run-owner-terminal-debian.py` | 20667 → 20754 | `6a219140ee5dc9e32f0fbcddd38bf65e9ed48bbec67e097c61ebdd5e7704814d` → `09e36c1b2104887b0d28eee5c713db913fb4a027c36b245be0311c9e0c5466c1` |
| `target/platform-lab/run-owner-watchdog-debian-clean.py` | 19921 → 20008 | `ce19638da8ae1a71829fd2a9a770dc3db825c48aedf9fc24137931606c0c10f2` → `270e8848c520521af070b9d0d4e872b1993f2782f78c609303ebd6e95538fc4a` |
| `target/platform-lab/run-owner-watchdog-debian.py` | 19874 → 19961 | `2c5c3a5c1a259a1110efcc8bea7ba42efe5df3d0e744407011b60853fa2db76c` → `e9534c62626574cf7e53aa19a83ed2e566efb596492afe1f920dd4efc212cedb` |
| `target/platform-lab/run-peerpidfd-probe.py` | 1576 → 1691 | `3d802d67e18a5665afcc671775aea9c9c665928af45298534a56367dbe61fdc9` → `88b7831e5675805f48e797bec4a27cec5118eb6d09df24b839d3a69a28f42348` |
| `target/platform-lab/run-terminal-death-debian.py` | 17929 → 18016 | `3d0c227876015d412ebf9cce562fcd07db4224d406ea6d1940906caff7ebedfb` → `028e3cdcfa60a25b7e0117d2fb4917ccd535dc72273a6b3fce0430e839088078` |
| `target/platform-lab/run-terminal-executor-debian.py` | 17911 → 17998 | `b53cc477441e9ac2b84a55bece020bd3a6f25571ea10abf05030d1b09ef4a2ad` → `d04947e9a517c00bc0813041b2b93ad9ba3371b8ffbae07ac6c832c21e8e045c` |
| `target/platform-lab/smoke-readonly-accounting.py` | 15059 → 15146 | `0052ceac0df8191ae73e5a0dd5da2c904289522fcce57d22f0e340259f647b14` → `c82bb97a876065441fb452bb44e9f6a820fce8f0b0500df61b0fa1c9beb242f7` |
| `target/platform-lab/switch-void-nft-backend.py` | 2357 → 2472 | `6a716ac1f7557f68808e239b0913a79228f947348b66f7550cff05f1c5a3a8ff` → `7dccac62c94f3744830ced97b7c88ea71b8d10061811ecc070b81201ec899557` |
| `target/run-netfilter-native-frozen.py` | 3841 → 3956 | `b416f4b44584c65eb8421313df2ff3afaf9e40a71244cd6b238e1f1422e126b9` → `c7c2fdbc80457253b01d773a1aee4082eb29275545cb9b37afd1469d513e4c07` |
| `target/run-shared-lease-regression-frozen.py` | 3574 → 3661 | `e5202eca37d34258a23008eced7d75690740fefbe38138f0559b8ed85857b9cc` → `b4e0b5bdf9f9fff21e8e48124f2b75adf3fe07b72cccd2112f96a5bad2db4d8b` |
| `target/run-transport-regression-frozen-original.py` | 3600 → 3687 | `c563cdbc71d900e6d8f97f96a556cff8747c0113f31cc40ed484e66884f7aced` → `55efc5fd30076ae1e2ca8315446ed20d704d707949d40e9ab0aec0fe79e1181b` |
| `target/run-transport-regression-frozen.py` | 5372 → 5546 | `efa4d4b9f14dfa70d4ac455424f0a2598738b8a9c54fde993bafaaa241c8d53f` → `3377a4101f9080118863febebd3e75d519d6bf003d74b7211942eecbc4f2e824` |
| `target/run-transport-regression.py` | 3378 → 3465 | `e9a6d1fee1a3df96cbc9ca887023821fde581fda1a29f606f5a41feb6c3a5db2` → `862495652e0dbe25e519d838072de5bd0086cbc45b2338f18f5b65a8b0858eec` |
| `tools/actual-program-inspect.py` | 5066 → 5153 | `47534809dcc76b362666eea3c5016ed1231e96444789ef3bea68daca1d47480c` → `e9ab2ae0cb132d36db6cb2b57f57159f15f901ea7c42079900deba3c9646fe84` |
| `tools/actual-program-oracle.py` | 18770 → 18857 | `979556480909e7b2fdad76febefa41627a1a43436d78736cc5afb7f3e1cbce3c` → `255b4abb95240b024c409ce6ffa63a77fce7bd9bd6e9f2f3dc41d312c9fcd0fb` |
| `tools/actual-program-path-trace-summary.py` | 2865 → 2952 | `3e61cecf04810884d089be065472a8082c80880dda4ae12b4946c9c3e81b173f` → `1e56c2bdc776f1a4a147d5d04f33c6cc91204b9f88e408d684ca5e355754195a` |
| `tools/actual-program-peer-trace-summary.py` | 2913 → 3000 | `238b82856d339c4548255173178251b2f455c19cf47f4ba7f377b2525d697585` → `44586c286e9e0dc71ab745eecb2a3ec81621b267ff7365016717a0fa92439bf5` |
| `tools/actual-program-stderr-classify.py` | 4273 → 4360 | `a661f38e28f77f6aed5afcb4c0e5857eb4e28bc1d6ee89df1864a13e4c47d107` → `56396c73783851fb00fef27fe8b4272ca12f4eec753b07dc53efea0446e59950` |
| `tools/actual-program-trace-summary.py` | 2714 → 2801 | `759d88885030b6b774cd71e712cd1e2a2143dc4dcc8cf9755e3fc9386215918e` → `13a5e9526120aa67c690b8eb5142cf519d018ce65594e57a2aadad63f2b8bf78` |
| `tools/guarded-transport-capture-oracle.py` | 5600 → 5687 | `381ce9f55a056073ad68b3988c9bf2a2b024ba01754a2084ad1ec3ae00ed97c0` → `9122a991d20a6f32b9b903d8779ad755d20494c4da621c511588cb9e0f2b074b` |
| `tools/guarded-transport-cleanup-wan.py` | 3827 → 3914 | `bb5f1a89aa3d92b979a401e16bb0d8fa1c605d48ff2d973d1adf083b10946f83` → `21a3f5799073e9e2aa2967ad88af79888c72d102bb82a92cd54f2c48b52ce74d` |
| `tools/guarded-transport-oracle.py` | 7062 → 7149 | `d3cbe59b23208d5e74c7efd8f2630fe432459cc9627efaa43e7c28125e818363` → `749d2f84600a065fdd5d18a95d833323263248d353e0e325e0bd5a2efc225d43` |
| `tools/pinned-tailscale-program-inventory.py` | 6921 → 6949 | `d7c61aa742db1b89606d80e416acdb2f75773a154ef547ec0fd30b986c731000` → `255a77af9a5cdecba88e64403628c15fab79270324303d7306a12b8902fe7773` |
| `tools/producer-placement-oracle.py` | 5795 → 5882 | `321b75faaea873e40ab16ab217d77dae27f7f51ff4aacdb84714de591b5f2fc1` → `9cdbdec9de581d6e51b33d0ecbda939a7709330f6e78f1b585ed85328823cef1` |
| `tools/worker-localapi-parser-oracle.py` | 2321 → 2408 | `44c34419c1fceb4766351921e9be250dff03e4e60304000df2ddbfeedf44d51b` → `6a31f1439cb90c440ef338a5822573b3814b35a06809d53906fd81e003aeae2e` |

## I1: restart attempt and new loss of continuity

The guest had already been abruptly stopped twice by outer-host resets at approximately00:21 and00:38 CET. This round attempted recovery using the existing helper, without recreating the overlay, seed, key or pin. It verified the original process binding, immutable base SHA512 and exact two-image backing chain, archived reused runtime logs/PID/socket and retained original `process.json`.

The first helper invocation safely refused before launch: its broad process-cmdline gate matched the enclosing shell command containing the freshly written helper source (both `qemu` and22036 text), reporting `live_qemu_for_state_or_port:65762`. No QEMU was launched by that refusal. The next invocation was a standalone helper command without embedded source; it performed the sole actual QEMU launch in this round. This gate false positive was not bypassed or weakened.

```text
python3 tools/rust-v2-lab/restart-clean-debian.py > target/rebuild-phase2-fixes2/restart-second.stdout 2> target/rebuild-phase2-fixes2/restart-second.stderr
{"process_record": "/DATA/AppData/vprouter-rust-v2/target/platform-lab/debian-clean-x86_64/process-restart-20261103T234741.969842Z.json", "pid": 67533, "start_time": 47852}
```

New record: `/DATA/AppData/vprouter-rust-v2/target/platform-lab/debian-clean-x86_64/process-restart-20261103T234741.969842Z.json`. Recorded outer QEMU PID **67533**, start tick **47852**, controller boot **4655f8b2-34c3-4889-b664-59bad073355f**, observed **2026-11-03T23:47:41.972117+00:00** (00:47:41 CET). These are the QEMU identities in debdev, not guest PID1/start. Original process-record SHA256 remains `2f8c1d8107eea43ea4d36f5bfbb99b12825a5ac807e1438586dc346c72c95200`; original recorded QEMU argv retained exactly by helper. Full restart record includes original base SHA512 and backing metadata.

The guest reached its serial login prompt at about23:47:52 UTC. Before a fresh authenticated health check, the outer execution session disappeared. On resumption, debdev boot ID was **70a4918d-3a53-4863-b2cd-5647da617223**, PID67533 was absent, and22036 had no listener. `journalctl --list-boots` gives prior last-visible entry **00:48:12 CET**, new boot first-visible entry **00:49:45 CET**. These are journal boundaries, not the exact reset instant. This is a **third observed outer-host discontinuity tonight**, after the two reported by the user; it is not proof of an autonomous guest failure or a diagnosed crash cause. No Cargo, subagents or heavy parallel operation was launched by this agent. Restart completion exit status was lost with the session; stdout/new process record and serial boot survived.

Current debdev PID1/start tick: **1/20**, current boot **70a4918d-3a53-4863-b2cd-5647da617223**. The read-only observation process was PID31074/start10470 at23:51:24 UTC. Current guest PID1/start/boot_id: **UNAVAILABLE**. Old guest boot IDs are historical and are not substituted. QEMU PID67533/start47852 is historical after this newest reset. Host observations and exact commands are in `host-after-discontinuity.json`. Its prior-boot kernel query returned no entries under the current non-sudo reader; this does not prove absence of a kernel fault.

No additional QEMU launch was attempted after this new host loss. Repeating a nested-KVM launch immediately would expose debdev to another observed failure pattern without resolving host stability. **Leaving the guest running is not achieved.** I1 requires a stable authorized restart and fresh strict handshake/health checks before phase3. No host settings or acceleration mode were changed as a workaround.

## Health checks and status helper

Fresh strict SSH (dedicated key, single stored pin, all four isolation options plus BatchMode/UpdateHostKeys=no/ConnectTimeout5) exited255: `ssh: connect to host 127.0.0.1 port 22036: Connection refused`. Exact argv/stdout/stderr is in `strict-ssh-after.json`. Pin fingerprint verification passed on the retained file, but **guest fingerprint verification via a successful strict handshake is NOT_RUN**. Guest `journalctl`, failed-unit/root-mount checks, Docker service and both phase2 image inspections, marker/machine identity, PID1/start tick and boot_id retrieval are **NOT_RUN after the newest reset**. Earlier-round positive health/image observations remain historical.

Surviving serial output from the attempted boot (`serial-after-restart.log`, copied read-only) records ext4 recovery required/completed, root remount read/write, fsck-root service finishing, system journal “corrupted or uncleanly shut down, renaming and replacing”, and the existing AF_VSOCK systemd-ssh-generator failure. It also reports initramfs fsck absent/skipped before later systemd fsck service handling. These are console observations before the third abrupt loss, not a fresh authenticated journal audit or complete filesystem integrity proof. No offline fsck/repair/conversion or disk mount was attempted.

Added `tools/rust-v2-lab/lab-guest-status.py`: read-only, no lifecycle or state-file writes; usable from any directory. It compares the pidfile process executable/full argv against preserved `process.json`, rejects zombie/dead/reused non-QEMU PID, reports QEMU PID/start tick, verifies a127.0.0.1:22036 listener via bounded `ss`, then runs confined strict SSH only if those local gates pass and reports guest boot_id. JSON `ok=true` and exit0 require all checks; otherwise exit1. SSH uses the dedicated key, alias to the sole pin, `-F /dev/null`, global trust disabled, IdentitiesOnly/IdentityAgent=none, BatchMode, strict checking, UpdateHostKeys=no and bounded timeouts. The remote command is only `cat /proc/sys/kernel/random/boot_id`. It does not validate guest filesystem/Docker health or replace phase admission.

Both negative liveness checks behaved correctly: before launch the stale PID91972 was absent; after the new reset PID67533 was absent. No SSH was attempted by the helper when local gates failed. Its exact SSH options independently passed `ssh -G`. Positive live-helper execution remains unavailable; no synthetic PASS is presented as live proof. Final observed helper JSON:

```json
{
  "qemu_alive": false,
  "argv_match": false,
  "port_22036_listener": false,
  "strict_ssh_reachable": false,
  "guest_boot_id": null,
  "controller_boot_id": "70a4918d-3a53-4863-b2cd-5647da617223",
  "errors": [
    "[Errno 2] No such file or directory: '/proc/67533/stat'"
  ],
  "ok": false
}
```

Run409 must start from a **fresh guest boot and a newly declared baseline**, with the preceding abrupt-stop history explicitly retained. A baseline was already intended to be new; no baseline was authored here, and the attempted boot cannot be silently reused as a live identity. Candidate/runtime acceptance, raw405/407/408 custody, one-shot admission/reservation and host-crash diagnosis remain open. `release_ready=false`.

## Validation, staging and limits

Validation: all changed Python sources and the helper compiled in memory; 159 old/new controller ASTs differed only in connection isolation options; all293 restored/archive/manifest entries matched; all457 `ssh -G` proofs passed. Scratch proof tooling initially needed missing fixture bindings for `b`, `repo` and cloud row-driven ports; final run passed without executing controller bodies. Existing staged patch was byte-identical to entry before adding this round. All three previously staged report/helper paths were preserved byte-for-byte; inventory retained its previous changes plus only IdentityAgent=none.

HEAD and ordinary refs remain unchanged. The initial full-ref equality assertion failed because the host application added a `refs/t3/orchestration-v2/checkpoints/.../ordinal/1` checkpoint ref during this session; no ref-write command was issued by this agent. Entry/current refs and this limitation are retained in `entry-refs.txt`, `current-refs.txt` and `refs-change.json`. A corrected audit excludes only host-owned `refs/t3/` when checking ordinary-ref equality; it does not claim all refs unchanged.

Exact staging is performed by explicit path list: existing tracked source tools, 147 archive copies, source-manifest and new status helper; this report uses `git add -f` because its documentation directory is ignored. Runtime `target/` controllers/state, keys, pins, guest disks/seeds/logs and scratch evidence are not staged. `git diff --cached --check` and staged-byte preservation checks are recorded in `final-stage.json`. No commit/push or deliberate ref write. No Rust change, therefore Cargo commands are NOT_RUN.

Primary receipts under `target/rebuild-phase2-fixes2/`: `controller-inventory.json`, `rg-ssh-scp.txt`, `changes.json`, `entry-manifest.json`, `ssh-G-proofs.json`, `ssh-G-failures.json`, `static-audit.json`, `restart.stdout`/`.stderr`, `restart-second.stdout`/`.stderr`, `host-after-discontinuity.json`, `strict-ssh-after.json`, `serial-after-restart.log`, `status-before.json`, `status-final.json`, `entry-index.patch`, `refs-change.json`, and `final-stage.json`. Evidence remains local and ignored; report includes durable controller hashes and explicit limits.

## Five-line summary

I2: all159 existing lab controllers confined;457 SSH/SCP-option proofs passed across160 controllers including the status helper.
All147 changed restored controllers match their archives; all293 manifest entries verify, with old/new hashes recorded.
Same guest launched as QEMU67533/start47852; a third debdev boot discontinuity then removed it; I1 remains blocked.
Guest is down; fresh handshake, guest journal/Docker/images and guest boot identity are NOT_RUN; no further relaunch attempted.
Tracked fixes/report staged only; no Cargo, subagents, outer-host sudo/settings changes, baseline, Bootstrap/run409, commit or push.
