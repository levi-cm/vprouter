# Task 8c rebuild phase 2 second fixes independent review

Overall: **PASS for the reviewed code changes. I1: BLOCKED_BY_HOST.** The guest is intentionally paused by user decision because nested KVM guest starts repeatedly crash debdev. Guest liveness is outside this review and is not a failure of these changes. This static review does not approve phase 3 execution or establish runtime acceptance.

Reviewed 2026-11-04, workspace `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, HEAD `d62ab24e172badb9245fa5f20d71f15930731839`. Read both prior independent reviews, both fixes reports, the staged diff and relevant restored/archive implementations. All existing staged files equal their worktree bytes. No guest connection, guest lifecycle action, QEMU/VM execution, QMP access, cargo, sudo, Git mutation, subagent or existing tracked/staged-file edit occurred. All scratch/bytecode is under `/tmp`; the user explicitly authorized this new report as the sole exception. Neither helper was run normally. The only SSH executions were `ssh -G`, which does not connect.

## Findings

- **Critical:** none found in the reviewed changes.
- **Important:** none found in the reviewed changes.
- **Minor:** none found in the reviewed changes.

No new defect/failure scenario requiring a file:line finding was identified. The precise implementation locations and scope limits are recorded below. Prior I2 is closed for the audited invocations. Prior M2 remains closed for the inventory/restart tools and existing guarded phase-3 controllers. Prior M1's unavailable historical before/after host-preservation proof remains an evidence limitation; this round supplies no new historical proof.

**I1 — BLOCKED_BY_HOST, out of scope.** No attempt was made to establish current guest liveness, host-key handshake, guest identity, filesystem/Docker health or runtime behavior. No earlier positive guest observation is relabeled as current. The historical failure to leave the guest running is not counted against this code-change verdict.

## SSH/SCP confinement and command preservation

Independent AST enumeration covered all 293 manifest-restored Python sources, maintained top-level `tools/*.py`, and the new status helper. It found **160 controllers** with literal SSH/SCP command constructors and reproduced **457 effective-configuration checks**, covering all enumerated platform variants and both Bootstrap SCP transfers. Remaining SSH/SCP text in other manifest/tool files was inspected: it names retained SSH outputs, metadata fields, provisioning packages/keys or guest sshd setup rather than another controller invocation. Controller bodies and remote payloads were not executed.

Each proof checks the source's exact connection option order, `-F /dev/null`, one dedicated identity, one explicit user trust file, effective `GlobalKnownHostsFile=/dev/null`, `IdentitiesOnly=yes`, `IdentityAgent=none`, `StrictHostKeyChecking=yes`, loopback host/user, and absence of ProxyCommand, ProxyJump, HostKeyAlias and KnownHostsCommand. For every effective port22036 proof, the trust file resolves to the shared dedicated pin and contains exactly one `[127.0.0.1]:22036 ssh-ed25519` row. Its freshly computed SHA256 is `38b48e872f7876cb68b02b9c823107ccc2969c5d63642b9b74561803688e139e`; the clean-Debian alias and `target/lab-state/known_hosts` resolve to the same file. No private key bytes or personal SSH configuration were read.

The exact per-site options, concrete `ssh -G` argv, source line/platform, complete stdout/stderr and effective configuration are in `/tmp/vprouter-fixes2-review/ssh-G-proofs.json`; `/tmp/vprouter-fixes2-review/errors.json` is `[]`. For SCP, which has no `-G`, the exact connection options were translated solely by replacing `-P` with SSH's `-p` and omitting SCP's transfer-only `-q`. Transfer operands and remote command operands do not participate in configuration and were omitted. The count is configuration proofs, not 457 transfers or guest connections. Historical ports22032–22035 remain historical mappings and have not been admitted for use.

Core phase-3/run409 sites independently checked:

| Source and line | Clean-Debian proofs | Result |
| --- | ---: | --- |
| `target/platform-lab/run-frozen-host-projection.py:180` | 1 SSH | PASS |
| `target/platform-lab/run-frozen-secret-bootstrap.py:36` | 1 shared SSH constructor | PASS; reused by listing/execution |
| `target/platform-lab/run-frozen-secret-bootstrap.py:44` | 2 SCP uses at45/46 | PASS |
| `target/inspect-secret-bootstrap-failure.py:52` | 1 SSH | PASS |
| `target/archive-secret-bootstrap-selectors.py:39` | 1 SSH | PASS |
| `tools/pinned-tailscale-program-inventory.py:42` | 1 explicit-argument SSH constructor | PASS; reused for acquisition/copy/cleanup |
| `tools/rust-v2-lab/lab-guest-status.py:40` | 1 SSH | PASS; helper not run |

Representative exact executed argv:

```text
ssh -G -F /dev/null -o GlobalKnownHostsFile=/dev/null -o IdentityAgent=none -i target/lab-state/id_ed25519 -p22036 -o IdentitiesOnly=yes -o UserKnownHostsFile=target/platform-lab/debian-clean-x86_64/known_hosts -o StrictHostKeyChecking=yes -o ConnectTimeout=5 vprouterlab@127.0.0.1
ssh -G -F /dev/null -o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o IdentityAgent=none -i target/lab-state/id_ed25519 -p22036 -o UserKnownHostsFile=target/platform-lab/debian-clean-x86_64/known_hosts -o StrictHostKeyChecking=yes -o ConnectTimeout=5 vprouterlab@127.0.0.1
ssh -G -F /dev/null -o GlobalKnownHostsFile=/dev/null -o IdentitiesOnly=yes -o IdentityAgent=none -i target/lab-state/id_ed25519 -p22036 -o UserKnownHostsFile=target/platform-lab/debian-clean-x86_64/known_hosts -o StrictHostKeyChecking=yes vprouterlab@127.0.0.1
ssh -G -F /dev/null -o IdentityAgent=none -i /DATA/vprouter-lab/lab-state/id_ed25519 -o IdentitiesOnly=yes -o BatchMode=yes -o UserKnownHostsFile=/DATA/vprouter-lab/lab-state/known_hosts -o GlobalKnownHostsFile=/dev/null -o StrictHostKeyChecking=yes -o ConnectTimeout=5 -p 22036 vprouterlab@127.0.0.1
```

All exit0. Effective values include `globalknownhostsfile /dev/null`, `identitiesonly yes`, `identityagent none`, `stricthostkeychecking true`, `hostname 127.0.0.1`, `user vprouterlab`, `port 22036`. The third argv is the SCP option translation and was checked independently for each transfer.

For **158** existing changed implementations, AST comparison against HEAD after stripping only the four confinement option pairs is identical:147 archived/restored controllers and11 maintained tools. Thus endpoint/port mappings, key/trust selection, timeouts, remote operations, data handling and assertions did not change. This is a semantic comparison; formatting is not treated as behavior. For the159th implementation, inventory has earlier staged phase-2 changes relative to HEAD. Its pre-round-two implementation was independently reconstructed in memory from the retained `target/rebuild-phase2-fixes2/entry-index.patch`, with every context/removal checked against HEAD. That reconstruction hashes to `d7c61aa742db1b89606d80e416acdb2f75773a154ef547ec0fd30b986c731000`. Removing only the newly inserted `'-o', 'IdentityAgent=none', ` bytes from the current tool reproduces it exactly. Its remote acquisition and cleanup assignment ASTs also equal HEAD. The second-round inventory change therefore does not alter remote behavior.

## Restored copies and manifest

All **293** entries freshly pass source/archive byte equality, recorded byte length and SHA256. Compared with HEAD, exactly **147** entries change, and their paths exactly equal the147 staged archive-source changes. Each original HEAD archive also verifies against the original manifest size/hash. Entry order, source/archive paths, other entry fields, manifest-level metadata and unchanged entries are preserved. The147 updated runtime sources under `target/` equal their staged archival counterparts byte-for-byte.

The maintained12 top-level tools and the two maintained lifecycle/status helpers are outside this historical target-source manifest; no claim is made that they have pre-existing archive entries. The staged-file and restored-file syntax totals below count both copies separately.

## Restart and status helper safety

`tools/rust-v2-lab/restart-clean-debian.py:18` rejects optimized execution before opening its lock or reading state. Lines23–39 require existing state/disk/seed/provisioning and the recorded clean-Debian endpoint/path choices. Lines24–25 take a nonblocking cooperative exclusive lock. Lines41–54 refuse matching live QEMU state/port cmdlines, fail closed on unreadable process cmdlines, and reject an unavailable loopback22036 bind. These gates run before base/backing validation and again at77 before archive creation. Lines57–76 verify the immutable base SHA512/checksum entry and exact existing two-image backing chain. No create/convert/repair/seed/key-generation path exists.

Lines78–102 create an exclusive timestamped archive/new record, copy the original process/serial/QEMU logs, move stale PID/QMP paths aside, preserve original `process.json`, and bind a new process record to the original hash/archive/host boot/start tick. The QEMU launch at89 uses the recorded argv; this path was not executed. This is a narrow explicit restart helper with a cooperative lock and process/port checks; it cannot guarantee atomic exclusion against an unrelated noncooperating launcher racing after the last probe. That existing scope limitation is not a newly introduced regression. The broad cmdline substring test can safely over-refuse enclosing command text, as the fixes report already documents.

Independent isolated tests extracted only `refuse_live` into a fake process/socket environment. Duplicate state and duplicate-port QEMU cases both raised `live_qemu_for_state_or_port:123`; an unreadable process raised `cannot_inspect_process:123`; a simulated port conflict raised errno98; an unrelated-process/free-port case returned normally. No real bind, guest process interaction or helper top-level execution occurred. Results: `/tmp/vprouter-fixes2-review/refusal-gates.json`.

`tools/rust-v2-lab/lab-guest-status.py:20` reads existing process metadata/pidfile/proc data, rejects dead/zombie or mismatched executable/argv, and reports the observed start tick. Lines32–39 run bounded read-only `ss`; lines40–56 prepare the confined strict SSH command and run it only if local process/argv/listener gates pass. Its sole remote operation is `cat /proc/sys/kernel/random/boot_id`; exit0 requires a valid UUID and all gates. `UpdateHostKeys=no` and isolated SSH configuration prevent trust-update/config side effects. It contains no lifecycle, state-file write or mutating remote command. It is a liveness indicator, not a restart-record identity/admission or filesystem/Docker health verifier. It was not executed, including under optimization, because it could connect if local gates passed.

## Optimized Python and syntax

The inventory and restart tools retain their explicit first-action `optimized_python_refused` guard at lines18–19. After checking code order, both were run with `-O`, `-OO` and `PYTHONOPTIMIZE=1`: all six cases exit1 with `RuntimeError: optimized_python_refused` before argument parsing/state/lock/SSH/QEMU work.

A broader check identified **33 staged Python files** with existing early guards, verified that only docstrings and standard-library imports precede each guard, then ran each with `-O`. All33 exit1 with the expected refusal, including projection, Bootstrap and its inspection/archive helpers. Guards/other assertions in existing controllers remain AST-identical except for connection options. This does not claim that every historical tool now rejects optimization: older unguarded tools were not run, and the new status helper contains no assertion-based checks to disable. The33 command/result receipts are in `/tmp/vprouter-fixes2-review/optimized-all.json`; the two-tool six-case receipts are in `results.json`.

Python `py_compile.compile(..., cfile='/tmp/vprouter-fixes2-review/<number>.pyc', doraise=True)` passed for **308 paths**: all161 staged Python files and all147 changed restored runtime copies. No source-tree `__pycache__` was requested. The full compiled path list is in `results.json`.

## Exact commands/results and evidence

All repository-relative commands below ran from `/DATA/AppData/vprouter-rust-v2`. The independent audit programs contain the exact nested command argv and assertions, and were written only under `/tmp`.

| Command | Result |
| --- | --- |
| `git rev-parse HEAD`; `git branch --show-current` | Expected full HEAD above; `rust/v2` |
| `git status --short`; `git diff --cached --stat`; `git diff --cached -- <reviewed paths>` | Read staged scope/diff; no Git writes |
| `git diff --cached --check` | exit0 |
| `python3 /tmp/vprouter-fixes2-review.py` | exit0;293 manifest entries,147 changed entries,158 normalized AST comparisons,160 controllers,457 SSH-G proofs,308 compiled paths; index/worktree preservation passed |
| `python3 /tmp/vprouter-fixes2-review-extra.py` | final exit0; exact pre-round-two inventory reconstruction and33 safe early-guard refusals |
| `python3 /tmp/vprouter-fixes2-review-gates.py` | exit0; five isolated process/port gate cases as above |
| `/usr/bin/python3 -O <guarded file>` |33 cases exit1 with explicit optimized refusal; per-file argv/stderr retained |
| `/usr/bin/python3 -OO <inventory or restart tool>`; `PYTHONOPTIMIZE=1 /usr/bin/python3 <inventory or restart tool>` | four additional cases exit1 with explicit optimized refusal |
| `ssh -G <exact site options> vprouterlab@127.0.0.1` |457 cases exit0; per-site exact options/effective outputs retained |

Scratch harness correction: the initial extra-audit invocation stopped on an overly broad assertion that *all* imports in a file must be standard-library imports. Some files import local modules after the early refusal guard. The harness was corrected to inspect only imports preceding that guard, then rerun successfully. This was a review-harness assertion, not a product failure; those later imports never ran under `-O`. The main audit and gate audit passed on their first invocation.

Evidence directory: `/tmp/vprouter-fixes2-review/`, containing `entry.patch`, `results.json`, `extra-results.json`, `ssh-G-proofs.json`, `errors.json`, `optimized-all.json`, `refusal-gates.json` and bytecode outputs. Scripts: `/tmp/vprouter-fixes2-review.py`, `/tmp/vprouter-fixes2-review-extra.py`, `/tmp/vprouter-fixes2-review-gates.py`. The captured index patch and staged/worktree bytes were checked for equality after verification and again at report completion. The sole new repository file is this unstaged report.

## Four-line summary

Code changes: PASS; no Critical, Important or Minor findings.
I2:457 SSH/SCP configuration proofs passed;147 changed archives and all293 manifest entries verify.
M2 preserved;33 early-guard optimization refusals and308 Python syntax checks passed.
I1:BLOCKED_BY_HOST; no guest/VM connection or lifecycle action, cargo, sudo, Git writes or subagents.
