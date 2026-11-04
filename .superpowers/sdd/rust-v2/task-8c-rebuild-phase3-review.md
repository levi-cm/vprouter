# Independent Task 8c rebuild phases 3 and 3b review

2026-11-04. Workspace `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`,
HEAD `6ca0073fb1f58706a670e9d4e333a831ae0d0628`; reviewed unstaged changes and
new untracked tools, their restored copies, and retained phase 3/3b evidence.

**Verdict: FAIL. Run 409: NO-GO.**

One Critical and one Important finding block execution. A Minor finding also
needs disposition. The first SSH payload has a deterministic syntax error after
the durable claim: the proposed command would spend the sole attempt without
starting Bootstrap or producing its driver-cost record. The passing supplied
tests and passing `--preflight-only` do not cover that payload.

All reviewer scratch, scripts, synthetic fixtures and command receipts are under
`/tmp/vprouter-phase3-review/`. This report is the only reviewer-written file
outside that directory. No real reservation was created or consumed; no run409,
Bootstrap payload, guest mutation, sudo on debdev, subagent, Cargo operation,
staging, commit, push or remote publication check was performed. The only live
guest probe was the permitted read-only `lab-guest-status.py`.

## Findings

### Critical C1 — Invalid directory-listing payload irreversibly spends the attempt

Locations: `tools/rust-v2-lab/target/platform-lab/run-frozen-secret-bootstrap.py:55`
through `:62`, mirrored in `target/platform-lab/run-frozen-secret-bootstrap.py`;
claim boundary at controller `:43` and
`tools/rust-v2-lab/run409-reservation.py:144`.

Moving the execution body inside `try` also indented the contents of its
triple-quoted `listing` string. The first line is unindented, while the following
`root=...` and `print(...)` lines each begin with a space. Python rejects this
remote script with `IndentationError: unexpected indent`. With the new boot
prefix, the error is at remote line 3; without it, at line 2.

Concrete failure: the exact proposed command passes provenance checks, writes
and fsyncs `run-409-consumed.json` with budget zero, creates the output directory
and captured inputs, then calls `before=directories()`. Strict SSH invokes
`sudo -n python3 -I -` with the invalid script. The controller raises
`CalledProcessError` and saves its controller-error receipt. Neither SCP nor the
Bootstrap fixture runs; `actual-program-run-409.json` is never created. The
reservation correctly refuses a retry, so the measurement opportunity is lost.

This is also a historical execution regression: unreserved historical calls
that pass the reservation guards use the same invalid listing. The HEAD
version's extracted listing compiles; both worktree variants fail. Thus the
report's assertion that historical execution behavior is unchanged is false.

Reproduction, entirely offline: `/tmp/vprouter-phase3-review/listing-compile.json`
records AST extraction and `compile()` of the actual HEAD/worktree strings,
with and without the boot prefix. No controller execution or guest call was
needed. Ordinary compilation of the containing controller succeeds because the
invalid program is merely string data. `--preflight-only` exits at `:46`, before
this string is even assigned, explaining its false reassurance.

Required repair: construct a correctly unindented listing and compile every
generated remote program before consuming the claim. Add a meaningful offline
regression that checks the actual listing on fresh and historical paths. Mirror
the repair, update the manifest and auditably rebind the unspent reservation;
retain all existing reservation generations and tombstone evidence. Do not
consume the present reservation to demonstrate the failure.

### Important I1 — Removing the reservation marker bypasses fresh checks in F/A

Locations: `tools/rust-v2-lab/target/inspect-secret-bootstrap-failure.py:9` and
`:59`; `tools/rust-v2-lab/target/archive-secret-bootstrap-selectors.py:8` and
`:46`. Restored copies have identical lines.

Both tools select the fresh-provenance branch solely with
`if 'run_reservation' in record`. Their admitted-guest-boot assertions use the
same condition. Removing that single field from a fresh run409 raw record makes
these tools treat it as historical. Neither checks the known run409 identity or
the captured reconciliation's `route='fresh-lab'` / false historical flags to
require the fresh branch. The directory binding does not contain an independent
original raw-record hash that would reject this deletion in F. A requires F's
hash-bound receipt, which F can produce from the downgraded record.

Concrete failure: a damaged or edited fresh record loses `run_reservation` while
retaining the run path, source/controller bindings and genuine failure rows.
F skips all active-generation, consumed-claim, fresh baseline/comparison and
admitted-boot checks, and can issue a receipt for those modified bytes. A can
then use that receipt and likewise reach its guest archival script without any
fresh check or boot assertion. Its original owner/gateway/selector gates remain;
they do not restore the missing reservation and boot binding. This violates the
phase 3b requirement to refuse unbound fresh provenance.

Offline reproduction: `failure-route-downgrade-check.py` uses disposable supplied
synthetic fixtures and intercepts `subprocess.run` before any SSH. For **each**
legacy tool, a valid marker reaches the intercepted call; a tampered SHA is
rejected before SSH; deleting the marker reaches the intercepted call again.
The exact six results are retained in `failure-route-downgrade-check.json`.
C and the new I helper reject the missing marker, so the prescribed complete
sequence provides an additional defense. The independently invocable F/A tools
still fail their claimed fresh-provenance gate.

Required repair: require fresh validation for run409 and/or independently
identified fresh declarations, with a mandatory marker. Make historical
fallback explicitly reject fresh identity, then cover field deletion and mixed
provenance in both tools with SSH blocked. Keep genuine historical branches and
all existing archival identity checks intact. Mirror and rebind as for C1.

### Minor M1 — Inspector timeout loses its partial diagnostic and writes no receipt

Location: `tools/rust-v2-lab/inspect-run409-state.py:79` through `:83`.

The receipt is written only after `subprocess.run(..., timeout=30)` returns.
`TimeoutExpired` and process-start errors escape before `m.save`. Concrete
scenario: after a Bootstrap failure or transport loss, the pinned connection
stalls during inspection; a partial public snapshot exists in the exception,
but the promised inspection receipt is absent and that partial output is lost.
The earlier C bundle still preserves the raw record, so this does not erase the
Bootstrap record or permit another attempt.

`inspector-timeout-check.py` injects `TimeoutExpired` with partial stdout using
the real inspector and a disposable valid fixture. It confirms the exception
escapes and no destination is created; no guest was contacted. Catch transport
exceptions, retain available stdout/stderr and a timeout/error classification in
an exclusive receipt, return failure, and preserve `archival_authorized=false`.

## Answers to the review questions

### 1. One-shot guarantee and raw preservation

The cooperating reserved path is otherwise fail-closed. The canonical path,
schema 2, exact parameters, unique complete 24-file binding set, active-generation
SHA and retained old SHA are verified. A nonblocking flock covers admission and
execution; O_EXCL creates the global consumed claim before any guest action.
Claim/raw/output collisions, including dangling symlinks, refuse admission.
`save()` uses O_EXCL/O_NOFOLLOW, mode0600, file fsync and directory fsync. It does
not overwrite a raw record. A partial claim or interrupted controller remains
spent. Lock release after a crash does not remove the claim.

Supersession preserves the old bytes and writes its tombstone before replacing
the active file; interrupted replacement fails closed. The old path/schema and
old bytes restored at the active path are refused. There is no reset API and no
second supersession API for the existing tombstone without further repair. This
is a cooperative mechanism, not protection against manually deleting evidence
or launching an unrelated historical copy outside it.

Current active SHA256:
`e3366fd4b99201f828c4ed844630007d54c7f4fed24515b9b9211d9838e36ff6`.
Retained superseded SHA256:
`3237686154de18668bee6182f24cc405b8c15a2eaa8d8d03e8305b574c1306e4`.
The real claim, raw409, controller-error409 and output-label directory remained
absent. C1 exploits no retry loophole: it wastes the correctly enforced budget.

### 2. Baseline honesty and strength

The fresh baseline is truthfully labeled. I decoded the saved independent
RTM_GET dumps with the authoring helper and reproduced the complete authored
baseline byte-for-byte under canonical JSON, including namespace and every
structural field. The independent SSH receipt's JSON equals the saved dump and
its remote-script hash matches the helper. Prior evidence and helper hashes
match. Retained command receipts order independent collection, successful
authoring, frozen projection, then comparison; successful authoring precedes
projection by approximately six seconds. This verifies the retained provenance
chain; it is not an independent historical observation of the implementation.

Counts are links3 / addresses6 / routes19 / rules5, namespace `[4,4026531840]`.
The canonical baseline SHA256 is
`da3f80f0da4c717443fcb9a2118ed938a6d5c4edeea69d40e755b97291b5a01a`.
All four complete multisets equal the frozen projection, including duplicate
multiplicity. Enumeration order differs, which is permitted: the guest's
`normalized_shape` and Rust's `guarded::exact` / `audit::same` also compare full
multisets. No projected fields were substituted into an old baseline.

The new validator reuses the unchanged strict template/shape checks and the
frozen projector's pure envelope validator. Original creator PID/start, clean
reap, route-socket identity, namespace, read-only/no-authority assertions and
`requested_at + 2` deadline are retained. Historical reconstruction/alignment,
continuity and host-authority flags remain false. The original historical
baseline assertion and all its surrounding checks survive in the historical
branch; the other three original validator functions are AST-identical.
The F/A dispatch bypass is the separate I1 finding.

The historical-gap disposition honestly distinguishes unavailable raw398–408,
original live identities and old archival evidence from the fresh lab. No
historical replay or recovered-original-resource proof can be inferred from
these new checks. Its phase-3 statement that the inspector is unchanged is
superseded by the phase-3b diff/report. The new environment cannot establish a
causal speedup over run408's accumulated 61-link environment.

### 3. Historical behavior and archive consistency

All **293** manifest entries match the restored and archived source bytes,
lengths and SHA256. The clean-Debian mapping addition leaves existing native
inspection mappings intact. The shared validator retains the original checks
on genuine historical declarations; the supplied synthetic historical tests and
an independent AST comparison confirm that limited claim.

Overall historical execution is **not unchanged** because of C1. F/A retain
their historical behavior when the marker is absent, but that fallback is too
permissive for fresh409 (I1). Archive consistency proves both copies contain the
same defects; it does not establish runtime correctness.

### 4. Post-run C/I/P/F/A path

The controller writes the raw record exclusively and durably **before** parsing
witness JSON, writing summaries or performing the final directory-list check.
Ordinary subsequent exceptions retain an exclusive controller-error record.
The new collector copies available original raw/controller/claim/binding bytes
before outcome validation and retains an error receipt on validation failure.
The supplied offline preservation cases pass for success, early failure,
timeout, no raw record and invalid provenance.

| Outcome, assuming C1 is repaired | Actual available sequence and limits |
| --- | --- |
| Exit0 with complete witness/controller row | C preserves and checks baseline provenance; I can capture current public state. P explicitly refuses exit0 and must be skipped. F/A require failure and must be skipped. The 15 new diagnostic rows are emitted on first error, so success is not expected to produce them. |
| Exit1, native_poll/result/Deadline, with complete diagnostics and directory binding | C → I → P → F. The parser accepts the original two-second boundary and the full 13 CPU + sleep + constructor rows. F needs its original input-manifest/host/controller/binding rows. A remains a separately authorized action after exact identity/selector review, never automatic on parser PASS. I1 must be repaired. |
| Early assertion, SSH failure, timeout124 or no raw record | C preserves available bytes/claim/controller error. I requires the same admitted guest and is subject to M1. P is inapplicable without exit1/complete Deadline diagnostics. F/A must stop when their original raw/binding/identity prerequisites are absent. A timeout does not establish owner or child death. |
| Raw saved but later summary/binding fails | C retains raw without needing directory-binding.json; I can use it. P works only if its closed diagnostic contract is complete. F/A refuse absent directory binding; no binding should be fabricated. |

The supplied phase-3b parser test contains no DRIVER rows, so it alone does not
prove the new 15-row path. I added a reviewer-only synthetic native_poll/result
Deadline example with all 13 wrapper, 30 nested, 24 retained, 15 owner and **15
driver** rows. The unchanged parser accepts it and retains the raw SHA. Removing
the constructor row is rejected; exit-zero success is rejected as inapplicable.
The frozen Rust source and amd64 artifact contain all three new DRIVER markers.
This establishes reader compatibility, not actual run409 output or timing.

C deliberately reports full Bootstrap witness validation `NOT_RUN`,
`runtime_acceptance=false`, `release_ready=false`. That is an explicit limitation,
not a full typed Bootstrap acceptance collector. Existing HOST collection remains
inapplicable to Bootstrap modes. Do not promote a preservation receipt or parsed
diagnostic into runtime acceptance.

### 5. Safety and current guest

All three new SSH constructors passed independently extracted `ssh -G` checks:
loopback22036, fixed lab user, `-F /dev/null`, global trust disabled, sole dedicated
identity, agent disabled, explicit pinned known_hosts and strict checking. The
modified Bootstrap SSH/SCP and legacy F/A retain the same confinement options.
New collection/admission/inspection code contains no guest network, namespace,
nft or container mutation; A's selector mutation remains an explicit future
action. No newly introduced credentials/private-key material was found in the
reviewed diffs and seven added tool/test sources. Credential files were not
inspected or reproduced.

The permitted fresh status checks passed at 2026-11-04T15:38:21Z and again at
15:45:56Z: QEMU2147340,
start tick1616810, exact recorded argv, loopback22036, strict authenticated SSH,
guest boot `e14efc10-050b-41b0-89d8-1e946725098c`, controller boot
`18f40876-a432-4ad1-9ded-03e0df43559a`. Broader guest/Docker/selector/clock gates
were inspected as retained phase 3/3b evidence, not rerun in this review. A direct
Seccomp0 clock probe does not establish a full frozen-driver service sample.

### 6. Execution readiness

**NO-GO.** Repair and independently verify C1 and I1 before spending run409;
dispose M1. Any repair changes bound bytes, so preserve and auditably supersede
or extend the current unspent reservation chain through reviewed tooling. Do
not edit reservation data in place or delete the claim/tombstone to reset it.
The original Root checkpoint/publication/remote-confirmation prerequisites also
remain outside this read-only review; the reviewed implementation is unstaged.
No execution authority or runtime/release acceptance is supplied by this report.

## Verification ledger and preservation

Exact argv, exit codes, UTC times and complete stdout/stderr for recorded checks
are in `/tmp/vprouter-phase3-review/*.command.json` and matching logs.

| Fresh review check | Result / retained evidence |
| --- | --- |
| `python3 -B tools/rust-v2-lab/test-run409-reservation.py` | exit0; 12 checks; `reservation-tests.*` |
| `python3 -B tools/rust-v2-lab/test-phase3b-provenance.py` | exit0; 21 tests; `provenance-tests.*` |
| Real controller with final `--reservation target/lab-state/run-409-reservation.json --preflight-only` and the brief's exact preceding candidate/platform/label/mode | exit0; guest_actions_executed=false, budget1; `bootstrap-preflight.*`. Source inspection confirmed return before output creation/SSH/SCP; existing lock file was retained. |
| Independent archive/compile/baseline/reservation/source-marker audit | exit0; 293 pairs, 593 Python paths compile in memory, 11 explicit `python3 -B -O` refusals; `independent-audit.*`, `audit.json`. No pyc files created. |
| Extracted actual remote listing, HEAD versus worktree | HEAD compiles; worktree fails in both boot-prefix variants; `listing-compile.json` |
| Synthetic F/A field-deletion regression | both bypass to intercepted SSH; no guest call; `failure-route-downgrade-check.*` |
| Synthetic inspector transport timeout | exception escapes, partial output not saved, no receipt; `inspector-timeout-check.*` |
| Independent complete 15-row reader example and negative cases | exit0; complete accepted, truncated/success rejected; `parser-check.*` |
| Static two-architecture candidate/context verification and extracted SSH configuration | exit0; all 203 current inputs match archive/root proof, ELF62/183 static, seven strict context files per architecture, retained x86 preflight digest/log match; `static-candidate-ssh.*` |
| Historical shared-validator AST check | exit0; original historical baseline assertions preserved; `historical-validator-check.*` |
| Read-only current guest status | exit0, admitted identities above; `guest-status.*`, `guest-status-final.*` |
| `git -c core.fsmonitor=false diff --check` | exit0; `diff-check.*` |

Stock candidate verifiers, baseline author/compare actions and native selftests
were not rerun because their output creation or payload execution exceeds this
review's scope. Independent static equivalents were used. Real C/I/P/F/A,
run409, fault injection, driver CPU sampling, historical raw replay, provider
connection, ARM runtime, publication and release/soak acceptance are **NOT_RUN**.

`entry.json` captures HEAD, porcelain status, index hash, 785 reviewed file
hashes and the four absent run409 outputs. The final preservation audit verifies
those bytes, Git state and absent outputs are unchanged
(`preservation-final.json`: zero changed inputs). The review file is the
sole permitted additional workspace write; all implementation findings are left
unmodified for the owner.
