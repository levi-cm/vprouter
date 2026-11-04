# Task 8c rebuild phase 3 review fixes

2026-11-04. Shared checkout `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`,
HEAD `6ca0073fb1f58706a670e9d4e333a831ae0d0628` throughout.

**C1, I1 and M1 are fixed and covered by offline regressions. Run 409 remains
NOT_RUN; the single total attempt is unspent.** The replacement reservation and
real controller `--preflight-only` pass, including the remote-program compile
gate. This is implementation/pre-execution evidence. Independent review and the
Root checkpoint/publication prerequisites remain outside this implementation;
`runtime_acceptance=false`, `release_ready=false`.

The existing phase 3/3b changes were retained and built on. No subagents, Rust or
Cargo changes, Git staging/commit/push, debdev sudo, guest lifecycle operation,
guest network/namespace/nft/container mutation, production or provider credential
use occurred. Live SSH was confined to the dedicated key/pin, loopback22036,
`-F /dev/null`, `GlobalKnownHostsFile=/dev/null`, `IdentitiesOnly=yes`,
`IdentityAgent=none`, explicit `UserKnownHostsFile` and strict host checking.
Guest sudo was used only for the permitted read-only gate probe.

Evidence root: `target/rebuild-phase3-fixes/`. `entry.json` and `entry/` retain
609 pre-edit inputs, HEAD/index identity, and the absent run409 outputs.
Every recorded gate has exclusive `*.command.json`, `.stdout` and `.stderr`
receipts with exact argv, exit code, UTC and duration. Prior phase 3/3b/review
evidence was not overwritten. The initial snapshot helper incorrectly treated
the worktree's `.git` file as a directory; it was corrected to use
`git rev-parse --git-path index` before source edits. One discovery read used the
nonexistent reviewer filename `independent-audit.py`; the actual `audit.py` was
then read and adapted. Neither discovery error changed implementation/state.

## C1: exact historical listing and compile admission

`target/platform-lab/run-frozen-secret-bootstrap.py:5` adds
`compile_remote_programs`. Its listing at `:11` is byte-identical to HEAD's
historical string, including its trailing newline. The fresh listing adds only
the admitted-boot assertion prefix. The exact generated listing and guest
program returned by this function are the strings subsequently sent over SSH.

At controller `:62`, the reservation's existing pre-claim callback performs full
fresh provenance validation and then compiles the listing, configured guest
program, public host builder and baseline builder. This callback runs under the
reservation lock, before `run409-reservation.py:175` can create the claim. The
historical route invokes the same compiler at controller `:72`, before output
creation or guest calls. `--preflight-only` returns at `:68` after this gate and
reports all four program names. Local context-checker and baseline-builder
compilation also remain before admission.

Regression: `tools/rust-v2-lab/test-phase3-fixes.py:223` extracts the actual
controller function, generates historical/fresh programs from the actual guest
and builder sources, compiles them and compares the historical listing to
`git show HEAD:tools/rust-v2-lab/target/platform-lab/run-frozen-secret-bootstrap.py`.
It also proves fresh listing/guest equality to historical bytes plus the boot
prefix. At `:237`, the actual controller reservation block is executed against
the real reservation helper in a disposable fixture. Injected syntax failures
in each of the four program compilations refuse before any temporary claim,
both in execution admission and `--preflight-only` (eight cases); subprocess
execution is blocked. The real, fully configured candidate preflight independently
compiled all four programs with no guest action.

## I1: fresh identity cannot fall back after marker deletion

`target/quarantine_evidence_base.py:34` adds `requires_fresh_provenance`. Run409,
the reservation marker, a fresh route/continuity declaration, false historical
continuity/recovery, or false reconstruction/alignment flags independently select
fresh validation. The predicate examines both the record and the captured
reconciliation, including contradictory/mixed declarations.

F uses it at `target/inspect-secret-bootstrap-failure.py:14`; A at
`target/archive-secret-bootstrap-selectors.py:13`. Their fresh branches require
the marker and retain the full existing reservation/claim/template/reconciliation/
comparison/boot checks. Their historical branches explicitly reject fresh
identity. Genuine older records can still use the historical path with or without
a captured reconciliation. The guest boot prefix now uses the same independent
fresh decision (F `:65`, A `:52`). Each actual generated script is compiled before
SSH (F `:66`, A `:53`). Original raw/directory/source/controller bindings, F's
public metadata checks, A's F-receipt/owner/cgroup/gateway/pidfd/selector checks
and remote script bodies remain in place.

Regression: `tools/rust-v2-lab/test-phase3-fixes.py:39`, with subprocess intercepted
before any SSH, exercises ten cases for each tool:

| Case, for both F and A | Expected and observed |
| --- | --- |
| Valid fresh marker | Reaches intercepted SSH; generated script compiles and includes boot assertion |
| Tampered marker SHA | Refused before SSH |
| Deleted marker on run409 | Refused before SSH |
| Valid marker with historical reconciliation | Refused before SSH |
| Historical run408/declaration | Reaches intercepted SSH, historical script compiles |
| Historical run408 without captured review | Reaches intercepted SSH, historical script compiles |
| Non409 with fresh reconciliation route and no marker | Refused before SSH |
| Non409 with false historical-continuity flag and no marker | Refused before SSH |
| Non409 with false reconstruction flag and no marker | Refused before SSH |
| Non409 with fresh continuity in the record and no marker | Refused before SSH |

All three original other shared-validator functions remain AST-identical to HEAD.
The original historical baseline flag assertion and surrounding body checks are
retained, verified by `historical-validator-check.py` and the 21-test provenance
suite. No historical flags or baseline bytes were altered.

## M1: retain partial inspection output on transport errors

`tools/rust-v2-lab/inspect-run409-state.py:78` compiles the generated remote body
before SSH. At `:80`–`:94`, `TimeoutExpired` and `OSError` become exclusive,
mode0600/fsynced receipts. Available stdout/stderr bytes are decoded with
replacement; strings are retained. Receipts include `error_type`, `error`, and
`error_classification` (`transport_timeout` or `transport_start_error`), and return
124 or 125 respectively. `archival_authorized` and `runtime_acceptance` remain
false. Successful subprocess results retain their original exit/output handling.

Regression: `tools/rust-v2-lab/test-phase3-fixes.py:101` injects a timeout with
partial stdout/stderr, including invalid UTF-8, and a process-start `OSError`
through the actual inspector on a disposable valid provenance fixture. Both
return failure, keep classified receipts and original partial diagnostics,
preserve false authority flags and mode0600, and refuse receipt overwrite.
The actual inspector body passed compilation; no guest was contacted by tests.

## Systemic remote-program audit

| Actual remote program/payload | Compile result and admission coverage |
| --- | --- |
| Bootstrap listing, before and after fixture | PASS; historical bytes equal HEAD; fresh prefix only; both calls reuse the compiled string; before-claim gate and real preflight |
| Bootstrap configured `secret-bootstrap.guest.py` | PASS; historical/fresh generated forms; exact real configuration compiled in preflight before claim |
| Embedded `quarantine_host_declaration.py` | PASS; separately compiled before claim, in addition to its compile in the guest |
| Embedded `host_baseline_declaration.py` | PASS; separately compiled before claim, in addition to existing local and guest compilation |
| Bootstrap SCP transfers | Only static ELF and immutable context tar, no SCP'd Python script; two static ELF architectures and both seven-file contexts independently validated |
| `collect-run409-evidence.py` | No remote program or subprocess; verified by source/AST audit and offline tests |
| `inspect-run409-state.py` generated `REMOTE` | PASS; compiled in the real helper before SSH and in intercepted timeout/OSError tests |
| `phase3-readonly-preflight.py` `REMOTE` | PASS; extracted actual template compiled offline; read-only guest gate also returned0 |
| `fresh-baseline.py` `REMOTE` | PASS; extracted actual template compiled offline; author-helper/source hash unchanged so existing authored provenance stays valid; collection/authoring not repeated |
| F and A generated scripts, historical and fresh | PASS; actual substituted bodies compiled before intercepted SSH, and a runtime pre-SSH compile gate is now present in each |
| `run-native-inspection-preflight.py` `remote` | PASS; actual `python3 -I -c` body extracted/compiled offline; prior platform mapping preserved; no new native execution |
| `run-frozen-host-projection.py` `remote` | PASS; actual `python3 -I -c` body extracted/compiled offline; source/controller hash unchanged; saved original projection envelope revalidated |
| `quarantine_evidence_base.py` | No remote payload; pure local validation only |

`test-phase3-fixes.py:274` audits the additional actual remote templates.
The Bootstrap guest has no other Python stdin/`-c` child program; its two dynamic
Python executions are the explicitly compiled builders. The controller's local
frozen-source verifier is not a remote payload. No further payload syntax defect
was found. F's pre-existing literal-substitution SyntaxWarnings appear in the
offline log when optional metadata is `None`; all bodies compile successfully,
and those remote checks were preserved.

## Mirroring and reservation chain

All four changed restored controllers are mirrored byte-for-byte into their
`tools/rust-v2-lab/target/` counterparts: Bootstrap runner, shared quarantine
validator, F and A. Only their four manifest entries changed in this fixes pass;
the existing native-preflight mapping/entry is preserved. All 293 manifest pairs
match bytes, lengths and SHA256. Versioned/untracked phase3 helpers remain in
their original locations; they have no restored duplicate to mirror.

The existing single tombstone was already occupied. The supersede mechanism was
extended at `tools/rust-v2-lab/run409-reservation.py:98`, `:103`, `:130` and `:196`
to append hash-named later tombstones, verify every retained generation and
transition, and keep the original tombstone unchanged. It preserves lock,
expected-SHA, unspent/collision checks and the existing durable sequence:
exclusive tombstone, hardlink old bytes, unlink active pathname, exclusive new
reservation. Pending/incomplete transitions fail closed. It does not reset or
replace the global consumed-claim path.

`tools/rust-v2-lab/collect-run409-evidence.py:53` now captures all tombstones and
retired generations before validation. `test-phase3-fixes.py:128` covers a second
supersession, preservation of prior bytes, refusal after restoring either older
generation, spent-budget refusal, four interrupted transition boundaries, and
collection of the complete two-transition chain. The existing phase3b controller
error regression adds the now precompiled `listing` to its post-admission fixture
(`test-phase3b-provenance.py`, `test_controller_error_before_raw_is_preserved`);
its original error-preservation behavior still passes.

Reservation generations (SHA256):

1. Original phase3, retained unchanged:
   `3237686154de18668bee6182f24cc405b8c15a2eaa8d8d03e8305b574c1306e4`.
2. Prior phase3b, now retained unchanged:
   `e3366fd4b99201f828c4ed844630007d54c7f4fed24515b9b9211d9838e36ff6`.
3. New active `target/lab-state/run-409-reservation.json`:
   **`533cdbe2da81b91c61902fcb700739922f30fd451578b7e0aea4b80fc0c664c3`**.

Each retired reservation remains at
`target/lab-state/run-409-reservation.superseded-<its SHA>.json`.
Original tombstone `target/lab-state/run-409-supersession.json` retains SHA256
`954f7af81c2912476040f820b5996760f638bf5f0886a739436bed7de35f5ae2`.
New tombstone:
`target/lab-state/run-409-supersession-e3366fd4b99201f828c4ed844630007d54c7f4fed24515b9b9211d9838e36ff6.json`,
SHA256 `3fa930b5cc47825c2def349647907ef4be53c630b98c7cb83e42f23a09880899`.

The new generation binds all 24 required execution/post-run inputs. Before
supersession the stale generation correctly refused controller drift. After
supersession the full chain and bindings pass. **One total budget remains 1,
unspent.** Claim, raw409, controller-error409 and the Bootstrap output directory
remain absent, including dangling-symlink checks. Prior reservation/tombstone
data was never edited in place or deleted. Historical declaration, reconciliation,
projection/comparison/admission, candidate and guest-identity inputs retain their
entry hashes. HEAD/index hashes match entry; no new source change is staged.

## Verification and limits

- Current versioned phase3 reservation suite: 12 checks pass, retaining the
  original ten checks plus the phase3b additions.
- Phase3b provenance/preservation suite: 21 tests pass.
- New fixes suite: 8 test groups pass, including 20 intercepted F/A cases,
  eight before-claim compile-error cases, two inspector transport cases, and
  reservation interruption/preservation/collection cases. The retained RED run
  failed on the original implementations; successive GREEN runs and final8 pass.
- Historical public-binding smoke: 26 checks pass.
- Complete synthetic parser example: 13 wrapper, 30 nested, 24 retained,
  15 owner and 15 driver rows accepted with the original native_poll/result
  two-second Deadline contract. Missing constructor and exit-zero success refuse.
  This is reader compatibility, not run409 output.
- Manifest/source audit: 293 pairs, 594 Python source paths compiled in memory,
  13 explicit `python3 -B -O` refusals. The frozen driver's three diagnostic
  markers are in both its source and amd64 artifact.
- Two-architecture static candidate/context audit: all 203 current build inputs
  equal the frozen source/root proof, static ELF62/183 and both strict contexts
  pass; retained amd64 preflight artifact/log hashes match.
- Full independent authored baseline still matches saved RTM_GET data and frozen
  projection multisets, with original custody/deadline validator preserved.
  Canonical baseline SHA256 remains
  `da3f80f0da4c717443fcb9a2118ed938a6d5c4edeea69d40e755b97291b5a01a`.
- Real controller preflight returned0 with `remote_program_compile=PASS` and
  `[baseline-declaration, guest, host-declaration, listing]`, budget1 and
  `guest_actions_executed=false`.
- Read-only current guest gates pass: protected parents/marker, eight absent
  selectors, admitted namespace, WAN, cached pinned images, Docker active/no
  containers, cgroup2 and direct CPU/BOOTTIME clock syscalls.
- Final strict guest status at 2026-11-04T15:54:25Z: QEMU2147340,
  start tick1616810, matching recorded argv and loopback22036;
  guest boot `e14efc10-050b-41b0-89d8-1e946725098c`, controller boot
  `18f40876-a432-4ad1-9ded-03e0df43559a`. No restart was performed.
- `git -c core.fsmonitor=false diff --check` returned0. Entry preservation audit
  reports zero unexpected changed inputs and unchanged HEAD/index.

**Known historical-fixture limitation:** rerunning
`python3 -B target/smoke-host-projection-controller.py` still returns1 with
`FileNotFoundError` for deleted
`target/continuation-20261028T044917Z/candidate.json`, after its pure synthetic
checks and while subprocess entrypoints are intercepted. This was already
recorded in phase3b; it is not reported as PASS, and no historical fixture was
manufactured. Current provenance tests and frozen projection-envelope checks pass.
The original scratch `target/rebuild-phase3/test-reservation.py` is a retained
pre-schema2 receipt artifact; its maintained versioned successor above was run.

NOT_RUN: run409/all Bootstrap modes, real post-run C/I/P/F/A, selector archival,
all guest network/namespace/nft/container mutations, fresh baseline reauthoring,
new frozen projection/native-filter payload runs, stock exclusive-output
candidate/context verifiers, driver CPU/runtime sampling, ARM runtime, historical
raw398–408 replay/original resource recovery, provider enrollment/connection,
client/soak/release acceptance, independent review and Git publication. Static
equivalents and retained-hash checks cover unchanged candidate inputs without
overwriting their prior evidence. Direct clock probes and parser/preservation
receipts do not establish full Bootstrap witness/runtime acceptance. The phase3b
outcome sequence and historical-gap disposition otherwise remain applicable.

## Exact gate command ledger

Each command below was invoked from the shared checkout through
`python3 -B target/rebuild-phase3-fixes/record-command.py LABEL COMMAND...`.
The receipts retain complete stdout/stderr. Expected negative cases remain
visible; no real reservation was consumed by tests.

| Receipt | Exact command | Exit |
| --- | --- | ---: |
| `fixes-red` | `python3 -B tools/rust-v2-lab/test-phase3-fixes.py` | 1 |
| `fixes-green1` | `python3 -B tools/rust-v2-lab/test-phase3-fixes.py` | 0 |
| `provenance-green1` | `python3 -B tools/rust-v2-lab/test-phase3b-provenance.py` | 0 |
| `fixes-green2` | `python3 -B tools/rust-v2-lab/test-phase3-fixes.py` | 0 |
| `fixes-green3` | `python3 -B tools/rust-v2-lab/test-phase3-fixes.py` | 0 |
| `fixes-green4` | `python3 -B tools/rust-v2-lab/test-phase3-fixes.py` | 0 |
| `sync-archives` | `python3 -B target/rebuild-phase3-fixes/sync-archives.py` | 0 |
| `reservation-tests` | `python3 -B tools/rust-v2-lab/test-run409-reservation.py` | 0 |
| `historical-validator-check` | `python3 -B target/rebuild-phase3-fixes/historical-validator-check.py` | 0 |
| `parser-check` | `python3 -B target/rebuild-phase3-fixes/parser-check.py` | 0 |
| `guest-status` | `python3 -B tools/rust-v2-lab/lab-guest-status.py` | 0 |
| `static-candidate-ssh` | `python3 -B target/rebuild-phase3-fixes/static-candidate-ssh.py` | 0 |
| `provenance-tests` | `python3 -B tools/rust-v2-lab/test-phase3b-provenance.py` | 0 |
| `historical-public-smoke` | `python3 -B target/smoke-quarantine-public-evidence.py` | 0 |
| `legacy-projection-smoke` | `python3 -B target/smoke-host-projection-controller.py` | 1 |
| `fixes-final` | `python3 -B tools/rust-v2-lab/test-phase3-fixes.py` | 0 |
| `guest-gates` | `python3 -B tools/rust-v2-lab/phase3-readonly-preflight.py target/rebuild-phase3-fixes/guest-gates.json` | 0 |
| `preservation-before-rebind` | `python3 -B target/rebuild-phase3-fixes/preservation-check.py --before-rebind` | 0 |
| `supersede409` | `python3 -B tools/rust-v2-lab/run409-reservation.py supersede --expected-sha256 e3366fd4b99201f828c4ed844630007d54c7f4fed24515b9b9211d9838e36ff6 --reason 'Phase 3 review fixes C1/I1/M1: compile every Bootstrap remote program before claim including preflight; refuse fresh-record provenance downgrade in F/A; preserve inspector timeout diagnostics; mirrored controllers/manifest and complete immutable supersession-chain preservation. Prior generations and tombstones retained; one total unspent budget; run409 NOT_RUN.'` | 0 |
| `bootstrap-preflight` | `python3 -B target/platform-lab/run-frozen-secret-bootstrap.py target/candidates/rebuild-20261103T231415Z/candidate.json debian-clean-x86_64 bootstrap409-driver-cost success --reservation target/lab-state/run-409-reservation.json --preflight-only` | 0 |
| `diff-check` | `git -c core.fsmonitor=false diff --check` | 0 |
| `preservation-final` | `python3 -B target/rebuild-phase3-fixes/preservation-check.py` | 0 |
| `final-guest-status` | `python3 -B tools/rust-v2-lab/lab-guest-status.py` | 0 |
| `final-audit` | `python3 -B target/rebuild-phase3-fixes/audit.py` | 0 |

Optimized-Python subcommands in `audit.json` each return1 with
`optimized_python_refused` before work:

- `/usr/bin/python3 -B -O tools/rust-v2-lab/fresh-baseline.py` — exit1
- `/usr/bin/python3 -B -O tools/rust-v2-lab/run409-reservation.py` — exit1
- `/usr/bin/python3 -B -O tools/rust-v2-lab/phase3-readonly-preflight.py` — exit1
- `/usr/bin/python3 -B -O tools/rust-v2-lab/collect-run409-evidence.py` — exit1
- `/usr/bin/python3 -B -O tools/rust-v2-lab/inspect-run409-state.py` — exit1
- `/usr/bin/python3 -B -O tools/rust-v2-lab/test-run409-reservation.py` — exit1
- `/usr/bin/python3 -B -O tools/rust-v2-lab/test-phase3b-provenance.py` — exit1
- `/usr/bin/python3 -B -O tools/rust-v2-lab/test-phase3-fixes.py` — exit1
- `/usr/bin/python3 -B -O target/quarantine_evidence_base.py` — exit1
- `/usr/bin/python3 -B -O target/inspect-secret-bootstrap-failure.py` — exit1
- `/usr/bin/python3 -B -O target/archive-secret-bootstrap-selectors.py` — exit1
- `/usr/bin/python3 -B -O target/platform-lab/run-frozen-secret-bootstrap.py` — exit1
- `/usr/bin/python3 -B -O target/platform-lab/run-native-inspection-preflight.py` — exit1

## Final run409 command — recorded only, NOT_RUN

```sh
python3 -B target/platform-lab/run-frozen-secret-bootstrap.py target/candidates/rebuild-20261103T231415Z/candidate.json debian-clean-x86_64 bootstrap409-driver-cost success --reservation target/lab-state/run-409-reservation.json
```

Only the same argv with final `--preflight-only` was executed. The command above
would consume the sole claim before any guest action. This report supplies no
runtime result or additional execution authorization.
