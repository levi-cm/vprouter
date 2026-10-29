# Task 8c.1 publication scope review

2026-10-29. Read-only scope/sensitivity audit against base
`b678e7bf98e0c311109ce82a3893b40127ef0825`; no Git/source/runtime mutation,
VM/SSH/Docker/privilege/credential access, build, or subagent work. Only this
report was created. Root alone stages, commits and pushes the authorized
checkpoint on `rust/v2`.

**Publication-content verdict: PASS for the inspected bounded checkpoint.**
This is not the independent functional/specification review of slice8c.1 and
does not certify native Bootstrap, autonomous recovery, client traffic or
release. The independent slice review subsequently landed with scoped
specification PASS and quality PASS, no findings; I read that report. New failure
localization and coherent build evidence remain separately scoped below. Reconcile
review-status wording before describing the milestone as independently verified.
Do not label raw398 as accepted Bootstrap.

## Exact intended scope

Six Rust files match the exact SHA256 values in
`task-8c-1-review-package.txt` and `task-8c-slice1-report.md`:

```text
crates/vprouter-worker/src/operation.rs
  2ec561f7beac44fe84a542baff1c0d37152303f22dffa323b32d7422e85c1771
crates/vprouter-worker/src/engine.rs
  5b7045736012a472573af427ad65b20f1e70fd8d5e63957607ffc2ea477b894a
crates/vprouter-worker/src/engine/tests.rs
  dd3e39bfb7d3e6f1b26cff59656d8bfa46e25e1972c157c8dac38cb5b76196b9
crates/vprouter-launch/src/handoff.rs
  da8e6c7b07bcbe3eca9bc44ed398e4eaaa33cd98a9b7162950671adf1a6585c7
crates/vprouter-launch/src/transport.rs
  ba7d139e1370205ec223a0c13236713b8fdadf28ccaaebd0d1419cac296b51ab
crates/vprouter-launch/src/expiry.rs
  914033572568cfa628bda81a7f38b1611286a581df3493d90f1950a8f105ba21
```

The source delta is confined to the policy receipt/failure-ordering slice and
its associated tests: 409 insertions, 19 deletions across the six files. No new
dependency, manifest/image-context change, syscall, unsafe block, capability,
process constructor, secret input or unrelated source module is introduced.
The source/package contains test bindings and hashes, not runtime credentials.
The private wire change requires later coherent host/worker artifact freezes;
unchanged existing manifests are not qualification of this delta.

Safe related documentation is the additive progress ledger, task-8c-1-brief.md,
task-8c-brief.md, task-8c-report.md, task-8c-slice1-report.md, task-8-report.md,
task-8c-bootstrap-fixture-audit.md, this report, and the exact source review
package plus independently authored review/localization reports when available.
The brief's protected-profile/identity instructions contain requirements only,
not actual secret material. New reports should preserve component/native/client
scope distinctions and original failures. No historical failure should be
rewritten or silently replaced by a corrected collector result.

The public redacted failure summary
`docs/rust-v2/task8c-bootstrap-attempt398.json` is also in scope. It contains only
source/artifact/controller hashes, public result fields and preservation
booleans. Private `target/` payloads, source archives, contexts, raw stdout/stderr,
profiles, keys, VM state, identities, sockets, captures and runtime resources
are outside this publication scope.

## Safe controller archive

Only these two controller source files were added under
`tools/rust-v2-lab/target/platform-lab/`:

| File | Bytes | SHA256 |
| --- | ---: | --- |
| run-frozen-secret-bootstrap.py | 10050 | 565ecefd0472be62e53c927bb6875519440fb95b4516749386501c11cc52eb8c |
| secret-bootstrap.guest.py | 22319 | 12a4d66ec4284a6d5de06bb3ac9fa6387514b94a4d7f3b78d9d8f525b86548a1 |

Both archived files are byte-for-byte equal to the independently reviewed active
`target/platform-lab/` files. The manifest preserves all 285 prior entries
exactly, including order, and appends exactly two entries. No existing entry was
changed or removed. I independently checked sizes and SHA256 for **all 287**
archived files. README count is 287; final manifest diff adds only 12 lines.

The new code retains frozen source/artifact/context checks, protected exact
selectors, independently authored preservation-only baseline, new synthetic
profiles and inert gateway, exact original identity checks, and original
failure/resource retention. The archive does not contain actual key/profile
files. Its `PrivateKey=` string is the code that composes a newly generated
synthetic profile inside the owned guest; no private key value is embedded.
Its peer public key and synthetic endpoint are public fixture data. Local VM
ports/key-file path references are controller configuration, not key contents.
README continues to prohibit treating the archive as an installer/runtime or
blanket procedure acceptance.

## Bootstrap398 is an original preserved failure

The public failure summary independently matches
`target/lab-state/actual-program-run-398.json`:

- Original raw record SHA256
  `6fb3bacc8b02f913b8ae2e90f2d8d0ceb3801a7a217b09a88533de2e0f74e34a`.
- Old frozen b51 source/archive binding and original amd64 artifact, runner and
  guest hashes agree exactly. This is not execution of the new six-file slice.
- Exit 1, 14.175 seconds, zero completed cases, no LAB_SECRET_BOOTSTRAP witness,
  diagnostic `secret_bootstrap_lab: ownership_mismatch`.
- Outer original-controller observations preserve prior host structural state,
  the inert gateway/native identity, one exact DOWN endpoint, absent owner unit,
  and original canonical/mount resources. Six fixed selectors were retained.
- `native_bootstrap_accepted=false`, no cleanup/retry claimed, production false,
  real-client acceptance NOT_RUN. Localization is initially UNLOCALIZED; any
  later diagnosis must be separately labeled source analysis until runtime
  proof establishes its exact failure location.

The public summary hash at this inspection is
`8e1d9c54a5210cc8c9ae7869bfbfeb3ba15b272468a40120cf3e5e7c2efbb624`.
Progress now includes this failure explicitly and retains full8c ACTIVE/open
native/runtime/client/release gates. Earlier audit wording of native NOT_RUN is
historical pre-execution scope, not a claim that398 passed or did not occur.

## Checks and final publication conditions

Performed here: read-only Git status/diff/stat and `git diff --check` (PASS);
six-file review-package hash binding (PASS); all287 archive size/hash checks
(PASS); original285 manifest entry equality/order preservation (PASS); two
new active/archive byte comparisons and Python AST compilation (PASS); redacted
398 summary binding to original failure/preservation observations (PASS); bounded
credential-pattern search and contextual reading (no embedded credential found).
No complete controller or guest was executed. No new Rust tests/builds were run
by this auditor. Root's inspected existing test logs record launch147 and
worker62 passes, focused Clippy success; these remain component checks.

At the latest inspected status, tracked changes were precisely the six Rust
files, progress ledger and archive README/manifest. Untracked safe additions
were the public398 summary and two archived controllers; ignored report/brief
files require Root's deliberate exact-path inclusion. Do not stage the ignored
target tree or unrelated untracked files as part of this checkpoint.

Remaining publication bookkeeping: include the independent slice review report
and actual verdict, append the read-only398 localization report when supplied,
and update task-8c-report.md, slice1 report and parent evidence index from
"review pending" only to the exact bounded review result. Full8c remains
IN_PROGRESS; current delta native/static cross-platform qualification,
Bootstrap family collector/acceptance, autonomous rebootstrap and all broader
runtime/client/performance/migration/soak/release gates stay open. Any additional
source/archive byte changes invalidate the exact hashes above and require a
narrow refresh. No functional review finding is waived by this content audit.

## Addendum: slice review and coherent manifest refresh

I read `task-8c-1-review.md` after it landed: specification PASS and quality PASS
for exactly the six hashed source files, no severity findings. It explicitly
excludes native/runtime/client/release/task9 acceptance and requires coherent
host/worker artifacts. That public report is safe and in scope. The final Root
checkpoint documentation should use this bounded result instead of the initial
"independent review pending" text.

Root then started a coherent offline static build/context refresh, outside this
auditor's actions. `docs/rust-v2/programs-amd64.json` and `programs-arm64.json`
are legitimate additional publication paths for that freeze. The observed
manifest diffs change only worker_observer and worker_monitor SHA256/byte sizes,
with no new role, executable path, execution policy, capability or authority.
Root retains final artifact/source/context hash verification. The independent
read-only completion check below supersedes the earlier pending-build status.
This content audit does not equate manifest regeneration with runtime acceptance.
Any build failure belongs in the evidence and must not be erased by later success.

### Coherent freeze completion check

I independently checked
`target/continuation-20261029T124811Z/candidate.json` and Root's small
`root-verification.json`. The frozen source snapshot is
`5a224c16a79c1e90f0d720e41cdbbc2e816d9580`, source archive SHA256
`8338b7b0f7ba7c10fb87716f1bd3a059ffff024349c6a15edbec96b5e460973e`;
binding records 202 verified inputs and aggregate
`8fc6f85b3b9ceb20c0942117e845ad127f920730d70245f50e48ede305c9af22`.
All six reviewed current Rust files and both current program manifests exactly
match the frozen archive bytes. The original six source hashes remain unchanged.

Both payload SHA256 values and static ELF architecture/no-dynamic-loader checks
pass independently. I executed only the existing read-only
`attachment_context_check.py::context_check` against both retained candidate-local
contexts and the frozen source. Both pass its exact seven-public-file whitelist,
fixed daemon/CA/source/base digests, archive metadata, program manifest
bytes/hashes/sizes and static ELF checks. No image/context was built or run by
this audit. Generated manifest diffs were independently machine-checked to change
only observer/monitor hash and size values, retaining all other fields and order.

| Architecture | Payload SHA256 | Context SHA256 |
| --- | --- | --- |
| amd64 | 9c55d3c89a2585591d713a08f9cb68435882537447e1d7c0fbfa4cfb20bfa30d | 18cc5dedb0104215b397414e35b0fe8282cb6bf27c40853671f9daafa1bbeea2 |
| arm64 | ea86ea3144f5651feb4fa545bc8d3074ba067316e1c0e78fd9bba53acbe3212b | 09e3e0bafa975c4998fc3da9d1d9fe5e54c82a0d75b6e23b2f4a55d4b7219d07 |

Root proof SHA256 is
`ae2abcfa870523623c7ddcaf5ccc75cec9f6fff8a047a8e5137b6a74c5f98746`;
the executed read-only context checker SHA256 is
`66be3dc0ba17ec34e551a39f37218259af8df5d3eb996f9f7986f4bdf37b9635`.
Root proof reports amd64 filter preflight PASS, ARM64 runtime NOT_RUN, native
receipt runtime NOT_RUN and release_ready=false. I did not rerun preflight or
verify all202 current/Git inputs independently; Root's proof supplies that wider
binding, while this audit directly checks the six source/two manifest bytes.
These artifact and manifest checks close the publication coherence prerequisite
only. No native receipt, successful Bootstrap or runtime acceptance is inferred.
