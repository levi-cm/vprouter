# Task 15 acceptance scaffolding — preparation only

**No Task 15 acceptance evidence exists. `release_ready=false`.** Task 8c runtime
and managed-client acceptance remain OPEN. The synthetic fixtures here test a
validator; they do not demonstrate protected traffic, leak containment, identity
preservation, migration, benchmark success, a supported platform or a release.

The binding inputs are [IMPLEMENTATION.md](IMPLEMENTATION.md), including Mandatory
acceptance and the local-testing amendment, [acceptance.json](acceptance.json),
[security-evidence-map.md](security-evidence-map.md), and both testing-2026-10-26.md
and testing-2026-10-29.md. The acceptance input is read-only and unchanged. Testing
will eventually require real Tailscale and Mullvad protocol traffic from local
systems. Remote installation access is outside scope.

## Offline commands

Run from the repository root, with Python 3, standard library only, Linux/glibc
for optional exclusive publication. `-B -I` is required; optimized Python is
refused. Commands have no network, capture, subprocess, sudo or host-control path.

```sh
python3 -B -I -m unittest discover -s tools/acceptance -p 'test_*.py'
python3 -B -I tools/acceptance/acceptance.py ledger
python3 -B -I tools/acceptance/acceptance.py rules
python3 -B -I tools/acceptance/acceptance.py fixture --configuration five_mullvad_one_direct --scenario migration.activate
python3 -B -I tools/acceptance/acceptance.py check --input tools/acceptance/fixtures/one_mullvad.bundle.json --expected tools/acceptance/fixtures/one_mullvad.expected.json
python3 -B -I tools/acceptance/acceptance.py preflight --plan tools/acceptance/canary-plan.json --declarations tools/acceptance/prerequisites-not-run.json
```

`check` returns 0 only for the **synthetic oracle**, 1 for a reported forbidden
egress and 2 for missing/invalid evidence. Its `acceptance_status` remains
UNVERIFIED on synthetic oracle PASS. `ledger` returns 0 for successful enumeration,
even when every gate is NOT_RUN; its exit code is not an acceptance verdict.
`preflight` always returns 2 and status NOT_RUN: it never executes the plan,
even if a caller declares all prerequisites PASS. Other errors use exit 2 with
a constant redacted JSON response; untrusted arguments, paths and values are not
included. `plan`, `declarations` and `fixture` emit reproducible data only.

## Ledger and status rules

[acceptance.py](../../tools/acceptance/acceptance.py) validates the entire input
before enumeration: exact fields, configuration counts, unique configurations,
all nine fault groups and all 71 fault names, all 11 global gates, exact traffic
and observation sets, and the binding local scope. Release-ready input is refused.
Duplicate keys, unknown fields, UTF BOM/UTF-16/invalid UTF-8, non-ASCII strings,
surrogates/control characters, fractional/exponent/nonfinite numbers, negative
integers, integers beyond signed 63-bit, bool-as-integer and excessive size/depth
are refused. Status spelling is exact; invalid source status refuses the input.
Unknown/skip observation statuses resolve UNVERIFIED and block claims.

The source ledger still has its original 71 fault names. Supplemental requirements
come from [mandatory-requirements.json](../../tools/acceptance/mandatory-requirements.json),
derived phrase by phrase from the spec by the explicit, reviewable mapping in
[build_requirements.py](../../tools/acceptance/build_requirements.py). Its entries
bind each spec phrase to a requirement ID, scenario IDs and configurations. The
completeness test extracts the failure list from IMPLEMENTATION.md independently,
checks every phrase and slash-separated item, then requires their matrix bindings.
It also checks migration lifecycle and journal/I/O operations independently.

The matrix has 1,535 rows:

- 71 faults × four configurations = 284 original mandatory fault cells.
- Per configuration: five traffic checks, four capture-point checks, positive
  controls and boot-capture-before-traffic = 44 additional explicit cells.
- Ten new fault IDs × four configurations = 40 cells: container restart,
  Tailscale freeze, wrong peer, route drift, identity/control/name revocation,
  and separate migration drain, stop and rename. The original `drain_stop`
  row is retained only as a legacy source row; it cannot satisfy the split IDs.
- 44 migration lifecycle and I/O operations × apply/resume/rollback × before/after
  × four configurations = 1,056 cells. Journal create/write/verify/file-fsync/
  rename/parent-fsync, release exchange, cleanup intent and terminal publication
  are independently addressable, as are adapter and service transitions.
- 25 marker/status/scope/artifact IDs × four configurations = 100 cells.
- Eleven global gates, including the two local migrations and 24h mixed soak.

Each fault bundle must itself cover every traffic protocol and every capture
point for every exit. No scenario in direct mode is silently skipped as inapplicable.
Every migration I/O ID additionally requires a future producer to sweep every
actual write chunk, staged file, journal generation and adapter ordinal. The
fixed operation/edge inventory is preparation; no native checkpoint coverage or
runtime boundary execution is established by enumerating these IDs.
Global review/platform/performance/canary gates remain unverified when a source
claims PASS: this scaffold has no trusted evaluator for those gates.

`ledger --observations OBSERVATIONS_JSON` accepts an exact object with
`schema_version:1`, `candidate_sha256`, and `observations`. Each observation has
`configuration`, `scenario`, `requested_status`, `bundle`, `bundle_sha256`,
`expected_run`. Run admission is an explicit caller input, never derived from
the bundle. It has the same contract as the separate check input below.
Duplicate/unknown row bindings refuse the input. Evidence is bound to the actual
acceptance-input byte hash, explicit candidate digest, exact configuration/scenario
and external bundle digest. Existing FAIL cannot be overwritten by later PASS.
A missing bundle cannot pass. Synthetic bundles always leave the row UNVERIFIED;
a reported forbidden egress makes it FAIL. Unexecuted rows remain NOT_RUN.
There is deliberately no real-acceptance PASS-producing path in this preparation.
With a fully valid synthetic bundle, an unknown/SKIP requested status can retain
`oracle_status=PASS` for content validity beside row `status=UNVERIFIED`. Consumers
must use row/acceptance status for gate admission. This is the M3 distinction.

## Evidence bundle and capture oracles

[evidence-schema.json](../../tools/acceptance/evidence-schema.json) describes the
closed bundle structure; `$defs.expected` describes the separate external binding
and `$defs.envelope` the fixture generator output. The Python validator adds the
strict decoder and semantic rules that JSON Schema alone cannot express.

The bundle includes exact candidate/ledger/configuration/scenario/run bindings,
synthetic fault injection and boundary, expected/actual result, cleanup/ownership,
one monotonic epoch, integer traffic windows, capture summaries and an immutable
manifest. Digests are lowercase SHA256. They bind canonical ASCII JSON with sorted
keys, compact separators and no trailing newline; published reports add one newline
and their filenames hash those exact published bytes. Formatting of input JSON is
not evidence: original ledger input bytes are separately hashed. The synthetic
candidate digest is deliberately `a` repeated 64 times, not a real artifact claim.

The external `--expected` object requires `expected_run` with `run_id`, `epoch`,
`not_before_ns` and `not_after_ns`. These are independently supplied by the caller's
run-admission authority. The context run ID and every capture/traffic epoch must
match, and the entire capture and traffic windows must fit that integer interval.
Freshness is relative to this external admission, without consulting wall time.
Relabeling/resealing a producer bundle cannot change the independent run object.
The deterministic fixtures contain example admission values only. This stateless
validator does not authenticate that authority or consume admissions: replaying
the same valid bundle/admission can still pass the synthetic oracle again. Real
producers need authenticated, fresh, one-use admission and a replay store (M1).

Each capture covers one point and one exit, with the selected mode checked against
the configuration. Its source is the canonical byte representation of a small
synthetic marker-record array; its `source_sha256` and counters are independently
recomputed. These arrays are not pcap or network observations. No packet parser
or network-capture implementation is included.
Forbidden-marker checks validate producer classifier summaries and exact synthetic
labels; they cannot independently derive cross-exit routes or host-IP equivalence
from packet bytes. Identical records across scenario fixtures provide no independent
origin/exit evidence. Packet parsing and classifier correctness remain NOT_RUN (M2).

For every protocol at every point/exit, positive controls must appear both before
and after traffic, and allowed synthetic workload records must appear during it.
Start ≤ ready < traffic start < traffic end < stop, on one epoch, with ordered
records. Equal capture-ready/traffic-start timestamps fail the oracle; there is
no wall-clock comparison, float rounding, clock reset accommodation or cross-boot
inference. Large integer nanoseconds retain exact one-nanosecond boundaries.
Missing controls, coverage, source bytes, counter consistency or zero-drop proof
cannot pass. A nonzero forbidden plaintext/cross-exit/host-as-Mullvad count or
matching synthetic source marker makes the oracle immediately FAIL, including an
incomplete bundle. Direct egress is expected only for the explicit direct exit;
its synthetic allowed records confer no protected-client claim.

Reports use an exact field/value allowlist. They contain enumerated scenario IDs,
controlled reason codes and digests, never arbitrary producer text, paths, users,
credentials, keys, identity records or IP addresses. Unknown strings and redaction
fuzz inputs cannot be echoed into a report. Digests are integrity references, not
credentials; future producers must separately prove that secret/key bytes never
enter public evidence fields. Hash consistency cannot prove producer honesty.

Optional publication uses `--publish-dir EXISTING_PRIVATE_DIRECTORY` on ledger,
check or preflight. The directory must already exist, be owned by the invoking
user and have mode 0700, with no symlink in its path. Publication pins every
component using directory FDs, creates an exclusive random temporary file,
writes and makes it 0400, fsyncs it, uses Linux `renameat2(RENAME_NOREPLACE)`, then
fsyncs the directory. No overwrite fallback exists; existing files/symlinks and
concurrent winners remain intact. A temp-name collision never removes the other
invocation's name. Parent-path replacement cannot redirect the pinned destination.
If final directory fsync fails, visible published bytes are retained and durability
is reported unknown. Retry refuses the existing name; it does not silently repair
or certify uncertain durability. Read-only mode and hash names protect the tool's
append-only interface; they are not filesystem WORM protection against the owner
or root. The private directory assumes cooperative processes under the same UID;
malicious same-UID mutation of temporary files is outside that custody model.

Bounds: 1 MiB input/output, depth 32, 100,000 JSON nodes, 1,024 characters per
string, 4,096 array members, 128 object fields, 24 captures and 128 records/capture.
Inputs must be singly linked regular files. The reader pins directory descriptors,
opens each file with O_NOFOLLOW and O_NONBLOCK, acquires a nonblocking shared flock,
and performs **one bounded os.read** into memory. A short read refuses rather than
assembling chunks. It compares fstat identity, size, timestamps, mode, owner/group
and link count before/after acquisition, refusing observed changes. It hashes that
exact buffer before parsing it. Check reports carry `input_sha256` and
`expected_sha256` for the acquired raw bytes, including whitespace; the existing
bundle/manifest digests still bind canonical JSON. Validation and publication use
only those in-memory snapshots and never reopen the input paths. Filesystem
identities and timestamps never enter reports.

Input handoff is explicitly **cooperative**: a producer must hold exclusive flock
while mutating a handed-off inode, or atomically publish a complete file and leave
that inode unchanged. Shared-lock contention refuses immediately. Before/after
metadata equality alone cannot prove immutability, and a single read is not a
kernel atomic-snapshot guarantee against an arbitrary concurrent writer. Same-UID
writers bypassing handoff and root are outside that custody model. The regression
does real same-size writes after acquisition starts; two invalid versions cannot
be stitched into the previously observed synthetic PASS. Separate regressions
check partial reads, metadata changes and replacement after acquisition.

## Local preserved-identity canary plan

[canary-plan.json](../../tools/acceptance/canary-plan.json) is data, not a runner.
[prerequisites-not-run.json](../../tools/acceptance/prerequisites-not-run.json)
records every prerequisite NOT_RUN. Preflight requires all declared prerequisite
keys, exact plan/scope, and an evidence digest for each declared PASS. Even a
complete declaration is only DECLARED_ONLY and cannot execute or establish truth.

The prerequisite set includes Task 8c completion, reviewed complete implementation,
immutable candidate/artifacts, whole-branch and namespace/firewall/unsafe/client
reviews, local guest/disposable clients, credentials, positive controls at all
capture points including boot, every fault matrix, prior compatibility/security/
artifact/performance gates, both preserved local identities, declared adapters
and hostname dependencies, stopped-state compatible rollback, no concurrent
identity copies, explicit direct authorization and a full 24-hour window.

The ordered cases are:

1. Local debdev: preserve the existing primary identity, credentials, addresses
   and approval through cutover/rename and actual protected-client verification.
   Do not clone, reset or reenroll it. Additional imported device profiles must
   remain distinct. Enable direct only by explicit authorized configuration.
2. A separate local legacy installation with its independently established test
   identity and declared adapters: cutover and compatible release **and state**
   rollback preserve that identity. Label it local compatibility-deployment
   migration; no remote installation was validated.
3. After preceding gates: 86,400 seconds of continuous mixed traffic/fault soak,
   retaining every failed attempt and per-exit observations.

The plan records exact argv templates and prerequisites, all NOT_RUN. Inspect and
plan are observational CLI commands; apply/rollback argv are explicitly future,
unimplemented interfaces, and the capture/fault/soak controller is explicitly
`ACCEPTANCE_CONTROLLER_NOT_IMPLEMENTED`. Placeholder uppercase arguments must be
bound to reviewed local inputs later. These templates are not runnable instructions
for the current candidate and no executor interprets them. All migration boundaries
(inspect through recover) require kill/resume/reversal cases, private stopped-state
backup, quarantine before cutover and compatible offline recovery on uncertainty.

Still needed: real credentials/profiles, disposable clients, preserved-identity
local canary hosts/guests, boot-capable independent capture instrumentation,
reviewed lifecycle/rollback adapters, trusted redacted source/artifact/provenance
records, actual supported-host checks and the 24h soak. Unmanaged/non-Linux clients
have no guarantee. Unavailable platform/hardware tests remain explicitly unverified.

## Invariant registry and tests

`acceptance.py RULES` and `rules` output are the authoritative invariant/rule
registry, with one enforcement function and one named behavioral mutation test
per entry. [security-test-map.json](../../tools/acceptance/security-test-map.json)
maps all 12 existing security-map rows to future fault groups/global gates and
the scaffold oracles; every runtime status is NOT_RUN. It hash-binds its source
map and is checked for all nine groups and all 11 gates.

The test suite checks registry completeness, missing/unknown/type-mutated evidence,
every bundle leaf with missing/null/wrong-type/NaN/huge/duplicate-key and
cross-scenario perturbations (identical-value swaps leave valid content), external bindings,
producer-resealed semantic mutations, exact large-clock boundaries, redaction fuzz,
all configurations, reproducible fixtures, source statuses, monotonic failure
retention, canary prerequisites, single-read input snapshots, atomic publication,
competing writers, symlink collisions, late destination races, pinned parent
replacement, and file/directory-fsync failure. RED observations and exact final
validation commands are in [task-15-report.md](../../.superpowers/sdd/rust-v2/task-15-report.md).
