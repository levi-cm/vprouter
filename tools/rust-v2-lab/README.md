# Rust v2 local lab controller source archive

This byte-for-byte archive saves the controller and evidence-validation programs
that were developed under ignored `target/` paths. The source manifest records
all 293 original relative paths, sizes and SHA256 hashes. Private keys, profiles,
VM disks, image contexts, raw traces, captures and identity state are excluded.

Run 410 adds three separately named Bootstrap runner/failure-inspector/selector-
archiver sources (296 manifest entries total). Its reservation, provenance,
collector, state inspector and offline tests live alongside this README. They
use `run-410-*` and `bootstrap410-driver-cost`; the consumed 409 reservation,
claim and original controller paths are not reused. The 410 runner always
requires its explicit reservation, including `--preflight-only`, and compiles
all four remote Python programs before any claim. Collection preserves recursive
baseline references as well as bound inputs. Full Bootstrap witness validation
and runtime/release acceptance remain separate from preservation receipts.

Run 411 forks those controls for `debian-arm64` / `bootstrap411-arm64`, using
only its own `run-411-*` reservation/claim/raw chain. Its candidate is the same
frozen run410 candidate's ARM64 payload/context, with an independently authored
ARM64 baseline. `source-manifest411.json` adds the four restored/archive source
pairs without changing the original manifest. `start-clean-debian-arm64.py`
requires the completed qualified sandbox bisect, no live QEMU, a verified base,
and absent state; it starts a 1024 MiB TCG guest with fresh AAVMF VARS/seed/overlay.
`fresh-baseline.py` and `phase3-readonly-preflight.py` accept `--platform
debian-arm64`; the latter checks aarch64 clock syscall113 and enp0s1, with no
registry image pull/inspection prerequisite because the fixture is FROM scratch.
The strict context inventory binds its pinned public programs offline. Run411
F/A refuse other run numbers before opening raw records. The shared 411 path
guard refuses both 409 and 410 claims, reservations, consumed markers, raw
records and evidence directories, plus `/DATA/vprouter-lab/preserved`, before
content opens or copies. It rejects symlink aliases and multiply linked
regular inodes. The four existing `target/{lab-state,candidates,run411-prep,
platform-lab}` storage bridges are translated to their exact
`/DATA/vprouter-lab/` backing paths after checking link text and inode identity;
opens never traverse those links. Admitted reads walk directories with `O_NOFOLLOW` and compare
the opened inode before reading. The frozen candidate exception permits its
ARM64 payload/context/source, candidate/root verification, and fresh ARM64
baseline/projection/411 output; old x86 evidence remains forbidden. Collector
bindings, tombstones and recursive references use this guard before capture,
while admitted 411 raw bytes are preserved before provenance validation.
See the ARM64 preparation report for actual status,
measured lab budgets and the exact command; preparation never authorizes execution.

Run 409's cleanly powered-off overlay and original records are read-only in
`/DATA/vprouter-lab/preserved/run409-guest/`; never boot that overlay writable.
Its cold disk preservation supersedes selector archival, which was not run.
The preparation report records the new guest/candidate/baseline and exact 410
command. Preparation does not execute or authorize the experiment.

These are development/test implementations, including historical variants.
Many expect their original `target/` working-directory layout, local ephemeral
VM ports and protected Root-owned lab markers. Do not execute this archive as
an installer or production runtime. Only the root controller may authorize
privileged local VM tests after verifying the exact frozen source and artifacts.

The checkpoint preserves progress; archived scripts are not an approval of
all test procedures or evidence. Source and runtime acceptance remain separate.

`parse-bootstrap-cost-diagnostics.py` is a separate maintained, read-only reader
for failed `secret_bootstrap_success` records with the fixed Deadline diagnostic.
It validates closed boundary fields, all13 wrapper rows, all30 nested rows,
the optional exact24 retained-cost rows and optional exact15 owner-cost rows,
plus an optional all-or-none driver extension: exactly13 ordered parent-thread
CPU rows, one existing-sleep row and one constructor-prefix row. Driver fields,
labels, order and canonical u64/u128 values are closed; CPU calls must match the
wrapper calls and sample/error counts must saturating-sum to calls. Without a
valid CPU or constructor sample, duration must be zero. Sleep requests equal calls times
1,000,000ns before call-count saturation; at saturation the accumulated request
may be larger. Complete driver rows append only `driver_cpu`, `driver_sleep`,
`driver_constructor` and a fixed `driver_scope`; absence preserves historical
metadata bytes. CPU brackets the parent thread, includes observer work and
excludes children. CPU/wall attribution requires complete unsaturated helper
rows; differing wall spans, clocks, observer effects, failed samples and original
constructor scalar precision limit inference. No scheduling cause, off-CPU
subtraction, exclusive sum or fit follows. The reader then exclusively creates
bounded mode0600 metadata at its second argument. Nested rows
overlap and are never summed. It does not contact a VM or grant state authority.
This reader is outside the293-file historical archive manifest.

`allocation-comparison-cost.rs` preserves the separate offline pure-comparison
experiment harness. It reads two allocation JSON fixtures supplied as arguments;
private fixture values and binaries are excluded. Its host compiler/dependency
bindings and results are recorded in the allocation-comparison cost report.
This experiment does not measure native VM cost share or release performance.

`digest-hex-cost.rs` preserves the separate actual-library digest experiment.
It uses only synthetic public byte fixtures, with no arguments, files or network.
Compile it in an isolated target-only Cargo project with path dependencies on
`vprouter-worker` and `vprouter-core`, sha2=0.11.1 and serde_json=1.0.150. The
original experiment binds frozen source17c914f4 and its repository lock; a later
changed library is a different oracle and cannot reproduce the original result.
The experiment report records the exact manifest/lock/profile, seven fixed
alternating batches, all samples and limits. Host timings do not establish native
VM savings, Bootstrap acceptance or release performance. This harness is outside
the293-file historical archive manifest.

Run411 review round 2 carries acquired bytes through every evidence consumer.
`run411-reservation.py.acquire` is the shared input boundary: it pins directory
components, rejects forbidden names/aliases, compares the first admitted inode
with the `O_NOFOLLOW|O_CLOEXEC` descriptor, checks type/link count and stability,
reads once and hashes those bytes. Per-operation capture scopes share snapshots
across hashing, JSON parsing, helper compilation and validation. The runner's
frozen-source verifier and context checker consume bytes; SCP sources are sealed
anonymous descriptors inherited explicitly with `pass_fds`, never the admitted
source filenames. OpenSSH identity and known-host inputs use exclusively created
0600 copies inside a private 0700 directory, populated from guarded snapshots;
all SSH/SCP commands use those private copies. Controller outputs use exclusive
guarded creation.

`TMPDIR=/var/tmp python3 -B tools/rust-v2-lab/test-run411-acquisition.py` runs the
static consumer boundary and full-runner replacement matrix. Admission, raw
record publication and SSH/SCP are intercepted in that matrix; only synthetic
scratch outputs are created. It covers the reviewer's 18 downstream cases,
preserved variants, both transfer sources, and post-stat inode races. Static
checks also pin complete subprocess/connection expressions and embedded guest
program literals. The exact permitted host opens and guest-only exceptions are
listed in the prep report's Review round 2. Real run411 remains NOT_RUN; changed
bindings require append-only supersession while retaining the single global
claim and one total budget.
