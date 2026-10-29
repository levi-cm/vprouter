# Independent review: run406 and digest-hex requirements

2026-10-29. Read-only review before the separate mechanism experiment review.

| Dimension | Verdict |
| --- | --- |
| Run406 diagnosis | **PASS** |
| Experiment requirements | **PASS**, within the already authorized target-only scope |
| Conditional one-file implementation requirements | **PASS** as requirements |
| Requirements quality/feasibility | **PASS**; no actionable revision identified |
| Application implementation readiness | **NOT AUTHORIZED**: actual experiment and independent review remain pending |

These verdicts approve the reasoning and bounded requirements. They do not
accept experiment results that do not yet exist, authorize application edits,
establish native cost savings or change any runtime/release gate.

## Exact binding

| Document | Independently verified SHA256 |
| --- | --- |
| `task-8c-bootstrap406-diagnosis.md` | `e37a5160cf446fc245f3742b399392a72affd8f5a11ae779f0dc8b461312f2e2` |
| `task-8c-digest-hex-experiment-brief.md` | `b9f4641b857ef1b95cf9921c8f8e6155c28226774ea7205496d4735f04e44c3e` |
| `task-8c-digest-hex-implementation-brief.md` | `0ec4fb2dc62edfa77cbd7f958469ef5b135e58cc5da07baabab585c107b48c47` |
| `docs/rust-v2/IMPLEMENTATION.md` | `353f0e82d9dcf7b3e1216c27ac4c505bdc8fa6ee06ee3e6b833f1d3e11594125` |
| Current worker `src/bootstrap.rs` | `1ddbb31c0e0a058fbc68522b17688d37bf0923282261f3accf83ad86b79fcff5` |

Root's frozen source context is `17c914f4`. A read-only comparison found all179
current Rust paths still matching the retained-cost after-hash snapshot. The
briefs name the later documentation checkpoint1188b26; their source target
remains the same frozen helper. No Git operation was used to make these checks.

## Diagnosis verification

The retained raw406 record, closed metadata, saved inspection, candidate and
current-only resource observation were read and independently hash-verified:

- Raw406: `e1b62ae23e6f7eedaaf40ebb99b9bf7692f9d6c2acd54cdfa483439e02eda693`.
- Closed406: `509714ea99b53586428ac313a698d8eeb051c8537a4193d0802779e6991f323d`.
- Saved inspection: `2b0eeb02ffe56dc810e2f03f3133d4d42ccef91640c01bd370b670aa04c7d2d7`.
- Candidate: `96854e572d72fdf8e7de6acf89d62c7a6214633cd9ce4ced3aba220394ddb7d3`.
- Resource observation: `4acbbe22d142e11ca92b5bea816da9b5baf028b758db5e908f05b59d77511cf0`.

Raw and candidate binding values agree on source17c914f4, archive,203 verified
inputs, source aggregate and the stated amd64 artifact. Candidate ARM metadata
does not establish ARM runtime behavior. Remote confirmation is Root-reported,
not independently checked by this reviewer.

The raw record says FAIL/exit1, outer12.889s, synthetic success component mode,
provider_profiles_used=false and real-client acceptance NOT_RUN. Stderr has376
lines and92 exact inventory/verified pairs. All13 wrapper,30 nested and24
retained rows were independently extracted from the raw text and matched the
closed metadata in order and value. The24 retained labels are the closed3x8
tuple, with zero elapsed values for both count-only categories.

The native_poll/reading/Deadline boundary retains query2/6 and owner2/12
hold/negative counts and both releases. Decimal recalculation confirms all
three public observation offsets and the797.276us/914.747us post-error
overruns. Canonical query slot0 has Birth/result=null and the stated non-null
verified_at; policy history0 has Birth/result=null/verified_at=null; subsequent
query slots are null. These facts establish neither parent ACK nor scope/case
completion. The current Reading/Result source transitions support the diagnosis:
Reading follows release, but a failure can occur before child verification,
during its later source-publication setup, or at other initial/final/nested
checks without assigning Result. The exact failing predicate remains unknown.

The wrappers sum1.944723696s: query0.374868131s, policy0.420876837s and18 native
polls1.148978728s. Their disjoint lab wrapper intervals include nested work and
scheduling; neither their sum nor outer wall time is CPU accounting. Different
work reached versus405 prevents controlled before/after attribution.

The four Binding inner rows have equal entry counts within each query/policy
family:4292 and4171 respectively. Owner.record's221.134431/202.379170ms is
largest among those four measured boundaries. Allocation-digest counts6522/6190
are different, so their24.420007/22.913468ms is not a measured fraction of that
Binding History row or an equal-work alternative to owner validation. Source
inspection confirms the digest region also runs through other History paths.
Transport/DATA and History/digest overlap; partial/error entries and observer
effects remain included. No subtraction or count extrapolation is justified.

Source.identity579/650 and Native.source1755/1961 entries support repeated
fanout, without classifying every call as redundant. The group-native timer
begins after Request.verify_retained succeeds; other group-verifier callers
and errors prevent inferring a per-call bijection from equal aggregate counts.
The current OwnerDomain::record path still verifies host preflight, durable
structure, namespace pairs, process/start/boot and cgroup observations before
cloning. It cannot be treated as pure formatting or a cacheable old verdict.

The saved inspection's selector/gateway/owner facts were read only as snapshot
metadata. Preservation, later archival and the next baseline authorship were
not re-audited; no present-resource assertion is made here.

## Digest mechanism and shared-output equivalence

The current public `vprouter_worker::bootstrap::digest(&[u8])->String` computes
`Sha256::digest(bytes)`, iterates its32 output bytes in order, formats each as
two lowercase hex characters with leading zeros, and collects their Strings.
Worker imports and the locked workspace pin use sha2 0.11.1 (digest 0.11.3).
The proposed lookup encoder can safely push the high and low nibble's ASCII
characters into one String with capacity64. It needs no unsafe code, new
dependency, API/error type, input change or SHA operation change.

For every byte0..255, the mapping must remain exactly `format!("{b:02x}")`;
retaining byte order and concatenating all32 mappings yields exactly the old64
lowercase ASCII bytes for every SHA output. This byte-level argument plus an
unchanged SHA invocation applies to every input, while finite digest fixtures
provide differential evidence rather than an exhaustive input proof.

The helper is shared far beyond allocation History. Source searches and
representative call sites show owner-unit/domain names, allocation/configuration
bindings, bootstrap nonce/configuration/program hashes, reviewed program
manifests and launch/resource/transport/enrollment records. Owner-unit input is
the exact deployment-owner string in Domains.owner_unit, and its result becomes
part of the service unit name. Exact global output equivalence is therefore a
preservation requirement, not a cosmetic formatting preference. No SHA input,
serialization, nonce, identity or stored digest can be changed or migrated.
All callers and live checks must stay byte-for-byte unchanged and recompute
the helper at every original call.

The diagnosis's parsing, namespace-representation, borrowed-comparison and
extra-owner-diagnostics alternatives are explicitly future work. They are not
authorized by either digest brief and do not justify skipping native reads.

## Requirements readiness and sensitivity

The target-only experiment requirements are appropriate: actual current public
library oracle, exact dependency/compiler/harness/lock binding, known empty/abc
vectors, all single-byte inputs, binary/Unicode/control/NUL fixtures, SHA boundary
lengths through65536 and synthetic owner/allocation inputs. Direct all256-byte
hex-encoder comparisons and mixed32-byte arrays test nibble/case/leading-zero/
order behavior independently of the SHA examples. Full64-character comparisons
before and after timing prevent prefix-only or timing-only acceptance.

Warmups, black_box, seven alternating batches, fixed preselected iterations,
every saved sample and medians/ratios form a bounded host mechanism experiment.
The oracle must actually be the frozen library, not another copy of the proposed
encoder or only a manually copied old function. Host libc/allocator/compiler
and optimization boundaries must remain explicit. No result has been reviewed
yet, and no host ratio may be scaled by406 entries into native savings or2s fit.

The conditional implementation requirements correctly own only worker
bootstrap.rs and necessary private helper/tests/imports. Old formatter/SHA
differential tests, known vectors, boundary/public byte fixtures and a retained
wrong-nibble/case/order mutant are meaningful. Preservation requires all178
other Rust paths unchanged and exact reconstruction outside that minimal diff.
The focused worker checks and later Root-owned workspace/static/context/source
binding and independent review remain necessary; this report does not perform
them or authorize an edit before experiment acceptance.

Publication is bounded to static source reasoning, document/artifact hashes,
fixed diagnostic labels/counts/times and public synthetic fixture definitions.
The experiment must use no current nonce, live state, private profile, identity
material or credential as a fixture. Target artifacts remain separate from any
later public-safe harness archival, which Root must review. This review copies
no raw request/profile content or resource identifier into the report.

## Scheduling and verification limits

The resource JSON records exact current owned-process matching and requested
QEMU options (-accel kvm,2 vCPUs,2048MiB,host CPU), allowed CPUs0-23 and four
inherited current cpu.max values of max100000. This is current configuration
evidence, not a measurement during406 or proof of historical KVM execution,
absent contention, guest steal, IO waits or throttling. No emulation/quota cause
or its absence is established. The diagnosis correctly keeps any future coarse
read-only scheduling capture separate, attributed to Root and overhead-labeled.

Only this review file was written. No code/Git mutation, application/helper/
test/build execution, VM/profile/privileged/native/resource operation or
subagent was used. Fresh verification consisted of source/document/JSON reads,
hash comparisons and retained-row/timing arithmetic. No preservation audit was
duplicated. Actual experiment evidence requires its own subsequent scoped
review before application authorization. Original398-406 failures remain FAIL;
Bootstrap/task8c/ARM/client/migration/performance/release gates remain open where
unaccepted.

## Addendum: frozen actual-public digest experiment review

2026-10-29, after the initial requirements review above. **Experiment evidence:
PASS. Experiment specification: PASS. Experiment quality: PASS. Conditional
implementation requirements gate: PASS.** No actionable blocker was identified.
This addendum supersedes the earlier pending-experiment status for that review
gate only. Root may accept this evidence and explicitly dispatch the existing
one-file implementation brief; this reviewer performs no application edit or
runtime authorization. Later implementation/source/tests/artifacts still need
their own independent review and evidence.

### Exact experiment binding

| Artifact | Independently verified SHA256 |
| --- | --- |
| `task-8c-digest-hex-experiment-report.md` | `a4d7f6a90d7546605484a159ee5161281a1c808cebbd4e2049a4fca532ada55c` |
| `target/task8c-digest-hex-experiment/artifact-hashes.json` | `8ddaa6766d8c024c04679802913b042ec2532fdb1446ab83a64f5d6d0de35b37` |
| `harness/src/main.rs` | `820b47932e1fbe8ea97380c3df0caea9e67d5a47ec537df721d75fea7ad05337` |
| Isolated `harness/Cargo.lock` | `96ba6ef2a5ddf1140e82ad107c406481e7f1fced81b31ffca66d7e555b4e3621` |
| `context.json` | `a4708a602c820dbb26561995515b4a6efe87f84fb2d1dd29f118c6f1cc813361` |
| `results.jsonl` | `e6bc417000c30765e2974d48fb8a654a6ae5d415be894fce3d7761246c070a49` |
| `summary.json` | `e676f31b806cbd687653a89e8865e3f853e5788419e914fce5c8d9d9afd54ad1` |
| `application-source-preserved.json` | `7a343999bf98bdd179c036f338627bfa34f66b6d5c21b35b9f318757bc31d6f3` |

All16 artifact-index entries and all nine context-bound paths were read/hash-
checked, including the executable, worker rlib and sha2 rlib. Their hashes match
the frozen report. Read-only checks also independently confirmed identical
before/after/current hashes for179 application Rust paths, no added/deleted Rust
paths, and all ten protected repository manifest/lock paths unchanged.

The isolated lock contains145 total packages:144 identities match the root lock
by name/version/source/checksum, with the harness itself as the sole extra.
Thus the report's dependency-match claim is supported;145 is the total package
count, not145 additional matching dependencies. Repository dependency pins and
source files were not changed for the experiment.

### Oracle provenance and mechanism

The complete harness, its manifest, extracted old function, context, relevant
verbose build commands, dependency pins, execution record and results were
read. The manifest uses the actual frozen worker path dependency. Retained
compiler commands build that worker from its real src/lib.rs and the dependency
file includes its real bootstrap.rs. The final harness command links the
context-bound worker rlib and the same sha2 0.11.1 rlib. The extracted helper
matches the frozen current public function. These independent source/build
links support actual-public-oracle provenance rather than a copied formatter
being substituted for the library call.

The scratch proposed function retains Sha256::digest(input), then maps each
of its32 bytes through fixed lowercase high/low-nibble lookups into one
String::with_capacity(64). It preserves byte order, leading zeros and complete
output. No input mutation, serialization change, cached value, native check or
authority construction is present. The32 transient per-byte format Strings
are visible in old source; their runtime allocator-call counts were not profiled.

Each retained pre/post event reports299 digest cases,8450 encoder cases and two
known vectors, all PASS. Source loop counts corroborate these numbers:299
executed inputs include repeated byte cases;8450 consists of8192 byte/position
arrays,256 deterministic mixed arrays and two uniform arrays. Complete string
equality, length64 and lowercase shape are asserted, with empty/abc known
hashes checked against both functions. Fixtures include binary/padding/block
boundaries through65536, all-byte ramps, Unicode/control/NUL and public synthetic
owner/allocation bytes. No private current state is read. The before/after
events bracket every timing sample in the sole retained execution. This is
finite oracle evidence plus the direct byte-mapping argument, not a general
proof for future edits.

### Timing fairness, arithmetic and confounders

The timed actual path is the public dependency function, with no inline
attribute and noLTO. The local proposed outer function is inline(never).
Both pass through the same black_box-opaque function pointer in measure, with
black_box input/output and String drop inside the measured loop. This prevents
an obvious direct-local-inline versus dependency-call comparison. Internal
formatting/hex/SHA optimization remains legitimate work within those outer
boundaries; identical machine code, alignment and cache state are not promised.

The manifest and compiler logs support opt-level3, codegen-units16, debug=false,
lto=false, unwind, host x86_64 GNU and the recorded compiler versions. Context
records glibc2.41/default system allocator, unset override flags and unpinned
affinity0-23. The initial build and pre-run harness-only rebuild are retained,
including dependency warnings; execution.json records one data run, exit0,
wall0.79739085s and empty stderr. No retained evidence suggests a selective
timing rerun. This review cannot independently audit unrecorded execution
history; its verdict binds the supplied frozen package.

The source fixes four scenarios,128 warmups per implementation, seven batches
and20,000/20,000/5,000/1,000 iterations before timing. Serialization, oracle work,
printing and summaries occur outside measured loops. Read-only arithmetic
verified all28 paired samples, their order/iteration/input-size fields, both
oracle events, four raw summaries and every min/median/max/ratio in summary.json.
Elapsed nanoseconds divided by calls yields the reported ns/call; the reported
ratio divides separate medians, rather than averaging ratios or mixing units.

| Scenario | Actual median ns/call | Proposed median ns/call | Median ratio |
| --- | ---: | ---: | ---: |
| Synthetic owner input45bytes |768.28235|61.99155|12.3933398987|
| Synthetic allocation623bytes |1000.8225|274.53065|3.6455765504|
| Binary4096bytes |2260.7852|1553.2908|1.4554809698|
| Binary65536bytes |24924.572|24045.091|1.0365763224|

These are local batch elapsed results. Seven alternating batches leave four
actual-first and three proposed-first pairs; warmups are direct calls, and code
layout, allocator/cache state, CPU frequency/load and scheduling remain
uncontrolled. There is no CPU/allocation profiler, confidence interval or
hardware performance acceptance test. In particular, the small65536byte ratio
must not be treated as a guaranteed improvement. No ratio can be multiplied by
406 counts or applied to the whole221/202ms owner boundary. History digest
also includes serialization that this timing excludes. Native static musl
behavior, actual cost share, full Bootstrap completion and original2s fit remain
unmeasured.

### Public-safe scope and next gate

The reviewed harness source contains static public synthetic fixtures and fixed
bounded loops. It reads no runtime file/profile/state, accepts no external
request fixture and creates no native resource. Its printed fields contain
fixed case labels, bounded counts/times and digests of those synthetic inputs.
The exact source is suitable for Root's separately scoped safe-source archival
review; this does not approve publishing the entire target package, binaries,
build logs, context or machine-specific absolute-path manifest. Existing local
paths in scratch provenance are not credentials, but are unnecessary to a
public standalone harness.

The previously reviewed implementation brief remains unchanged and sufficient:
only worker bootstrap.rs, unchanged public API/SHA operation/call sites/identity
bytes, meaningful old-formatter differential checks and a retained mutation
failure, preservation proof, focused worker tests/fmt/strict Clippy, then fresh
independent source review. Experiment PASS supports removing that pure local
formatting work. It grants no cache/live-check/deadline/provider/retry change
and no wider source scope.

Only this addendum was written during this evidence review. No timing, tests,
build, helper/executable, Git, source mutation, VM/profile/native operation or
subagent was run. Verification was limited to retained source/log/metadata
inspection, hash/lock/source comparisons and sample arithmetic. All original
failures and remaining native/client/migration/platform/benchmark/release gates
remain unaccepted where open. Root retains acceptance and explicit dispatch.

### Public archival follow-up before final freeze

Root subsequently archived `tools/rust-v2-lab/digest-hex-cost.rs`. Read-only
byte comparison confirms it is exactly the reviewed frozen harness main.rs,
SHA256 `820b47932e1fbe8ea97380c3df0caea9e67d5a47ec537df721d75fea7ad05337`.
The public-copy sensitivity and factual-scope verdict is **PASS** for that
exact synthetic source; the target-package exclusion above remains unchanged.

The updated `tools/rust-v2-lab/README.md`, SHA256
`849c3a12e4740998f658226768c9b875761171ce699f09c59b2994398550c560`,
was also read at the relevant sections. Its reader description correctly adds
the optional exact24 rows without implying that partial extensions are valid.
Its new harness description accurately states synthetic/no argument/file/network
inputs, isolated target-only Cargo reproduction with the required path crates
and sha2/serde_json pins, the frozen17c914f4 oracle/repository-lock dependency,
seven alternating batches, report-bound exact profile/lock/samples and host-only
limits. It correctly places the harness outside the historical293-file archive
manifest and grants no VM/Bootstrap/release acceptance. **README factual-scope
and sensitivity verdict: PASS.** This follow-up reviews the current text and
exact copy; it does not claim a separate reconstruction of unrelated README
history or approve other target files for publication.
