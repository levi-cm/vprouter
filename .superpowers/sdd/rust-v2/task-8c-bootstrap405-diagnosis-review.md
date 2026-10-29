# Independent review: run405 diagnosis and retained-cost requirements

2026-10-29. Read-only review before implementation dispatch.

| Review dimension | Verdict |
| --- | --- |
| Diagnosis | **PASS**, for the corrected frozen document below |
| Specification | **PASS**, for the exact five-file diagnostic scope |
| Quality | **PASS**, at requirements/source-feasibility level |
| Requirements readiness | **PASS**, suitable for Root's explicit implementation dispatch |

No source implementation is approved by this report alone. Root's explicit
dispatch remains required. No outstanding finding requires a requirements
revision. Implementation, normal-build equivalence, tests, builds and native
behavior still require their separate evidence and independent review.

## Exact document binding

| Document | SHA256 verified during this review |
| --- | --- |
| `task-8c-bootstrap405-diagnosis.md`, corrected freeze | `2620a12cffaba63457ecb44b1c0cdfad4a2204177cb43b45eadd813145eadffb` |
| `task-8c-bootstrap-retained-cost-brief.md` | `5624e0e29001744dbb849f7fa08ca7c6ab8db74ad5d605488024d45936932e07` |
| `docs/rust-v2/IMPLEMENTATION.md` | `353f0e82d9dcf7b3e1216c27ac4c505bdc8fa6ee06ee3e6b833f1d3e11594125` |

The initially supplied diagnosis hash
`dfb3fe40b24ef90fcddd938566df626f5fb575885db846714a9fe1ceb1363225`
contained one ambiguous/inaccurate canonical-snapshot sentence. Review found
that it conflated the query's non-null verified timestamp with the policy's
null verified timestamp. The author corrected that sentence and re-froze the
document; the corrected text was read and hash-verified. The diagnosis PASS
binds to the corrected hash, not the initial one.

Source context is Root's named frozen milestone `bf3247b`. Without using Git or
executing application code, this reviewer checked all 179 current Rust path hashes against
the retained comparator after-snapshot; every path still matched. This check
establishes source identity for this review, not a build or runtime claim.

## Diagnosis findings and factual checks

The raw run405 record, retained inspection JSON and closed metadata were read.
Their independently calculated hashes match the diagnosis:

- Raw run: `426dfae8b336943c7dcefe3e2bbae3b945568a44bf0d04f07f5869fdaf62ba1a`.
- Retained inspection: `891951dab0260c7e61d0419b1f30424bca13f281ba8fc8d4ca16d9d121948fc0`.
- Closed metadata: `f743c668eaefc61a3681dbcf94f2c8e269d6d69bb8c8f26f690aa1fe24c039e3`.

The raw record says exit1, FAIL, wall11.728s, synthetic success component mode,
provider_profiles_used=false and real-client acceptance NOT_RUN. Its source
binding reports the stated source tag, archive, 203 verified inputs, aggregate
and artifact hashes. These are retained metadata assertions; no archive was
rebuilt and no remote push was independently checked here.

The 352 stderr lines contain 92 exact, ordered io_inventory /
io_inventory_verified pairs. Those are diagnostic stages, not Result ACKs.
The failure row reports native_poll/result/Deadline, both queued/released
sequences and original query2/6 and owner2/12 hold/negative counters. Decimal
recalculation confirms the public timing table and the post-error overruns:
6.191181ms for the boundary row and 6.276830ms for the later HOST failure row.
Neither observation is the exact failing predicate time.

Canonical HOST query slot0 has Birth, result=null and
verified_at=201350.594514042; policy history0 has Birth, result=null and
verified_at=null; subsequent query slots are null. The corrected diagnosis now
states these facts separately. It correctly declines to infer accepted parent
ACK, completed scope or a completed case from them.

All 30 closed nested rows were independently parsed from raw stderr and matched
the metadata exactly. The 13 wrapper rows sum1.953713909s, including query
0.386489051s, policy0.402504505s and 19 native polls totaling1.164720353s.
The retained and allocation-entry totals are respectively9058 and4399.
The cited404 retained/allocation rows and its93 inventory pairs were checked
against the retained raw404 record. The differing counts and work reached
prevent controlled attribution of a native comparator effect.

The Step::Reading/Result transitions and initial/final deadline checks in
`attachment/operational/bootstrap.rs` support the stated localization limits:
Result is assigned after installing the child and starting result publication,
and failure can still come from the same call's final clock check or a later
advance. No specific inner predicate is established by the post-call step.

The source fanout was checked through operational/host-addition/producer-binding
custody, host-link receipts, quarantine Binding, producer Source/Native,
Bootstrap Request/Pins, mounted transport/DATA pins, inventory, OwnerDomain and
History validation. The diagnosis distinguishes repeated finite composition
from a cycle and correctly avoids deriving exact runtime calls from source.
`Source.identity` first verifies retained custody and then calls Native.source
again on success; Native.source reaches request/binding validation and fresh
group metadata, ancestry and cgroup files. OwnerDomain::record calls verify
before cloning: host preflight, four self/PID1 namespace pairs, process/boot,
pinned/named cgroup and /proc/self/cgroup observations remain live work.
History validation separately recomputes allocation serialization/digest and
walks the retained histories and duplicate-input set in memory. The current
worker digest's byte-by-byte formatting supports the limited future mechanism
proposal, without establishing material native savings.

The retained inspection's selector/gateway/owner observations were checked only
as facts of that saved snapshot. This review does not duplicate the separate
preservation405 audit, inspect present resources, authorize cleanup or assert
their present state.

## Five-file feasibility and evaluation order

The brief owns exactly the five existing source paths required by the diagnosis.
No additional production source, controller/parser, dependency, manifest or
filter edit is needed to implement the described measurements. The existing
`cfg(test)` lab_cost module and snapshot emitter provide the necessary
integration points.

- Transport and DATA retained timers can wrap their existing calls separately
  in `owned/preparation/quarantine.rs`; they must end at those call boundaries.
- The owner timer must live in a minimal expression block around only the
  existing owner.record call. It must remain behind every earlier `||` operand,
  preserve the `?` error and drop before the subsequent equality comparison.
  Moving the call into an eagerly computed local would violate the brief.
- The full History timer can wrap the existing p.validate call. Its nested
  allocation-digest timer in `owned/preparation.rs` must remain behind the
  member mismatch condition and surround the original serialization+digest
  expression, preserving `AllocationMismatch` on serialization error. No
  serialized value, digest, validation result or successful verdict is reused.
- Source.identity and Native.source entry counters belong before their existing
  entry checks, so error entries count too; they must invoke no native check or
  new time observation.
- The group-native RAII region begins only after the existing
  Request.verify_retained succeeds and covers the unchanged remainder through
  successful return or early error. Request/binding work is intentionally
  excluded from that region. Failed requests therefore do not enter its count.

These insertions can preserve the original call/evaluation/error order and all
authoritative clock observations. Diagnostic elapsed-time reads are the intended
observer effect, not new validation observations or deadline authority. The
normal-build reconstruction requirement is appropriate: excluding the new
cfg(test) statements and only their minimal expression braces must reproduce
original production expressions and every unowned path. Its actual proof must
be assessed on the later implementation diff.

## Accounting, child filters and bounded publication

The eight closed keys across three existing loop-entry families give24 added
rows. A separate fixed table with selected-row updates is feasible without
enlarging the old30-row State copied by existing timers. Per-row Cell storage,
or an equivalent bounded design, can avoid live borrows across measured work.
Metadata/session state must remain shared with the existing active/creator/
epoch/family boundaries rather than creating an independently active collector.
Entry tokens must capture family; drops must reject stale/stopped epochs; reset
must clear new rows; counts and nanoseconds must saturate; count-only elapsed
values must remain zero. Nested timers must count independently without holding
a mutable borrow through the instrumented call.

No timer/counter path needs getpid. The current publisher filter in `kernel.rs`
allows clock_gettime and omits getpid, consistent with the existing timer
restriction. New bookkeeping must reuse metadata and leave child writes
COW-private. It must never merge child totals, export them as parent evidence,
or weaken the creator check on the unrestricted stop/export boundary. This is
source feasibility, not a fresh filtered-child runtime proof.

The existing failure emitter stops collection before printing. Extending its
Snapshot emission after the unchanged30 old rows permits the added24 rows
without modifying operational/bootstrap.rs. Closed family/category labels,
bounded numeric fields and no request/path/identity fields limit publication
to diagnostic totals. With existing u64/u128 widths and the analogous category
row spelling, even maximum-width values total at most5567 added bytes across24
rows; the precise later format still needs review. No new per-poll text belongs
inside measured work.

A finite byte count does not bound blocking stderr latency. The implementation
must preserve the existing best-effort behavior: output errors cannot replace
the original failure, collection stays stopped during output, and no timing or
authorization depends on publication. No new logging error propagation, syscall
permission or retry/poll is justified. Extra clock/accounting and cache effects
can alter observed native time even with no production semantic change.

The brief correctly calls these inclusive elapsed regions. Transport can
include DATA; History includes its digest; entries include errors and partial
work; family is captured at lab-loop entry, not an exact inner phase. Adding or
subtracting these overlapping regions into CPU attribution, successful-call
counts or saved budget would be invalid. A timer count is not an ACK or case.

## Requirements quality and remaining boundaries

The requested helper checks address meaningful collector behavior: inactive,
count-only, early-error, nested, family/epoch, stopped/old-token and creator/COW
semantics. Existing helper coverage should be preserved and extended only where
the new table/control behavior needs it. Snapshot/output field order and
normal-build exclusion must be verified from the actual implementation and
retained local test/fmt/strict launch Clippy evidence at the next review.

The diagnosis proposes measurement before any digest optimizer, does not
authorize that optimizer, and does not treat live native reads as historical
cache candidates. The brief preserves all original2s windows, holds/negatives,
release/ACK/pending/writer/fence/custody checks and failure behavior. Its local
testing, Root-only native/build/VM boundary and preservation requirements are
consistent with the binding contract.

Only this review file was written. No application source or Git mutation,
test/build/helper execution, native/VM/SSH/Docker/privileged/profile operation or
subagent was used. Read-only source/JSON/hash/arithmetic checks are the fresh
verification here. No native cost witness exists for the proposed diagnostics;
implementation quality and filter/runtime behavior remain to be reviewed and
tested. Original398-405 failures remain FAIL, and full8c/ARM/client/migration/
performance/release gates remain open/NOT_RUN where unaccepted.
