# Run404 diagnosis and allocation-comparison requirements review

2026-10-29. Independent read-only source/counter/evidence and bounded requirement
review. Only this Markdown written. No application source edit,Git action,build/
test,benchmark execution,VM/SSH/Docker/privilege,helper main or subagent action.
The historical controller/native/preservation audit is not duplicated.

**Diagnosis SPEC PASS / QUALITY PASS / EVIDENCE PASS within its limits. Narrow
brief requirements PASS. No open findings.** These are not implementation,
optimization,native performance or acceptance approvals. Full8c remains ACTIVE;
original404 remains FAIL/zero completed cases and all release gates remain open.

## Exact reviewed state and corrected documentation

Diagnosis task-8c-bootstrap404-diagnosis.md under .superpowers/sdd/rust-v2:
SHA2567274438192f33cc1197f070a35c16bae5b302379a956ae994c28c63ec08b7191.
Brief task-8c-allocation-comparison-brief.md in the same directory:
SHA256a254476aa537f891546be3b044f16112334bc20eecf7dda3551dec477976ad6f.

Two minor factual-currentness/citation issues in the initial8d561bc3 diagnosis
were corrected by its author before final review:the six-selector statement now
explicitly describes the pre-archival snapshot and reconciles the later exact-six
receipt;the Path serializer reference now cites locked serde_core1.0.228 rather
than an installed1.0.229 copy. Both are resolved. No source or raw failure record
was changed. Root/author were notified of both concerns and the refrozen hash.

The diagnosis's raw404b476430f,inspection7d58bdc2,directory-binding2e1291af,
4451c8a source/archive/aggregate/artifact and six frozen source hashes agree with
the existing independently checked evidence. At this review,all203 root-proof
build-input hashes again equalled current and archived bytes. Remote checkpoint
statements are explicitly Root-reported;this auditor performs no remote check.
The base diagnosis excludes the separately authorized scratch experiment and
claims no benchmark result. No scratch benchmark is run or reviewed here.

## Boundary,counters,intervals and inclusive cost scope

Exact raw404 has native_poll/result/Deadline,query/policy presence,both required
held2 counts,negatives6/12 and releases true. Zero case witnesses/exit1/8.69s,
354stderr lines and93 inventory/verified pairs match. Canonical first query has
birth/facts/verified_at;first policy has birth and null result/verified_at;later
query slots are null. Step::Result follows Verified work and Result queueing by
frozen source order,but the post-call Step is not necessarily the poll-entry Step
or exact failing method. No durable Result ACK/accepted policy receipt/completed
Host scope is inferred from the93-writer prefix or canonical bytes.

Original requested_at199575.470574895 and deadline199577.470574895 preserve2s.
Boundary lateness341.503us and later Host-log lateness416.554us are correct
post-error observations. Query birth/verification and policy birth times match
saved canonical values. Remaining1.219421415s at query verification and0.307156267s
at policy birth are correct arithmetic,not renewed clocks or successful scope
witnesses. Exact inner Deadline remains unlocalized.

All13 wrapper count/duration values and all30 nested table count/duration values
match raw404. Disjoint outer query354637758ns +policy405169077ns +native19calls/
1186815519ns =1946622354ns. The diagnosis correctly avoids adding the new nested
rows to that sum. Binding retained4292+4396+442=9130 and allocation memory
2153+2053+226=4432. Timer-drop counts include early Result errors and do not count
only successful validations or particular serializers.

Binding retained335.094473ms query/339.254664ms policy exceeds expected encoding
2.747405ms/13.715089ms as observed inclusive categories. That is a bounded
category comparison,not a demonstrated comparator-specific share or exact CPU
bottleneck. Categories overlap,expected encoding is nested within global JSON,
family is cached lab-loop entry rather than exact inner phase,and other-family
constructor work can precede the query window. TLS/timer and COW-private child
overhead/scheduling limits remain explicit. Earlier403/404 boundary and walltime
variation is not promoted into an optimization result.

## Independent retained-validation source trace

The cited composition is supported by current frozen source:

- OperationalOwner::custody and mutable service access repeat original owner/
  reservation and HostLinkedAssembly custody. HostLinkedAssembly checks retained
  completion/generation,producer-bound custody and four acknowledged host receipts.
- ProducerBoundAssembly host_custody and operational_source retain original
  service/producer/Source checks;Source acknowledged history is checked again.
- Binding::verify_service_custody checks transport,creator/allocation memory,
  original shared/member/owner relations and calls verify_retained.
- One successful Source::identity calls verify_retained -> Native::source and
  then Native::source again. Each native source validates the original created
  group,beginning with producer Request::verify_retained -> Binding retained.
  Therefore its two retained-binding paths are real;no ownership cycle is implied.
- Binding retained includes same_allocation,original owner/services/host pins
  and complete selected preparation History validation. History recomputes an
  allocation digest and walks retained histories/inputs. Allocation-memory
  checking separately calls Record::bind_anchor,which validates preparation.

This explains finite fanout without proving which inner work dominates. Ordinary
live/custody/pending-refusing checks remain required. Replacing their successful
verdicts with cached authority is not supported by this diagnosis or review.

## Exact Serde/path/Result contract

owned.rs same_allocation currently evaluates serde_json::to_vec(A),mapping its
Error to OwnershipMismatch,then to_vec(B) with the same mapping,and compares the
Vec bytes. Current AllocationRecord has four derived serialized fields and each
ExitAllocation has ten,including PathBuf state_dir. Their scalar/String/ordered
Vec/Option and current two-unit-variant ExitMode representations are deterministic
and injective for these current types. There are no custom/skipped serialized
allocation fields or floats that add a separate ordinary serialization failure.

Cargo.toml/Cargo.lock pin serde and serde_core1.0.228. I read that exact local
serde_core ser/impls.rs908-928:Path calls to_str and serializes its String or
returns an invalid-UTF8 Error;PathBuf delegates to Path. Thus invalid UTF8 maps
to OwnershipMismatch even when an earlier valid field/vector/entry would differ.
A comparator returning false before checking a malformed later path changes the
old Result contract. All paths of A must be validated in order before B,and
both records' relevant UTF8 checks must precede ordinary mismatch false.

Derived PathBuf/Path equality uses path components and can collapse raw spelling
distinctions. It cannot substitute for JSON's exact valid UTF8 spelling. Valid
paths must compare exact original strings/OsStr bytes,including repeated/dot/
trailing separators;no lossy conversion,canonicalization or Unicode normalization.
For valid UTF8,exact string equality and exact underlying UTF8 bytes agree.
The diagnosis and brief preserve this distinction and the A-then-B Error boundary.
These are source/equivalence requirements,not an executed new comparator proof.

## Bounded requirements verdict and remaining gates

The brief is sound as a conditional one-file requirement:only owned.rs private
same_allocation implementation,necessary private helpers/imports and focused
tests may change;every call site,other function/statement,actual resource check,
canonical serialization/digest,diagnostic,clock and deadline remains exact. It
requires exhaustive AllocationRecord/ExitAllocation destructuring without ..,
ordered/duplicate/length/mode/Option/scalar coverage and exact path handling.
No cache,stored authority,freshness waiver,filesystem access,sorting or mutation
is authorized by these requirements.

The old serializer is an appropriate differential Result oracle. Required cases
cover each outer/exit field,ordered/duplicate/empty/length vectors,modes and
Option distinctions,control/NUL/Unicode strings,path spellings and invalid UTF8
in either record hidden behind earlier scalar/vector/entry mismatches. Actual
Result/Error equality matters,not only valid-record booleans or log text.
Existing meaningful ownership/frame/IO/deadline/fence and held-negative tests
must remain. Focused tests/Clippy/source-preservation proof and independent
implementation review remain future work;none is claimed performed here.

The brief explicitly withholds implementation authorization until Root accepts
the separate offline mechanism experiment. Public-shape scratch benchmarking can
supply a local mechanism result with compiler/allocator/shape/scheduling limits;
it cannot establish native comparator share,sufficient2s budget,speedup across
remaining scopes or release acceptance. Benchmark evidence is pending/separate
from this frozen base and is NOT_RUN by this review. No application change,
optimization/cache or native retry is approved by this report.

Both reviewed documents were fully read and bounded credential-pattern checked;
no embedded credentials/private profiles found. No raw private artifact is in
publication scope. Original failures/resources and independent acceptance gates
remain intact. Final git diff --check passes. Review frozen for Root staging.

## Subsequent user steering: bounded relay-catalog publication

Bounded public-scope/factual-equality check:PASS. New sanitized public document
 docs/rust-v2/mullvad-lab-catalog-20261029.json is byte-identical to Root's saved
 target/task8c-nested-cost-root-20261029/mullvad-public-catalog-check.json.
Both SHA256d97cac280382677dc73d434e82a5d3db0ff8d9da67beab9d89456c81dc0a5c9e.
The saved observation time is2026-10-29T16:32:41.585877+00:00 and source is the
public api.mullvad.net/www/relays/all/ catalog. Its five closed server rows record
present=true for all,de-fra-wg-402 active=false and de-dus-wg-102/de-fra-wg-003/
de-ber-wg-102/de-ber-wg-002 active=true. These exact values agree with Root's
latest ledger statement,SHA256
51681ff9e05275895b71e1bff96da6fa91ff350ad17ebca03b1027113244cb29.

Root reports a bounded certificate-verified GET;this auditor performed no live
fetch and independently establishes saved-byte/claim consistency only. Catalog
active flags do not prove present tunnel/provider/handshake reachability,which
remains NOT_RUN. No profile/credential/identity/production change is represented.
Raw404 provider_profiles_used=false and its synthetic scope do not establish any
remote-relay cause for the original Bootstrap Deadline. Future supplied-server
selection remains a separate live qualification decision,preserving existing
approved identity/state. The sanitized catalog contains no credentials/private
profiles;no secret-bearing raw artifact is added to publication scope.
