# Run407: Reading Deadline; parser proposal and owner-cost decision

2026-10-29. Read-only diagnosis requested by Root. Only this report was written;
no application source, tests, builds, Git, VM/native runs, retries, resources,
profiles or preserved failures were changed. All 179 Rust files still match the
frozen digest-implementation snapshot (proof below).

407 is FAIL, zero completed cases, HOST native_poll/reading/Deadline. The query
has a durable verified_at; policy result and verified_at are null. Owner.record
remains the largest measured retained region among equal-count Binding portions.
No row isolates parser cost or proves that another optimizer will fit the window.
For native attribution, owner-inner diagnostics are a more grounded next
application change than parser optimization. A separately authorized target-only
parser experiment is useful as bounded equivalence/mechanism screening; it is
not a native-fix decision. Neither option has been implemented or run here.

## Evidence and original window

Independently hashed inputs:

- Raw `target/lab-state/actual-program-run-407.json`:
  `4c16ab618e83a95bc56121e850494c2efde15c6711eedcaeffc9212bffe6e922`.
- Closed `target/task8c-digest-hex-root-20261029/bootstrap407-closed-metadata.json`:
  `2a61b8c7774c5461c99ac2ed51d73a1200e2492da5bfd283a8ff90d5a33a32ff`.
- Root inspector `target/lab-state/secret-bootstrap-failure-run-407.json`:
  `5e4aadc3dd51f78926ef0d261c675251bc17f0f9e80a10026a2190da00051bf5`.

Source commit 51c15016353936288067f5cd3e4c2a6715be1061; archive
f5cecc2f3af90a7e638f9bfdcb1d2db3a70abb7666d678b2133fe88601d9aa7c;
203 verified inputs; aggregate
d9fe3200b57f73d8cf5c6e847277dbf463c5ab672559f208383c49f81de12167;
amd64 artifact fe3567ab22819b05ecf0523ddcfb6dd14fea8869d6b6a6e7f77b9804b2a926d3.
Debian clean x86_64, exit1, outer wall19.377s. Synthetic success component mode,
provider_profiles_used=false, real-client NOT_RUN. Outer wall includes context
build/setup and is not the original two-second window or CPU cost.

Raw stderr has376 lines:73 phase,184 journal,48 attachment, one boundary,
13 wrapper,30 nested,24 retained and three final failure lines. Independently
verified all92 ordered inventory/verified pairs and exact raw equality with all
13+30+24 closed cost rows. Writer stage pairs are not ACKs. Inspector snapshot
has all six fixed selectors and both canonical files present; gateway running,
owner unit inactive/not-found and owner cgroup absent. This is inspection-time
presence, not proof of later archival; Root owns archival and resource actions.

```text
helper=native_poll step=reading reason=Deadline
query_present=true query_child_present=true query_accepted_present=true policy_present=true
query_queued=true query_held=2 query_negatives=6 query_released=true
own_queued=true own_held=2 own_negatives=12 own_released=true
original_requested_at=Some(204882.642003901)
original_deadline=Some(204884.642003901)
observed_boot_now=204884.651831267
```

Boundary observation is9.827366ms beyond deadline; later HOST failure observation
204884.651950687 is9.946786ms beyond it. These are post-error observations, not
exact predicate timing. Reading and presence flags do not establish accepted
policy receipt, Result, completed scope or the exact failing inner clock check.

| Durable public observation | Boot time | Since original request | Remaining budget |
| --- | ---: | ---: | ---: |
| HOST query Birth |204883.241521630|0.599517729s|1.400482271s|
| HOST query Verified |204883.423858534|0.781854633s|1.218145367s|
| HOST policy Birth |204884.425688486|1.783684585s|0.216315415s|

Canonical query slot0 has facts and non-null verified_at above (no result field);
subsequent query slots are null. HOST policy history0 has Birth, result=null and
verified_at=null. These query and policy statuses must remain separate.
The13 wrappers total1.956654344s: query0.354023115s, policy0.442623541s,
and18 native polls1.160007688s. Inclusive nested rows must not be added to them.

## What the retained rows establish

| Category | Query calls / ms | Policy calls / ms | Other calls / ms |
| --- | ---: | ---: | ---: |
|retained_transport|4292 /47.013617|3924 /44.228831|442 /4.470714|
|retained_data|4292 /25.687520|3924 /24.697310|442 /2.429600|
|retained_owner_record|4292 /223.044898|3924 /218.390253|442 /21.460135|
|retained_history|4292 /29.290696|3924 /30.600866|442 /2.702607|
|history_allocation_digest|6522 /12.549100|5856 /12.474576|675 /1.224143|
|created_group_native|1755 /16.127474|1800 /18.023290|205 /1.674816|
|source_identity_entries|579 /0|597 /0|67 /0|
|native_source_entries|1755 /0|1800 /0|205 /0|

Broad retained Binding rows are4292/337.845713ms,3924/331.703304ms and442/32.240072ms.
Allocation-memory rows are2153/28.103452ms,1870/30.996823ms and226/2.849020ms.
The owner boundary is largest among same-family/same-entry-count Binding parts;
it includes live IO, pure validation, cloning, observer and scheduling effects.
No exclusive CPU share or saved budget follows. Family is cached loop-entry Step;
Other may precede the original window; entries include early errors.

Compared with406, query digest has the same6522 entries and lower observed elapsed
(24.420007ms ->12.549100ms); query owner has the same4292 entries and elapsed
221.134431ms ->223.044898ms. This is not a controlled causal estimate of digest
benefit or a native regression. Policy entry counts differ (4171 ->3924), so
policy duration comparisons do not represent equal work. Digest entries also
differ from History entries: no digest/History share or exclusive subtraction is
valid. Source.identity's successful path reaches Native.source twice, but other
call sites and early errors prevent exact redundancy counts from these totals.
No current live observation or retained record check may be removed.

## Bounded pure-parser experiment proposal only

Frozen `process.rs:145-249` contains three allocation/scan opportunities:

1. `stat_start`: retain rsplit_once(final ") ") and the exact PID-prefix check;
   replace only token Vec collection with state next and nth(18) for token19.
   Missing delimiter/bad PID stay ProcessChanged; fewer than20 fields, state byte
   length !=1, or Z/X/x stay ProcessUnavailable; invalid/overflow/zero start stays
   ProcessChanged. Preserve arbitrary other single-byte states, Unicode whitespace,
   extra-token acceptance, and comm parentheses/spaces/newlines. Do not silently
   strengthen PID/comm/state grammar or optimize prefix formatting in this slice.
2. `initial_map` and UID/GID: exact3 tokens ["0","0","4294967295"] plus end,
   and exact4 zero tokens plus end, using iterators. Preserve textual comparisons,
   Unicode whitespace, and rejection of extra tokens or normalized numbers.
3. `role_credentials`: optionally replace eight status-line scans with a fresh
   per-call fixed8-slot borrowed-field index. Preserve status.lines(), exact
   strip_prefix matching before trim, first value and duplicate detection, missing
   fields, ignored unknown/leading-indented lines, CRLF, trim and validation order.
   Record duplicate state then validate Uid/Gid/NoNewPrivs/Seccomp/Threads/caps in
   the existing order. Setup NoNewPrivs0/Guard1, Seccomp0, Threads1, and all three
   hex-u64 capability checks remain exact. Setup requires HOST_SETUP_CAPS; Guard
   requires that mask without bit19 and rejects bit19 present; unrelated extra
   capabilities retain current acceptance. Failures remain UnsupportedPlatform.

`lib.rs` keeps process private; role_credentials/HostRole are also private. An
external harness cannot truthfully call those production private symbols. A
possible separately reviewed target-only harness can embed byte-identical frozen
pure bodies, HostRole and HOST_SETUP_CAPS, bind them to the real public
vprouter_launch::Error/Result types, and expose harness-local invocation wrappers.
Verify extraction body bytes and source hashes; label this an extracted frozen
implementation oracle, not a direct production-function call. Use actual Result
Eq (including u64 and enum variants), never bool-only acceptance or a substitute
error enum. The initial_map helper additionally compares exact booleans.

First compare adversarial deterministic cases: each stat error branch, mixed
short+invalid states, multibyte states, token19 boundaries/overflow/zero, long
extra tails and comm delimiters; map token cardinality/text/Unicode whitespace;
every required status field missing/duplicated/malformed, shuffled and unknown
lines, indentation/CRLF, map/LSM failures, Setup/Guard and each capability mask.
Only after complete equivalence, a separately bounded single timing session may
use realistic short/full/near-limit input shapes and opaque input/function/output
black_box barriers. Fix iteration/shape/batch limits in the authorization brief,
retain construction/drop costs consistently, record compiler/dependency/source
binding, and recheck equivalence after timing. Compare Vec removal and scan removal
as separate candidates so their effects stay attributable. No adaptive reruns,
native projection, call-count multiplication or application optimizer is implied.

`role_preflight:263-282` must retain single_threaded, /proc/self open/fs_type,
status65536 ->uid_map4096 ->gid_map4096 ->attr/current256 reads, credentials, then
/sys/fs/cgroup open/fs_type in that order. Native callers, bounds, error propagation,
record validation, fresh namespace/process/boot/group checks and clones remain.
No new FDs, persistent verdict, parser cache, live-call pooling or deadline change.

## Native-attribution decision

`supervision.rs:125-144` owner.record calls verify then clones. verify performs
host_preflight, record.validate, four self/PID1 namespace pairs, current process,
boot, pinned/named cgroup identities and /proc/self/cgroup. Current rows do not
separate these. After the digest change, another parser optimizer would still be
based on source plausibility rather than measured native share.

For learning where the223/218ms goes, the stronger proposal is test-only owner
inner timing around preflight, record.validate, namespace identities, the existing
final native predicate chain, and clone. Preserve every call, short-circuit/order,
Result and record comparison. Reuse the existing active/epoch/creator/family and
separate per-row Cell approach; keep all old13+30+24 rows unchanged, no enlarged
old-State copies, timer/count getpid, child merge/export or output while active.
The existing test-only lab_cost visibility allows a two-source-file diagnostic
slice (supervision.rs and lab_cost.rs), subject to a concrete reviewed brief.
It would locate broad costs rather than exact Deadline predicate or CPU time;
finer parser attribution would still require evidence. No diagnostic source,
new run or resource capture is authorized by this report.

## Source preservation and status

Reference `target/task8c-digest-hex-implementation/rust-after.json` SHA256
f31ce696bd7f647a841da2904f8a383d4ab8fee37662d3678539e86a6ac03b3b:
all179 keys rehashed byte-for-byte equal; current crates/**/*.rs path set also
exactly equals those179 keys (zero changed/missing/extra paths).
`crates/vprouter-launch/src/process.rs` SHA256
8cc519f527f675d4fe487ea39fb30fdae2279e11e3447c5ee73000131d819cb6;
`supervision.rs` SHA256
4f864fa5bce9140dd426fc584303f5ce4ee4c03ec08338009e00ff24bf619ef0.
No source/test/build/Git/VM/native operations were run for this diagnosis.

Failures398-407 remain preserved FAIL. Full Bootstrap/task8c and unaccepted
ARM/client/migration/performance/release gates stay open/NOT_RUN. The earlier
resource snapshot was not captured during407, so neither a quota explanation
nor absence of contention is established. Provider profiles were unused; this
Deadline supplies no evidence for changing Mullvad relays or other live profiles.
