# Run405: Result Deadline; measure retained native and pure work separately

2026-10-29. Read-only diagnosis requested by Root. Only this report was written;
no source/test/build/Git/VM/SSH/Docker/privileged action, native retry, profile
read or resource operation was performed. All179 application Rust paths still
match the frozen comparator after-hash snapshot. Source remains frozen.

405 remains FAIL/zero completed cases/native_poll/result/Deadline after both
held-regression sequences and releases. The one-file comparator passed its
separate equivalence review, but405 does not establish its native cost share,
a controlled before/after effect or sufficient original two-second budget.

The strongest grounded next action is a separately authorized diagnostics-only
retained-validation breakdown. Existing inclusive rows do not distinguish fresh
owner/process/namespace/cgroup/descriptor work from allocation digest/history
work. In particular, the repeated OwnerDomain::record call performs extensive
fresh native reads; it must not be treated as a cached historical value.

## Exact evidence and snapshot limits

- Raw `target/lab-state/actual-program-run-405.json`, SHA256
  `426dfae8b336943c7dcefe3e2bbae3b945568a44bf0d04f07f5869fdaf62ba1a`.
- Source tag `05238109d41e8ba4376e27c16aaa1bd41caffede`; Root reports reviewed
  comparator milestone bf3247b and source tag remotely confirmed.
- Source archive `c32d6c1bf51d888f89fb16fc34a66e7356d073ef263d357f64151a8ab0b644ed`;
  203 verified inputs; aggregate
  `4386b3a9d46ec99dee76c7dafb7cac6a04923c428bc60b0126af8576e3fdf43a`.
- Artifact `4435526772afaf82ca584adde1ceadbdad4c710106bcac99c525580c21dcdce9`.
- Root's unchanged inspection `target/lab-state/secret-bootstrap-failure-run-405.json`,
  SHA256 `891951dab0260c7e61d0419b1f30424bca13f281ba8fc8d4ca16d9d121948fc0`.
- Closed metadata `target/task8c-allocation-comparison-root-20261029/bootstrap405-closed-metadata.json`,
  SHA256 `f743c668eaefc61a3681dbcf94f2c8e269d6d69bb8c8f26f690aa1fe24c039e3`.

Exit1, outer wall11.728s, success component mode, provider_profiles_used=false,
real-client acceptance NOT_RUN. Stderr has352 lines and92 exact io_inventory /
io_inventory_verified pairs. The counts differ from404's93 pairs. These are
writer diagnostics, not an independently captured Result ACK or case success.

At Root's inspection snapshot, all six fixed selectors were present; the gateway
was running, and owner_cgroup_exists was false. The inspection states read_only,
no private-profile contents read and no signals/unmount/cleanup. Selector status
here is explicitly that inspection snapshot, pending any later Root archival;
this report does not assert their present status. Resource preservation and any
six-selector archival remain Root/auditor work and are not duplicated here.

## What the failure boundary proves

```text
helper=native_poll step=result reason=Deadline
query_present=true query_child_present=true query_accepted_present=true policy_present=true
query_queued=true query_held=2 query_negatives=6 query_released=true
own_queued=true own_held=2 own_negatives=12 own_released=true
original_requested_at=Some(201349.774675338)
original_deadline=Some(201351.774675338)
observed_boot_now=201351.780866519
```

The first post-error observation is6.191181ms beyond the original deadline;
the later HOST failure observation201351.780952168 is6.276830ms beyond it.
Neither timestamp is the exact failing predicate evaluation. Both hold/release
sequences completed with their original2/6 and2/12 coverage intact.

| Public observation | Boot time | Since original request | Remaining original budget |
| --- | ---: | ---: | ---: |
| Query birth |201350.408371351|0.633696013s|1.366303987s|
| Query Verified |201350.594514042|0.819838704s|1.180161296s|
| Policy birth |201351.509127569|1.734452231s|0.265547769s|

The canonical snapshot's HOST query (bootstrap_queries[0]) has Birth,
result=null and verified_at=201350.594514042; its HOST policy history
(bootstrap[0]) has Birth, result=null and verified_at=null. Subsequent query slots
are null. These durable fields do not prove parent ACK acceptance or a complete scope.
Process-local Step::Result is separate control-flow evidence: operational
bootstrap.rs:466-472 installs a Verified child and calls start_bootstrap_source
before assigning Result. An error can occur in that same advance call's final
query clock check, or a later Result advance's initial clock/progress, pending
writer, receipt acceptance, current Request/process-pin checks or final clock
(:352-378,475-500). The post-call Step alone does not localize the inner Deadline.
No scope witness or completed case exists.

## Existing elapsed rows and comparison limits

The13 outer wrappers sum1.953713909s: query0.386489051s,
policy0.402504505s,19 native polls1.164720353s. They include scheduling/IO and
nested work; they are not CPU accounting. Outer11.728s includes work beyond
the original query window and is not that window's execution cost.

| Category | Query calls / ms | Policy calls / ms | Other calls / ms |
| --- | ---: | ---: | ---: |
|allocation_anchor_memory|2153 /39.655354|2020 /35.297447|226 /3.867348|
|binding_service_custody|283 /65.394571|254 /53.207456|30 /7.061799|
|binding_retained|4292 /346.400525|4324 /327.523870|442 /34.338248|
|owned_progress|25 /9.563045|129 /47.321471|0 /0.000000|
|typed_bootstrap_progress|0 /0.000000|31 /117.334864|0 /0.000000|
|original_proof|0 /0.000000|93 /35.109194|0 /0.000000|
|record_json_encode|116 /10.519942|473 /40.462592|1 /0.089080|
|expected_record_json_encode|25 /2.624263|129 /11.491304|0 /0.000000|
|record_sha256|66 /0.680142|219 /2.239983|1 /0.009520|
|journal_advance|8 /6.743810|6 /4.586406|0 /0.000000|

All30 rows are inclusive and overlap. Family is cached lab-loop-entry Step,
not exact inner phase; Other includes constructor work. Do not add the rows to
wrappers, subtract them into exclusive CPU, or multiply counts into exact
successful checks/serialization calls. Timer drops include error exits.

Retained-binding entries total9058 (404:9130); allocation-memory entries4399
(404:4432). Query retained has the same4292 entries but346.400525ms versus
404's335.094473ms; policy has4324/327.523870ms versus4396/339.254664ms.
Different work reached, writer/counter counts, scheduling and diagnostic overhead
prevent controlled A/B attribution. The comparator is no longer serializing two
buffers, but this run neither disproves its local mechanism nor measures native
saved time. Its offline host timings must not be scaled by these counts.

## Repeated Source and custody trace

Paths below are relative to crates/vprouter-launch/src.

1. `attachment/operational.rs:64-81` checks the operational reservation and
   delegates retained host custody; mutable service access repeats custody.
   `attachment/host_addition/operation.rs:227-280` rechecks its retained owner,
   generation, producer-bound host custody and four completed host receipts.
   `attachment/producer_binding.rs:309-337` validates producer-bound service
   custody; operational_source additionally verifies acknowledged Source history.
2. `owned/preparation/host_link.rs:442-467` calls Binding service custody,
   validates full preparation History and binds/rechecks all four original
   receipts. `owned/preparation/quarantine.rs:41-54` checks transport service
   custody, Native.require_creator/allocation memory and exact shared/member/owner
   relationships before retained validation. `owned/preparation.rs:1035-1039`
   reaches `owned.rs:1622-1648` allocation memory/bind_anchor, which also validates
   preparation history. This is repeated finite composition, not an observed cycle.
3. `kernel/producer_creation.rs:338-350` Source.verify_retained validates original
   success/reap/EOF/time facts and calls Native.source. `:368-370` identity first
   calls verify_retained, then Native.source again before Identity::of. The
   descriptor method repeats this pattern (:372-380). Thus a successful identity
   reaches Native.source twice, without asserting any exact run405 identity count.
4. Native.source (`:107-121`) freshly checks descriptor registration and invokes
   `attachment/quarantine/producer.rs:154-199` verify_created_group. That first
   calls Request.verify_retained (:70-78), which checks current parent token and
   parent identity, then Binding.verify_retained. The group verifier additionally
   checks current group metadata/name, opens and checks its parent, and reads
   cgroup.procs/type/subtree_control/events. These observe external mutable native
   state; their apparent duplication is not a license to remove an observation.
5. Acknowledged history/write verification composes require_acknowledged and
   receipt verification (`kernel/producer_creation.rs:293-308,322-349`). Bootstrap
   Request verifies direct Source, Pins and Source.identity separately
   (`attachment/operational/bootstrap.rs:145-179`). Pins verifies acknowledged
   Source, eight registered slots with current metadata/fs/flags, Source.identity
   and original producer ancestry (`attachment/operational/producer.rs:119-181`).
   These paths repeatedly reach the same Binding while checking distinct current
   custody/native facts. No call count is inferred from source shape alone.

## What is inside Binding retained

`owned/preparation/quarantine.rs:56-101` performs, in original order:

- Transport and DATA retained pin checks. Each mounted object's verify_retained
  (`kernel/{fresh_transport_mount,namespace_attachment}.rs:412-424`) checks
  request pins and mounted pins. Those pins include current descriptor inventory,
  fstat/fstatfs, placeholder and namespace identity, and named openat2 checks
  (:152-179). Transport request additionally checks its original retained Source
  and identity (`attachment/transport.rs:415-433`). Registration.contains and
  retained_slots call live_slot; observed identity uses fresh /proc/self/fd statat
  and descriptor flags (`inventory.rs:89-99,165-175,375ff`).
- Allocation/record/service cardinality and exact owner check. OwnerDomain::record
  calls verify before cloning (`supervision.rs:125-144`). That executes
  host_preflight, current host/self namespace identities, process start/boot,
  pinned and named cgroup identity and current /proc/self/cgroup. Namespace checks
  open both self and PID1 pins for four namespaces (:147-168). host_preflight
  itself reads thread/credentials/status/maps/LSM and checks proc/cgroup filesystem
  type (`process.rs:253-281`). This substantial fresh work is currently hidden
  inside the broad retained row; its elapsed share is unknown.
- Host registration/network identity, then complete History.validate (:85).
  `owned/preparation.rs:90-222` recomputes serialized allocation SHA256, validates
  original windows/input identities, and walks inspection/mount/transport,
  WireGuard/query/producer/filter/host/Bootstrap histories. This part is pure
  in-memory validation, including fresh serialization and a duplicate-input
  HashSet. Its elapsed share is also unknown. The final Binding comparisons
  additionally bind original result/five operations/configuration/movement.

No source evidence makes a successful earlier validation a substitute for any
later live observation, including within one poll: external state can change
between syscalls. A borrowed or cached "already verified" token would need a
separate explicit scope/concurrency/equivalence design, not just Rc identity.
It is not the proposed next implementation.

## Concrete bounded next proposal, not implemented or authorized here

Recommend a diagnostic brief before another semantic optimizer:

The minimal proposed source scope is exactly five existing files (no edits now):

| File under crates/vprouter-launch/src | Bounded diagnostic insertion |
| --- | --- |
| owned/preparation/quarantine.rs | Timers around existing transport.verify_retained, data.verify_retained, owner.record expression and p.validate call |
| owned/preparation.rs | Timer around existing allocation Serialize+digest expression in History.validate |
| kernel/producer_creation.rs | Count entries to Source.identity and Native.source; no call or check replacement |
| attachment/quarantine/producer.rs | Timer around native group body after existing request.verify_retained succeeds |
| owned/preparation/lab_cost.rs | Fixed diagnostic keys/counters/storage/snapshot and focused helper checks |

Owner and namespace-pin timings are at their existing Binding caller boundaries;
no edits to supervision.rs, process.rs, either mounted-kernel implementation,
transport.rs, inventory.rs, owned.rs or operational/bootstrap.rs are needed.
The existing snapshot emitter can retain all old rows and emit added fixed rows
from the diagnostic helper. Source.identity/native source insertions count calls
without changing their duplicated live observations. Each application insertion
must be cfg(test), removable to reproduce original production bytes. This is a
measurement proposal only; the optional digest optimizer below is a different
future brief and is outside these five-file diagnostic insertions.

1. Add cfg(test)-only fixed-label elapsed/count measurements around the existing
   Binding transport call, DATA call, owner.record expression and History.validate
   call; separately measure allocation serialization+digest inside History.
   Retain exact expression/short-circuit/error order and all original statements.
   Place the owner timer around that existing expression, not a precomputed value
   moved ahead of earlier conditions. Use RAII so early errors remain counted.
2. Add counts for Source.identity and Native.source entries, and an elapsed/count
   region for verify_created_group's native body AFTER its existing
   Request.verify_retained succeeds. This distinguishes fanout and current
   group/ancestry work without removing that request/binding check. No new poll,
   clock retry, production log, per-entry text/identity output or check is added.
3. Keep the13 wrappers and30 existing totals. Additional labels are bounded:
   five retained/history elapsed categories, one group-native elapsed category,
   two entry counters, each in the same three loop-entry families. Avoid making
   each existing timer copy a larger whole-table TLS state just to add these rows;
   review a separate fixed selected-row update or similarly bounded accounting.
   Preserve thread/epoch/creator/child-COW boundaries, no getpid in restricted
   publisher timer paths, no permissions/filter changes, no child merge/export.
   Time accounting itself adds observer/scheduling cost; report it explicitly.
4. Require normal-build exclusion/source-equivalence proof, focused diagnostic
   helper behavior checks, source freeze and independent review. Root alone owns
   coherent/static builds and a new preserved native run with all original2s,
   proof/custody/hold/negative/release/ACK and failure boundaries unchanged.

The new rows would still be elapsed inclusive mechanism boundaries; history and
its digest overlap, transport can include original DATA checks, and counters
include errors. Do not subtract rows into CPU attribution or promise speedup.
Choose the next pure-work brief only after actual observed portions justify it.

One feasible pure-work experiment, if digest/history is material, is streaming
that exact allocation Serialize output directly into a local SHA256 writer,
then producing the identical lowercase hex string, instead of a temporary Vec
followed by `vprouter_worker::bootstrap::digest`. The current digest implementation
(`crates/vprouter-worker/src/bootstrap.rs:76-80`) also formats each byte into a
small String. A local bounded helper could avoid those transient buffers while
keeping every validation/call site and recomputing on every call. Before any
implementation it needs exact old Result/digest differential oracles for all
field/order/path/error cases, the same serializer and hex bytes, no cache or
new authority, and an isolated mechanism measurement. No digest representation,
canonical serialization or stored value may change. Its native share and budget
benefit are unknown; it is secondary to the diagnostic proposal, not an inferred
fix. Existing expected-record encoding is still a smaller measured category and
has no demonstrated cache priority.

No source/test/build work is authorized by this report. Original398-405 failures,
Bootstrap/task8c/client/migration/platform/benchmark/release gates remain open.
405 is synthetic with provider_profiles_used=false: switching Mullvad servers
cannot explain this Deadline or change this read-only scope.
