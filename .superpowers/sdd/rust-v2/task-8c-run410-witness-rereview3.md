# Independent fourth review: run-410 offline witness validation

2026-11-06. Branch `rust/v2`, HEAD
`35c3befd8e8bee60b00630d0a9171eefaad199ac`. No subagents started.

**Verdict: FAIL.** I9, I10, M2 and the additional Initial-query discriminator
reproduction are fixed. With the originally reviewed frozen bindings, all
**70 retained earlier mutation records** fail through the CLI; the original
record and two retained valid copies pass **20/20**.
The requested full suite also passes: **38 tests, 102,334 leaf mutations**.
Nevertheless, independent source-driven mutations reproduce **25 false PASS
records in four Important finding families**, plus one Minor constant mismatch.
These are detectable contradictions in serialized evidence. They do not show
that the original run executed incorrectly.

**Final live-worktree qualification:** a subsequent real-record rerun exits1,
FAIL19/20 because `frozen_bindings` detects a concurrent change to
`tools/rust-v2-lab/fresh-baseline.py`. This is a correct drift refusal, separate
from the semantic findings below. The earlier real-PASS, suite results and
false-PASS reproductions refer to their tested point-in-time bindings. No
helper was restored or changed by this reviewer to make the final check pass.

This review concerns **offline typed validation and recorded-witness
consistency**. It grants no runtime, requirement-8, migration or release
acceptance. `runtime_acceptance=false` and `release_ready=false` remain correct.
No Critical finding.

Scratch evidence is `/tmp/vprouter-witness-r4/reviewer/`, a separate subdirectory
from the implementer's retained r4 work. Every reported false PASS was generated
from the real record and run through:

```text
python3 -B tools/rust-v2-lab/validate-run410-witness.py <scratch-fixture.json>
```

Every such retained invocation exited **0**, verdict **PASS**, all **20/20**
checks PASS, including the frozen bindings at its execution time.
Fixtures and their `.stdout`/`.stderr` are retained. Only this repository report
was written by the reviewer; no implementation changes were made.

## Important I11: actual network results lack canonical plan bindings and native success guards

Python locations:
`tools/rust-v2-lab/validate-run410-witness.py:1818-1840,1901-1914,2030-2033`.
The checks enforce namespace, populated results, down/kind, the original host
pair, and selected move-to-query equality. They do not bind all WireGuard
results to the allocated device name/alias and recorded input public key, check
the device's own name/index against its Link, enforce the one-peer/default-route
contract, preserve the original provision-to-query Link, or enforce native Link
constraints beyond down/kind.

Rust rejects these states on the actual success path:

- `crates/vprouter-network/src/plan.rs:34-48,81-86` derives the ownership alias,
  allocated WireGuard name and device public key from the public plan.
  `crates/vprouter-launch/src/attachment/provision.rs:66-76` uses this plan.
  The frozen guest records each synthetic input's actual derived device public
  key at `target/platform-lab/secret-bootstrap.guest.py:101-107`; its hash matches
  `record.guest_sha256`. No private key inspection is needed to compare that
  recorded public key to a result.
- `crates/vprouter-network/src/native/readback.rs:144-159` requires the requested
  name/kind, correct ownership alias, down state, **MTU1420, controller0, empty
  port_kind, promiscuity0, all_multicast0 and no alternate names**. Both WG and
  veth success paths use these reads. See
  `secret_role/provision.rs:386-430`, `secret_role/veth.rs:337-391` and
  `secret_role/movement.rs:391-427` in the same crate. `native.rs:502-518`
  independently contains the equivalent token guards.
- `crates/vprouter-network/src/native.rs:697-710` requires the device index to
  equal the original Link index, name to equal the plan name, public key to equal
  the plan key, exactly one peer, the planned peer key/endpoint, and precisely
  `[(0.0.0.0,0)]` allowed IPs. These checks run at
  `secret_role/provision.rs:430`, `secret_role.rs:411-412` and
  `secret_role/movement.rs:427`.
- `crates/vprouter-network/src/secret_role.rs:407-412` requires the query's Link
  to equal both the current readback and its original provision Link.

**REPRODUCED**, 21 fixtures (all suffixes below include `.json`):

| Fixture or fixture family | Mutation, with retained copies coordinated |
| --- | --- |
| `wireguard_public_key_foreign_from_input_all_copies` | Flip byte0 of every WG device public key; recorded input metadata remains original. |
| `wireguard_name_foreign_from_allocation_all_copies` | Every WG Link name becomes `foreignwg`; allocation remains original. |
| `wireguard_alias_foreign_from_allocation_all_copies` | Every WG Link alias becomes `foreign-alias`; allocation remains original. |
| `wireguard_provision_query_key_mismatch` | Change only provision-result public keys and their retained copies; query/move remain original. |
| `wireguard_peers_removed_all_copies` | Every WG device has `peers=[]`. |
| `wireguard_result_device_name_differs_from_link` | Every WG device's own name becomes `foreignwg`; Link names remain original. |
| `wireguard_result_device_index_differs_from_link` | Increase every WG device's own index by100; Link indices remain original. |
| `wireguard_original_provision_query_link_mismatch` | Increase only provision-result Link MTU by100 in every retained copy; original query Link remains unchanged. |
| `wireguard_link_guard_{mtu,controller,port_kind,promiscuity,all_multicast,alternate_names}_all_copies` | Six separate fixtures: every WG Link gets respectively1400,1,`bridge`,1,1,`["foreign-alt"]`. |
| `wireguard_allowed_ips_empty_all_copies` | Every peer has `allowed_ips=[]`. |
| `veth_link_guard_{mtu,controller,port_kind,promiscuity,all_multicast,alternate_names}_all_copies` | Six separate fixtures: every vprouter veth Link gets the same six invalid values above; pair/move/inventory and retained copies agree. |

The omitted planned peer key/endpoint comparisons were traced in source, but no
separate key/endpoint mutation is counted as a finding here. The table reports
only executed reproductions. The absent addresses/routes checked by native
readback cannot be fully reconstructed from these result objects and remain a
native-only limit.

The registry labels the final `wireguard`/`host_link` histories as roots at
validator `:1951-1956`; binding repeated observations to those roots does not
validate these root-to-plan or intra-result relationships. Required correction:
port the available serialized success guards and canonical plan/public-input
bindings, including provision/query continuity, while explicitly retaining the
limits for unrecorded live inventory. Evidence: `bindings.py`, `wg-more.py`,
`link-guards.py`, `peer-host.py` and their result JSON files.

## Important I12: WAN observation window is treated as an independent root

Python location: `tools/rust-v2-lab/validate-run410-witness.py:2044-2047`.
`wan_observation_window` has `mode='root'`; the binder skips comparisons for
roots at `:2102-2103`. `monotonic_deadlines` at `:1657-1677` checks its own
two-second window only. `baseline_consistency` at `:2565-2567` correctly binds
WAN identity/declaration, but adds no operation-window binding.

Rust explicitly carries the **same start and end** from the WAN read into the
HOST InitialQuarantine request:
`crates/vprouter-launch/src/attachment/quarantine.rs:658-674,704-716`.
The request requires that original WAN receipt at `:188-190`;
`attachment/host_declaration.rs:207-218` checks `self.end == end` and original
observation time against that clock. Its emitter at `:226-238` serializes
`requested_at=end-2`, the original deadline and verified time. Thus these fields
are not independent timing roots: they belong to `preparation.netfilter[1]`.

**REPRODUCED**:

| Fixture | Mutation |
| --- | --- |
| `wan_window_foreign_from_host_policy.json` | Add1 to only WAN `requested_at`, `deadline` and `verified_at`, preserving its internally valid two-second interval. The corresponding host policy retains its original window. |
| `wan_verified_after_host_policy_birth.json` | Set only WAN `verified_at` to host-policy birth time+0.001. It remains inside the WAN window but claims the prerequisite WAN read completed after the native policy child was born. |

Both return **PASS20/20**. Bind WAN start/end to the canonical host policy and
enforce available prerequisite time ordering. The first fixture alone directly
violates the explicit equal-deadline guard, without inferring a live clock.
Evidence: `more.py`, `more-results.json` and per-fixture outputs.

## Important I13: the host-addition intent digest may be all zero

Python locations: `tools/rust-v2-lab/validate-run410-witness.py:1367-1370`
checks `addition` shape and index width; `:1888-1914` checks the move
discriminator/index/result; `:1753-1757` checks named digest fields but does not
visit the digest at `addition[0]`. Registry `host_operations` at `:1996-2000`
copies `addition` equality without its nonzero guard.

Rust explicitly rejects zero at
`crates/vprouter-launch/src/owned/preparation/host_link.rs:86-92`:
`digest == [0;32]` is an ownership mismatch. The original Request obtains this
digest from the actual HostAdditionPlan at
`attachment/host_addition/operation.rs:58-65`.

**REPRODUCED**: `host_addition_zero_digest_all_copies.json` replaces only
`addition[0]` with32 zeros in the move observation and every retained canonical
host-link copy. Index, namespace, birth, result, writers and all other fields
remain unchanged. The CLI returns **PASS20/20**. This is a missing serialized
success guard, independent of any residual limit on regenerating nonzero
request/plan digests. Add the nonzero check and an end-to-end regression.
Evidence: `fresh.py`, `fresh-results.json`.

## Important I14: DATA and TRANSPORT can claim different original journal directories

Python locations: `tools/rust-v2-lab/validate-run410-witness.py:1776-1784`
validates DATA's directory locally; `:1808-1817` validates fresh creation/mount
directory equality locally. Registry `transport_mount` at `:1969-1972` correctly
binds its observation to fresh mount history, but no entry or complementary
guard binds that directory to the preceding DATA attachment directory.

Rust takes both from the **same retained journal.dir**:
`crates/vprouter-launch/src/owned/preparation/mount.rs:404-425` duplicates it for
DATA and `:439` checks its identity against the mount request;
`owned/preparation/fresh_transport.rs:256-283` duplicates it for TRANSPORT and
`:298` checks its identity against creation. Fresh mount then duplicates that
original creation directory and checks equality at
`attachment/transport.rs:358-361,425-426`. Provision preserves the original
service/preparation at `attachment/provision.rs:861-885`. This is a recorded
same-origin identity relationship, not a request to reopen a live directory.

**REPRODUCED**: `transport_directory_foreign_from_original_journal.json`
increments the inode by100 in every populated fresh-transport creation
directory, every fresh-mount directory, and the transport-mount observation's
`original_directory`. It preserves DATA attachment/mount directories. Device,
placeholder identity/mode, names, requests and births remain unchanged. The CLI
returns **PASS20/20**. Fresh observation-to-history equality holds while the
original journal identity has been substituted. Bind these canonical directory
identities and retain I9's current observation equality checks.
Evidence: `bindings.py`, `binding-probe-results.json`.

## Minor M3: assembly's fixed capacity constant is unchecked

Python locations: `tools/rust-v2-lab/validate-run410-witness.py:2255-2265`
validates assembly charges/reservation but omits its `global_child_capacity_limit`.
The schema merely permits u64 at `:594`; the handoff's distinct capacity field
is checked at `:1587-1588`.

The frozen emitter hardcodes the assembly value64 at
`crates/vprouter-launch/src/attachment/assembly.rs:354`.
**REPRODUCED**: `assembly_child_limit_wrong.json` sets only
`host_addition.producer_binding.assembly.global_child_capacity_limit=65` and
returns **PASS20/20**. This is a literal evidence inconsistency with lower impact
than the identity/result contradictions above. Require64 for this frozen profile.

## Earlier findings and exact I9/I10/M2 assessment

| Item | Rust contract | Python implementation and result |
| --- | --- | --- |
| I1-I8 | Respective first/second review sources | All retained reproductions, including the four second-round control records, now fail. Prior reports remain unchanged. |
| I9 creation | `kernel/fresh_transport.rs:498-505`; `owned/preparation/fresh_transport.rs:112-120` | `validate-run410-witness.py:1967-1968` compares request, source/host/data **full dev+ino identities**, full birth **PID/start/born_at/deadline**, request time, original deadline and verification time to canonical creation history. All earlier creation substitutions fail. |
| I9 mount | `kernel/fresh_transport_mount.rs:852-861`; `owned/preparation/fresh_mount.rs:115-120,452-453` | `validate-run410-witness.py:1969-1972` compares full birth/time/deadline/placeholder, original source->source and original directory->directory. Placeholder includes full identity and u32 mode. All earlier mount substitutions fail. |
| I9 names and request context | `owned/preparation/fresh_mount.rs:25-36`; `attachment/transport.rs:358-376` | Mount observations do not serialize their own name/request digest. `canonical_histories` at Python `:1809-1816` checks fresh name against allocation, fresh/mount name and source/directory equality; timing at `:1648-1679`. The additional coordinated foreign-name probe fails. The separate common-journal relation remains missing (I14). |
| I9 successful provision | `attachment/provision.rs:878-885` | Python `:1809-1813,1967-1971`: source distinct from host/data, mount source=creation source=canonical transport. Earlier coordinated source-substitution fixture fails. |
| I10 actual down/kind | `attachment/provision.rs:1002-1005`; `attachment/movement.rs:824-835` | Python `:1833-1835` checks populated results themselves. All-copies UP and wrong-kind fixtures fail. |
| I10 original move | `attachment/movement.rs:824-835` | Python registry `original_wireguard_move` at `:2032-2033` compares DATA move name/alias/public key/peers with **original TRANSPORT query result**, not a substituted moved copy; canonical destination is checked at `:1837-1840`. All four original moved-only substitutions fail. Further original-result guards remain missing (I11). |
| M2 Route.kind | `crates/vprouter-network/src/project.rs:68` is u8 | `test-validate-run410-witness.py:197-198,343-352` now selects8 bits and independently tests256. The retained actual-u8 overflow fixture fails `typed_witness`; full source-width test passes. |
| Initial discriminator | `owned/preparation/inspection.rs:142,864-875` | Python `:1988-1991,2099` binds the first observation's kind to literal Initial. Independently changing only it to BootstrapHostRecheck fails `observation_bindings`. |

## Independent source-to-registry inventory and difference

This inventory was traced from the Rust histories, request/native emitters and
successful lab branches, then compared with the executable registry. It was not
inferred from the real record's shapes or the implementer's coverage test.
The exported registry and independently rerun coverage are retained as
`binding-registry.json` and `binding-coverage.json`.

Notation: `P=witness.preparation`, `H=host_addition`, `B=H.producer_binding`,
`A=B.assembly`, `Q=A.quarantine`, `M=Q.movement`, `V=M.provision`,
`T=V.attachment`. Paths starting with H below are relative to witness.
Identity means both dev/ino; birth means PID/start/born_at/deadline.

| Required observation/canonical relationship, from Rust | Registry disposition |
| --- | --- |
| Original preparation birth/member/namespaces/owner/history/writers; `owned/preparation.rs:1567-1662` | 1 canonical root. Canonical fields are checked by separate functions; root designation itself makes no comparison. |
| T,V,M,Q,A,B,H,handoff historical preparations retain populated original histories and writer prefixes; successful branches of the attachment emitters | 8 projection entries. Populated history fields and list prefixes bind to P; null earlier fields skip comparison and need stage guards. |
| V creation->P.fresh_transport: request, source/host/data identities, birth, start/end/verified; `kernel/fresh_transport.rs:498-505` | `transport_creation`. |
| V mount->P.fresh_transport.mount: birth, start/end, source/directory/placeholder; `kernel/fresh_transport_mount.rs:852-861` | `transport_mount`. Common journal-directory source omitted: I14. |
| T mount->P.attachment: same mount evidence fields; `kernel/namespace_attachment.rs:854-890` | `data_mount`. |
| T validator birth->P.birth; `attachment/mount.rs:690,832-845` | `validator_birth`; zero wait status separately checked. |
| T.second_query, T.postmount_query, M.movement_query, Q.quarantine_query, Q.producer_query, B.query, witness.queries[*]->their selected histories: kind/birth/facts/start/end/verified; `owned/preparation/inspection.rs:8-24,142-326` and `kernel/docker_query.rs` emitter | 7 query entries, correct canonical slots/index capture. |
| T.first_query->P.inspection.initial birth/facts/verified and P.inspection start/end, with literal Initial kind; `inspection.rs:142-165,864-875` | 3 initial-query entries, including fixed discriminator. |
| V.operations[*], M.operations[*]->P.wireguard[*]: kind/request/birth/start/end/result/accepted->verified/original PID/start; `kernel/wireguard_role.rs:1540-1592` | 2 operation entries. Actual result-to-plan and provision/query/intra-result relationships omitted: I11. |
| Q.operations[*]->P.netfilter[*]: same operation bindings plus scope; `kernel/netfilter_role.rs:702-753` | `quarantine_operations`. Host declaration digest is additionally bound outside registry at Python `:2554-2567`. |
| H.operations[*]->P.host_link[*]: operation bindings plus namespace/host/declaration/admission/addition; `kernel/host_link.rs:783-824` | `host_operations`. Addition nonzero omitted: I13; native Link guards omitted: I11. |
| witness.operations[*]->P.bootstrap[*]: operation bindings, namespace/scope/query/policy/pins/group; parent/name->P.producer_creation; `kernel/bootstrap.rs:529-565`, `owned/preparation/bootstrap.rs:77-136` | `bootstrap_operations`, `bootstrap_producer_source`. Correct result/publication checks supplement registry. |
| B.observation->P.producer_binding: original request/birth/result/acceptance/source/query/policy/six pins; `kernel/producer_binding.rs:545-582` | `binding_operation`. |
| Q.producer->P.producer_creation: request/source/group/name/DATA/query/birth/start/end/verified/PID/start; `kernel/producer_creation.rs:672-713` | `producer_operation`. |
| B.original_group->P.producer_creation.group; `attachment/producer_binding.rs:1038-1042` | `binding_original_group`. |
| H intent75, Bootstrap query-intent87 and policy-intent90->original writers; `host_addition/operation.rs:988-1002`, `operational/bootstrap.rs:1071-1087` | 3 intent entries for PID/start; indices/polls/status/release checked separately. |
| Q intent42->original writer PID/start/deadline/verified/status; `quarantine/producer.rs:820-843` | `quarantine_intent`; exact request window also follows writer deadline and two-second guard. |
| A.resources[0..15] and handoff.resources[0..5]->original job births, with reservation member/owner->P; `kernel.rs:2490-2516`, `owned/preparation/assembly.rs:77-91,303-316` | 20 retired-job entries + 2 reservation-owner entries. Kind, status, retirement and lower-charge flags checked separately. |
| P.wireguard[4] move->P.wireguard[2] original query name/alias/key/peers; `attachment/movement.rs:824-835` | `original_wireguard_move`; I10 fixed. |
| H.admission->original host-link admission triple/declaration/host namespace; `host_addition/operation.rs:739-741` | `host_admission_history`. |
| H.admission baseline/namespace->stdout authored baseline; `host_addition/operation.rs:732-741` | `host_baseline`; digest/size/template bindings separately checked. |
| Final H host inventory namespace/addresses/routes/rules->original admission baseline; links->original pair/move plus prior links; `host_addition/operation.rs:1099-1115` | `host_inventory` plus explicit `host_inventory_links` root; exact one-added-link comparison separately checked. Native added-Link guards omitted: I11. |
| Q.wan identity/uplink->original host declaration; digest->that declaration's digest; `host_declaration.rs:226-238` | `wan_declaration`; digest equality outside registry at Python `:2567` correctly rejects independent digest mutations. |
| Q.wan start/end/verified->HOST InitialQuarantine original request; `quarantine.rs:658-674,704-716,188-190` | **Incorrect independent root** `wan_observation_window`: I12. |
| A.foreign_eligibility eligible parent PID/start->original WG sockets birth; standalone foreign worker observation has no canonical worker history | `foreign_capacity_parent`, `foreign_capacity_observation` root. Refusal/status/counters/time are separately checked; live eligibility not claimed. |

The disposition counts are exactly **67 registry entries**. Fresh execution of
`binding_coverage` reports **1,615 observation objects, zero uncovered**. That
count is reproducible, but is **not a completeness proof of semantic bindings**.
At Python `:2122-2145` it recognizes selected identity/time key names and accepts
a registered ancestor prefix; canonical-root fields and root-only WAN timing
therefore count as covered even when an available relationship/guard is absent.
In particular WG device objects and peer facts require semantic contracts beyond
this identity-key heuristic. Root mode's `guards` labels are documentation;
`bind_observations` skips root equality and the separate checks must enforce the
actual contract. I11-I14 demonstrate where that contract remains incomplete.

## Successful endpoint guard audit

The following enumerates the serialized successful-endpoint guard families
checked while auditing those bindings. Native-only clauses are classified below;
private transient states are not invented from the completed projection.

| Rust successful guard family | Python coverage / difference |
| --- | --- |
| `owned/preparation.rs:95` History validation: member/allocation/configuration/owner/input identity, original birth/result windows and ordered optional histories | Exported member/owner/birth and selected histories checked at Python `:1629-1645,1648-1914,2434-2470`. Full private allocation/configuration/input/PublicValidation history is not exported; corresponding native/full-history clauses remain unavailable. |
| `owned/preparation/inspection.rs:142-326`: nonzero requests; exact kind/initial discriminator; initial/recheck equality; original birth/facts/PID range/window; predecessor completion and selected stage/query | Python `:1753-1757,1787-1805`, typed schemas, `monotonic_deadlines`, ordered operation/query checks. Initial/recheck, attachment, movement, quarantine, producer, binding and all3 Bootstrap selectors traced. |
| `owned/preparation/mount.rs:26-110`: valid origin/source/name/directory, original inspection, exact two-second window/birth/placeholder, mounted/query/published order, DATA/base publication | Python `:1772-1805`, registry mount/query entries, timing and controller origin bindings. Full PublicValidation report equality lacks a second exported canonical report. |
| `owned/preparation/fresh_transport.rs:21-68`, `fresh_mount.rs:20-79`: nonzero request; names/directory/host/DATA/source distinctness; birth/result/window; exact0600 placeholder; original creation->mount->publication | Python `:1808-1817`, transport registry and timing. Common original journal directory still omitted (I14). |
| `owned/preparation/wireguard.rs:60-148`: five kinds/namespaces, immutable configuration, original move query/destination, predecessor completion, native birth, result presence/namespace/acceptance | Python `:1818-1840`, closed move/nonmove schemas, timing and registry. Actual result native/plan guards omitted (I11). |
| `owned/preparation/quarantine.rs:328-433`: six scope/kind pairs; nonzero request/policy/host declaration; same configuration; namespace, positive start, move/predecessor completion; DATA query; result namespace/policy/observed time | Python `:1841-1863`, timing, digests, baseline declaration equality and query binding. Supporting WAN request window omitted (I12). |
| `owned/preparation/producer_creation.rs:37-100`: completed producer query/time; correct DATA/group name; six completed policies; parent/group identity/dev/distinctness; original birth and accepted time | Python `:1864-1872`, timing and producer registry. Group receipt native custody remains unavailable. |
| `owned/preparation/producer_binding.rs:65-136`: original creation/source/DATA/query/policy; six parent/group/device pins; original publication; birth/result/observed/accepted window | Python `:1685-1695,1873-1887`, timing, registry, retained binding flags and entry producer checks. |
| `owned/preparation/host_link.rs:44-190`: four kinds; nonzero request/declaration; namespaces; original admission triple/order; move-only addition/nonzero digest/planned index; predecessor; native birth/time; socket-null results; original down pair; exact moved pair/index | Python `:1888-1914,2286-2311`, registry, timing, controller/baseline. Addition digest guard missing (I13); lower network result guards missing (I11). |
| `owned/preparation/bootstrap.rs:40-139`: three ordered scopes; completed own query/prior scope or host move; original creation and published binding; completed policy; eight distinct pins; original birth/result/group/namespace/policy/pins/observed/accepted time | Python `:1685-1757`, timing, registry and recorded pin mode/type guard `:2429-2431`. |
| `owned/preparation/assembly.rs:45-109,303-395`: original owner/member/job set, completion, transfer marker, limits, original fully retired resources and suffix | Python handoff `:1583-1611`, resource guards `:2340-2347,2403-2422`, reservation checks `:2261-2265`, binding entries. Root assembly capacity literal missing (M3). |
| `attachment/mount.rs:843-968`: success status/reaped/reserved/pending/fence/base, 17 exact writers/phases/windows; retained mount+postquery; base/DATA publication, pristine/continuation flags | Python `recorded_emitters`, `preparation_idle`, `writer_histories`, registry and query/namespace checks. |
| `attachment/provision.rs:861-1005`: 33 writers with original17 prefix; original owner/member/DATA/inspection/attachment; idle/pristine; completed distinct creation/mount; original socket borrowing; three operation/history results, acknowledgment and down/kind | Python retained/prefix/operation/transport checks. I9 and I10's cited guards fixed; additional result guards I11/I14 remain. |
| `attachment/movement.rs:677-849`: 42 writers/prefix33; original3 histories/operations; owner/namespace/preparation continuity; current query/process deadline; query sequence advance; original5 operation receipts; move source and down/kind/name/alias/key/peers | Python `retained_success`, `recorded_emitters`, `writer_histories`, timing, move registry. I10's moved-only substitutions rejected; coordinated original-result defects remain I11. |
| `attachment/quarantine/producer.rs:824-1023`: intent42/index/PID/start/status/polls/window; 69 writers/prefix42; six original policy receipts; producer query/source/group acknowledgment, original final-process time and false publication | Python intent/retained/operation/query/producer checks; WAN prerequisite gap I12. Held polls are **at least2**, not exactly2. |
| `attachment/assembly.rs:315-354`: 15 retired resources, unchanged preparation/writers69, reaped/uncollected/reserved/idle, complete reservation, charges15/11->0/0, repeats, continuation/drop/false authority | Python `:2255-2265,2340-2347,2403-2422`, retained flags. M3 constant omitted. |
| `attachment/producer_binding.rs:955-1077,1124-1160`: 75 writers/prefix69 and retained fields, original group/request/query/creation, successful result/ack/native registration, published entry and creating/absent state, final process window,25 negatives and charges0/0->1/1 | Python binding registry, `retained_success`, `preparation_idle`, canonical publication and width/timing checks. |
| `attachment/host_addition/operation.rs:950-1153`: 87 writers/prefix75, intent75/queued1/held2/released/12 negatives; original four operation receipts/registrations/status/results; canonical20 negatives; exactly one down addition and preserved inventory; charges1/1->5/5; continuation flags | Python retained/original operation/intent/baseline/inventory/prefix/charge checks; lower Link guard omission I11 and zero addition digest I13. |
| `attachment/operational.rs:479-588`: successful retained host, five exact suffix jobs,20=15+5, repeated retirement refusal, completed reservation, charges5/5->0/0, unchanged preparation, capacity64 | Python `handoff`, charge conservation, registry, resource flags. |
| `attachment/operational/bootstrap.rs:1028-1287`: final105 writers/prefix87, exact idle/creating/absent/producer/retained16 fields, intents87/90,18 phases/windows,3 query/operation/history bindings, acknowledgment/result/acceptance, final process times,39 negatives, charges3/3 retained, postdrop contexts and false authority | Python `bootstrap_success`, `preparation_success`, `bootstrap_scopes`, timing, registry, writer schedule and charge conservation. |
| `kernel/{fresh_transport,fresh_transport_mount,namespace_attachment,docker_query,wireguard_role,netfilter_role,producer_creation,producer_binding,bootstrap,host_link}.rs` successful emitted status/identity/registration/release/ack/EOF/source/result fields | Python closed schemas, `original_operation`, `recorded_emitters`, registry and timing; actual retained-FD/capability proof remains native-only. |
| Network native readback/provision/query/move/veth success: original name/alias/down and fixed Link attributes, public WG plan/device/peer/index/name, provision/query identity, original readback | Serialized missing comparisons reproduced as I11. Actual readback execution and absent addresses/routes cannot be certified offline. |

No further suspected false PASS is promoted without a fixture. In particular,
`host_admission_one_poll.json` and `quarantine_intent_too_many_polls.json` are
accepted **without a finding**: the former is not proven impossible by the
source admission loop, and the latter satisfies the explicit at-least2 guard.
`host_addition_foreign_nonzero_digest_all_copies.json` is also accepted, but
independent regeneration of that plan/request digest was not performed; only
the independently explicit zero-digest contradiction is counted in I13.

All226 independently generated coordinated boolean probes are rejected. This
supports the checked serialized booleans; it cannot establish correct integer,
array, time or cross-source relationships. Earlier WAN digest, Initial-kind,
intent-window and allocated transport-name probes are rejected as expected.

## Read-only behavior, receipts and limits

**PASS for the requested offline IO and receipt-safety scope.** The standard
library validator reads evidence/artifacts without importing controller code.
Its sole explicit write operation is `save_receipt()` at Python `:2631-2642`:
`O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`, mode0600, `fchmod(0600)`, file
flush/fsync and parent-directory fsync. It does not create parent directories,
replace files, acquire claims/reservations or invoke guest commands.

The independent audit hook observed **61 read opens** and only two write-open
attempts to the explicitly selected scratch receipt: successful exclusive
creation and refused overwrite. It rejects subprocess/system calls, network
connect/bind, preserved-tree accesses, other write opens and remove/rename/link/
mkdir mutations. No prohibited event occurred. FD write/fchmod/fsync paths were
also source-inspected. This is a bounded Python audit, not a whole-host syscall
trace. See `io-review.py` and `io-results.json`.

Independent CLI receipt creation succeeds with mode0600. A second creation
exits1 and preserves bytes. A symlink receipt exits1 and preserves its target.
Both `python3 -B -O` and `python3 -B -OO` exit1 with
`RuntimeError: optimized_python_refused` before creating a receipt; the
unconditional guard is Python `:17-18`.

The existing r4 receipt is mode0600 and SHA256
`a50fdf4f30f58d22ee08aab685791cd74707262a33ceefdb76d5e9cc6e430e8f`.
Its parsed contents equalled fresh CLI validation of the same relative
real-record path before the later helper drift. All r1-r4 receipts remain
unchanged. Seven explicit `does_not_prove`
limitations, `validation_scope`, false runtime/release flags, and the report's
native-only residual limits are appropriate. Creator/Rc/Weak provenance,
unexported full journal/PublicValidation/configuration, FD custody/access modes/
UID/GID/fstatfs/registration capabilities, actual durable progress, live original
processes/guest state and post-drop survival remain **NOT_RUN/unavailable**.

The implementation report's statement at
`task-8c-run410-witness-validation.md:1148-1150` that the registry closes missing
observation-to-history accounting is incomplete because of I12/I14, and its
full-validation PASS label still exceeds the checked offline semantic coverage.
The finite-test/native-custody caveats are honest, but they do not explain away
the available recorded contradictions above. Historical RED-first claims were
not independently reconstructed.

## Verification ledger

All Python invocations used `python3 -B`. Test temporary directories used
`TMPDIR=/tmp/vprouter-witness-r4/reviewer`; explicit py_compile output used
`PYTHONPYCACHEPREFIX=/tmp/vprouter-witness-r4/reviewer/pycache`.

| Verification | Fresh result | Scratch evidence |
| --- | --- | --- |
| Every retained earlier record fixture via CLI, original bytes unmodified | **70/70 mutations exit1/FAIL**: round1=18, round2=15 including4 controls, round3=37; valid retained real and reserialized copies both exit0/PASS20/20 | `prior-cli-results.json`, per-fixture `review--`, `rereview--`, `r3--` outputs |
| Original `target/lab-state/actual-program-run-410.json` via CLI, before helper drift | exit0, PASS20/20; raw SHA256 `bd3d1819f6387491c69388b371f9b05fa28d5e773658223f950ffd743413f0ff` | `real.stdout`, `real.stderr` |
| Final original-record CLI after concurrent helper drift | **exit1, FAIL19/20**; `frozen_bindings` rejects `reservation binding: tools/rust-v2-lab/fresh-baseline.py`;19 semantic/other groups still PASS | `real-final.stdout`, `real-final.stderr` |
| New independent source-driven probes | **260 executed**:231 rejected;25 Important false PASS +1 Minor false PASS;3 accepted probes explicitly not classified as findings above | `all-new-probes.json`, six scripts/result files and per-fixture outputs |
| `python3 -B tools/rust-v2-lab/test-validate-run410-witness.py` | **exit0;38 tests;258.827s;28,782 leaves,102,334 end-to-end leaf mutations**;29 serde structs/218 fields in source-width inventory | `test-validate-run410-witness.log` |
| `python3 -B tools/rust-v2-lab/test-run410-fixes.py` | exit0;8 tests, OK; existing generated-template SyntaxWarnings | `test-run410-fixes.log` |
| `python3 -B tools/rust-v2-lab/test-run410-isolation.py` | exit0;21 tests, OK | `test-run410-isolation.log` |
| `python3 -B tools/rust-v2-lab/test-run410-provenance.py` | exit0;21 tests, OK | `test-run410-provenance.log` |
| `python3 -B tools/rust-v2-lab/test-run410-reservation.py` | exit0;12 checks; `real_lab_claim_created=false` | `test-run410-reservation.log` |
| `python3 -B -m py_compile` validator, witness tests, all4 `test-run410-*.py` | exit0; output redirected to scratch pycache | `py_compile.log`, `suite-results.json` |
| `git diff --check` | exit0 | `git-diff-check.log` |
| Independent registry execution |67 entries,1,615 objects,zero uncovered; completeness limitations reproduced above | `binding-registry.json`, `binding-coverage.json` |
| Source vs frozen candidate archive, read without extraction | **51/51 selected Rust files byte-identical**; includes all preparation modules, attachment emitters, network/native/readback/plan/secret-role paths used in findings | `frozen-source-results.json` |
| Guest input-key emitter vs original record binding | Both repository copies match `record.guest_sha256`; no guest program executed | Independent Python hash comparison |
| Read-only hook/exclusive0600/overwrite/symlink/-O/-OO | All independent safety assertions pass; existing r4 receipt equalled fresh CLI result before helper drift | `io-results.json`, `receipt-results.json` |
| Preservation | **694/698** baseline hashes/sizes/modes unchanged at the final sample. Four files changed during the review through activity outside this reviewer: two lab helpers, lab README and the pre-existing Task14 report, listed below. Validator/tests/implementation report/original evidence remain unchanged. Reviewer wrote only this new repository report. | `baseline.json`, `preservation-results.json` |
| Branch/HEAD and pre-existing dirty work | Requested branch/HEAD preserved; concurrent performance changes excluded from preservation assertions | `git-status-before.txt`, `git-status-after.txt` |
| Cargo, sudo, network, guest/VM/QEMU/process operations; runtime/release acceptance | **NOT_RUN**; outside this offline review | No operations against `/DATA/vprouter-lab/preserved`; run409/410 claims/reservations only read |

The preservation baseline covers lab tools, SDD reports, lab-state files,
run410-evidence and the frozen candidate tree. It excludes concurrent
`tools/performance/*`/performance documentation work. The observed changing files
were `tools/rust-v2-lab/phase3-readonly-preflight.py`,
`tools/rust-v2-lab/fresh-baseline.py`, `tools/rust-v2-lab/README.md` and
`.superpowers/sdd/rust-v2/task-14-report.md`. Their before/after hashes are
retained in `preservation-results.json`; the reviewer did not write or revert
them. After detecting this drift, the real CLI was rerun and exits1 with
FAIL19/20 (`real-final.stdout`), correctly refusing the changed reservation
binding. The earlier suite results describe the bytes
and times actually tested; no current guest-state inference follows from them.
An independent final scan of all34 reservation bindings finds both helper
paths above changed (`final-binding-drift.json`); the validator reports the
first mismatch and does not overwrite evidence or repair bindings.
No staging, reset, stash,
commit, push or other Git mutation command was run. The external index was not
part of the file-hash baseline; no index-byte claim is inferred from status.
No new experiment, acceptance decision or consumed-budget reuse is authorized.
