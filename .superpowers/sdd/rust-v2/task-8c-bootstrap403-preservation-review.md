# Bootstrap403 failure, diagnostics and selector preservation review

2026-10-29. Independent read-only saved-evidence/source-binding/controller audit.
Only this report written. No VM/SSH/Docker/privilege, source edit, build/test/native
execution, helper main, archival/resource operation, profile/credential contents,
Git mutation or subagent action. Root owns live operations.

**Failure/provenance/preservation verdict: PASS**, preserving original403FAIL.
**Exact-six archival prerequisite verdict: PASS**, conditional on all fresh gates
in the unchanged reviewed archiver. No findings in this narrow scope.
Native bootstrap remains FAIL/zero completed cases, ARM runtime NOT_RUN,
release_ready=false; full8c ACTIVE. No semantic or performance fix is approved.

## Original evidence and exact candidate binding

| Evidence | SHA256 |
| --- | --- |
| target/lab-state/actual-program-run-403.json | 8e63c00123fca75a1fbf8347566fd226e794cfd214a87c0e1b7f085654901241 |
| target/lab-state/secret-bootstrap-failure-run-403.json | 80ad66bd3d10804cdde2b3adea39ba925332cf1ca6ea4832c73075f1fca05431 |
| target/continuation-20261029T153856Z/candidate.json | c82dceeb441a2730ec79fcc8780aa737d3d10e60d12958fbe0bd2bc616721910 |
| bootstrap-helper-diagnostic-20261029/directory-binding.json within that candidate | 8ca913a787143e340c1578bc0e38f4487f6b830881584e5bb09e8b1e3d66d5d7 |

Inspection raw path/hash, source/artifact/platform, directory binding and previously
reviewed diagnostic frozen candidate agree exactly:

```text
source_commit c6f3c5e8917f81ee7b4b9070388ee3c524531b8b
source_archive_sha256 56c1c02b4806c4d490100b098b9e9c1ac7dca4d42bd4fec7b047a7fc6844d633
tracked_build_inputs_verified 202
source_aggregate_sha256 f1a84685bb540b74b23f1a6393470b4a845b9ed11523a21f1f1ec8d65c54b57a
amd64 artifact 9486d7e15faeaa6c855ca72bd465d68f285a27e5e55e8bc8f0dcecc1314c5a86
amd64 context f95434ea47702d720772ce10f5b23237c00f4e93837f8ddbcfb9d61711d7b9bc
platform debian-clean-x86_64
```

Actual source archive, payload and context hashes agree. All202 frozen root-proof
source hashes equal archived and current bytes. This is independent byte binding,
not a repeated source-semantic approval or new test execution. Captured runner,
guest, context checker, HOST and baseline declaration builders, authored template
and reconciliation actual hashes equal raw403 fields. Captured controller summary
identifies this record, exact exit/mode/stderr and runtime_events=[]; captured
controller.stderr equals raw stderr. The runner adds runtime_events only for
LAB_SECRET_BOOTSTRAP success witnesses/case objects. Raw stdout has neither.

Captured55-link template SHA256 is
c2aacc8f867f358e2d149d9521630bff62d17ff98f29de87040e17077227f8af;
reconciliation SHA256 is
8f89c5db097744b4d91cedf0e09272ae73a3e8f6686790c944e803511a278b69.
These equal candidate-local reviewed files and raw fields. Its baseline equals
the actual input declaration, with links55/addresses51/routes154/rules5; canonical
sorted JSON digest equals the recorded baseline digest. This is run403's input,
not authority to substitute later observations into a new expected declaration.

## Exact failure and diagnostic limits

Original result FAIL/exit1/outerwall13.92s is retained. There are zero completed
case objects/success witnesses,73 Bootstrap phase lines,91 io_inventory and91
io_inventory_verified lines. Final stderr is secret_bootstrap_lab: deadline.
There is exactly one first-error boundary and one existing POLL_FAILURE marker:

```text
helper=native_poll step=intent reason=Deadline
query_present=true query_child_present=true query_accepted_present=true policy_present=true
query_queued=true query_held=2 query_negatives=6 query_released=true
own_queued=true own_held=2 own_negatives=12 own_released=false
POLL_FAILURE step=intent reason=Deadline request_present=true query_child_present=true
```

The exact frozen cfg(test) source emits retained scalar presence/counters after
the wrapper returns its original error. query_accepted_present is process-local
presence evidence, unlike an inference from disk bytes. It does not establish
successful policy acknowledgement, cleared pending, accepted Bootstrap receipt,
completed Host scope or a completed case. Policy release was not called.

Original requested_at197538.988574814 and deadline197540.988574814 retain a2s
window. Boundary observed_boot_now197540.99594918 is7.374366ms after that deadline;
existing Host error-handler now197540.99599542 is7.420606ms after it. These are
post-error observations, not an exact inner-predicate error clock.

Exactly13 fixed helper rows have the source measurement label
wrapper_elapsed_including_nested_validation. All calls/durations parse as bounded
nonnegative integers. NativePoll records13 calls/923556681ns; PolicyRelease is
0calls/0ns. The sum of all13 rows is1959655450ns. Source measures Instant elapsed
around each wrapper and includes nested validation/IO/scheduling. This sum is not
predicate CPU, independent non-overlapping operation attribution, all program
walltime or the exact consumed deadline budget. No optimization or deadline
relaxation follows from these numbers alone.

Durable BootstrapHostRecheck retains birth/facts/verified_at and a1.307298476s
verified_at-requested_at interval, while later two canonical query slots are null.
Canonical bytes alone do not prove parent ACK/cleared pending/accepted receipt.
The new local diagnostic does not retroactively identify run402's failed helper,
its inner deadline predicate or its cost. Original402 remains unlocalized at its
previous evidence scope. No exact inner predicate is established for403 here.

## Original resource and exact-selector preservation

Saved inspection owner equals original descriptor/owner_probe and canonical
owner unit: not-found/inactive/dead,MainPID0,empty ControlGroup/InvocationID,no
owner cgroup. Canonical root,allocations.json,namespaces.json remain present;
both allocation objects equal the original descriptor; preparation allocation
digest and retained owner equal the original descriptor/namespaces owner epoch.
Original gateway is running/unpaused with exact PID/StartedAt; spec retains its
container ID/process-start/StartedAt. Original raw manifest is inert,mounts=[],
provider_state_mounted=false. No substitute resource is accepted.

Both profile metadata records equal original path/device/inode/size/root UID/GID/
mode0600 and single-link identity. No profile contents were read. Inspection
records read_only=true,private_profile_contents_read=false and
signals_unmount_or_cleanup=false. These are saved Root observations, not an
auditor live recheck or new owner authority.

Captured guest source requires equal prior host links and exact route/rule/
address/stable-neighbor snapshots, allowing only the original planned new veth
endpoint DOWN. Raw outer preservation records that exact added host endpoint
vh7bd6c60869d0,index1542016454; canonical final host-link result agrees in full
name/index/kind/DOWN. Original gateway native identity/canonical/mount resources
remain retained. The host link set is accurately not claimed unchanged.

Inspection fixed_selectors contains exactly these six ordered keys:

```text
owner-domain-nonce
secret-attachment.json
secret-attachment-spec.json
secret-attachment-staging.json
secret-quarantine-host.json
secret-host-baseline.json
```

Nonce/configuration/spec/staging hashes bind to original manifest/gateway;
HOST/baseline hashes and entire public declarations equal original inputs.
Recorded selector dev/inode/size are positive and bounded,hashes valid. The
successful unchanged inspector enforces root-owned regular0600 single-link files.
No admission/image selector keys occur in this exact reference.

| Exact unchanged reviewed script | SHA256 |
| --- | --- |
| target/inspect-secret-bootstrap-failure.py | 64537a9d291d7e4df754e7cd194ac3bd6375f61ed538da0b1d8023e0cd879411 |
| target/archive-secret-bootstrap-selectors.py | e36a8e8c122663d9adc36ab8827f2923bd01147601efd248823f9cff0c62b9c0 |

## Conditional exact-six archival gates

Root may execute only those unchanged archiver bytes with the exact403 reference
and directory binding. Before moving any selector, recheck exact owner unit
not-found/cgroup absence; original gateway running/PID/StartedAt/pidfd/process-
start/source namespace; original root:root0700 nonce directory; each selector's
original dev/inode/size/hash/root0600/regular/single-link identity; and destination
nonexistence. Drift or collision refuses; no gate may be bypassed.

Only these six fixed names may be hardlinked into their same original nonce
synthetic-input directory as403-failed-<name> and unlinked at fixed source name.
The six moves are sequential,not atomic. After interruption inspect the exact
archived prefix/both-link state,retain evidence and never blindly rerun/delete.
Root must retain completion output and exclusive archive-run403 receipt before
claiming all six archived. This report does not claim archival has occurred.

Profiles,canonical records,links/namespaces,mounts,containers/images and gateway
are not archival sources. No cleanup,retry,new baseline adoption,semantic/source
change,ownership/clock relaxation,membership/removal/activation or client/release
authority is granted. Original398-403 failures/resources remain preserved;
full8c remains ACTIVE.

## Subsequent Root completion and final public-claim audit

**Completion/public scope/sensitivity verdict: PASS; no findings.** Root subsequently
executed the exact unchanged archiver after fresh gates. Saved receipt
`target/lab-state/secret-bootstrap-selector-archive-run-403.json`,SHA256
1899f4010aa7b68e339d0864768eef1b73b32c5fa8e74a38a981ac86b44d3a32,
identifies original raw403/source/platform/exact absent owner. All six ordered
403-failed-<name> destinations equal the approved list inside the same original
nonce directory. Retention/no-profile-read/no-signals/no-unmount fields agree.
This checks saved Root completion evidence, not auditor live archival.

Public docs/rust-v2/task8c-bootstrap-attempt403.json,SHA256
9d88fc921a123ae3211312de574a32ca42fc7f9fbc1847e1b0fa3b2e62df4e82,
exactly binds original raw/source/artifact/runner/guest/result/exit/wall,zero cases,
91journal pairs, diagnostic helper/step/error/retained counters,all13 wrapper
rows,sum,post-error observation delta,canonical field presence,whole outer
preservation,inspection hash and completed archival receipt. It accurately
records selectors_archived6/selectors_retained0,resources retained and no native
acceptance. Archival moves only selectors,not the underlying fixture resources.

Closed metadata target/task8c-helper-diagnostic-20261029T153811Z/bootstrap403-closed-metadata.json,
SHA25619c6cc36f7e6b51d160392d0431625e35441239ca7755bf76f4fb356335d7360,
contains only record/hash/source binding,closed boundary fields,wrapper rows,
sum,delta and scope. I independently reconstructed the full boundary values and
all13 ordered wrapper rows from exact raw lines and compared every output/public
value. Scope explicitly says nested validation/IO/scheduling,not predicate CPU
or exact predicate clock. Root's original parser was inline; no retained parser
file was available,so this is an independent output reconstruction/source-binding
check,not approval of unavailable parser implementation.

Public docs/rust-v2/task8c-helper-diagnostic-verification.json,SHA256
277b8b2a9c69b42b24e386583cbc86a6aba17681b70e4e42280b51fb4b2a5126,
changes native_bootstrap only to FAIL_ATTEMPT403. Exact source/platform/evidence
hashes remain consistent; ARM runtime NOT_RUN and release_ready=false. Its55-link
baseline remains the input to403,not a new expectation including403's added link.
Prior component/provenance/source PASS do not become native-family acceptance.

The current progress ledger accurately retains original403FAIL/zero cases,
process-local diagnostic limits,722550398ns query-wrapper and313548371ns policy-
wrapper sums,conditional review followed by completed exact-six archival,and
full8c ACTIVE/release_readyfalse. The current public JSON documents and ledger
were contextually read and checked for bounded credential patterns; no embedded
credentials/private profiles were found. Raw/runtime/private artifacts are
outside publication scope. No semantic fix or optimization is selected here.

All202 frozen source/archive/current bytes remain unchanged. Final
`git diff --check` passes. This report is frozen for Root staging.
