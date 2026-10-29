# Bootstrap405 failure provenance and exact-six archival prerequisite review

2026-10-29. Independent narrow read-only saved-evidence/controller/provenance
and preservation audit. Only this Markdown written. No Git mutation, application
edit, build/test/benchmark, helper main, VM/SSH/Docker/privilege, profile/credential
contents, resource action or subagent. Root owns fresh gates and archival.
The separate source/cost diagnosis is outside this review.

**Failure/provenance/preservation PASS. Exact-six archival prerequisites PASS,
subject to the fresh gates below. No open findings.** Archival is not claimed
completed by this prerequisite review. Original405 remains FAIL/zero completed
cases; original398-404 failures remain retained. Full8c ACTIVE, native comparison
cost effect unproved, ARM runtime NOT_RUN and release_ready=false remain binding.
The new comparator still failed the original budget; this is no source/cost/2s
fix, native equivalence, complete Bootstrap or release acceptance claim.

## Exact candidate, controller and failed-record binding

| Saved evidence | SHA256 |
| --- | --- |
| target/lab-state/actual-program-run-405.json | 426dfae8b336943c7dcefe3e2bbae3b945568a44bf0d04f07f5869fdaf62ba1a |
| target/lab-state/secret-bootstrap-failure-run-405.json | 891951dab0260c7e61d0419b1f30424bca13f281ba8fc8d4ca16d9d121948fc0 |
| target/continuation-20261029T164255Z/bootstrap-allocation-comparison-20261029/directory-binding.json | 8ff97ca54487f68e2b8730229b102d58d0912382454ba55240629772d9205652 |

Raw405, saved inspection and captured directory binding agree with the already
independently reviewed exact candidate:

```text
source_commit 05238109d41e8ba4376e27c16aaa1bd41caffede
source_archive_sha256 c32d6c1bf51d888f89fb16fc34a66e7356d073ef263d357f64151a8ab0b644ed
tracked_build_inputs_verified 203
source_aggregate_sha256 4386b3a9d46ec99dee76c7dafb7cac6a04923c428bc60b0126af8576e3fdf43a
amd64 artifact 4435526772afaf82ca584adde1ceadbdad4c710106bcac99c525580c21dcdce9
amd64 context f95434ea47702d720772ce10f5b23237c00f4e93837f8ddbcfb9d61711d7b9bc
platform debian-clean-x86_64
owned.rs b14900907cba93637bed606130467bdf82dbb864da3e4953129dba1ffdb9b6c7
```

Fresh read-only hashing again matches all203 current input hashes in Root proof,
actual source archive, retained payload and context. Source semantics are covered
by separate source review7968a825 and candidate review7178870f; those verdicts
are not expanded into native acceptance here.

All captured runner, guest, context checker, HOST and baseline declaration
builders, authored baseline and reconciliation hashes match raw405. Captured
controller.json identifies exact run405, exit1, secret_bootstrap_success,
runtime_events=[] and exact stderr; controller.stderr equals raw stderr. No
successful case/witness object is present. directory-binding new_directories=[]
is retained as recorded, not interpreted as a claim that no runtime resource
was created inside the original fixture root.

## Original failure and closed diagnostic scope

Raw result FAIL/exit1/outerwall11.728s remains intact, with zero completed cases.
There are352 stderr lines,73 Bootstrap phase lines and92 exact io_inventory /
io_inventory_verified pairs. Terminal stderr is secret_bootstrap_lab: deadline.
Exactly one first-error boundary and existing POLL_FAILURE report:

```text
helper=native_poll step=result reason=Deadline
query_present=true query_child_present=true query_accepted_present=true policy_present=true
query_queued=true query_held=2 query_negatives=6 query_released=true
own_queued=true own_held=2 own_negatives=12 own_released=true
POLL_FAILURE step=result reason=Deadline request_present=true query_child_present=true
```

Original requested_at201349.774675338 and deadline201351.774675338 preserve2s.
Boundary observed_boot_now201351.780866519 and later existing Host failure log
are post-error observations, not exact inner-predicate clocks. Both query and
policy required hold/negative/release paths are evidenced; release flags and
Step/result alone do not prove accepted policy Result, parent ACK, cleared
pending, complete Host scope or full Bootstrap success.

Canonical first bootstrap query has birth/facts/verified_at; its two later query
slots are null. Canonical first policy has birth, with result and verified_at
null. Those durable prefixes alone grant no accepted receipt or runtime authority.
The exact inner Deadline and cost diagnosis remain outside this audit.

Unchanged closed parser tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py
SHA25631e70538076ea97538ad4ab09aa8126a74543985e92e6727ad7d0f84d1d3a5d7
produced Root's retained bootstrap405-closed-metadata.json SHA256
f743c668eaefc61a3681dbcf94f2c8e269d6d69bb8c8f26f690aa1fe24c039e3
under target/task8c-allocation-comparison-root-20261029. No parser main ran here.
Independent direct reconstruction from raw stderr reproduces its boundary,
all13 ordered wrapper rows and all30 ordered family/category nested rows exactly,
including closed measurement/grouping labels and bounded unsigned values.
Query wrappers386489051ns +policy402504505ns +native19calls/1164720353ns
sum1953713909ns. Nested rows are inclusive, overlap and are never added to that
sum. They group by cached lab-loop entry family, not exact inner phase; elapsed
includes scheduling/live checks and observer effects, not isolated CPU or native
comparator savings. No microbenchmark extrapolation or improved-budget claim
follows from405, timer counts or comparison with404.

## Exact original resources, canonical state and57-link input

Inspection owner exactly matches original descriptor/owner_probe/canonical owner
unit: not-found/inactive/dead, MainPID0, empty ControlGroup/InvocationID and no
owner cgroup. Canonical root, allocations.json and namespaces.json remain.
Both canonical allocation objects equal the original descriptor and fixed spec;
primary selector and preparation allocation digest match. Preparation owner is
the original canonical owner epoch. No replacement owner/resource is accepted.

Original gateway remains running/unpaused/not restarting/not dead with exact
PID43523 and StartedAt2026-10-29T16:49:51.378865124Z. Fixed spec retains original
container ID and process-start20134514; gateway manifest retains original source
namespace, inert=true, mounts=[] and provider_state_mounted=false. Captured guest
pins and rechecks the original gateway PID/process/namespace identity across the
native invocation. Saved inspection is Root's observation, not an auditor live
recheck. Both synthetic profile metadata records retain original path/device/
inode/size, root UID/GID,0600 mode and single-link identity; no contents were read.

Captured authored57-link template SHA256
e7c41cd08192d10a56b9b8a9774ab26a4afbe8a4cb919a9281997c5d4b0d949f
and reconciliation7ec60d8c491097dcbc0041eba3f65254cd31e8980f57d31cfb829dffce546cb8
equal the exact reviewed candidate files. Actual staged public baseline matches
that template's complete original57links/51addresses/154routes/5rules, original
allocation digest/namespace and raw recorded hashes. It is405's input, not a new
baseline that adopts the endpoint subsequently created by405.

Outer preservation records one exact additional veth/DOWN endpoint:
name vh1725555785a4,index1758018966. Canonical host_link final result matches
its entire recorded endpoint, original planned index, primary host-interface name
and deployment/generation/member alias. Captured unchanged guest bytes check all
prior links and exact address/route/rule/stable-neighbor snapshots, allowing only
that planned DOWN addition. Therefore the link set is accurately not claimed
unchanged; canonical/mount/gateway resources remain retained. This review authors
no58-link expectation and grants no cleanup/removal/membership/activation authority.

## Exact retained selectors and unchanged archival helper

Saved inspection contains exactly these six ordered fixed selector keys:

```text
owner-domain-nonce
secret-attachment.json
secret-attachment-spec.json
secret-attachment-staging.json
secret-quarantine-host.json
secret-host-baseline.json
```

Nonce/configuration/spec/staging bytes and hashes bind the original input and
gateway. HOST and baseline full public declarations/hash/size equal the original
inputs. Every saved selector device/inode/size is positive and its encoded public
content independently reproduces hash and size. The successful unchanged inspector
enforces root-owned regular0600/single-link identity. No image/admission selector
key occurs in this exact reference, despite the helper's wider historical allowlist.

| Exact unchanged reviewed helper | SHA256 |
| --- | --- |
| target/inspect-secret-bootstrap-failure.py | 64537a9d291d7e4df754e7cd194ac3bd6375f61ed538da0b1d8023e0cd879411 |
| target/archive-secret-bootstrap-selectors.py | e36a8e8c122663d9adc36ab8827f2923bd01147601efd248823f9cff0c62b9c0 |

Root may use only those exact unchanged archiver bytes with this exact raw405,
directory binding and saved six-selector reference. Before any move, freshly
recheck original owner not-found/cgroup absent; original gateway running and
unpaused with exact container/PID/StartedAt, live pidfd, process-start and source
namespace; original root-owned0700 nonce input directory; each selector's exact
original device/inode/size/hash/root0600/regular/single-link identity; and all
six destination names absent. Drift or collision refuses; no bypass/substitute
reference is allowed. The fresh live gates are Root's work, not performed here.

Only these six fixed names may be hardlinked within the same original nonce
input directory as405-failed-<name>, then unlinked at each original fixed name.
The approved helper iterates the exact six reference entries. Moves are sequential,
not atomic: interruption requires exact prefix/both-link inspection and retained
evidence, never blind rerun/deletion. Retain completion output and an exclusive
archive-run405 receipt before claiming all six archived. This prerequisite PASS
does not claim completion, and a later receipt/public failure document requires
its separate completion/public-scope audit.

Profiles, canonical records, links/namespaces, mounts, container/image, gateway
and identity state are not archival sources and must remain retained. No new
fixture, retry, expected-state adoption, semantic source/clock/ownership waiver,
resource cleanup or production/client/release operation is authorized by this
review. Original405 FAIL/zero cases and all remaining acceptance gates stand.

Final git diff --check passes. Review frozen for Root archival prerequisites.


## Subsequent exact-six completion and final public scope

**Completion/public-scope/sensitivity PASS. No findings.** Root subsequently ran
the exact unchanged archiver with fresh original-owner/gateway/selector gates,
reported exit0 and retained an exclusive receipt at
 target/lab-state/secret-bootstrap-selector-archive-run-405.json SHA256
be9621acfe7ff32de3b6c0ffa1011c91bf8b665e3468a8d14f33b9c2d211cd3e.
The receipt binds exact original raw405/source/platform, original absent owner
unit and exactly the six ordered approved same-nonce405-failed-<name> destinations.
Retention/no-private-read/no-signals/no-unmount flags agree. This is independent
checking of saved Root completion evidence, not live auditor archival or new
resource authority. The earlier prerequisite-only wording above is historical.

Final public docs/rust-v2/task8c-bootstrap-attempt405.json SHA256
a60c8102ccc165f93bafdbba1dbf924be6e72939bc88ed4261c1073a6f924cbc
matches exact original raw/source/artifact/runner/guest/result/exit/wall and zero
completed cases. All boundary fields, all13 wrapper/all30 nested rows, wrapper
sum, original post-error observation delta, canonical query-field presence and
bootstrap-history count, whole outer preservation object, inspection/closed
metadata/parser hashes and no-acceptance flags independently equal saved evidence.
The6archived/0fixed-retained status and receipt hash agree with completed Root
archival. All other resources remain retained; resource_cleanup_performed=false.
Canonical bytes alone still do not prove ACK, cleared pending or an accepted
policy receipt. The original57-link input is retained, not replaced with an
adopted58-link expectation.

Public docs/rust-v2/task8c-allocation-comparison-verification.json SHA256
6fc77b3d2416ba91cc26ff627eeeed4c1ffb4804a938eb4b38b7e9a9ba6fb3b8
was compared against the pre405 final JSON saved in this review session. Only
native_bootstrap, runtime_cost_effect and performance_limit changed. The new
FAIL_ATTEMPT405 / UNPROVED_ATTEMPT405_FAILED status and explicit failed-budget
limit match the evidence. Source/platform/static/local-check/baseline bindings
and earlier review flags remain identical. ARM runtime NOT_RUN and
release_ready=false remain. All203 current source hashes and referenced public
evidence hashes were freshly rechecked unchanged; no application source change
is part of this failure publication.

Current ledger SHA256
8cc6301d42f924ec02d28016d12e445586ccf83f8ee96a4eb3762ab140d48c98
retains original405FAIL/zero cases, unchanged2s budget, non-additive diagnostic
limits and no controlled native A/B or sufficient-budget claim, then records
completed exact-six archival with all other resources retained. Full8cACTIVE and
releasefalse remain. Its checkpoint/tag remote-confirmation and freshly active
production-service statements are explicitly Root-reported observations; Root
reports systemctl is-active returned active, without a retained target artifact
for that command. They are not independently refreshed or promoted to production
runtime/acceptance proof by this saved-fixture audit.

The four intended publication changes are public attempt405 JSON, comparison
verification JSON, ledger and this review. No diagnosis, new source change or
cost-fix approval is bundled into this scope. Public docs/review were contextually
read and bounded credential-pattern checked; no embedded private profiles or
credentials were found. Raw target receipts/logs/runtime/canonical/projection
artifacts, profiles/keys, captures, private state and binaries are excluded from
publication. Original failed records/resources and all remaining native/client/
runtime/release gates remain preserved and unaccepted. Root owns staging/push.
Final git diff --check passes. Completed review frozen for Root publication.
