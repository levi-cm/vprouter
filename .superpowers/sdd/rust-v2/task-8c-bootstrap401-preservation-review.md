# Bootstrap401 exact failure and selector preservation review

2026-10-29. Independent narrow read-only saved-evidence/controller audit. Only
this report written. No VM/SSH/Docker/privilege, native/build/test execution,
profile/credential contents, source/Git mutation, helper main, selector archival
or subagent operation. Root retains all live execution and archival actions.

**Failure/provenance verdict: PASS for accurate binding and preservation of the
original failed401 record, not for native behavior.**

**Exact-selector archival verdict: PASS for Root's unchanged reviewed archiver
and precisely the six run401 selectors below, subject to every fresh refusal
gate.** No resource cleanup, unchanged-payload retry or new baseline authority.

Run401 remains **FAIL/zero completed cases**. It progresses beyond run400's
QueryIntent boundary and fails query_result with CgroupMismatch. This audit
does not establish the internal failed cgroup predicate or approve a new fix.
Full8c/runtime/client/release acceptance remains open.

## Exact original failure/source/controller binding

| Evidence | SHA256 |
| --- | --- |
| target/lab-state/actual-program-run-401.json | 40a6ca6c3dc9b430a87e5dba11a4b4446f9ee71a6f825aea2a514d5b2d6e9bc7 |
| target/lab-state/secret-bootstrap-failure-run-401.json | cd82789829434e0b8f15ccdd36391c7b01d86b2cd1e3867f6f98ae27b49c9e7d |

The inspection's raw path/hash, full source binding, artifact/platform match
the original record and exact directory binding at
`target/continuation-20261029T134857Z/bootstrap-pending-progress-20261029/directory-binding.json`.
Candidate/root proof bindings are the already independently reviewed:

```text
source_commit cc0081baeb14caaa15fd4577258f6d01cc6de8bc
source_archive_sha256 1c2ece5f0707a41d7de8a28ac9d59c4dbe20a3cd5c32af8c3c767f45502a5d67
tracked_build_inputs_verified 202
source_aggregate_sha256 ac3db8ba5dc32abaf8bef7d63a0736cef4319f2b81212329f020bc813b848fad
amd64 artifact f8e6c9b1fc0669b1fe937ff543a7773d3d072bf65ffebb7d2c0c33404b1f83c1
platform debian-clean-x86_64
```

Actual source archive/artifact hashes still agree and all202 archived source
inputs remain byte-equal to current workspace files. Actual captured runner,
guest, context checker, HOST/baseline declaration builders and captured authored
baseline/reconciliation hashes match the raw record. The latter remain exact
reviewed templatec119742f8b7c5e7e92daa5811cf24ba7b62cbd5a5b01afa9ac437c888bf506ef
and review4f9a872340085072de5457aa0ec36c1c6ea96afd64f11dfe178e3d6859221e05.
This confirms which unchanged controller and new reviewed payload actually ran;
it does not rewrite the pre-execution proof's historical NOT_RUN fields.

Raw exit1/resultFAIL/wall12.485s are retained. There are no case objects and no
LAB_SECRET_BOOTSTRAP success witness. Exact stderr contains once:

```text
LAB_SECRET_BOOTSTRAP_POLL_FAILURE step=query_result reason=CgroupMismatch request_present=false query_child_present=true
secret_bootstrap_lab: cgroup_mismatch
```

The final line is the latter error. QueryIntent success, query_spawn begin/ok
and query_birth_queue begin/ok markers are present. Both journal io_inventory
and io_inventory_verified counts equal90. These are boundary observations, not
a completed Bootstrap scope/case or policy request. No policy request is present
at this failure; the original query child is present according to the diagnostic.

The saved canonical BootstrapHostRecheck slot has birth/facts/verified_at fields;
remaining two query slots are null. **Those disk fields establish durable
proposal/write evidence only, not parent process-local Result ACK, successful
post-ACK acceptance or cleared pending state.** This audit does not infer a
successful native query/policy receipt from them.

## Exact preserved resources and selector identities

The bound inspection records the original owner not-found/inactive/dead,
MainPID0,empty ControlGroup/InvocationID and no owner cgroup. Its exact owner
unit equals the original descriptor/owner probe. The original gateway is
running/unpaused with original PID/StartedAt, while the original gateway manifest
is inert,mounts=[],provider_state_mounted=false. Spec container/process-start/
StartedAt equals that exact gateway. No replacement/prefix-selected gateway or
owner is accepted.

Both synthetic profile metadata records preserve their original paths/device/
inode/size,root UID/GID,mode0600 and single-link status. No profile contents were
read. Canonical root and allocations/namespaces files remain present; canonical
allocation object and preparation allocation digest equal the original descriptor,
and the stored owner unit agrees. Inspection explicitly records read_only=true,
no private-profile read and no signals/unmount/cleanup.

Original raw outer preservation records one exact newly added veth/DOWN endpoint
`vh7828b913cc58`,index1243536425, matching the complete canonical HOST result.
Prior addresses/routes/rules/stable neighbors remain preserved; original gateway
native identity and canonical/mount resources remain retained. The host link set
is accurately not described as unchanged. This is structural saved evidence,
not membership/removal/activation authority or a newly authored baseline.

The inspection fixed_selectors contains exactly these six ordered keys:

```text
owner-domain-nonce
secret-attachment.json
secret-attachment-spec.json
secret-attachment-staging.json
secret-quarantine-host.json
secret-host-baseline.json
```

Nonce/configuration/spec/staging hashes equal the original manifest/gateway
digests. WAN/baseline hash and full public content equal their original declared
objects. All recorded selector device/inode/size values are positive and bounded;
the successful unchanged inspector enforces root-owned regular mode0600,
single-link sources. There are no admission/image selector keys in this reference.

| Exact unchanged reviewed script | SHA256 |
| --- | --- |
| target/inspect-secret-bootstrap-failure.py | 64537a9d291d7e4df754e7cd194ac3bd6375f61ed538da0b1d8023e0cd879411 |
| target/archive-secret-bootstrap-selectors.py | e36a8e8c122663d9adc36ab8827f2923bd01147601efd248823f9cff0c62b9c0 |

Approval is limited to those exact script bytes and six-key401 reference. Root
may hardlink each original fixed selector to `401-failed-<name>` inside its same
original root:root0700 synthetic-input directory, then unlink only the fixed
source name. Fresh gates must recheck exact owner/cgroup absence, original
gateway PID/StartedAt/pidfd/process-start/source namespace, protected destination
and nonexistence, and each selector's original dev/inode/size/hash/root0600/
single-link identity. Any drift/collision refuses; no gate may be bypassed.

The six moves are sequential, not atomic. On interruption inspect exact archived
prefix/both-link state; retain evidence and do not blindly rerun or delete.
Root must retain completion output and exclusive archive-run401 receipt before
claiming all six archived. Profiles, canonical records, links/namespaces, mounts,
containers/images and gateways are not archival sources. This auditor executed
neither archival nor a live VM recheck. `git diff --check` passes.

This preservation approval grants no native success, new baseline learning,
resource adoption/removal, ownership/clock relaxation, semantic fix, unchanged
native retry or runtime/client/release authority. Original398/399/400/401 failures
and their resources remain preserved; full8c remains ACTIVE.

## Subsequent Root archival, public claims and current-namespace oracle

**Saved completion/public scope verdict: PASS** at the exact hashes below.
Root subsequently executed the approved unchanged archiver. I independently
bound the completion receipt
`target/lab-state/secret-bootstrap-selector-archive-run-401.json`,SHA256
`d2c09a7c46822c1d48e79a7b233070a6addf47164d61ded56b908a081c658d8a`,
to original raw401/source/platform/exact owner. Its ordered six destinations are
exactly the six approved names with `401-failed-` prefixes, all inside the same
original nonce's synthetic-input directory. Resource-retention=true and
private-profile-reads/signals/unmounts=false match the scoped approval. This
verifies Root-collected completion evidence; no auditor archival/live VM check.

Current public `docs/rust-v2/task8c-bootstrap-attempt401.json`,SHA256
`f43c7304b8498ce56923b270101634d9f555b4c13f44f4adbf646a3c2bb58c65`,
matches original raw hash/source/artifact/runner/guest/exit/wall/result, zero
cases, query_result/CgroupMismatch/requestfalse/childtrue, exact73 Bootstrap
phase marker lines and90 inventory pairs. Its complete outer preservation and
canonical-field presence booleans match the original raw/inspection. The
at-failure selectors_retained=6 is distinct from subsequent six-selector archival;
the latter's receipt hash/retention/no-private-read/no-signals flags agree. Disk
write versus parent-ACK qualification and native acceptance=false remain clear.

Current `docs/rust-v2/task8c-pending-progress-verification.json`,SHA256
`bec3a714f7d26540f7b7af2c0241ef391f68d6fc659b4202698815682c08b54c`,
preserves exact source/platform proof and actual evidence hashes while accurately
updating native_bootstrap to FAIL_ATTEMPT401. ARM runtime remains NOT_RUN and
release_ready=false. Its53-link baseline is the prior exact **input to run401**,
not a declaration incorporating its later added endpoint. Component/source/
provenance PASS fields remain scoped historical prerequisites, not native PASS.

Root's read-only oracle
`target/task8c-pending-20261029T133358Z/cgroup-root-dotdot-oracle.json`,SHA256
`c8d0d7e1117ef9c3029db1e09b5f46a44247086d2b592701f039b9aec347db93`,
binds original raw401/source and explicitly records current_namespace_only=true,
read_only=true,original_owner_return_trace_proven=false, no production/private
profile changes. Its current cgroup mount root is dev27/ino1/mode040555, while
the directory reached by '..' is dev22/ino2/mode040755. Those identities differ;
the mount metadata records cgroup2 mounted at /sys/fs/cgroup with mountroot'/'.
The public oracle hash/unequal/current-only/no-original-return-trace values agree.
This is a later current-mount-view observation, **not** a captured trace of the
original owner's exact CgroupMismatch return or proof of a semantic fix.

The latest ledger accurately records original401FAIL, completed scoped archival,
all other retained resources, current-only oracle and no unchanged retry/new
source approval. Bounded credential-pattern search and contextual reading of the
two public JSON documents and ledger found no embedded credentials/private
profile material. No raw private artifact belongs in this checkpoint. Original
failure records and all receipt/oracle timing limitations remain preserved.

## Independently reconstructed next foreign-history expectation

Without author-helper main or new live observation, I rechecked run401's captured
53-link authored input and reconciliation hashes against raw401, strict template
shape/source/platform and every prior_evidence hash. The four retained canonical
HOST history kinds and durable fields remain complete; their entire final
veth/DOWN endpoint `vh7828b913cc58`,index1243536425, agrees with original outer
name/index/single-DOWN-addition and address/route/rule/neighbor preservation.

Deep-copying the prior53-link input, rejecting name/index collision and appending
only that whole known endpoint preserves every previous field. Strict shape
validation passes for this **expected history**, before future ordering alignment:

```text
links54 addresses51 routes154 rules5 namespace[4,4026531840]
unaligned expected canonical SHA256
fb0ba09a1ab43a64f2162a4f63b5a193ede2553e01648b9d4bf200de9a749f8f
```

No new candidate/projection/template is accepted by this reconstruction. Future
authoring still requires exact multiset comparison and protected output/provenance
review. This gives no membership/removal/activation/owner authority, no parent-ACK
proof and no cleanup or unchanged-payload retry. The next cgroup semantic source
fix has **not** been reviewed or approved by this audit. All original failures
remain retained, full8c ACTIVE; final `git diff --check` passes.
