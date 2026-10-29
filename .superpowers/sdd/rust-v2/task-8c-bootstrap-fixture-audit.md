# Task 8c native Bootstrap fixture audit

Read-only audit, 2026-10-29. No cargo/build, payload invocation, VM/SSH/Docker,
privilege, credentials, or Git mutation was performed. Only this report was
created. All native Bootstrap family outcomes remain NOT_RUN in this audit.

## Source and conclusion

The private native fixture exists and is substantial enough for Root to run the
original Bootstrap family before autonomous integration. It is test-gated, not
ordinary startup: `actual_lab_main.rs:157-174` dispatches seven exact single-arg
flags to `transport_lab::run_secret_bootstrap`, which performs `admit(true)` and
calls `attachment/operational/bootstrap.rs::lab_run`.

I compared these current files byte-for-byte with the source archive referenced
by `target/continuation-20261029T122356Z/candidate.json`: operational/bootstrap.rs,
operational.rs, actual_lab_main.rs, native-role/producer_bootstrap.rs, and
netfilter/fixed_bootstrap.rs. All matched frozen b51b5d7dd7a127d88a6e770f0b8780951190805b.
The candidate archive hash is
`efd893b6b136e2f0bae55cadcea6cfe1823ecd0129bef32fe76093271201d98d`;
its binding verifies 202 tracked inputs and aggregate
`0ce0488bee605e94f7aaf6fa4df915cc1284227efa3d773d78b6130bbfd06fe6`.
Both candidate-local architecture context copies match their candidate hashes.
Compilation success is supplied context, not independently rerun here.

The initial blockers were controller/collector coverage and authored baseline
input. The appended pre-native review below resolves the first-execution
controller and baseline prerequisites; strict collector coverage remains open.
No definite new production-source defect was established by this narrow
audit. Successful native installation and all seven mode results must still be
proved by Root. Existing ordinary 17-case runtime results and filter preflight
must not be relabeled as this family's native execution.

## Seven modes and exact expected counts

All flags begin `--ignored-secret-bootstrap`; the success flag has no suffix.
Each successful oracle invocation exits zero even when it deliberately tests a
failure. An unexpected error exits one via `secret_bootstrap_lab: {error}`.

| Fault | Flag suffix | Case label | Writers | Queries | Operations | Completed scopes | Final charges |
| --- | --- | --- | ---: | ---: | ---: | ---: | --- |
| 0 | none | actual_original_three_scope_bootstrap_after_exact_twenty_handoff | 105 | 3 | 3 | 3 | [3,3] |
| 1 | -postbirth-failure | actual_bootstrap_postbirth_failure_retains_original_twenty_owners | 103 | 3 | 2 | 2 | [3,3] |
| 2 | -result-failure | actual_bootstrap_result_failure_retains_unacknowledged_data_policy | 105 | 3 | 3 | 2 | [4,3] |
| 3 | -registration-failure | actual_bootstrap_registration_failure_retains_original_data_policy | 103 | 3 | 2 | 2 | [2,2] |
| 4 | -handoff-fence | actual_twenty_handoff_fence_refuses_all_suffix_retirements | 87 | 0 | 0 | 0 | [5,5] |
| 5 | -handoff-partial | actual_twenty_handoff_partial_fence_retains_original_suffix | 87 | 0 | 0 | 0 | [4,4] |
| 6 | -handoff-duplicate | actual_twenty_duplicate_reservation_refused_before_bootstrap | 105 | 3 | 3 | 3 | [3,3] |

Charges are two-element JSON integer arrays: launch/native-role live capacity.
`charges_before_drop == charges_after_drop` for every outer Bootstrap witness.
Do not confuse retired charge capacity with resource cleanup or disappearance.

For every mode, `lab_handoff` first performs **successful** HOST addition through
`host_addition::lab_added()` (inner fault 0). Therefore all seven modes retain
one newly added, exact-index, DOWN HOST veth endpoint. The existing HOST guest's
`changed = mode in ('success','result-failure')` is wrong for Bootstrap faults
1/3/4/5/6. It must be true for all Bootstrap modes. Prior links, addresses,
routes, rules, and stable neighbor identity must remain preserved.

All preceding 87 writers must equal the inner HOST witness's full original
writer array. New writers are six per scope in Host, Transport, Data order:
`bootstrap_{host|transport|data}_query_{intent|birth|result}` followed by
`bootstrap_{host|transport|data}_{intent|birth|result}`. Each query and its policy
operation share one original two-second window. There are three new windows,
not separate two-second allowances for each writer. Only writer 104 has actual
wait status 9 and null verification in fault 2; other present writers have
status 0 and finite verification before their original deadline.

The first policy Intent is writer 90. Its `own_intent_polling` object has integer
`index=90`, `pid`, `start`, `queued_polls=1`, `held_pending_polls=2`,
`negative_checks=8`, and boolean `released=true`. It is null for faults 4/5.
Canonical negative checks are integer 39 for faults 0/6, zero otherwise.

## Event and JSON contract

Successful `lab_run` prints exactly two family events, in this order:

1. JSON object with exactly `case` (the selected string above) and `result="PASS"`.
2. `LAB_SECRET_BOOTSTRAP ` followed by a JSON object.

The nested preceding fixtures run in continuation mode and do not print their
own case or LAB marker. The outer controller must parse `LAB_SECRET_BOOTSTRAP`,
not wait for `LAB_SECRET_HOST_ADDITION`. `case_count` in the existing controller
really counts these two event objects, not two test cases. Expected injected
faults can produce `LAB_SECRET_BOOTSTRAP_FAILURE scope=Data reason=...` diagnostic
stderr; nonempty stderr alone is not failure or proof of failure acceptance.

The outer object has exactly these **30 fields**:

```text
schema fault own_intent_polling canonical_negative_checks host_addition handoff
preparation operations queries failed_constructor failure_retry
retained_result_writer charges_before_drop charges_after_drop
final_process_verified_at scope_process_verified_at result_writer_held
whole_chain_retained_after_drop original_nine_contexts_retained_after_drop
operational_context_retained_after_drop bootstrap_context_retained_after_drop
bootstrap_context_created bootstrap_all_scopes_acknowledged parent_pristine
placement_authorized up_authorized health_ready_authorized
resource_cleanup_authorized multi_exit_runtime_proven requirement8_complete
```

`schema` is integer 1; `fault` is integer 0..6. Reject booleans where integers are
required, duplicate JSON keys, nonfinite constants/numbers, and unknown fields.
`host_addition`, `handoff`, `preparation` are objects; `operations` and `queries`
are arrays with counts above. Failed-constructor, failure-retry and retained
result-writer fields are object-or-null. Both charge fields are two integer
arrays. `final_process_verified_at` is finite number only for faults 0/6 and
null otherwise; `scope_process_verified_at` is an array of 3, 2, or 0 finite
numbers as in the table. Every scope timestamp follows its Result writer ACK
and precedes its original deadline.

All remaining fields are booleans. `result_writer_held` is true only for fault 2;
`bootstrap_context_created` and `bootstrap_context_retained_after_drop` are true
except faults 4/5; `bootstrap_all_scopes_acknowledged` is true only for 0/6.
`whole_chain_retained_after_drop`, `original_nine_contexts_retained_after_drop`,
`operational_context_retained_after_drop`, and `parent_pristine` are true in all
emitted final witnesses. Every `*_authorized`, `multi_exit_runtime_proven`, and
`requirement8_complete` field is false.

Each native operation/failed constructor has exactly 30 fields exported by
`kernel/bootstrap.rs:504-542`:

```text
request query requested_at deadline parent group name scope namespace policy pins
original_pid original_start actual_wait_status birth native_born native_job_state
registered_native_slots original_registration_slots_verified
borrowed_registration_count complete_native_registration durable_birth_released
result accepted_at acknowledged eof context_retained
bootstrap_installation_observed placement_authorized up_authorized
```

Digests (`request`, `query`, `policy`) are 32-byte JSON integer arrays; identities
(`parent`, `group`, `namespace`) are `{dev:int,ino:int}` objects. `scope` serializes
as `host`, `transport`, or `data`. `name` is a string. `pins` is exactly eight
three-element integer arrays `[dev,ino,mode]`, all distinct device/inode pairs;
positions 0/1 identify original parent/group and positions 6/7 retain cgroup
root/system.slice ancestry. `birth` is null or `{pid,start,born_at,deadline}`.
Result is null or `{namespace,group,policy,pins,observed_at}`. The result must
agree with original canonical history and query, not merely parse correctly.

Successful operations have actual status 0, true `eof`, and an observed result.
Only fault-2 DATA is unacknowledged: the canonical DATA history has null result
and verification while `pending_bootstrap[2]` contains the exact result proposal
and accepted timestamp. It is not a completed third scope. Canonical pending
is true only for fault 2; mutation fenced is true for faults 2/4/5.

Faults 1/3 inject on DATA, after HOST and TRANSPORT have completed. Their
`failed_constructor` has `borrowed_registration_count=2`, null original_start,
birth and result, false complete registration and durable birth release.
Fault 1 has native_born=true and actual status 9; fault 3 has native_born=false
and null actual status. Fault-1/3 native error must be DescriptorInventory.
Fault 2 holds Result writer 104, fails with ChildFailed, and retains its same
original charge through collection, two retry polls and Drop. Its retained
writer is not an acknowledged policy receipt.

`failure_retry` exists only for 1/2/3, with integer `polls=2`, equal integer
native_births_before/after, equal charge arrays before/after, and true
same_original_request, same_step, original_error_retained,
operational_owner_reuse_refused. Faults 4/5 exercise rejection during handoff,
not this Bootstrap retry path.

## Exact twenty-owner handoff and fixed role mechanics

`operational.rs:231-334` preserves the original HostAddedPrimary before deriving
or reserving any transfer plan. The handoff object has fields `resources`,
`reservation`, `charges_before`, `charges_after`, `retired_suffix_jobs`,
`repeat_retirement_refusals`, `duplicate_reservation`, `fence_counts`,
`preparation`, `historical_original_jobs=15`, `complete_original_job_set=20`,
`complete`, `resources_collected=false`, `global_child_capacity_limit=64`.
There are five suffix resource tickets in addition to 15 historical original
jobs. Normal/duplicate handoff retires 5 original charges, taking [5,5] to [0,0],
and refuses five duplicate retirement attempts. Fault 4 fences before retirement
(0 jobs, [5,5]); fault 5 fences after one (1 job, [4,4]). Both refuse two further
polls with OwnershipMismatch and preserve original suffix resources. Fault 6
also refuses duplicate operational reservation without altering counts.

The fixture uses the original source and exact scope-specific prior authority:
initial quarantine for HOST/TRANSPORT, producer observation for DATA. A fresh
Docker recheck precedes each scope; it revalidates the original admitted process
and namespace, not an arbitrary rediscovered container. Each Bootstrap request
owns eight registered read pins and retains exact Rc origin identity.

The fixed role is `Role::ProducerBootstrap`, installed inside the native child
after setup and before accepting its gate. It uses `filter::producer_bootstrap`,
not a flag-based authority shortcut. Existing netfilter socket inputs are
retained. The ancestry policy allows only selected directory FD/name-pointer
`newfstatat` queries with AT_SYMLINK_NOFOLLOW and exact argument high words.
Root/system.slice/container/group paths must match retained cgroup2 directory
identities, root UID/GID, nonwritable mode, fixed docker-<64hex>.scope container
name and safe original group name. The group must remain protected, empty,
domain, populated 0/frozen 0, and have empty subtree control. Before/after native
Bootstrap installation, the child rechecks group and policy, consumes the exact
offline authority, and installs the original exclusive Bootstrap permit.
No new public metadata can construct this authority. No placement, UP, READY,
full forwarding, cleanup, or provider/client acceptance follows.

## Baseline prerequisites and preservation boundary

No literal `authored_host_baseline.py` was found. Relevant actual helpers are
`target/platform-lab/host_baseline_declaration.py`, `host_baseline_prior.py`,
`host_baseline_arm_history.py`, and `target/author-host-baseline-template.py` /
`author-host-baseline-after-addition.py` (tracked sources under tools/rust-v2-lab).
Do not substitute a similarly named or newly learned baseline mechanism.

At the initial audit read, the b51 candidate directory had **no**
authored-host-baseline-*.json or host-baseline-reconciliation-*.json. Root supplied
both during this audit; their independent validation is appended below.
The template is owner UID, regular, single-link, mode 0600, at most 256 KiB;
exact template keys are schema, platform, source_binding, baseline,
baseline_sha256, prior_evidence, review_sha256. Its source binding must equal the
candidate, review hash must match, and each of 1..64 prior evidence references
is a hashed relative target/*.json path without traversal. Review also binds
namespace/baseline hash and claims explicit reconstruction and multiset-only
ordering alignment. Independent review cannot be inferred from those booleans.

The baseline is exactly `{namespace,links,addresses,routes,rules}`; namespace is
two positive integers, category values arrays, total entries <=4096 and canonical
shape <=128 KiB. `host_baseline_declaration` additionally binds deployment_id,
generation, original allocation_digest, host_namespace and exact planned index
exclusion. This is public preservation input; host_authority_granted stays false.

The frozen read-only projection must exactly equal the independently authored
shape after ordering normalization. At audit time the candidate's recorded
Debian-clean projection has 50 links, 51 addresses, 154 routes, 5 rules, namespace
[4,4026531840], including 30 historical vprouter-v2 aliases. The older
`target/continuation-20261028T080736Z/authored-host-baseline-debian-clean-x86_64.json`
has 49 links and the same category counts otherwise. These observations do not
authorize adopting the observed full HOST. Explain the additional original
endpoint through prior bound ACK/history evidence or stop; preserve all aliases,
mounts, containers, canonical data, failures and original owner resources.

After an accepted case, the next independently authored baseline must preserve
the prior expected shape plus that case's exact acknowledged HOST endpoint.
`author-host-baseline-after-addition.py` demonstrates the narrow operation:
append the exact result host endpoint, then require equal full multisets before
aligning order, write `.next.json`, and never replace fixed inputs silently.
It currently accepts standalone HOST records/collector sidecars, so it also needs
an explicit Bootstrap-continuation adapter; do not fake a standalone HOST record.

## Minimal safe Root controller adaptation

1. Add separate Bootstrap runner/guest copies or an explicit family switch.
   Preserve captured helper bytes/hashes, strict frozen-source/artifact/context
   validation, static ELF checks, manifest validation, and new output directory
   exclusivity. Require frozen actual_lab_main flag and LAB_SECRET_BOOTSTRAP in
   operational/bootstrap.rs. Map all seven modes explicitly; record
   component_test_mode=`secret_bootstrap_<mode_with_underscores>`, distinct partial
   result classification, and all existing NOT_RUN/production/profile limits.
2. Reuse the external two-profile synthetic input path: random keys created by
   the guest outside Rust parent, profile mode 0600/root-owned, distinct clamped
   keys, one enabled exit and one disabled, no private profile bytes in argv,
   environment or public configuration. Preserve the inert network-none,
   read-only, cap-drop-ALL gateway, its pinned original process/netns, exact image
   and program manifest, root-owned isolated-acceptance marker and selectors.
3. Keep independent WAN declaration and authored baseline checks. Supply only
   reviewed candidate-bound baseline inputs; never fill omissions from live
   projection. All modes permit precisely one expected DOWN HOST endpoint and
   no prior-link/address/route/rule/stable-neighbor mutation. Preserve original
   gateway identity and all canonical/mount resources.
4. Parse exactly one case and one LAB_SECRET_BOOTSTRAP event. Require expected
   label, schema, fault, exact mode counts, ACK/timing/history/retention invariants
   above. Retain original stdout/stderr, nonzero records and timeout diagnostics.
   RuntimeMaxSec/outer timeout remain explicit fixture limits, not permission to
   extend any native two-second deadline. Run first success, then each new case
   sequentially with a new nonce/profile pair and explained next baseline.
5. Existing `quarantine_evidence_base.validate_prefix(...host_addition=True)`
   cannot be reused unchanged: its mode table, frozen-label check, marker parser,
   exact event comparison, manifest-mode mapping, and external changed-link
   expectations all assume standalone HOST fault numbering. Adapt these gates
   explicitly for Bootstrap, then validate the nested original prefix in
   continuation mode. Maintain strict original checks instead of removing them.
6. Existing `host_addition_evidence_schema.OUTER` omits the new
   `continued_original_context` field. It requires charges_after_drop=[5,5] and
   host drop-retention flags true. Bootstrap's nested HOST has
   continued_original_context=true, charges_after_drop=null, and those flags
   false, because original custody continues into handoff. Add an explicit
   continuation schema branch with exact allowed differences; keep all 87
   original writers, four operations, native receipts, plan/index, canonical
   history and expected [5,5] before-drop checks. Do not rewrite null to a claimed
   Drop observation. Nested producer/assembly continuation semantics must stay
   equally explicit. The final outer witness supplies actual whole-chain Drop
   retention evidence.
7. Archive selectors only after exact identity/content and original unit absence
   checks. Existing guest hard-links admission markers then unlinks selectors;
   no canonical resources, namespaces, containers or mounts are cleaned. For an
   unexpected failing harness, retain fixed selectors and original resources for
   exact-owner review and stop the family. Do not bypass collisions, remove stale
   endpoints, or run on production. Existing directory-binding's empty
   task8b2-N delta is only that directory check, not proof that no resources were
   created.

## Remaining acceptance limits

At the initial audit read no Bootstrap runner or collector existed in the
inspected target/tool paths. Root then staged the runner/guest reviewed below;
there is still no strict Bootstrap collector. Minimal runner adaptation alone
proves only the native Rust oracle and
external guest checks; a new strict Bootstrap collector is required before
calling the family collected/accepted. No original failure may be overwritten
by a later pass or collector correction. Source compilation/filter preflight
and ordinary existing-suite passes do not close this gap.

Autonomous integration, real clients/providers, multi-exit runtime, physical
devices, migration, performance, reboot/soak and release readiness are outside
this audit. No additional runtime/resource authority was requested or exercised.

## Addendum: independent pre-native review of Root preparation

**Scoped verdict: PASS for first raw native execution preparation. Native
Bootstrap remains NOT_RUN in this audit; any initial raw result is UNVERIFIED
until a strict Bootstrap collector and original receipts are reviewed.** No
source, VM, Docker, SSH, Git, privileged, or credential operation was performed.

Root supplied candidate-local authored baseline/reconciliation files during the
audit. I independently read and validated both, including regular-file owner
UID, mode 0600, single link, bounded size; exact template shape and source binding;
review hash; every cited prior-evidence/helper hash; and the declaration helper's
strict schema, canonical digest and shape validation.

I executed the read-only public `host_baseline_prior.py` conversion against the
exact HOST scope from
`task8b2-current-20261029/metadata.json`. Its 50 links, 51 addresses, 154 routes
and 5 rules reconstructed using explicit Debian absent/default expectations
match **both** the complete template and the independently frozen HOST projection
as exact multisets. No differing observed field was filled in or substituted.
I also checked the projection's captured controller hash, b51 source binding,
read-only/no-declaration/no-HOST-change authority fields, the metadata's
read-only/no-production-change fields, and the cited directory binding against
actual-program-run-397's source/archive/artifact binding and its created
directory. Run397 itself has no platform field; the platform binding is supplied
by its captured directory-binding and frozen projection records.

The address array order differs between template and projection, but every
entry and duplicate count matches. This is permitted by the guest's normalized
comparison and the native network `guarded::exact` multiset comparison; it is
not a structural difference. Namespace [4,4026531840] is bound by the frozen
projection and preserved template. The earlier 49-link template comparison is
historical context only: the newly supplied independent run397 reconstruction
accounts for all 50 expected links. It does not grant removal/member ownership
over historical resources, or silently learn the current HOST as authority.

Reviewed hashes:

```text
authored-host-baseline-debian-clean-x86_64.json
  3e745b4346d021371e67dfe4872423f05a9bf1a55be88bb14775b64c344c793f
host-baseline-reconciliation-debian-clean-x86_64.json
  4c9a8f52bcda37fcdb9f5fb5f40a927289a7e975dcc6ae75dfe23b4f790463da
canonical baseline digest
  21468b000422cf5170621f4554a8b31c5434d619bf12ad055f22dfbb182adf1a
target/platform-lab/run-frozen-secret-bootstrap.py
  565ecefd0472be62e53c927bb6875519440fb95b4516749386501c11cc52eb8c
target/platform-lab/secret-bootstrap.guest.py
  12a4d66ec4284a6d5de06bb3ac9fa6387514b94a4d7f3b78d9d8f525b86548a1
```

I reviewed the exact diffs against the HOST runner and guest. The runner uses a
closed seven-mode mapping, verifies the frozen original Bootstrap marker at its
correct source path, parses the new marker and records the new family. Existing
source/artifact/context, independently authored baseline, inert gateway,
synthetic profiles, selector collision, original process identity, and preserved
structural-state checks remain intact. Reused HOST names in two diagnostic
strings are cosmetic. Captured helper bytes/hashes remain present.

The new guest requires the exact expected DOWN endpoint for **every** zero-exit
Bootstrap mode. A nonzero unexpected early failure may leave either the exact
endpoint or no new endpoint; all prior structures remain unchanged, and extra,
wrong-name, wrong-alias, non-veth, UP or LOWER_UP additions fail. Permitting no
endpoint on nonzero status preserves the original failure diagnostic without
converting it to success. Failed original resources/selectors remain retained.

Beyond Root's supplied 16-check summary, I independently compiled the two Python
ASTs and executed **only** the extracted closed flag assignment and actual guest
HOST-delta statements against synthetic in-memory structures: 35 checks passed.
These comprise seven exact flag bindings, seven successful-mode positives,
seven missing-endpoint success rejections, two nonzero preserved-state cases,
and twelve independent structural mutations (missing/changed prior link, extra
link, wrong new name/alias/kind, UP, LOWER_UP, route/rule/address/neighbor drift).
No complete controller or guest was executed by this audit.

No blocking defect was found for the first raw native invocation at these exact
bytes. The runner's `PASS_PARTIAL_SECRET_BOOTSTRAP` string is a raw process/oracle
classification, not collected family acceptance. Strict event/JSON/type checks,
nested continuation schemas, original native ACK/timing/retention receipts, and
new baseline provenance between sequential cases remain required before any
family acceptance. Stop on unexpected failure; retain original evidence and all
resources. The review does not authorize live HOST adoption, member removal,
production execution, autonomous integration, readiness, or release.
