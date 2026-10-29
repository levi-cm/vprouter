# Run398 native Bootstrap failure: bounded read-only diagnosis

2026-10-29. This investigation read existing local source and evidence only and
created this report. No build, test, VM, SSH, Docker, privileged operation,
protected profile/credential/identity access, cleanup, retry, source edit, or Git
mutation was performed. The six task8c.1 source files remain frozen.

## Conclusion

Run398 failed with `secret_bootstrap_lab: ownership_mismatch` before the first
Bootstrap query journal writer reached its inventory marker. Existing evidence
and unchanged source localize the direct error to the nested successful-host
fixture's post-operation checks, the exact20 operational handoff, or
`PendingBootstrap::new` before that constructor successfully returns. They do
**not** identify the particular ownership predicate. No native Bootstrap policy
installation or completed scope is proved. This is a failed native component
attempt; full8c, runtime recovery, client and release acceptance remain open.

The useful next step is phase-specific evidence across this short boundary,
preserving all ownership fences and the original failure. A blind retry,
cleanup, relaxed reservation check, or longer deadline would not diagnose it.

## Authoritative evidence

- `target/lab-state/actual-program-run-398.json`: exit1, outer wall14.175s,
  `result=FAIL`, component mode `secret_bootstrap_success`. Source is frozen
  `b51b5d7dd7a127d88a6e770f0b8780951190805b`, not the newer task8c.1 delta.
- Binding: 202 tracked inputs; aggregate
  `0ce0488bee605e94f7aaf6fa4df915cc1284227efa3d773d78b6130bbfd06fe6`;
  source archive
  `efd893b6b136e2f0bae55cadcea6cfe1823ecd0129bef32fe76093271201d98d`;
  AMD64 artifact
  `7383d330350bdf445f2a77d95229955de38060426aa6ec7f8df17d7d2fb8d21b`;
  context
  `1170bc2a5980ab5adfb140e81bd91ed8fd28b6d2d7c2d58da91dff22119032e7`.
  Platform: `debian-clean-x86_64`.
- Its embedded stderr has223 lines:87 `io_inventory`,87
  `io_inventory_verified`,48 `LAB_ATTACHMENT_PHASE` records, and the one final
  OwnershipMismatch line. There is no `LAB_SECRET_HOST_ADDITION_FAILURE`,
  `LAB_SECRET_BOOTSTRAP_FAILURE`, or `LAB_SECRET_BOOTSTRAP` witness. The48
  attachment phase records report success. The embedded stdout contains13
  controller/setup objects and no case/PASS event.
- `target/task8c-20261029T123514Z/bootstrap-success-summary.json` independently
  records exit1 and `case_count=0`. The sibling `bootstrap-success.stderr` file
  is currently empty; use the embedded stderr in the run398 record, not that
  convenience file, for diagnostic counts.
- Embedded controller evidence records one exact DOWN host addition:
  `vh9b3cfeb03bd0`, ifindex60719893. It reports host addresses/routes/rules and
  stable neighbors preserved, the original inert gateway identity unchanged,
  and canonical/mount resources and selectors retained. This establishes the
  observed host change, not canonical result acceptance or exact20 transfer.
- Native environment bracketing is approximately186512.1376 to186515.6678,
  about3.53s. The14.175s outer duration is not the measured native operation
  window and does not establish expiry of an individual two-second request.
- Read-only `git diff b51... --` was empty for operational.rs,
  operational/bootstrap.rs, host_addition/operation.rs,
  owned/preparation/assembly.rs, and owned/preparation/host_link.rs. The traced
  ownership paths therefore match the frozen source for those files.
- Root subsequently supplied the retained public metadata snapshot
  `target/lab-state/secret-bootstrap-failure-run-398.json`, bound to the original
  run record SHA256
  `6fb3bacc8b02f913b8ae2e90f2d8d0ceb3801a7a217b09a88533de2e0f74e34a`.
  Its `canonical.namespaces.json.entries[0]` is still `creating`; all four
  host_link histories (`transport_sockets`, `pair`, `host_sockets`, `move`)
  have birth, result and verified_at present. No Bootstrap fields are serialized
  in preparation. This proves canonical acceptance of all four host operations
  and rules out an unaccepted last host result. It does not prove post-host
  fixture checks, exact20 retirement, or absence of an uncommitted queued query.
  Root reports the six selector identities/hashes retained, owner unit absent,
  no owner cgroup, and the same inert gateway running. These are Root-collected
  observations; this investigation performed no VM operation.

## Why this narrows the stage

`kernel.rs:1750-1759` emits exactly one marker pair per journal constructor,
before socketpair/fork. The verified marker proves that constructor's inventory
verification passed; it does not prove native writer completion or canonical
ACK. The host prefix expects75 writers before its four three-writer operations,
then87 total (`host_addition/operation.rs:898-917`). Bootstrap's first native
query would add writers88-90, before any policy installation.

`host_addition::lab_added` calls `lab_build(0,true)`
(`host_addition/operation.rs:634-636`). Its ordinary native polling error path
prints `LAB_SECRET_HOST_ADDITION_FAILURE` (`:775-794`), which is absent here.
After the native loop, however, many checks still return OwnershipMismatch
without a phase marker (`:881-1071`). Continuation mode returns the complete
owner and witness silently (`:1086-1090`); absence of a host PASS/witness does
not distinguish successful continuation from one of those checks failing.

`operational.rs:231-330` then validates the host witness and original anchors,
constructs the operational plan, reserves the exact five-job suffix against the
original15, retires five capacities with repeated-retirement refusal checks,
checks final counters/reaping, derives resource evidence, and compares the
whole preparation witness. All of these are uninstrumented direct error paths.

`PendingBootstrap::new` (`operational/bootstrap.rs:471-506`) checks complete
operational custody, derives context, creates a bound Host recheck, moves the
same owner into Native, then calls `start_inspection`. These steps can fail
before the first query writer exists. Query creation checks the original
process, binding, service, digest and request window
(`attachment/quarantine.rs:277-336`); `start_inspection` validates the selected
history slot and queues canonical inspection (`owned/preparation/inspection.rs:838`).

There is a further discriminator: before the first Bootstrap query finishes,
`Native.request` (the policy request) is absent. If polling that phase returned
an error, `lab_run`'s error handler would itself return `Interrupted` when
reading that missing request (`operational/bootstrap.rs:676-683`), before its
failure marker. The observed final error is OwnershipMismatch. Combined with
the87 marker pairs and fault0, the unchanged control flow points to a direct
`?` before `PendingBootstrap::new` successfully returns, rather than a failure
returned through initial Bootstrap query polling. This is source-path
localization, not a reconstructed stack trace.

## Remaining hypotheses and discriminating observations

1. **Host post-operation assertion or schema-negative oracle.** Root's retained
   canonical snapshot now proves the last host-link result accepted, but does
   not prove that the host fixture returned. Relevant checks include writer count/status/identity,
   unchanged prefix histories, operation/history equality, exact host inventory,
   `lab_host_schema_checks`, and `[5,5]` charges
   (`host_addition/operation.rs:898-1071`). Its schema oracle rejects20 mutated
   public record copies (`owned/preparation/host_link.rs:681-763`). No specific
   mutation acceptance or malformed field has been observed.
2. **Exact20 handoff construction, capacity retirement, or witness check.** A
   canonical record alone cannot prove process-local charge retirement,
   reservation identity, or which resource caused refusal. The original
   reservation/extension design explicitly keeps transferred resources
   nonquiet. `NativeJobs::drained` must remain false while such resources are
   retained; it is not evidence of a leak or reason to prune transferred jobs.
   Review found no proved circular reservation bug and no basis to weaken it.
3. **Initial Bootstrap constructor.** If the host and handoff return, separate
   `require_complete`, context, `for_bootstrap`, service access, and
   `start_inspection` results. A successful queue can exist before native writer
   birth; an on-disk journal alone cannot exclude all these paths.

Root's supplied public canonical metadata resolves last-host-result acceptance.
It cannot reconstruct process-local counters, reservation identity, or transient
queued state. Further on-disk inspection alone therefore cannot identify the
remaining exact predicate. Preserve the exact nonce/resources and original
run398 record.

If existing retained evidence cannot distinguish these paths, the minimal
source change to propose for Root's review is test-gated, secret-free phase and
error-stage witnesses at: host native completion; grouped post-host assertions;
host schema oracle; host return; anchor/witness validation; operational plan
and reservation; each suffix retirement; final counters/resource evidence;
preparation comparison; and each initial Bootstrap constructor step. Log only
phase, bounded public counts, and existing error class. Preserve original
errors, clocks, ownership, custody, failure latches and retention. A coherent
reviewed rebuild and an explicitly controlled native observation would then
be required; no fix or new native run is claimed here.

## Limits

No stack trace or phase predicate identifies the cause. The controller's
preservation observations do not prove native ACK, exact20 handoff completion,
Bootstrap policy readback, autonomous operation, recovery, READY, real clients,
or release acceptance. No cleanup or retry was requested or performed, and
run398 remains a preserved failure.
