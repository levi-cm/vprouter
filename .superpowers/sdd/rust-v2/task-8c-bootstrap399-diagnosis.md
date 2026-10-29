# Run399: first query boundary and masked lab error

2026-10-29. Read-only local source/evidence investigation; only this report was
written. No source changes, builds, VM/SSH/Docker/privileged calls, cleanup,
retry, protected-state access or Git mutations. The diagnostic source remains
frozen pending Root's next brief.

## Observed result

`target/lab-state/actual-program-run-399.json` binds frozen source
`73a352604303796adbe60e4752b27ec6d60ff9de`, archive
`5e2a8061c0cc1880ba1b5130f1954015bb5b74c13bbb262810e6d96fc3e72186`,
202 verified inputs and aggregate
`cbfc97b88d05bcbc83aff4347780dc1f87b173450a9830a2908c7493727bb53a`.
It records exit1, outer wall13.639s, zero case/PASS witnesses and final
`secret_bootstrap_lab: interrupted`.

Its293 stderr lines contain68 new phase events,88 journal inventory/verified
pairs,48 attachment phase records and the final error. Every entered new host,
exact20 handoff and initial Bootstrap constructor boundary completed. In
particular all five retirement pairs, preparation equality, service access,
initial query queue and Bootstrap return report success. One further journal
constructor then reached inventory verification. There is no Bootstrap failure
or final Bootstrap witness.

Root's public retained snapshot
`target/lab-state/secret-bootstrap-failure-run-399.json` is bound to run record
SHA256 `2f40352d1e74848f997c04f8d0ebf5672d2935f00b2498839bf27402a7b57a2b`.
Its selected entry remains creating with four host-link histories. The
three-element bootstrap_queries array has index0 `BootstrapHostRecheck` present,
with birth/facts/verified_at all absent; indices1 and2 are null. Thus the first
query Intent was canonically accepted, but no query Birth was accepted. Root
performed that observation; this agent read only the resulting local report.

Run399 reached a later boundary than run398. It is a different failure, not proof
that the original OwnershipMismatch was fixed. No native Bootstrap policy
operation or completed scope is proved by this attempt.

## Proved diagnostic defect

`PendingBootstrap::poll` returns the error from `Native::advance`, after
latching it through `n.fail(error)` and collecting only original owners. The
fixture's `lab_run` error handler then obtains
`n.request.as_ref().ok_or(Error::Interrupted)?` **before** reporting or returning
that error.

`n.request` is the later policy request. It remains absent throughout the first
QueryIntent/QueryBirth/QueryReading phases and until QueryResult accepts the
query. Consequently an error during those phases is replaced in the final lab
Result by Interrupted. The original error remains latched in the failed native
owner; this is masking in the reporting/return path, not evidence that its
failure latch changed. Run399's canonical query history and missing Birth are
consistent with that proved masking mechanism. The original error class cannot
be recovered from the existing stderr.

## Narrow remaining execution window

Canonical Intent acceptance does not by itself prove
`Server::poll_inspection_intent` returned `Some(Intent)`. After accepting its
writer, that function still obtains the selected history and retained allocation
lease and verifies the newly constructed Intent
(`owned/preparation/inspection.rs:893-915`). It can return an error there.

If that succeeds, `operational/bootstrap.rs` QueryIntent next:

1. Runs `kernel::docker_query::spawn(self.query.clone(), intent)`.
2. Obtains the retained service and calls `start_inspection_birth` with the same
   child.
3. Changes its step to QueryBirth only after that queue succeeds.

The failure could therefore be post-ACK Intent construction/verification, query
construction, or Birth queue setup before writer89. No particular Docker,
descriptor, deadline, owner, or history predicate is established. Do not change
enforcement or ownership checks on this evidence.

## Smallest proposed one-file diagnostic/preservation increment

In `attachment/operational/bootstrap.rs` only:

- In the existing test-only `lab_run` error handler, log a fixed Step label,
  existing error class and `request_present`/`query_child_present` booleans
  before requiring the policy request. If no policy request exists, return the
  original `Err(error)` immediately. Preserve the existing request-present
  injected-fault collection/oracle path and every failure latch. No report or
  collection capability should be invented from a missing request.
- Add `cfg(test)` fixed markers only when QueryIntent polling returns Some,
  then begin/ok around the existing query spawn and Birth queue expressions.
  This avoids logging each pending poll and adds no reads/clocks/IDs.
  Missing query_intent success identifies the remaining post-ACK Intent path;
  query_spawn begin without ok identifies query construction; successful spawn
  followed by unfinished query_birth_queue identifies Birth queue setup.

This is a correction of a proved lab diagnostic defect plus narrowly targeted
observability. It is not a semantic enforcement fix. Root authorization, scoped
review and a coherent diagnostic artifact/native observation remain required
before using it. No such source change or new native run is claimed here.
