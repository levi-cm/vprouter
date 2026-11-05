# Task 8c run 410 result

2026-11-04/05. Branch `rust/v2`; preparation commit `8a5942f` (pushed to `fork/rust/v2`,
remote confirmed equal) on top of candidate source `da75562`. Independent prep review:
PASS (`task-8c-run410-prep-review.md`); its only blocker (checkpoint/push) was cleared
before execution. Exact command (one shot, claim consumed, budget now **0**):

    python3 -B target/platform-lab/run-frozen-secret-bootstrap410.py \
      target/candidates/run410-da75562-20261104/candidate.json debian-clean-x86_64 \
      bootstrap410-driver-cost success --reservation target/lab-state/run-410-reservation.json

`--preflight-only` PASS immediately before (4 remote programs compiled, no guest action).

## Outcome

Exit 0, `result=PASS_PARTIAL_SECRET_BOOTSTRAP`, `component_test_mode=secret_bootstrap_success`,
wall 11.999 s, guest boot `77108fa0-82db-4a1b-9441-196f2b62e305`. Raw record written;
no controller-error receipt. **The run-409 failure (host.inventory ownership_mismatch) did
not recur:** the controller went through host.inventory, the 20-job handoff and the
three-scope Bootstrap.

Bootstrap witness (read directly from the raw record; not a typed validator pass):
`bootstrap_all_scopes_acknowledged=true`, `bootstrap_context_created=true`,
`fault=0`, `failed_constructor=null`, `failure_retry=null`, `canonical_negative_checks=39`,
`parent_pristine=true`, handoff `complete=true` with 20 original jobs (15 historical +
5 retired-suffix), charges 5→0 at handoff and 3→3 across drop, whole chain/operational
context retained after drop, all authorizations (`up/placement/health_ready/
resource_cleanup`) false, `multi_exit_runtime_proven=false`, `requirement8_complete=false`.
Controller summary: harness exit 0, owner unit absent, inert gateway retained with unchanged
native identity, single down host link added, host addresses/routes/rules and neighbours
preserved. `host_links_and_stable_routes_unchanged=false` is the expected consequence of
the one added down veth (`host_single_down_link_added=true`); not investigated further.

## Evidence (preserved, local `target/`, untracked)

| Artifact | SHA256 |
| --- | --- |
| `target/lab-state/actual-program-run-410.json` (raw) | `bd3d1819f6387491c69388b371f9b05fa28d5e773658223f950ffd743413f0ff` |
| `target/lab-state/run-410-consumed.json` (claim) | `fbb9b321d971646a1d184831aacdf5be5be18792fa3d2e7ec35092ff0b62ac9a` |
| `target/run410-evidence/receipt.json` (collector C) | `c151977a52d1448144325ffb560a5f60a8df898ab3ba6df51240145277f29179` |
| `target/run410-evidence-post-state.json` (inspector I, failed) | `dfbe182739bf26311ce49e47a2e7adddeff1a87789c92b75472677ad9fbd6a01` |

C: `provenance_valid=true`, `outcome=bootstrap_exit_zero_preserved`, 1 witness,
`runtime_acceptance=false`, `release_ready=false`.

## Guest lost after the run

I (read-only state inspector) exit 255: `Connection refused` on 127.0.0.1:22036. The 410
QEMU (PID 3152758) was terminated by `SIGTERM from pid 1051 (systemd --user)` at
2026-11-05 00:32 local (`qemu.log`), ~5.5 h after the run; host did not reboot. Serial log
ends at the run (WireGuard load) with no shutdown sequence. Consequences:

- Live post-run identities (gateway pid/pidfd/netns, owner cgroup) are unobservable; the
  guest overlay `guest.qcow2` remains on disk (not booted by this step).
- F (failure inspector) and A (selector archiver) are failure-path tools (A asserts
  `exit_code != 0`); they are **not applicable** to a successful run and were not run.
  P (cost-diagnostics parser) is also failure-path (no Deadline boundary, no driver-cost
  rows were requested to be emitted on success): driver-cost speedup evidence is **not**
  produced by this run beyond the successful completion itself.
- Not established: why systemd stopped the scope/unit (likely the user manager lifecycle;
  see debdev host-crash notes).

## Still open / NOT_RUN

Typed full Bootstrap witness validation, driver CPU/sleep/constructor samples,
real-client acceptance, ARM64 runtime, migration/performance/release acceptance.
`release_ready=false`; Task 8c stays ACTIVE. Budget for 410: 0 (consumed); 409: 0.
Any further runtime evidence needs a separately authorized new run with a new guest.
