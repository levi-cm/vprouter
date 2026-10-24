# Independent task6b review

Reviewer /root/review_launch_execution, reviewed c4b2236..6a2cbb3.
Spec compliance FAIL; task quality Needs fixes; no Critical.

## Important findings (verbatim)

1. **PID1 descriptor isolation can succeed without being verified.**
   `crates/vprouter-launch/src/kernel.rs:1019` silently discards directory enumeration and parsing errors; individual `close` results are also ignored. PID1 calls this helper at `kernel.rs:945` and proceeds to confinement/readiness without independently checking its remaining descriptor set. Unlike the worker’s `final_fds`, this path can accept a partial scan and retain inherited authority. Make enumeration errors fatal, close using a checked strategy, and verify PID1’s exact final descriptor inventory before readiness. Add focused failure-path coverage.

2. **Repeated signals can postpone escalation indefinitely.**
   `crates/vprouter-launch/src/kernel.rs:743` and `kernel.rs:971` replace the shutdown deadline whenever another TERM/INT/HUP arrives. Signals arriving faster than the grace period can therefore prevent escalation against frozen descendants; a later signal can also postpone the immediate deadline established after worker exit. Preserve the earliest deadline, and handle forwarding/escalation errors explicitly. Test repeated signals against a frozen descendant with a fixed total shutdown bound.

3. **The signal test masks failed forwarding/reaping with forced cleanup.**
   `crates/vprouter-launch/src/execution_lab.rs:551` sends TERM, sleeps, then unconditionally calls `terminate()` at line 554 before checking process disappearance. `terminate()` sends SIGKILL to the outer child, whose death chain can remove descendants even if signal forwarding or PID1 escalation never worked. Thus the case can pass with broken behavior. Assert bounded natural completion before forced cleanup, prove the descendant actually reached its frozen state, and use a separate observable witness for forwarded signals. Reserve forced termination for failure cleanup.

## Minor findings (verbatim)

- `crates/vprouter-launch/src/lib.rs:2` — The crate description still says it performs no namespace entry, mutation, or execution, although private execution modules now exist. Update it to describe the public admission-only boundary and private staged executor accurately.
- `crates/vprouter-launch/src/kernel.rs:1` — Keeping unsafe operations in one module satisfies the requested boundary. Its internal functions have identifiable roles, but section boundaries separating namespace/mount setup, lifecycle, confinement, and test-only helpers would make this 2,166-line review surface easier to maintain.

## Strengths and verification limits

Test-only probe authority binds artifact and compiled policy; ownership binds real
allocation lock; exclusive generation-bound namespace creation retains interrupted
state offline; wrappers release roots/authority; host proves worker/privatePID1
state and namespace identity. Report distinguishes synthetic success from release.
Actual worker/Go policy, production resolver/state integration, guard/quarantine,
usable transport, real-client leakage and other platforms remain NOT_RUN.
Review read full diff sequentially; no source reopening, unchanged-code exploration,
test execution, privileged/live commands or checkout mutations.
