# Controlled performance measurement implementation report

Actual benchmark, measured improvement and mixed 24-hour soak: **NOT_RUN**.
This independent task implemented measurement tooling only. Runtime/client
assembly and all release acceptance remain with the source agent and Root.
No production Python files, services, Docker, network, credentials, VM workloads,
Git index/HEAD, build manifests, candidate artifacts or shared status were changed.

## Implemented

- `tools/performance/collect.py`: reviewed fd-relative/bracketed cgroup/procfs
  sampling, original boot/clock windows, exact executable classifications and
  stable PID/start inventory, process state, kernel/socket accounting, observer
  cost, public source/artifact/config/workload/host/Tailscale bindings. No command
  execution, argv/environment/profile/secret reads or workload mutation.
- `tools/performance/analyze.py`: strict bounded duplicate-key-safe JSONL
  parsing, paired sequence/read/flush validation, monotonic cumulative counters,
  unavailable PSS suppression, lifecycle history, OOM and complete accounting.
- `tools/performance/measurement.py`: manifests, exact public evidence binding,
  externally produced real-client byte/latency/deadline validation, repetitions,
  paired ratios/spread, conservative gates and actual 24-hour timeline validation.
- `tools/performance/example-manifest.json`: schema example with synthetic
  placeholders; native collection and acceptance cannot use it unchanged.
- `tools/performance/test_measurement.py`: offline synthetic regression checks.
- `docs/rust-v2/performance-measurement.md`: complete accounting/CLI/integration
  contracts and explicit limitations.

Vendored base sources retained their reviewed identity/bracketing semantics:

| Read-only source | SHA256 |
| --- | --- |
| `target/platform-lab/readonly-accounting.guest.py` | `182a6afac179a34423c1a96fce73bc34ce2c7e053af975e57c172036921590a3` |
| `target/summarize-readonly-accounting.py` | `98ac545c694d81a655c39ab241573c808e7f332f764c5d5b1eef620fcf32eaab` |

Current tools explicitly add a helper-code hash and preserve product source,
artifact and config hashes in each bound run. Raw record hashes must agree
between descriptor checks and both streaming analysis passes. Freeze all three
scripts with actual evidence; no product artifact was built for this task.

Total service footprint sums disjoint cgroup memory.current including charged
kernel/socket memory and the complete Root-reviewed runtime/Tailscale coverage.
Whole-host kernel/cache/buffer/CPU figures remain context, with no cache gate.
Control/Tailscale PSS are separate, in bytes. CPU is core-seconds/second with
bracketed bounds and derived percentages. Existing mixed container cgroups are
supported: memory is counted once; per-role PSS uses original identities; mixed
CPU remains measured but supervision CPU becomes unavailable rather than
charging Tailscale/runtime to control. The one-exit CPU gate is INSUFFICIENT in
that case, while other measured gates remain exposed.

Comparisons require at least two matched 600-second repetitions for each
steady/load one/five/six-exit shape. They retain paired ratios, raw bindings,
spread and accounting declarations. Bad repetitions cannot be averaged away.
No six-exit PSS target was introduced; original 5/1/180/45/90-second clocks remain
required. Synthetic or incomplete evidence cannot satisfy acceptance.

## Local verification and failed attempts

Initial tests failed because the new measurement module did not exist. Focused
RED cases then exposed missing complete raw traffic/deadline projections,
cross-shape concurrent-run rejection, per-pair ratios/spread and missing
kernel/OOM coverage. Root additionally identified mixed-container baseline
accounting and numeric overflow; dedicated RED regressions reproduced both
before fixes. Early file-handle ResourceWarnings were corrected using explicit
context-managed streaming reads. All synthetic gate fixtures remain test-only;
no synthetic output was written as benchmark or soak evidence.

Focused command:

```bash
python3 -B -m unittest discover -s tools/performance -p 'test_*.py' -v
```

Result at implementation handoff: **40 tests PASS** in under one second.
Coverage includes byte/CPU arithmetic, nested/duplicate cgroups/PIDs, complete
sample pairs/windows, PID reuse/state/lifecycle, OOM/reset/unavailable PSS,
unknown/missing required metrics, oversized/nonfinite/boolean numeric input,
original monitor deadlines, recomputed p95/throughput, repetition pairs and
spread, mixed shared cgroups, nonconcurrent runs, and full-duration soak timeline
parser behavior. These are offline fixture checks, not elapsed runtime proof.

CLI help was checked without collection. The empty comparison emits NOT_RUN for
all six scenarios and exit 2. No actual collector, traffic workload, 600-second
benchmark, candidate optimization, privileged action or 24-hour soak was run.

## Integration and limits

Root must review exact complete nonoverlapping native cgroup/process inventory,
outside-domain overhead, pinned tooling/product artifacts, actual public
workloads and original real-client monitoring streams before collection. Complete
inventory is a reviewed declaration, not something a sampler can prove.
Unavailable native metrics terminate collection as incomplete and preserve the
prior JSONL. Stable identity/state changes and lifecycle events remain visible;
there is no silent baseline reset. Snapshot PSS may miss short-lived processes;
cgroup CPU/memory include charged transient work. Bracketed procfs snapshots
cannot rule out exec/membership ABA. Sampled maxima are observed snapshots,
not a guarantee that no higher transient peak occurred. Final output flush
cost after the final observer sample remains explicitly excluded.

Traffic/deadline sidecars require exact raw-record/original-window binding,
complete byte intervals, all latency samples and per-exit original monitor
observations. Root retains and reviews the actual producer/capture/raw evidence
identified by hashes; a self-declared actual origin cannot authenticate itself.
Public metadata/parser tests are not real-client, security, migration, platform
or release acceptance. Actual sustained behavior, performance gains and soak
remain NOT_RUN until Root performs the authorized isolated workloads after the
runtime/client prerequisites pass.

## Independent-review corrections

Root independently reproduced the original40-test result; review then identified
real acceptance gaps. Six added RED checks reproduced: control-labelled work in
a mixed runtime group omitted from declared control mappings, cross-scenario
Rust source changes, cross-scenario Rust artifact changes, cross-scenario
collector changes, absent retry evidence, and completion exactly at a deadline.
All six were corrected; all observed control-bearing mixed groups now suppress
exact supervision CPU, suite-wide source/artifact consistency is required per
implementation, tooling/host/Tailscale consistency is global, missing conditional
retry evidence refuses no-monitor-miss acceptance, and deadlines are exclusive.

The original monitoring exporter contract was semantically wrong:180/45/90 are
not handshake/health/watchdog polling periods. Read actual engine.rs, state.rs,
health.rs and expiry.rs; traffic schema2 now preserves actual5s sample/heartbeat
ticks, original evidence anchors with45s freshness/44s Session margin, handshake
age plus elapsed structural time strictly below180s, and original90s liveness
leases with min(session,lease)−5s terminal triggers. No runtime code/constants
were changed. Every initial provider operation has explicit no-trigger coverage
or exactly one eligible retry after its original1s not-before timer, with fresh
pre/post-delay interface/route/handshake checks. Outer operation completion at
its deadline counts as a miss; the1s retry not-before instant is not an expiry.

Fourteen additional original-clock regressions exercise valid triggered retries,
missing/eligible/permanent retry branches, shortened timers, reused pre-delay
checks, missing operation coverage,45s health age, structural handshake age,
Session margin, original lease origins,2s message expiry, exact operation
deadlines and refusal of the old fictitious polling schema.

Updated focused result: **60 tests PASS**, under one second, using the same
`python3 -B -m unittest discover -s tools/performance -p 'test_*.py' -v` command.

Remaining exporter limitation: the exact Rust contract has three independent
transport/data/host writers with44s/5s internal margins; legacy Python must
provide reviewed actual authority/export semantics rather than fake equivalent
receipts. Until such telemetry exists its monitoring gate is INSUFFICIENT.
Eligible retries aborted by failed structural recheck, blocked/no-evidence
health states and other unrepresented fault paths likewise remain INSUFFICIENT;
a future exporter extension requires exact original failure/quarantine evidence.
This preserves missing coverage honestly and is not complete mixed-fault-soak
acceptance. Actual workloads, benchmark improvement and24h soak remain NOT_RUN.

## Reviewed legacy Python adapter and safe fault branches

Root approved a genuine source-bound legacy variant after independently reading
`/DATA/AppData/vprouter-first-site/router_runtime.py` and `host/orchestrate.py`.
Only those two source files were read; no production execution, configuration,
environment, private state or credentials were read or changed. Exact public
source SHA256 values are recorded in `PYTHON_LEGACY_SOURCES` and the guide.

`python_legacy_v1` now supports actual work-then-sleep5s router cycles, urllib
per-attempt timeout12s without an invented total-operation deadline, actual
wall handshake bounds strictly below180s, integer WALL health heartbeat age
strictly below45s with observed clock uncertainty, and per-site host work→actual
manager WATCHDOG receipt→sleep2s cycles. The original systemd90s lease is bound
to its reported CLOCK_MONOTONIC property and microsecond uncertainty. Raw notify
calls cannot stand in for accepted manager receipts. MONOTONIC/BOOTTIME brackets
remain intervals; suspend/discontinuity cannot become exact synthetic leases.
Every actual host cycle requires its original per-site health-read bracket.
The source is Mullvad-only; an actual direct legacy implementation remains
unrepresented rather than fabricated for the six-exit comparison.

Both variants now support eligible retries safely aborted by a failed fresh
structural recheck: before-delay aborts contain no timer or attempt2; after-delay
aborts preserve the original1s timer and actual failed-check/protection proof.
BLOCKED observations retain actual withdrawal/quarantine evidence with null or
absent unavailable health/Session data, without invented freshness or leases.
Other unrepresented cases remain INSUFFICIENT. No configured intervals or
runtime code were changed. The Root-supplied actual producer remains future
integration work, as explicitly permitted for this tooling task.

Updated result: **79 focused tests PASS** (`python3 -B -m unittest discover -s
tools/performance -p 'test_*.py' -v`, about1s). Added RED/GREEN legacy source/timing/
clock/health coverage checks and safe-abort/BLOCKED regressions. Actual runtime
measurements, performance gains, real producer execution and24h soak remain
NOT_RUN. Independent review is still required before accepting tooling changes.

The final added RED/GREEN regression models host `runtime_health_state` failure:
quarantine/raise occurs before notification or sleep. Such a BLOCKED host event
contains actual protection and the original health-read window, with no invented
manager receipt or timer. Conversely, ordinary notifying cycles require the
legacy source's genuinely fresh heartbeat check even when its state is BLOCKED.

## Renewed-review outer-window and BLOCKED-order corrections

The reviewer cleared prior fixes and legacy source hashes, then identified two
further concrete blockers. Focused RED tests reproduced accepting a Rust
completion35s after the original start when only its deadline was extended40s;
repeated/decreasing BLOCKED watchdog timestamps; and a healthy observation
regressing behind the preceding BLOCKED timestamp. All were corrected.

Rust `started_ns` now explicitly denotes the original Engine.sample outer-timeout
start, including pre-provider work, with an exact original deadline of start+34s.
Completion at or beyond that unchanged deadline remains a miss. No34s deadline
was added to the legacy adapter: its explicit per-attempt12s setting and null
outer deadline remain unchanged. Watchdog validation separately retains
`previous_at` across every state; resetting lease history after BLOCKED cannot
reset observation ordering. Repeated or regressed observations refuse evidence.

Updated focused verification: **84 tests PASS**, about1.15s, with the unchanged
`python3 -B -m unittest discover -s tools/performance -p 'test_*.py' -v` command.
Additional positive regressions retain exclusive34s expiry and legacy operations
without an invented34s total bound. No runtime/source/workload modifications or
actual measurements were performed. Benchmark improvement and actual24h soak
remain NOT_RUN.

## Confirmed unchanged-legacy direct and topology limitation

The confirmed source locations are
`/DATA/AppData/vprouter-first-site/router_runtime.py` (SHA256
`36a087a833d260fc6c951ed407c22db2448a1a6dea55fdbf5aa8928bb3e11901`) and
`/DATA/AppData/vprouter-first-site/host/orchestrate.py` (SHA256
`fe62364ae1c88c409f9e830f448a5a04f00e31927e5d02f24ea5a6b51f1296c9`).
The read-only audit traced the actual entrypoint: `orchestrate.py:91-109`
requires the profile and rejects extra mode fields; `:332-356` provisions
WireGuard and its default route; `:418` always invokes that provisioning.
`router_runtime.py:32-55` requires `wg0`, default-via-WireGuard, and a positive
Mullvad response. `orchestrate.py:515-525,550-575` always verifies WireGuard
before its sole health/watchdog branch. There is no direct alternative in this
unchanged source. The existing legacy adapter must not accept fabricated direct
receipts; the mixed six-exit comparison remains **INSUFFICIENT** until a genuine
direct implementation and its actual source-bound monitor are reviewed.

For a five-copy legacy baseline, `orchestrate.py:22-24` fixes the shared bridge,
transport IP and subnet; `:116-143,214-241` uses shared host-wide
`vprouter_guard`/`vprouter_quarantine` tables and replaces or releases them.
Independent copies in the same ownership/network domain can therefore interfere.
Root must explicitly account for that isolation in the controlled measurement
plan and bind the actual topology/overhead to evidence. This identifies a source
constraint; it does not prescribe new hardware or a new topology, change the
baseline, or authorize runtime modifications. Six Mullvad exits are a different
workload and cannot stand in for five Mullvad plus direct.

This documentation-only clarification preserves the tooling. No additional tests,
workloads, configuration/private-state reads or source/runtime changes were made.
Actual performance and soak remain NOT_RUN.
