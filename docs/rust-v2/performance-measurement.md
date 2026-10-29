# Controlled performance evidence tooling

Status: implementation and offline regression checks only. Actual Python/Rust
benchmarks, performance improvement, and the actual mixed 24-hour soak are
**NOT_RUN**. These tools do not grant release acceptance or launch workloads.
Root alone selects approved local workloads, identities, process inventory and
cgroup domains after runtime/client/migration prerequisites pass. Never use the
old production-discovery sampler as a controlled baseline.

## Files and interfaces

- `tools/performance/collect.py`: read-only cgroup-v2/procfs JSONL collector.
- `tools/performance/analyze.py`: strict streaming raw-record analysis.
- `tools/performance/measurement.py compare`: paired repetitions and gates.
- `tools/performance/measurement.py soak`: original-window timeline validation.
- `tools/performance/example-manifest.json`: deliberately synthetic, unusable
  native identities. Replace every sample binding; it cannot establish evidence.
- `tools/performance/test_measurement.py`: offline synthetic regression fixtures.

Python standard library only. Execute from the worktree or use absolute script
paths; the adjacent helper module must remain with the scripts. Keep immutable
copies of all three scripts with each evidence set. Collector and helper hashes,
analyzer and analysis-helper hashes, raw input digests and public bindings remain
in the reports. Repetitions require identical instrumentation versions.

The collector preserves the reviewed fd-relative, nofollow, native identity and
bracketed read design from
`target/platform-lab/readonly-accounting.guest.py`, SHA256
`182a6afac179a34423c1a96fce73bc34ce2c7e053af975e57c172036921590a3`.
The raw analyzer derives from `target/summarize-readonly-accounting.py`, SHA256
`98ac545c694d81a655c39ab241573c808e7f332f764c5d5b1eef620fcf32eaab`.
Those original target files are unchanged by this work.

Commands below are integration instructions, **not commands run as benchmarks**:

```bash
python3 -B tools/performance/collect.py /approved/public-manifest.json --seconds 605 --interval 1 > /approved/run.jsonl
python3 -B tools/performance/analyze.py /approved/run.jsonl > /approved/analysis.json
python3 -B tools/performance/measurement.py compare --python /approved/python-1.json /approved/python-2.json --rust /approved/rust-1.json /approved/rust-2.json
python3 -B tools/performance/measurement.py soak /approved/soak-timeline.json
```

The example comparison supplies one scenario; full performance PASS requires
at least two matched repetitions for **each** steady/load one/five/six-exit case
(24 complete raw records minimum). Collection can exceed 600 seconds slightly
so the first-to-last actual sample-start span reaches 600 seconds. Steady-state
warmup and traffic startup happen before that original window. Do not reset
counters or discard failed runs. Use unique output names and retain failures.
All tools write only stdout; redirecting output is the controller's operation.
The collector never changes cgroups, limits, services, networking or processes,
executes no commands, and reads no argv, environment, private profiles or secrets.

Exit code 0 means a successful analysis/help operation or a comparison/timeline
PASS. Comparison/timeline absent or insufficient evidence, failing gates and
invalid evidence return 2. Collector interruption produces an `incomplete`
record and preserves prior flushed records. Optimized Python (`-O`) is refused
by collector/analyzer because inherited native checks use assertions.

## Public manifest contract (schema 2)

The example supplies all exact fields; unknown manifest/binding/group fields,
duplicate JSON keys, overlapping roots/native identities, unsupported methods,
nonfinite/out-of-range numeric values and weakened monitoring are rejected.
The manifest is a regular, single-link, nofollow file, owned by the collector's
UID with exact mode 0600, at most 65536 bytes. Root supplies it; collecting must
not trigger enrollment, discovery, credential reads or workload creation.

`binding` contains:

| Field | Meaning |
| --- | --- |
| `implementation` | `python` or `rust` |
| `source_sha256`, `artifact_sha256` | Frozen public source snapshot and exact product artifact |
| `config_sha256` | Same normalized effective public configuration contract across implementations |
| `workload_sha256` | Exact public workload, rates, protocol mix and traffic/client contract |
| `identity_set_sha256`, `peers_sha256` | Public fingerprint of the original approved identity/peer set; never credentials |
| `network_conditions_sha256` | Same isolated-host/network conditions contract |
| `host_id_sha256` | SHA256 of stripped `/etc/machine-id`; verified locally |
| `tailscale_version`, `tailscale_artifact_sha256` | Exact pinned Tailscale version and artifact |
| `run_id`, `repetition` | Globally unique run ID and matched positive integer repetition |
| `exits`, `exit_ids`, `exit_modes` | Stable public exit IDs; 1/5 Mullvad or five Mullvad plus explicit direct |
| `scenario` | `steady` or `load` |
| `monitoring` | Exact provider 5s, retry 1s, handshake 180s, health 45s, watchdog 90s |

`boot_id` binds the native boot. `evidence_origin` is `actual_runtime` or
`synthetic`. Synthetic records always remain insufficient for acceptance.
A declaration of actual origin is not cryptographic proof that traffic happened;
Root must review immutable public evidence and producer provenance. The tool
checks binding/consistency; it cannot authenticate a dishonest producer or infer
unlisted components from a process snapshot.

Each `groups` entry declares a unique role, relative cgroup-v2 root, original
`[st_dev, st_ino]`, and `accounting_class`: `control`, `runtime`, `tailscale`,
`mixed` or separate `workload`. Roots must be disjoint, including descendants;
PID duplication across roots invalidates aggregate PSS. Existing mixed Python
or Docker layouts are supported without restructuring. `executable_labels`
maps exact native executable SHA256 to host guard/publisher, worker control,
init/shim, Docker/runtime, Tailscale, workload or observer labels (see constants
in `measurement.py`). Classification uses the pinned executable, never comm,
process names or command lines. `stable_processes` pins each persistent process's
PID, start ticks, executable digest and group. Root must include all relevant
persistent daemons; a missing inventory entry is not discoverable proof of its
absence. PID reuse, movement, exec and state transitions are retained.

`accounting` declares the method
`disjoint_cgroup_v2_memory_current`, public scope/review SHA256, complete isolated
coverage, and mappings for `host_guard_publisher`, `worker_control`, `init_shim`,
`docker_runtime`, `tailscale`. Components can share one mixed root. The reviewer
must explicitly establish `outside_domain_overhead=none_on_isolated_host` and
`kernel_buffers=included_in_memory_current_and_memory_stat`. An incomplete or
unavailable declaration cannot pass the strict schema. If relevant overhead
cannot be placed in the declared nonoverlapping accounting domains, retain the
incomplete evidence and mark total-memory acceptance INSUFFICIENT. Do not claim
completeness merely because a cgroup is readable. Whole shared runtime/daemon
roots can be conservatively charged, with the same method on both versions.
Different methods or coverage declarations cannot satisfy the memory gate.

## Accounting and failure semantics

Every memory value is in **bytes**. CPU uses measured cumulative cgroup
core-seconds and bracketed core-seconds/second, with explicit derived one-core
percentages. The service CPU total includes all accounted non-workload roots;
separate whole-host CPU reports IRQ/softirq and other host work. cgroup CPU
includes short-lived processes missed by PSS snapshots.

Total service footprint is the sampled sum of nonoverlapping non-workload
`memory.current` domains, including control, init, runtime and Tailscale. Charged
kernel/socket memory is already included: **never add `memory.stat` kernel/sock
or whole-host memory again**. `memory.stat` byte gauges are separately reported;
its page/event counters are retained as raw counters, never renamed as bytes.
Control PSS and Tailscale PSS are independently reported. Per-field memory.stat
peaks may occur at different times and must not be added. Snapshot maxima are
observed sampled maxima, not proof that no transient larger peak occurred.

Mixed-group CPU is retained as whole-group CPU. Every observed control-bearing
mixed group is tracked, including a mixed runtime/Tailscale group omitted from
the declared control-component mapping. Per-role PSS still derives from
original process identities, but cumulative mixed CPU cannot reliably separate
short-lived control work from Tailscale/runtime. Supervision CPU is then `null`
with `INSUFFICIENT:mixed_cgroup_transient_cpu_unattributable`; the one-exit CPU
gate stays INSUFFICIENT while other valid gates and measurements remain visible.
The tool does not attribute the entire mixed group to control, subtract invented
overhead, or force cgroup changes merely to obtain a passing baseline.

Whole-host `/proc/meminfo` kernel, slab, page tables, per-CPU, cache, buffers,
free/available memory and `/proc/stat` CPU are context. They include the observer
and unrelated host activity. **There is no whole-host cache/used-memory gate.**
The manifest review must resolve relevant overhead outside charged domains;
whole-host context does not establish causal attribution or fill missing metrics.
Observer CPU/max RSS are retained separately; collector output serialization
cost after its final measurement is excluded, as explicitly recorded.

The original CLOCK_BOOTTIME origin, read/counter/flush brackets, cadence and
all sample sequences remain intact. Clock resets, incomplete pairs, changed
cgroups, counter resets, duplicate PIDs, unknown executable classification and
missing required metrics refuse a complete analysis. Process churn, stopped/
zombie/dead state, stable identity changes, OOM and missed collection deadlines
remain explicit problems. Missing PSS suppresses entire-run aggregate/control
PSS instead of treating vanished processes as zero. Native read unavailability
terminates collection as incomplete; earlier samples remain available. No
counter, time window or lifecycle baseline is silently reset.

Bracketed snapshots are not atomic; exec/membership ABA or short-lived processes
between reads cannot be ruled out. Resource measurement itself consumes CPU and
memory. Independent native safety review and workload/platform/fault acceptance
remain mandatory even if a comparison passes.

## Real traffic and monitoring sidecar (schema 2)

A run descriptor is a JSON object with exact keys `record`, `traffic`,
`record_sha256`, `traffic_sha256`. Paths resolve relative to that descriptor;
both files are independently hashed. The comparator reanalyzes raw JSONL instead
of trusting supplied summaries. Raw bytes must remain identical across both
analysis passes and match the descriptor.

The `traffic` JSON object has exact fields:

- `schema: 2`, `evidence_origin: "actual_runtime"`, exact `binding`,
  `record_sha256` and exact `window_boottime_ns` from analysis.
- `provenance`: `producer_sha256`, `raw_evidence_sha256`, `review_sha256`,
  `kind: "real_disposable_tailscale_clients"`. Root retains and reviews actual
  source measurements/captures identified by these digests; these identifiers
  are not substitutes for those artifacts.
- `traffic_protocols`: exactly `ipv4`, `dns`, `ipv6`, `tcp`, `udp`.
- `throughput_intervals`: contiguous original `{start_ns,end_ns,bytes}` counters
  covering the exact whole window; positive `throughput_bytes_per_second` is
  recomputed from their measured byte count and window.
- `latency_ns`: `p95`, `samples`, `complete: true`, `values_ns` containing every
  positive integer latency sample. Nearest-rank p95 is recomputed. Sampling or
  summary-only values cannot claim complete measurements.
- Nonnegative `unexpected_restarts`, `oom_events` from actual lifecycle evidence.
- `monitoring`: explicit source-bound `variant`, `source_bindings`, exact
  `contract`, `window_boottime_ns`, `complete: true`, `deadline_misses` and
  `retry_coverage`, plus the variant-specific fields below.

Select `rust_native_v1` only for Rust, with
`source_bindings:{source_sha256:<exact binding source hash>}`. Select
`python_legacy_v1` only for the separately reviewed source contract below.
Schema 1 traffic sidecars are refused: their old periodic 180/45/90-second
streams did not represent the runtime. The immutable source references used to
correct this contract are `crates/vprouter-worker/src/engine.rs` (`CADENCE`,
`sample_inner`, `Runner::run`, `operational_sample`),
`crates/vprouter-core/src/state.rs` (`HealthMachine::check`),
`crates/vprouter-core/src/health.rs` (`Session::expires_at`/`accept_inner`), and
`crates/vprouter-launch/src/expiry.rs` (`LeaseClock::trigger`/`liveness`). Bind the
actual frozen source hashes to each run; these paths alone do not pin bytes.

**Cadence is an interval; the other numbers are age/lease bounds.** Every exit
has a `cadence` stream of original five-second ticks. A tick has
`{scheduled_ns,completed_ns,deadline_ns,action,sample_id}`; `action` is `sample`
or `heartbeat` while that original sample operation remains pending. Tick
schedules are consecutive5s ticks, including relevant preceding and final
boundary ticks; missing/skip evidence is insufficient. Completion at or after
an original exclusive deadline counts as a miss. The parser never treats the
34s Rust outer provider operation as a new provider cadence or permits it to
reset pending deadlines.

Every exit has a `health` stream retaining original observations with exact
fields `observed_ns`, `provider_at_ns`, `structural_at_ns`, `heartbeat_at_ns`,
`verified_at_ns`, `message_sent_ns`, `handshake_age_at_structural_ns`,
`session_deadline_ns`. The four evidence anchors must be younger than45s;
message delivery must be younger than2s. The actual Rust Session expires at
`min(message_sent_ns, provider_at_ns, structural_at_ns, heartbeat_at_ns,
verified_at_ns)+44s`, further bounded for Mullvad by
`structural_at_ns+180s-handshake_age_at_structural_ns`. The measured handshake
age plus elapsed time since the structural observation must remain **strictly
below180s**; direct has a null handshake age. No periodic180s handshake poll or
45s health poll is invented. Health observation order and previous original
expiry must cover the entire original window, without an unobserved expiry gap.
A new heartbeat/message timestamp cannot rejuvenate old evidence anchors.

The current exact Rust writer contract requires three `watchdog` streams per
exit, with additional `writer` values `transport`, `data`, `host`. Each original
lease observation has `observed_ns`, `liveness_sent_ns`, `accepted_ns`,
`lease_deadline_ns`, `session_deadline_ns`, `trigger_ns`, `sequence`. Liveness
acceptance is younger than2s; the original liveness deadline equals
`liveness_sent_ns+90s`. The actual terminal trigger equals
`min(session_deadline_ns,lease_deadline_ns)-5s` and is exclusive. Session expiry
must match the corresponding original health observation. Preserve every
liveness renewal/sequence, observed receipt and independent writer check;
repeating a sequence cannot change its original sent/accepted times. Coverage
cannot skip past the previous original trigger. No90s polling interval is
introduced. These private receipts apply only to `rust_native_v1`. The genuine Python
baseline uses the separate legacy adapter below; it never emits or fabricates
Rust receipts and does not need runtime/cgroup restructuring.

`retry_coverage` contains **one provider operation for every original sample**,
including all no-trigger operations. Exact fields are `scope`, `sample_id`,
`started_ns`, `completed_ns`, `original_deadline_ns`, `first_result`,
`first_finished_ns`, `retry`. IDs map to cadence sample/heartbeat ticks; there
are no missing, duplicate or unreferenced operations. An operation completing
at its original outer deadline is a monitor miss. For `rust_native_v1`, `started_ns` is the original **outer Engine.sample timeout
start**, including initialization and structural work before the first provider
attempt; it is not the first HTTP-attempt start. The validator requires
`original_deadline_ns=started_ns+34000000000` exactly, matching OPERATION in
engine.rs. Completion at or beyond that unchanged end is a miss. Neither a
later provider start nor a heartbeat/retry can move the outer clock. The distinct
legacy variant keeps a null outer deadline; urllib12 is not a total bound.

When the initial result is noneligible, `retry` is exactly
`{coverage:"not_triggered",reason:first_result}`. Supported noneligible outcomes
are `success`, `http_permanent`, `tls_permanent`, `malformed`, `negative`,
`wrong_server`. Eligible outcomes are `http_408`, `http_429`, `http_5xx`,
`transport_eligible`, `attempt_timeout`; these require exactly one triggered
retry, with exact fields `coverage:"triggered"`, `reason:first_result`,
`pre_delay_check`, `delay_started_ns`, `original_not_before_ns`,
`post_delay_check`, `retry_started_ns`, `retry_completed_ns`, `retry_result`.
`original_not_before_ns` equals the original delay start plus **exactly1s**.
This is a not-before timer, not an expiry deadline: a retry can start at that
instant, after the fresh post-delay check. Both structural checks contain
`checked_ns`, `interfaces_sha256`, `routes_sha256`, `handshake_age_ns`; they must
occur after initial failure and on their correct sides of the original1s timer,
with fresh valid handshake age for Mullvad (null for direct). The retry outcome
is one of the same outcomes; no second retry is representable. Fresh observation
timestamps and source/raw provenance are required; equal unchanged route hashes
do not mean the checks may be cached. A safe eligible retry aborted by structural recheck uses `coverage:"aborted"`,
`reason`, `stage:"before_delay"|"after_delay"`, `failed_check`, `protection`.
`failed_check` has `checked_ns`, `failed_component` (`interfaces`,
`default_route`, `handshake`), `event_sha256`. `protection` has actual
`kind` (`tailscale_down`, `host_quarantine`, `terminal_quarantine`, `withdrawal`)
and `evidence_sha256`. A before-delay abort has **no timer and no second
attempt fields**. An after-delay abort additionally retains its successful
`pre_delay_check`, `delay_started_ns`, `original_not_before_ns`; the failure
occurs after that original1s timer. Neither variant invents a successful retry
or a new deadline. Other unrepresented failures remain INSUFFICIENT.

A Rust BLOCKED health or watchdog observation can instead contain exactly
`{observed_ns,state:"BLOCKED",protection}`. It asserts observed fail-closed
protection, with raw evidence, and carries **no fabricated Session/freshness/
lease anchors**. Observation-clock ordering is strictly increasing across **every** watchdog
state, including repeated BLOCKED and healthy-after-BLOCKED. Clearing lease
history never clears that clock ordering. A later READY observation again
requires actual original health/lease evidence; these data records themselves cannot grant readiness.

### Source-bound Python legacy adapter

The approved `python_legacy_v1` source bindings are exact public bytes:

| File | SHA256 |
| --- | --- |
| `router_runtime.py` | `36a087a833d260fc6c951ed407c22db2448a1a6dea55fdbf5aa8928bb3e11901` |
| `host/orchestrate.py` | `fe62364ae1c88c409f9e830f448a5a04f00e31927e5d02f24ea5a6b51f1296c9` |

These are the two entries of `source_bindings`. Root separately binds their
actual frozen source/archive/artifact and producer/raw/review hashes to the run;
a file path alone is not provenance. Only these reviewed source semantics are
supported. The source checks `mullvad_exit_ip=true` and WireGuard handshakes;
**a legacy direct-mode source is unrepresented and stays INSUFFICIENT**. Root
must separately review a genuine direct baseline implementation before a
five-Mullvad-plus-direct legacy case can be accepted. The validator cannot
fabricate that implementation from this Mullvad-only source.


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

The monitoring object has exactly `variant`, `source_bindings`, `contract`,
`window_boottime_ns`, `complete`, `deadline_misses`,
`monotonic_boottime_brackets`, `router_cycles`, `health`, `host_cycles`,
`retry_coverage`. There are **no Rust streams/private receipts**.

`monotonic_boottime_brackets` contains measured
`{monotonic_before_ns,boottime_ns,monotonic_after_ns}` samples covering both
original BOOTTIME window boundaries. It preserves the MONOTONIC↔BOOTTIME offset
as an uncertainty interval, never an exact conversion. Disjoint brackets after
suspend or an unrepresented clock discontinuity are INSUFFICIENT. No timer is
silently restarted. Original sleep/retry/work and systemd timestamps below
remain in their specified native clock domains.

Each `router_cycles` entry has `scope`, `clock:"CLOCK_MONOTONIC"`, `cycles`.
Every original cycle has `sample_id`, `started_ns`, `work_finished_ns`,
`sleep_started_ns`, `original_wake_ns`, `woke_ns`, `event_sha256`.
`original_wake_ns=sleep_started_ns+5s` **after work completes**; actual waking
can be delayed and is retained as measured scheduling lateness, not a fictitious
fixed Rust tick. Consecutive work windows cannot overlap. The original sleep
request is unchanged; the adapter does not invent an upper provider-operation
deadline from this loop structure.

Each retry operation maps to exactly one router work cycle, shares that
CLOCK_MONOTONIC domain and includes `attempt_timeout_ns:12000000000`,
`original_deadline_ns:null`, and `handshake`, in addition to the common operation
fields. urllib's12s setting is a **per-attempt timeout configuration**, not an
invented12s total-operation deadline. Healthy handshake evidence contains
`wall_before_ns`, `wall_after_ns`, integer `latest_handshake_seconds` from the
public latest-handshake observation, and `event_sha256`; its entire possible
wall-age interval must remain in `[0,180s)`. A structural retry abort has null
final handshake evidence and the actual failed-check/protection records above;
no first/second successful handshake is invented. Other source failure paths
without the required observations remain INSUFFICIENT.

Each `health` entry has `scope`, `observations`. A record has
`read_begin_ns`, `read_end_ns` in BOOTTIME; `wall_before_ns`, `wall_after_ns` in
WALL time; exact legacy `state`, integer `time`, integer `heartbeat`,
`status_result`, `protection`, `event_sha256`. The legacy integer heartbeat is
used exactly as the source does: READY requires its whole bounded wall age in
`[0,45s)`, with `status_result:"ready"` and null protection. Clock uncertainty
straddling either boundary is INSUFFICIENT. No integer WALL timestamp is
converted into a Rust Session/lease. Wall/BOOTTIME offset brackets must remain
consistent; steps/drift beyond observed uncertainty are reported insufficient.
A BLOCKED record has `status_result:"blocked"` and actual protection evidence;
`time`/`heartbeat` can remain null when unavailable/stale. That cannot claim READY
or manufacture fresh anchors. Other unrepresented health states stay insufficient.

`host_cycles` contains all original per-site orchestrator cycles. Exact fields
are `scope`, stable public `service_id_sha256`, `started_ns`, `work_finished_ns`,
`notify_started_ns`, `notify_finished_ns`, `manager_read_started_ns`,
`manager_read_finished_ns`, `reported_clock`, `reported_property`,
`reported_timestamp_us`, `watchdog_usec`, `sleep_started_ns`, `original_wake_ns`,
`woke_ns`, `event_sha256`. These timestamps remain CLOCK_MONOTONIC.
`original_wake_ns=sleep_started_ns+2s` follows the actual work/notification.
Every site is covered by its genuine separate service/manager observations;
service IDs cannot be reused to fake independent loops. Each host work window
contains its actual health-read bracket for that site, with clock uncertainty
included. Sparse health samples cannot stand in for missing host checks.

When `runtime_health_state` rejects missing/stale health, the host source
installs quarantine and raises **before WATCHDOG notification and sleep**.
Represent that genuine abort with exactly `scope`, `service_id_sha256`,
`started_ns`, `work_finished_ns`, `event_sha256`, `outcome:"BLOCKED"`,
`protection`, together with the matching BLOCKED health read. There are no
notification/manager/sleep fields to invent. A normal notifying host cycle still
requires the source's actual fresh heartbeat check, even when state is BLOCKED;
null/stale health cannot be paired with a fabricated successful notification.
Incomplete protected intervals or later unrepresented recovery remain insufficient.

The actual manager property is `WatchdogTimestampMonotonic`, with reported clock
`CLOCK_MONOTONIC`, `watchdog_usec:90000000`. The timestamp's microsecond precision
is retained as `[stamp,stamp+1us)`. A raw `WATCHDOG=1` call is **not evidence of
manager receipt**: `notify_systemd` can swallow errors. Require an actual
advancing systemd-reported receipt in the observed notification/read bracket,
and conservatively check original current/previous90s lease expiry using the
uncertainty bounds. Missing/late manager evidence stays insufficient or fails;
no Rust transport/data/host receipt is required or fabricated. The manager
reported clock must never be relabeled as BOOTTIME.

Root must retain actual producer/capture/raw evidence for every original cycle,
health read, manager notification/receipt and retry. The producer can be supplied
later; this validator does not modify production or install tracing. These
records validate declared original sequences and bounds; they do not authenticate
a dishonest producer. Sidecars are bounded to16MiB; retain longer raw evidence
separately and partition long timelines into complete contiguous measured
segments when necessary. Never drop latency samples, original receipts or retry
operations to fit the bound. Unrepresented clock/health/lease/fault cases remain
INSUFFICIENT and cannot establish complete mixed-fault soak acceptance.

## Comparisons and the actual 24-hour timeline

At least two matching repetition IDs per Python/Rust steady/load 1/5/6 case are
required. Source/artifact bytes remain fixed across the **entire submitted
suite** within each implementation, and instrumentation/host/Tailscale versions
remain fixed across all scenarios;
normalized config/workload, host, Tailscale, identities/peers and network contract
match across the pair. No measured runs may overlap on the same host/boot, even
across different shapes. A reboot changes boot binding but must retain the same
host contract. Simultaneous copies of an identity are never authorized.

Reports expose each paired ratio, original window, source/artifact/run binding,
accounting declaration, individual measurement ranges and conservative worst
Rust/best Python ratios. Repetition spread and read brackets are uncertainty,
not invented statistical significance. Gates are:

| Gate | Requirement |
| --- | --- |
| One-exit supervision CPU | At least 50% below the newly measured Python baseline |
| Total service memory | No greater than matched Python baseline |
| Control PSS | At most 16 MiB for one, 48 MiB for five |
| Throughput | At least 95% of Python baseline |
| p95 latency | At most 105% of Python baseline |
| Monitoring/lifecycle | No monitor miss, unexpected restart or OOM |

There is **no six-exit PSS target**. Incomplete evidence does not become zero or
PASS. The comparison never changes monitoring/security checks or optimizes code.

The soak input has exact fields `schema:1`, `evidence_origin:"actual_runtime"`,
`binding`, `window_boottime_ns`, `segments`, `provenance`. Bind it to the six-exit
five-Mullvad-plus-direct mixed workload. `provenance` contains
`review_sha256`, `raw_timeline_sha256`, `producer_sha256`. `segments` contains the
same raw-record/traffic descriptors as comparison. Segments retain the same
source/artifact/config/workload/run binding, boot and accounting method, and
cover one original contiguous window of **at least 86400 seconds**, without gaps,
overlaps, clock reset, OOM, unexpected restart or monitor miss. Each segment has
at least 600 seconds of actual measurements. Use one continuous `--seconds
86405 --interval 1` collection if possible; the maximum supported request is
90000 seconds. Short test fixtures cannot satisfy this real-time requirement.
Root must separately review mixed fault/capture coverage and earlier release
prerequisites; timeline PASS alone is not complete soak/release acceptance.

Focused checks (no workloads or long collection):

```bash
python3 -B -m unittest discover -s tools/performance -p 'test_*.py' -v
```
