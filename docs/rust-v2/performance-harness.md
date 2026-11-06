# Task 14 offline performance preparation

**No product performance claim.** Fresh comparable Python baseline and Rust
candidate recordings are absent. Task 8c runtime/ARM/client acceptance is OPEN.
Real Mullvad/Tailscale credentials and a qualified owned guest/workload are not
available to this implementation task. `release_ready` remains false;
`acceptance.json` is unchanged. Every actual performance gate is **NOT_RUN**.

The full binding work package is IMPLEMENTATION.md package 11 and the Task 14
brief. Existing 20-second uncontrolled resource observations exclude relevant
overhead. `audit-comparison-benchmark.json` measures one standalone comparison
function. `test-resource-inventory.json` is historical inventory, not current
credential availability or permission. None is an acceptable performance baseline.

## Implementation and interfaces

Python standard library in `tools/performance/` matches the existing measurement
and release engineering conventions, avoids new dependencies and Rust build
memory, and makes native-text parsing/accounting testable without Linux resources.
`accounting.py` is a pure deterministic library: caller-provided strings/objects
in, values out; it never reads `/proc`, cgroups, clocks, identities or credentials,
opens sockets or writes output. Its explicit sibling import loads the existing
pure contracts in `measurement.py`, including original Python/Rust monitoring
validators; there is no host discovery. Imports of local Python source are the
usual module-loading I/O, not resource collection.

`offline.py` is the bounded filesystem/CLI adapter. `loopback.py` is a separate
short local harness self-test. Neither starts product services. The existing
collector, analyzer, traffic contracts and legacy CLI remain unchanged. Their
old two-repetition contract is distinct from the stricter six-repetition
accounting layer; no result from either tool grants release acceptance.

Run from the repository root (all paths may also be absolute):

```bash
python3 -B -I -m unittest discover -s tools/performance -p 'test_*.py' -v
python3 -B -I tools/performance/loopback.py --iterations 3
python3 -B -I tools/performance/offline.py summarize tools/performance/fixtures/synthetic-short-run.json
python3 -B -I tools/performance/offline.py compare --output /approved/new-report.json
```

The fixture and empty comparison return exit **2 / INSUFFICIENT_DATA** as intended.
The loopback driver returns `SELF_TEST_PASS`, `performance_evidence:false` and
`release_ready:false`; it cannot qualify product traffic. Accounting CLI exit 0
means complete valid run analysis or a fully passing comparison, never release
readiness; complete run analysis may contain failed arithmetic metrics that the
comparator evaluates. Errors and incomplete comparisons return 2. An insufficient/malformed run summary emits only the fixed redacted failure response on stdout and publishes no file, even with `--output`. A complete comparison with missing suite shapes may publish an insufficient comparison report; malformed records refuse publication. Only explicit
`--output` publishes a file; otherwise output is canonical JSON on stdout.

Publication pins every parent directory with `O_DIRECTORY|O_NOFOLLOW`, creates
an exclusive private temp file, writes fully, fsyncs it, calls Linux
`renameat2(RENAME_NOREPLACE)`, then fsyncs the directory. Existing destinations
(including symlinks) are never overwritten. There is no overwrite fallback.
Before-rename failure removes the temp file; process death may leave a temp file
for inspection. A directory-fsync failure after rename leaves the published file
in place with durability uncertain and reports failure; retain it, use a new name,
and do not silently retry over it. No directories are created by the CLI.

Input files must be regular, single-link, nofollow and unchanged across their
bounded read. Each input/output is at most 16 MiB, JSON nesting at most 32;
duplicate keys, nonfinite/overflow numbers and oversized integer strings fail.
At most 128 raw runs are submitted; the CLI analyzes one file at a time and keeps
compact summaries. No input path, account name, raw exception text, kernel title
or absolute cgroup path appears in results. Public run/exit labels use bounded
identifier syntax; host metadata is output as a contract digest. Output ordering
is stable, including when run arguments are reversed.

## Run schema 1

`tools/performance/run-schema.json` provides the structural schema;
`accounting.summarize` is the normative semantic validator. All named object
fields are required; unknown fields fail except extensible native counter maps.
Unknown measurements are explicit nulls and make the run insufficient; an omitted
field is invalid. Every raw integer is unsigned and <=2^64-1 unless a tighter bound
is specified. Booleans are not integers. Memory is bytes, ticks are raw cumulative
ticks, cgroup CPU is cumulative microseconds, and clocks/latencies are integer ns.

| Object | Required fields and meaning |
| --- | --- |
| Run | `schema:1`, `evidence_origin:synthetic/actual_runtime`, `purpose:harness_self_test/runtime_measurement`, `binding`, `host`, `boot_id` (public boot SHA256), `clock:CLOCK_BOOTTIME`, `interval_ns`, `warmup_discard_ns`, `duration_ns`, `instrumentation_sha256`, `domains`, `accounting`, `samples`, `traffic`, `runtime_evidence`, `failure_domains` |
| Binding | Exact schema-2 binding from performance-measurement.md: implementation, source/artifact/config/workload/identity/peer/network/host/Tailscale hashes and version, unique run ID, positive repetition, exit count/IDs/modes, scenario, unchanged monitor contract |
| Host | `kernel`, `cpu_model`, `architecture`, `logical_cpus`, `governor`, `memory_total_bytes`, `swap_total_bytes`, `tick_hz`, `tick_bits`, `thermal_limit_millic`. Kernel/CPU labels are exact normalized public identifiers (or exact model hash); retain raw public metadata separately. Contract must stay identical across the suite. |
| Domain | `id`, `scope` (1–16 public cgroup ancestry labels), `native_identity:[device,inode]`, `components`. 1–32 domains; roots/descendants and native identities must be disjoint. Native identity need not match after a stopped-state implementation switch. |
| Components | `supervision`, `workers`, `guard`, `init_shim`, `container`, `tailscaled`, `observer`, `workload`; all must be covered. Architecture differences must be represented honestly, with reviewed scope declarations. |
| Accounting | `complete` and `isolated_host` booleans, `kernel_networking:included_in_domains/unavailable`, `outside_overhead:none/unavailable`, `review_sha256`. A coverage declaration is review input, not automatically established by a readable cgroup. |
| Sample | `mono_ns`, `read_end_ns`, `wall_before_ns`, `wall_after_ns`, `domains` (exact declared IDs), `processes`, `host`. 2–10001 original samples. |
| Domain sample | `cpu` (`usage_usec`, `user_usec`, `system_usec` plus bounded integer extensions), `memory_current_bytes`, `memory_stat` (at least anon/file/kernel/sock), `memory_events` (at least oom/oom_kill), `io` by major:minor with rbytes/wbytes/rios/wios and optional dbytes/dios, `member_pids` from recursively enumerated and bracket-verified cgroup.procs (<=4096), `pids_current` (native thread count), `cpu_exited_usec` (cumulative independently recorded transient/exited CPU), `memory_other_bytes` (aligned charge outside member USS), `memory_stat_other_bytes` (aligned charge outside anon/file/kernel), `io_other` (cumulative aligned per-device block I/O outside stable members) |
| Process | `pid`, `start_ticks`, `executable_sha256`, `domain`, `component`, `utime_ticks`, `stime_ticks`, `pss_bytes`, `rss_bytes`, `uss_bytes`, `threads`, `fds`, `wakeups`, `io` (per-device completed block I/O with the same keys/units as domain `io`, never logical syscall bytes). <=4096 processes/sample; exactly one domain per PID; all cgroup members represented. Counter values may be null only to preserve unavailable evidence. |
| Sample host | `irq_ticks`, `softirq_ticks`, `swap_in_pages`, `swap_out_pages`, `swap_used_bytes`, `thermal_throttle_count`, `temperature_millic`, `busy_ticks` (whole-host cumulative busy CPU ticks), `other_cpu_usec` (cumulative independently recorded CPU outside the measured domains); null is insufficient. These are context, not added to service totals. |
| Traffic | `bytes` over the exact measured post-warm-up window, complete positive integer `latencies_ns` (<=100000), `monitor_misses`, `unexpected_restarts`, `oom_events`. Never use generated rates/configured limits as actual measurements. |
| Failure domains | Exact keys `supervision`, `workers`, `guard`, `init_shim`, `container`, `tailscaled`, `observer`, `workload`, `kernel`. Each requires full-run counts `memory_oom_kills`, `kernel_oom_kills`, `unexpected_restarts`, `monitor_misses`, `missing_samples`. Zero requires reviewed original coverage, including warm-up/startup/tail. Missing/null/invalid evidence refuses; any positive count makes the summary insufficient and relevant gates retain failures. For the kernel, memory-event counts cover kernel work charged to measured cgroups; kernel-log coverage also includes unattributed/global kills. Do not fabricate a kernel cgroup or a monitor/restart for an unmonitored kernel: the reviewed producer must define coverage (boot/collector continuity for kernel lifecycle). |
| Runtime evidence | Null for synthetic fixtures. For actual use, the existing schema-2 real-client traffic sidecar and original source-specific monitoring, including producer/raw/review digests. `record_sha256` is SHA256 of sorted compact ASCII JSON for the entire run excluding only `runtime_evidence`; window and binding must match exactly. |

`runtime_evidence` is validated by `accounting.validate_exact_traffic`: full contiguous
traffic intervals, all latency observations, exact original cadence/retry/health/
watchdog receipts, source-specific Python or Rust contract and protocol coverage.
It reuses the original `measurement.validate_monitoring` replay after nested item validation. Accounting validates traffic intervals and nearest-rank latency with exact integer arithmetic. `throughput_bytes_per_second` must be an integer, an exact `{numerator,denominator}` rational, or an exact raw-unit `{bytes,duration_ns}` pair matching the original byte count/window; legacy float projections are refused in this path. The older measurement CLI and its contract remain unchanged. The accounting traffic projection must agree exactly. A generic zero miss count cannot
substitute. The Python legacy adapter cannot represent direct mode; six-exit
Python evidence therefore remains insufficient until a genuine direct baseline
and source-specific monitoring are independently reviewed. No fake Rust receipts,
six-Mullvad replacement or runtime restructuring may bypass that restriction.
Hashes/declarations do not authenticate a dishonest producer. Root must retain
and review immutable original producer, native-read, traffic and capture evidence.

## Strict native parsing and clocks

Pure parsers consume `/proc/PID/stat`, `smaps_rollup`, `sched` wakeups, numeric fd
entries, and cgroup-v2 `cpu.stat`, `memory.current`, `memory.stat`, `memory.events`,
`io.stat`, `cgroup.procs`. Unit-bearing memory must say exactly `kB` and is converted
by 1024; RSS/PSS/private-clean/private-dirty are mandatory and ordered consistently.
USS is private clean+dirty; nonzero hugetlb is unsupported and refused because
Linux excludes it from Rss/Pss. Duplicate/unknown smaps keys, duplicate native map
keys/devices/PIDs/fds, missing required counters, malformed units and integer
overflow (including aggregate overflow), reversed smaps address ranges, stopped/terminal
process states and unknown host metadata fail. Unknown cgroup statistic names are retained as unsigned native
counters, never relabeled as bytes. Memory.stat byte gauges may decrease; event
counters and every CPU/I/O/wakeup counter may not reset or regress. The parser
understands a 32-bit tick bound, but acceptance requires 64-bit ticks: wrap or
ambiguous width is rejected, never repaired by adding 2^32. Wakeups are specifically
`se.statistics.nr_wakeups`; context switches are not wakeups. Missing schedstats
returns null and blocks completeness. fd counts come from actual numeric entries.

Only BOOTTIME defines resource durations. Wall read brackets provide independent
clock-step/suspend consistency checks, never durations. All times are nonnegative
finite integers, samples strictly increase, read brackets cannot overlap and read
or wall uncertainty is at most 10% of interval. Cadence is 0.25–10s; any adjacent
spacing more than +/-10% from the requested interval is a sampling gap. Wall-minus-
BOOTTIME offset brackets must have a common intersection across the entire run.
Clock regressions, drift/steps beyond observed read uncertainty and gaps are
insufficient. There is no interpolation, counter resetting or gap filling.

Warm-up discard is explicit and must end exactly on an original sample boundary.
At least 600 seconds must remain between actual post-warm-up first/last sample
starts. `duration_ns` equals original first/last start span (max 90000s), not the
requested timer or final read tail. Cumulative CPU uses conservative read-duration
bounds, including transient children captured by cgroups. Thermal readings at or
above the reviewed limit, any nonzero throttle count, swap use or cumulative
swap-in/out count block comparison. This conservative policy requires a clean
known boot; it deliberately does not erase historical contamination. Unknown
thermal/swap metadata blocks comparison even if the machine seems idle. Failed
runs and warm-up OOMs are retained, never silently excluded.

## Reconciliation and failure coverage (review round 1)

This uncommitted draft schema 1 now requires additional evidence. Earlier draft
records without it are insufficient; no missing field is defaulted to zero. No
executable producer currently supplies this contract. A reviewed producer must
collect aligned charge/block-I/O/lifecycle evidence, or mark the run unavailable.
Residuals are original measured evidence with retained provenance, never computed
by this analyzer to make a discrepancy disappear. The synthetic fixture computes
consistent values solely to exercise validation; it is not producer evidence.

For each adjacent pair, **every prefix anchored at the original first sample**,
and every post-warm-up prefix anchored at its first sample, compare cgroup CPU delta to stable
member `(utime+stime)` tick deltas plus independently recorded exited CPU. Absolute
discrepancies in either direction must be within
`2 * stable_members / tick_hz` CPU seconds plus
`logical_cpus * (previous_read_width + current_read_width) / 10**9` CPU seconds.
The two ticks per member allow independent user/system endpoint quantization.
Read brackets bound CPU sampling skew at full host capacity. Aggregate host busy
ticks must match all domain CPU plus independently measured outside CPU, within
`12 * logical_cpus / tick_hz` CPU seconds plus that same skew bound. The host
busy total sums user/nice/system/irq/softirq/steal ticks per CPU. Explicit host
`user_ticks` includes nice, `system_ticks` excludes IRQ/softirq, `idle_ticks`
includes iowait, and guest/guest_nice are not added again. Every busy category
must reconcile exactly with the same atomic host read; IRQ+softirq cannot exceed
busy at a snapshot or across any checked endpoints. Domain user/system and stable
member user/system deltas have separate subset/reconciliation checks, including
original `cpu_exited_user_usec` and `cpu_exited_system_usec`, whose sum must equal
`cpu_exited_usec`. Neither host busy+idle nor
domain CPU can exceed elapsed time times logical CPUs (host tick allowance below). Native CPU usage must
match user+system within 2 microseconds, conservatively allowing unit truncation.
These consistency tolerances never relax any WP11 performance threshold.

The derivation is endpoint based. A cumulative process user or system tick count
is truncated to ticks: its endpoint error lies in a one-tick interval. Subtracting
two endpoints changes that error by less than one tick per field, hence less than
two ticks/member for user+system together. For host counters use the more
conservative symmetric one-tick endpoint bound: two endpoints times six busy
categories times CPUs gives `12*ncpu` ticks. Adding idle and iowait gives
`16*ncpu` ticks for busy+idle capacity. Host user/nice and system subset checks use
`4*ncpu` ticks, conservatively covering both user/nice fields. If endpoint read
widths are `w0,w1` ns, at most `(w0+w1)*ncpu` CPU ns can fall between aligned
read instants; add that exact rational quantity once to CPU reconciliation.
Capacity instead uses the outer elapsed bracket (`last.read_end-first.mono`),
which already includes acquisition uncertainty. These bounds are granted ONCE
for every anchored window, including the whole original and measured run; they
are never summed over intervals. Increasing sample count cannot enlarge the
whole-run allowance. Stable identity changes refuse qualification; exited work
must have original cumulative split counters and cannot be invented as a residual.

At each aligned observation, `pids_current` equals member thread counts (Linux
pids.current counts tasks, not just leader PIDs), and cgroup membership equals
recorded leader PIDs. Under the required reviewed private-charge/isolated policy,
member USS plus `memory_other_bytes` equals memory.current; anon+file+kernel plus
`memory_stat_other_bytes` also equals memory.current. Sock is checked against the
charge ceiling. Its charge belongs either in the reviewed kernel total or in the
measured residual and must never be added twice. Per-process RSS and
the sum of disjoint domain charges, aggregate PSS and aggregate USS cannot exceed
host RAM. RSS/PSS are never
summed and equated to cgroup charge: shared mappings and charge ownership differ.
A producer unable to establish private-charge ownership cannot qualify this
reconciliation. Memory residuals include page cache, shared charge and kernel
charge, with their independently retained attribution evidence.

For each device/counter, completed block-I/O deltas from stable members plus
`io_other` equal cgroup deltas. Logical read/write syscall byte counts are
incompatible and refused by the producer contract. Device/membership changes,
counter regressions, unavailable metrics or residuals refuse qualification.
Memory, I/O and PID reconciliation use exact aligned observations: clock skew
alone provides no finite bound on bytes or task churn, so there is no invented
byte/count epsilon. A skew-induced discrepancy conservatively refuses and
requires better original acquisition; these checks cannot prove alignment from
the input declarations alone. Counter residuals must be monotonic; memory
residuals are gauges. Future kernel/platform semantics require independent review.

Plausible deltas cannot hide impossible initial counter offsets. Process start
ticks must be no later than the current boot-clock tick; cumulative process CPU
is bounded by its lifetime times host CPUs (plus two ticks/CPU). Cumulative host
busy+idle is bounded by boot time times CPUs plus the same 16 ticks/CPU capacity
allowance, and cumulative cgroup CPU by boot time times CPUs. This fixed host
contract excludes CPU hotplug since boot unless a conservative CPU ceiling can
be established independently. These checks do not authenticate host history.

The executable `INVARIANT_REGISTRY` in `accounting.py` names every physical
equation family, enforcement function, refusal code/status and raw mutation test.
The Review round 2 implementation report contains the corresponding table.
Each entry must have live constraints and signed raw boundary tests; removing a
row, its constraints, test binding, or verdict enforcement fails completeness or
mutation checks. All contradictions return INSUFFICIENT_DATA; a performance gate
can separately FAIL, and insufficient evidence takes precedence.

The draft now also requires host `link_capacity_bps`, `max_fd_entries` (a reviewed
upper bound on FD entries per process, not file descriptions), and inclusive
`pid_max` (maximum allowed PID and host task population). FD/thread counts are
gauges and may decrease; process wakeups are monotonic counters without an
invented per-second maximum. Member thread sums equal cgroup pids.current and
the aggregate task population cannot exceed the host ceiling. Summed FD entries
are not compared to file-nr because inherited/duplicated entries share file
descriptions. Physical-link `network_rx_bytes`/`network_tx_bytes` counters are
monotonic and individually bounded by full-duplex capacity times the outer
elapsed bracket, without an interval-count-dependent allowance; delivered
payload is bounded by measured RX+TX bytes. These must describe one reviewed
physical workload link with counters for serialized bytes, not summed overlay,
loopback, offload completion, or duplicate interface counters. A producer unable
to bind a fixed capacity and byte semantics must return unavailable.

Process `swap_pss_bytes <= swap_bytes`; sum SwapPss and disjoint cgroup
`swap_current_bytes` must each be <= host swap used <= swap total. Raw Swap is
not summed because shared swapped pages can appear in multiple processes.
Any used swap, process/cgroup swap or swap-in/out activity prevents PASS.
Memory comparisons use zero byte tolerance: no observed read-width alone can
bound memory churn. PSS rounding down cannot create an excess over MemTotal.
Cgroup memory.current bounds the member **USS** sum under the private-charge
contract; PSS is separately bounded by RAM, never equated to charge ownership.
All added fields are mandatory; unknown is unavailable, never zero.

The numeric property corpus traverses every numeric schema position (including
first/last array endpoints, each domain/component and both original monitoring
adapters), applies signed one-unit, large and u64-boundary perturbations, and
checks the production verdict against violated registered predicates. Separate
hand-derived raw mutations establish every predicate and exercise its consumer.
An independent retained insufficiency/failure must never become PASS through a
different numeric perturbation. Repairing the sole invalid measurement can
legitimately restore qualification; no irreversible verdict latch is implied.
JSON decimal/exponent tokens are rejected before conversion. No floating values
are used in this verdict path, including reused monitoring replay; statistics,
rates, bounds and gates remain integer/Fraction arithmetic.

All measured domains and all nine failure roles are mandatory. OOM deltas from
all declared cgroups, including `oom_group_kill`, are retained over the entire
recording before warm-up discard. Kernel log and per-role memory events, restarts,
monitor misses and missing samples are also mandatory. Positive counts anywhere
prevent PASS, including observer/workload failures; raw service/traffic and
all-domain counts are combined conservatively by maximum, never subtracted or
claimed as an exact deduplicated kill count. A schema declaration does not prove
that omitted or hidden events were collected. That remains a producer review gate.

## Accounting and statistical method

Total service memory is the maximum **simultaneous sum** of disjoint service
cgroup `memory.current`, covering supervision/workers/guard/init/shim/container/
Tailscale and charged kernel buffers. Kernel/sock memory.stat breakdowns, process
PSS/RSS/USS and whole-host memory are not added again. Uncharged kernel networking
or external/shared runtime work must be conservatively included in reviewed
nonoverlapping domains, otherwise coverage is unavailable. No invented subtraction
of idle-host, Docker or Tailscale work is allowed. Conservatively charge whole
relevant runtime roots identically on both versions when isolation permits.

Control PSS sums actual control-component process PSS only; total footprint still
includes Tailscale/runtime. Cgroup CPU includes short-lived processes. A domain
mixing control and noncontrol has unidentifiable supervision CPU and cannot pass
that gate. A service domain mixed with observer/workload is insufficient. Explicit
observer cgroup CPU and peak memory are reported separately, as are whole-host
IRQ/softirq and swap deltas; record startup/shutdown/serialization overhead in the
producer evidence. Instrumentation bytes and contracts must match on both versions.
The runner must include observer descendants, not just its own PID. This library
cannot verify a producer's unrecorded startup/tail; any such unmeasured cost must
be recorded as unavailable rather than a claim of complete overhead.

Per-process diagnostics retain identity hashes, tick/wakeup deltas, peak PSS/RSS/
USS and thread/fd counts. Every original raw value remains in input. Changed,
missing, reused or moved process identities block complete PSS; membership must
match recursive cgroup.procs at every sample. Snapshots do not prove absence of
unobserved short peaks or exec/membership ABA; original bracketed producer evidence
and cgroup totals remain essential. Totals are sampled peaks, not memory ceilings.

Statistics use sorted values: median averages the two central values for even n;
p95/p99 use **nearest rank ceil(p*n), no interpolation**; MAD is the median absolute
deviation from the median. Flag distances >3*MAD; when MAD=0, flag every value
unequal to the median. Retain all values/outliers for every gate and interval.
No exclusion/tuning is performed. Singleton percentiles equal that observation;
empty/nonfinite/negative distributions are invalid. At most 10000 observations
are summarized with confidence intervals; longer latency arrays retain exact
nearest-rank p95/p99 and counts without claiming an independent-sample CI.

The median CI is an exact distribution-free two-sided binomial order-statistic
interval: largest k with `2*P(Binomial(n,0.5)<k)<=0.05`, interval `[x[k],x[n-k+1]]`
using one-based ranks. No randomness/bootstrap seed is involved. Fewer than six
observations cannot yield a finite 95% interval and return null; six give the
sample range (96.875% coverage). For 1..20 the interval is [6,15]. CIs require
independent representative repetitions; no independence is inferred from time
samples, exits, epochs or packets. Latency sample CI is descriptive under that
assumption only; it is not gate evidence. The harness requires **at least six
matched repetition IDs per implementation per steady/load 1/5/6 case**: 72 runs
minimum, stricter than the earlier two-repetition tooling. This supports finite
median CIs but does not itself prove independence or statistical power.

Gates compare worst candidate with best baseline, never just medians or pooled
traffic. CIs describe spread; passing arithmetic is not a significance claim.
Raw rates, duration bounds, worst-run selection, medians, MAD, outlier flags and gate inequalities use integers/Fractions end to end. No float projection drives a verdict. CPU cores are `usage_usec * 1000 / duration_ns`; byte rate is `bytes * 10**9 / duration_ns`; tick cores are `ticks * 10**9 / (tick_hz * duration_ns)`. Ratios use exact cross-multiplication. The Python API returns Fractions; canonical JSON emits integral Fractions as integers and nonintegral Fractions as `{numerator,denominator}` with positive denominator. Derived summary numerators may exceed u64; the u64 limit applies to raw counters. Direct arithmetic/statistics APIs refuse float arguments. For input rate projections whose reduced numerator would exceed u64, `{bytes,duration_ns}` preserves both raw u64 values and applies the exact `10**9` unit conversion internally. Zero or tiny baselines are
insufficient (minimum supervision 1e-6 core, memory 1 byte, throughput 1 byte/s,
latency 1ns); invalid/missing metrics are insufficient, including event counts.

| Gate | At boundary | Just inside | Just outside |
| --- | --- | --- | --- |
| One-exit supervision CPU vs 100 | 50 PASS | 49 PASS | 51 FAIL |
| Total service memory vs 1000 B | 1000 PASS | 999 PASS | 1001 FAIL |
| One control PSS | 16777216 B PASS | minus 1 PASS | plus 1 FAIL |
| Five control PSS | 50331648 B PASS | minus 1 PASS | plus 1 FAIL |
| Throughput vs 1000 B/s | 950 PASS | 951 PASS | 949 FAIL |
| p95 latency vs 1000 ns | 1050 PASS | 1049 PASS | 1051 FAIL |
| Monitor misses/restarts/OOM in either implementation | 0 PASS | negative invalid | 1 FAIL |

No six-exit control PSS target is invented. CPU reduction is the brief's one-exit
gate. All other ratios/events apply to every shape. Any insufficient input makes
the enclosing scenario/suite `INSUFFICIENT_DATA`, even when separate gates show
FAIL; those failures remain visible. Otherwise any failing gate yields FAIL,
and only a complete all-shape suite with all gates passing yields PASS. Every
result keeps `release_ready:false`. Synthetic evidence, missing runtime proof,
wrong/missing/mixed host or workload, too few/unmatched/duplicate repetitions,
source/artifact/Tailscale/instrumentation/accounting changes, overlapping same-host
runs, unknown metrics, contamination, short runs or sampling defects cannot PASS.

## Workload driver specification

The production driver is **SPEC ONLY / NOT_RUN**. Root must supply a reviewed,
hashed real disposable-client workload with IPv4/DNS/IPv6/TCP/UDP, stable exact
packet size/rate/mix/concurrency, routes, MTU, endpoint/peer versions, per-exit
mapping, latency observation method, ingress/capture points, clocks and original
counter windows. Run the identical steady and controlled-load workloads on the
same isolated host and conditions, with pinned Tailscale bytes and preserved
approved identities. Drain/stop/verify and stopped-state backup/quarantine precede
switches; never run copies of an identity concurrently. Retain every failed run.
No reduction of security checks, coverage or provider cadence is authorized.

The implemented micro-driver exercises payload roundtrips and DNS-like framing
on newly allocated **127.0.0.1 ephemeral sockets only**. TCP uses a local listener
and connected client; UDP echoes a tagged payload; DNS-like UDP uses a fixed
`offline.test` A question and loopback A answer. It uses no DNS resolver, existing
service, namespaces or privileges, accepts no destination argument, has 0.1s
socket timeouts and a checked 2s deadline, and permits 1–20 iterations. It records
only protocol success counts. This is a harness self-test, with no measured
throughput/latency and no product performance evidence.

## Owned-guest measurement runner specification (NOT_RUN)

There is deliberately **no executable guest runner in this task**: a CLI that
looks operational without the producer, credentials and approved workloads would
misrepresent readiness. The following is the exact proposed runner interface;
`owned-guest-runner.py` is a future required component, not an existing command.
Every command below is **NOT_RUN / SPEC ONLY** and must currently be refused:

```bash
# Proposed interface: repeat separately for steady and load and for Python/Rust.
python3 -B -I tools/performance/owned-guest-runner.py --implementation python --exits 1 --scenario steady --repetitions 6 --warmup-seconds 30 --measured-seconds 600 --interval-ms 1000 --manifest /approved/python-one.json --workload /approved/real-client-workload.json --output-directory /approved/new-python-one
python3 -B -I tools/performance/owned-guest-runner.py --implementation rust --exits 1 --scenario steady --repetitions 6 --warmup-seconds 30 --measured-seconds 600 --interval-ms 1000 --manifest /approved/rust-one.json --workload /approved/real-client-workload.json --output-directory /approved/new-rust-one
python3 -B -I tools/performance/owned-guest-runner.py --implementation python --exits 5 --scenario steady --repetitions 6 --warmup-seconds 30 --measured-seconds 600 --interval-ms 1000 --manifest /approved/python-five.json --workload /approved/real-client-workload.json --output-directory /approved/new-python-five
python3 -B -I tools/performance/owned-guest-runner.py --implementation rust --exits 5 --scenario steady --repetitions 6 --warmup-seconds 30 --measured-seconds 600 --interval-ms 1000 --manifest /approved/rust-five.json --workload /approved/real-client-workload.json --output-directory /approved/new-rust-five
python3 -B -I tools/performance/owned-guest-runner.py --implementation python --exits 6 --scenario steady --repetitions 6 --warmup-seconds 30 --measured-seconds 600 --interval-ms 1000 --manifest /approved/python-mixed.json --workload /approved/real-client-workload.json --output-directory /approved/new-python-mixed
python3 -B -I tools/performance/owned-guest-runner.py --implementation rust --exits 6 --scenario steady --repetitions 6 --warmup-seconds 30 --measured-seconds 600 --interval-ms 1000 --manifest /approved/rust-mixed.json --workload /approved/real-client-workload.json --output-directory /approved/new-rust-mixed
# Run all six again with --scenario load and new unique output directories.
```

Prerequisites: Task 8c runtime/ARM/client review and applicable migration/release
integration; currently qualified owned Linux 6.1+ cgroup-v2 guest; stable resource
budget and fresh guest/boot/source/artifact identity; independent reviewed scope
and clock/thermal/swap instrumentation; exact pinned Tailscale/OCI/source/config
bytes; legitimate independent approved Mullvad/Tailscale identities and real
clients/peers; stopped-state backups, quarantine/client containment/captures;
a reviewed five-copy Python isolation topology and a genuine reviewed Python
mixed direct baseline/monitor adapter; immutable private storage with capacity;
full process/cgroup/kernel/runtime/observer inventory; approved workload/producer
and independent representative repetition order. No credential appears in argv,
logs or these manifests; manifests contain references/public digests only.

Runner obligations: fail preflight before traffic on any absent prerequisite;
never enroll/clone/recreate identity; freeze artifacts/config/monitoring/workload;
record raw metadata, calibration and immutable native read brackets/counters;
recursively enumerate/bracket membership, executable and start identity; capture
all original traffic and source-bound monitor events; include setup/tail/observer
costs or declare them unavailable; warm up 30s then collect >=600s between actual
sample starts without deleting the warm-up/failure record. Publish each raw run,
sidecar, captures and failures atomically to unique destinations. No averaging away
failed attempts, resampling, counter repair, security weakening or hidden reruns.

After the reviewed producer exists, analyze each actual run with:

```bash
python3 -B -I tools/performance/offline.py summarize /approved/run.json --output /approved/new-run-analysis.json
# Enumerate all 36 baseline and all 36 candidate files explicitly in this interface.
python3 -B -I tools/performance/offline.py compare --baseline /approved/python-one-steady-r1.json --candidate /approved/rust-one-steady-r1.json --output /approved/new-suite-report.json
```

The displayed one-pair comparison is intentionally incomplete and returns
INSUFFICIENT_DATA; it is an interface example, not an acceptance invocation.
Unsupported platforms/workloads, credentials, thermal counters, kernel attribution,
legacy direct baseline, producer provenance and statistical independence stay
explicitly unavailable. No actual baseline/candidate numbers, measured improvement,
threshold satisfaction, optimization, canary, runtime/ARM/client or release
acceptance are delivered by this preparation.
