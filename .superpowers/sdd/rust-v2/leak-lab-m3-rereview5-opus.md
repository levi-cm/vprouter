# Leak-lab M3 adversarial re-review, round 5 (final offline gate) — Opus

Target: `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, commit `9427346`
(`git diff b3c26c4..9427346`, fix round 4).  Reviewer: Claude Opus 5.5, no subagents.
Date: 2026-11-09.  Scratch: `/var/tmp/leaklab-m3r5-opus` (deleted at the end).

Inputs read: "Fix round 4" in `leak-lab-m3-fix-report.md`,
`docs/rust-v2/leak-lab-m3-clients.md`, `leak-lab-m3-rereview4-gpt.md`,
`leak-lab-m3-rereview4-opusA.md` and `leak-lab-m3-live-readiness-opusB.md`.
Accepted by design and not raised as findings: the login URL on stderr, and an
offline router (same ID, same `/32`) during hold samples.

Status: COMPLETE.  **PASS: no Critical, no Important.**  There are 4 Minors.
None of them can produce a false PASS.

## Required suites (once each, from `tools/leak-lab`, `TMPDIR` in scratch)

- `python3 -B -W error -m unittest test_leak_lab`: **Ran 344 tests, OK** (13.9 s)
- `python3 -B -W error -m unittest vm.test_vm`: **Ran 302 tests, OK** (30.3 s)

Both counts match the fix report.  These are offline component tests, not a
live leak qualification.

## Harness and method

- Every phase row below runs the real `run_phase.run_phase` through
  `vm.test_vm.ClientRunPhaseTests._run`: the fake router and client QGA, the
  real `clientprobe` evaluator, and the real `clientscan` over crafted pcaps.
  The real `ClientActionSampler` thread runs as well.
- Rows marked "unit" call the production function directly.  Rows marked
  "host" ran the generated shell unprivileged on this host.
- **Harness caveat (important for reading I-1 results):**
  - The sampler thread waits in *real* time (`Event.wait`), but the action
    advances the *fake* clock instantly.
  - Unsynchronised, the thread therefore usually takes **no** action sample.
  - My reproducers add a `Sync` subclass (`poll_interval=0.001`).  After every
    fake second of the action, the main thread waits until the thread has taken
    every due sample (the same technique as the repo's healthy-action test).
  - Rows are labelled `sync0` (repo style) or `sync1` (the thread really
    samples).
- Sample strings such as `paaaafhe` list the `kind` of each recorded sample in
  order: pre, action×4, fault, hold, end.
- Scripts: `common.py`, `r1_deadline.py`, `r2_action.py`, `r2c_reboot.py`,
  `r3_stop.py`, `scan_test.sh`, `r4_b1_l1.py`, `r5_conc.py`, `r5b_conc.py`,
  `r5c_stuck.py`, `r6_stuck_leak.py` and `r7_cli.py`, all in scratch.  The
  essential hooks are described with each table, so each row can be rebuilt.

## 1. Round-4 reproducers, re-run on 9427346

### GPT R4-I1: a delayed deadline stat with a late-only pair (FIXED)

- **Hook:** GPT's `deadline.py`, ported to the new schedule (`r1_deadline.py`):
  - h0 is the first main-thread `stat` after the fault, which is now S_fault.
  - The delay is injected at the main-thread `stat` whose hold offset is
    `>= at`.
  - The guest clock is tied to host time ("tied").  An "untied" variant keeps
    +1 s per pair, so the guest-gap rule cannot fire and only the host rules
    decide.
- **Schedule:** S_end now starts at hold offset 27 (deadline − 3 s), not 30.

| Case | Result |
|---|---|
| GPT literal, hook at offset 30, delay 0/1/2/3 s, late pair 0/1 | exit 0 PASS. The hook never fires (`delayed_at=null`): no size read happens at or after the deadline. The pairs up to offset 20 fill the window (13.5, 27]. Healthy control |
| tied, last ordinary pair at 13, S_end delay 0, no late pair | exit 2 INVALID `probe_hold_window_empty` |
| untied, last pair at 13, delay 1 s / 1.5 s, pair written **during** the delayed read (offset 28 / 28.5, before the deadline) | host rules **accept** it (window 14.5 / 15.0 s, `stat_end` 28 / 28.5 ≤ 30). The run is INVALID only through `probe_clock_stalled`, from the untied clock. Legitimate: that pair was written inside the hold |
| untied, last pair at 13, delay 2 s / 3 s | INVALID `probe_hold_window_late` (window 15.5 / 16.5 s) |
| untied, last pair at 13, delay 4 s (pair at 31, **after** the deadline) | INVALID `probe_hold_deadline_late` + `probe_hold_window_late`; S_end `stat_end` 44.0 vs S_fault 13.0 + 30 |
| untied, last pair at 20, delay 4 s / 6 s (pair at 31 / 33, after the deadline) | INVALID `probe_hold_deadline_late`, `probe_hold_window_late` |

- **Why it holds:** a credited line must be in the prefix that S_end's size
  read observed.  That read must end by the deadline: the runner checks
  `vm/run_phase.py:4942-4943` and the evaluator checks
  `clientprobe.py:399-409`, against S_fault's `stat_start`.
- **Result:** no line first written after the deadline was credited in any
  case.  `post_fault_*` counts are also bounded by `end_sequence`
  (`clientprobe.py:510`).

### Opus A I-1: a silent 60 s action (FIXED)

- **Hook** (`r2_action.py`):
  - `run_router_fault` first spends 60 fake seconds with the client loop
    silent (`silent_hold`) and the guest clock frozen.
  - The "clock advancing" variant keeps the guest clock running.
  - The "healthy" variant keeps the 1 Hz loop running.

| Phase | silent, frozen, sync0 | silent, frozen, sync1 | silent, clock advancing, sync1 | healthy 60 s, sync1 |
|---|---|---|---|---|
| restart-docker | INVALID `probe_hold_window_late` (`pfhe`, 0 action samples) | INVALID `probe_hold_window_empty` (`paaaafhe`) | INVALID `probe_hold_window_empty` | **PASS** (`paaaafhe`) |
| kill-wireguard | INVALID window_late | INVALID window_empty | INVALID window_empty | PASS |
| kill-container | INVALID window_late | INVALID window_empty | INVALID window_empty | PASS |
| stop-router | INVALID window_late | INVALID window_empty | INVALID window_empty | PASS |
| start-router | INVALID window_late | INVALID window_empty | INVALID window_empty | PASS |

Partial silences inside a 60 s restart-docker action (sync1, frozen):

| Silence | Result |
|---|---|
| fake seconds 20-34 (14 s, inside the 15 s design bound) | PASS (by design) |
| fake seconds 20-40 (20 s) | INVALID `probe_hold_window_empty` |
| fake seconds 0-26 (silent from S_pre on) | INVALID `probe_hold_window_empty` |

**reboot-with-router-enabled** (`r2c_reboot.py`):

- The client harness cannot reconnect a real QGA socket, so the unpatched
  phase is always a `Refusal` (`wait_for_reboot` times out).
- I replaced `wait_for_reboot` with: 60 fake seconds (sync1), then the same
  router HarnessQGA reporting a new boot ID.  `wait_boot_control_sent` was
  stubbed.  The rest of the reboot block is real: enable, stage control, read
  the boot ID, `shutdown("reboot")`, `run_silence_check` and
  `wait_router_ready`.

| Case | Result |
|---|---|
| reboot, healthy client | exit 0 PASS, `paaaafhe`, `boot_id_changed=true` |
| reboot, silent, frozen client | exit 2 INVALID `probe_hold_window_empty`, `paaaafhe` |

The repo's own `test_opus_r4_i1_silent_fault_action_is_never_covered` passes,
but only through the sync0 path (`probe_hold_window_late`, no action sample).
See Minor m-4.

### Opus A M-1: a writer that outlives a clean-looking stop (FIXED)

`r3_stop.py`, idle phase, `ghost_writer_after_stop=2`.  At stop 2, `is-active`
says `inactive` and `MainPID` is 0.  A writer then appends a current-run
`m:false` line every P s, the first one F s after the stop.

| Writer | Result |
|---|---|
| P=5, F=3, visible to the `/proc` scan (round-4 case) | exit 2 INVALID `client_traffic_stop_failed`; `traffic_stop_proven=false`, snapshot untrusted |
| P=5, F=3, hidden from the scan | exit 1 **LEAK** `client_writer_not_quiescent`, leak latched and persisted |
| hidden, P=F=11 s / 12 s | exit 1 **LEAK** (12 s quiescence) |
| hidden, P=F=13 s | exit 0 PASS. The leak line lands in the guest log after collection. Residual: it needs systemd to lie *and* a writer whose command line does not name the script *and* a gap above 12 s. The real script always names itself and writes every ≤ 12 s. Not raised |
| visible, P=F=13 s | exit 2 INVALID (the scan sees it) |

### Opus B B-1: `/32` `ExitNodeStatus` (FIXED)

Unit (`r4_b1_l1.py`): `client_peer_is_active` on a real-shaped document
(`ExitNodeStatus.TailscaleIPs = ["100.64.0.9/32", "fd7a:…/128"]`).

| Entries | pre-fault (online) | hold sample (offline, `require_online=False`) |
|---|---|---|
| `/32` + `/128` (real) | True | True |
| bare `100.64.0.9` | True | True |
| `100.64.0.9/255.255.255.255` | True | True (same `/32`, harmless) |
| only `/128`; `100.64.0.0/24`; `100.64.0.9/24`; another `/32`; `100.64.000.9/32`; `" 100.64.0.9/32"`; `::ffff:100.64.0.9/128`; a string instead of a list; `[]`; `null` | False | False |

The pre-fault check with the router offline is False, as it should be.
`client_peer_ipv4` still takes the bare `PeerStatus` address.

Phase runs:

| Case | Result |
|---|---|
| idle, real shape | exit 0 PASS, `reverified=true`, every sample `exit_node_ok=true` |
| stop-router, real shape | exit 0 PASS |
| stop-router, `Online:false` (same ID and `/32`) in every sample after S_pre | exit 0 PASS (accepted by design) |
| stop-router, one action sample sees `100.64.0.0/10` | exit 2 INVALID `client_exit_node_lost`, `exit_node_ok` = `[T,T,F,T]` |

### Opus B L-1: CorpDNS (FIXED)

| `CorpDNS` in prefs | unit result | idle phase |
|---|---|---|
| `true` | `client_accepts_dns` | exit 2 INVALID, no `traffic_start` |
| missing | `client_prefs_incomplete` | exit 2 INVALID, no traffic |
| `"false"`, `0` or `null` | `client_accepts_dns` | exit 2 INVALID, no traffic |
| `false` (control) | None | exit 0 PASS |

- client-login runs `systemd-run --unit=vprlab-client-login … tailscale up
  --reset --hostname=zz-vprclient-01-do-not-use --shields-up
  --accept-routes=false --accept-dns=false` and gives exit 0 PASS.
- A `strings` check of the host `/usr/bin/tailscale` (read-only) found no
  `json:"CorpDNS…` tag.  `false` is therefore emitted, not omitted.  The client
  runs 1.104.5, so verify this on the first live login.

### Opus A M-2 (standalone evaluator binding): FIXED

`r7_cli.py` runs the real `clientprobe.py` CLI on evidence written by the
runner.

| Evidence | CLI result |
|---|---|
| healthy 33 s run (hold extended to 39) with `--hold-seconds 39` | exit 0 PASS |
| one sample `exit_node_ok=false` | exit 2 `client_exit_node_lost` |
| the runner's own INVALID `client_exit_node_lost` record | exit 2 |
| `kind` fields removed, or the final `end` sample dropped | exit 2 `probe_hold_samples_invalid` |

Passing the requested hold (`--hold-seconds 33`) instead of the hold actually
used gives exit 2 `probe_hold_deadline_late`; passing 45 gives exit 2
`probe_hold_short`.  An operator mistake fails closed.

## 2. Concurrency: the client action sampler

Code: `ClientActionSampler` `vm/run_phase.py:3679-3719`, the action block
`:4802-4900` and the backstop `:5037-5046`.

- **Socket ownership.**
  - Between `start()` (`:4834`) and `halt()` (`:4884`), the main thread runs
    only the router action: `run_router_fault(router_client, …)`, or the
    reboot block, which uses only `router_client` and the new client returned
    by `wait_for_reboot` on the router socket.
  - `QGAClient` keeps all its state per instance (`qga.py:111-117`); there is
    no module-level shared state.
  - Instrumented over all six fault phases, reboot included (`r2c_reboot.py`):
    every client QGA exec during the action came from
    `vprlab-client-action-sampler`, and every router call from `MainThread`.
  - The refusal at `:4811` (client is router) is belt-and-braces.
- **Signals.**
  - The handler only sets a flag (`:2601-2606`).
  - Nothing on the sampler's call path calls `check_interrupt`:
    `take_client_coverage_sample` → prefix read → `read_client_status` →
    `QGAClient.execute`.  So the thread can never consume the one-shot
    `PhaseInterrupted`.
  - C4 (`r5_conc.py`): a **real** `os.kill(SIGTERM)` sent from inside an
    action sample.  Result: exit 2 INVALID `phase_exception:PhaseInterrupted`,
    sampler joined, no live `vprlab*` thread, probe collected, cleanup ok.
  - C5 (`r5b_conc.py`): a real SIGTERM delivered while the main thread is
    blocked in `join()` on an in-flight sample.  The join completes, the next
    `wait_until` check raises, and the result is exit 2 INVALID
    `PhaseInterrupted`, no live thread.
- **Exceptions.**
  - C1: `take` raises `QGAError` at action sample 1 or 3.  Result: exit 2
    INVALID `client_sampler_failed` (+ `probe_hold_window_late`).
  - C3: action sample 2 is untrusted (truncated).  Result: exit 2
    `probe_action_sample_untrusted`, `probe_log_truncated`.
  - C8: the action raises.  Result: exit 2 `phase_exception:RuntimeError`,
    sampler joined, collected.
  - Every `note()` makes the run INVALID (`combine_verdicts`, `:4105-4111`).
    So a thread that died or stopped early can never PASS, even when every
    window happens to be short.
- **Stuck thread** (C7, `r5c_stuck.py`): the action sample blocks on an event
  and the join timeout is 0.05 s.
  - Result: exit 2 INVALID `client_sampler_stuck`.
  - **Zero** client QGA commands after the block; no `client_shutdown`
    request (QEMU is killed instead); `probe_collected` not set.
  - The thread is alive when `run_phase` returns (a daemon, as intended) and
    gone once it is released.
  - In production, every `execute` has its own deadline: one sample is at most
    15 + 30 + 30 + 20 s.  So the 180 s join (`:161`) is only reachable through
    a bug.
  - See m-1: the stuck path drops already-observed LEAK flags.
- **Deadlock on the join.**
  - `halt()` sets the event, then calls `join(timeout)`.  The thread checks the
    event at least every `poll_interval`, and only blocks inside one sample.
  - `halt()` on a thread that never started (`ident is None`) returns True.
    No deadlock path was found.
- **Samples after the action.**
  - C6: action sample 5 is in flight when the action ends.  It completes after
    `halt()` (fake t = action end) and is recorded as `kind: "action"`
    (`paaaaafhe`).
  - S_fault is then scheduled 13 s after it (`:4906-4912`).
  - This credits nothing extra: the coverage windows are contiguous from S_pre
    to S_end, and every window needs its own new exit attempt.
  - Healthy: PASS.  Silent, frozen: INVALID `probe_hold_window_empty`.
  - The label is slightly loose ("action" can also mean "just after the
    action").  This is a documentation nit, not a finding.

## 3. Scheduling (S_pre, S_fault, S_end, windows, deadline margin)

- **`client_hold_schedule`, brute-forced** for 14 281 requested durations
  from 30 to 3600 s in 0.25 s steps:
  - the hold is never shortened;
  - spacing is always in [12.0, 14.0];
  - `windows × spacing == hold − 3` for every value.
  - Extended holds: 32-38 → 39, 46-50 → 51, 60-62 → 63, 74 → 75.  The rest
    are unchanged (30, 31, 39-45, 51-59, …).
- **33 → 39 in a phase:** `hold_seconds=39`, `hold_requested_seconds=33`,
  samples `pfhhe` (3 × 12 s windows), PASS.
- **No window above 15 s is ever accepted:**
  - `clientprobe.py:389-393` refuses `stat_end(later) − stat_start(earlier) >
    15.0`.
  - A late hold sample, a slow status call or a slow action sample only makes
    windows longer, so INVALID (R4-I1 rows above; C1).
  - Offsets are rounded to 1 ms, so a 15.0004 s window can round to 15.000.
    That is negligible.
- **Deadline and margin:**
  - S_end is due at `hold_base + windows × spacing = deadline − 3`.
  - Runner and evaluator both refuse `stat_end > deadline`.
  - The evaluator refuses `stat_start < deadline − 3 − 0.001` as
    `probe_hold_short`.
  - By design, the last ≤ 3 s of the hold are not window-covered.  Lines
    written there are still parsed for LEAK.
- **Action cadence:** 13 s start to start, with S_fault on the same cadence.
  In every sync1 action run, every recorded window was ≤ 13 s plus read
  latency.

## 4. Proven stop

- **Order** (`vm/run_phase.py:3395-3429`): `stop`, `reset-failed`, then
  `is-active ∈ {inactive, failed}`, `MainPID == 0`, and the `/proc` scan count
  `== 0`.  After that comes `client_probe_writer_quiescent`: two size reads
  ≥ 12 s apart (`:3461-3479`).
- **Through the phase** (`r3_stop.py`): each of these gave exit 2 INVALID
  `client_traffic_stop_failed` with the snapshot untrusted:
  - `is-active` printing `unknown` or `deactivating`;
  - a stop that lies;
  - `MainPID` 4242 or unparsable;
  - a scan count of 1, or an unparsable scan.
- **Real scan snippet, run on the host** (`scan_test.sh`, `/bin/sh` = dash).
  The snippet comes from the production `client_traffic_process_scan_script()`.

| Process set | Count |
|---|---|
| none | 0 |
| `python3 … /usr/local/sbin/vprlab-client-traffic MARKER ip ip` (real argv shape) | 1 |
| + an unrelated `exec -a /usr/bin/python3 sleep` | 1 |
| + a truncated `…/vprlab-client-traffi` | 1 |
| + `--x=/usr/local/sbin/vprlab-client-traffic.bak` | 2 (false-INVALID only) |
| scan launched by a parent `sh -c` whose command line embeds the scan text | 0 |

The scan never matched itself.  The `[c]` bracket keeps the literal path out of
its own command line.

- **Can the scan miss the writer?**
  - With the real script, no.  Under the `#!/usr/bin/env python3` shebang the
    interpreter argv still names the script path, and QGA runs as root, so
    `/proc/*/cmdline` is readable.
  - It does fail open if `tr` cannot run (m-2).

## 5. Other round-4 changes

- `wait_client_router_peer` (60 s, 1 s polls, full match rule on every read):
  it fails closed, and the repo test with 2 offline reads passes.
- `OOMScoreAdjust=-900`; the `/var/tmp/vprlab-ts` extraction; `MemAvailable`
  at boot and at the end; the runtime computed from the extended hold; the
  netplan header and OK-line text: none of these is a verdict path.
- The docs (`leak-lab-m3-clients.md`, `leak-lab-vm.md`) match the code.  No
  stale "2 s quiescence", "deadline + 2 s" or "first sample = S_fault" text
  remains.
- The client cadence (`vm/guest.py:918-1010`) gives a margin of only 0 to 1 s
  against the 12 s minimum window (m-3).

## Findings

### m-1 (Minor): a stuck sampler discards observed LEAK flags, so a real leak is reported INVALID instead of LEAK

- **Where:** `vm/run_phase.py:4884-4893`.  When `halt()` fails,
  `action_sampler.results` is never applied, and that includes `result.leak`.
  The stuck path then never collects the probe log (`:5043-5046`).
- **Reproducer** (`r6_stuck_leak.py`):
  - Action sample 1 sees a current-run `m:false` exit success
    (`result.leak=True`).  Sample 2 blocks, with a join timeout of 0.05 s.
  - Stuck: **exit 2 INVALID** `client_sampler_stuck`,
    `probe_leak_observed=false`, no probe file.
  - Control, not stuck (sample 2 raises): **exit 1 LEAK**, latched and
    persisted.
- **Impact:** never a false PASS, and practically unreachable (per-exec QGA
  deadlines are below the 180 s join).  But it would hide a seen real-IP
  success behind INVALID.
- **Fix:** on the stuck path, snapshot `list(action_sampler.results)`.  The
  list is append-only, so the snapshot is safe in CPython.  Latch
  `probe_leak_observed` if any result has `leak=True`, and note `client_real_ip`.

### m-2 (Minor): the `/proc` scan fails open when `tr` cannot run

- **Where:** `vm/run_phase.py:3376`.  `command=$(tr …) || continue` skips any
  entry whose read fails, so a failing `tr` yields `TRAFFIC-PROCS:0`.
- **Reproducer (host):** with a real-shaped decoy running, `env
  PATH=/nonexistent /bin/sh -c "<scan>"` prints `TRAFFIC-PROCS:0` (exit 0).
  The normal PATH counts the decoy.
- **Impact:** defence in depth only.  `is-active` and `MainPID` are still
  required, and the 12 s quiescence still runs.  coreutils is essential in the
  client image.
- **Fix:** count the entries actually read, and require that count to be ≥ 1:
  the scanning shell's own entry is always readable.  Alternatively, use the
  shell builtin `read -d ''`, or treat a `tr` exit status of 126/127 as a
  scan failure.

### m-3 (Minor, live robustness, false INVALID only): the 12 s windows have under 1 s margin over the worst-case exit-attempt spacing

- **Where:** `CLIENT_HOLD_SAMPLE_MIN = 12.0` (`vm/run_phase.py:150`), and the
  loop `curl -m 4`, `PROBE_BACKSTOP = 4.5`, `LOOP_SLEEP = 3.0`
  (`vm/guest.py:918-920`, `:1007-1010`).
- **Arithmetic:** with the exit node down, the gap between exit writes is about
  4 + 4 + 3 s plus two curl spawns, so about 11.2-11.5 s on a 256 MiB guest.
  With the backstop it is up to 12 s.
- **Where it bites:** extended holds (32-38 → 39, 46-50 → 51, 60-62 → 63,
  74 → 75) use exactly 12.0 s windows.  An observation interval of
  `[obs_prev, obs_next]` can then hold no new exit, giving
  `probe_hold_window_empty`.
- **Fix:** `LOOP_SLEEP = 2.0`, or raise the minimum to 13 s.  Alternatively,
  document that the operator should request 30/31/39-45 s holds.

### m-4 (Minor, test coverage): the repo's I-1 regression never lets the sampler sample the silent action

- **Where:** `vm/test_vm.py:7918-7963`.  The 60 s fake sleep runs while the
  real-time-polling sampler is idle.  Every subtest ends `pfhe` with 0 action
  samples and is INVALID only through `probe_hold_window_late`.
- **Reproducer:** the sync0 column of the I-1 table.
- **Impact:** a regression in which action samples credited a silent action
  (for example, applying a stale prefix) would not be caught by this test.
  The sync1 rows show the code is right today.
- **Fix:** synchronise as `test_long_healthy_fault_action_is_sampled_by_the_helper_thread`
  does, and assert `action_samples == 4` and `probe_hold_window_empty`.

## Method notes

- No sudo, QEMU, tcpdump, ip, nft, iptables, docker, useradd, systemctl or
  network command was run.
- I did not read `/etc/vprouter`, `/DATA/AppData/vprouter/conf`, `/root`,
  `/var/lib/vprouter`, `/var/lib/vprlab`, any `*.zip` or any key.  The only
  binary inspected was `/usr/bin/tailscale`, read-only, with `grep -a`.
- I ran the scan snippet unprivileged on the host, against my own decoy
  processes.
- No repository file was modified except this report.  Nothing was staged,
  committed or pushed.  All Python ran with `-B`.

- During this review another session committed `4b1e8c5` on top of
  `9427346`.  It changes only `.superpowers/sdd/rust-v2/progress.md` (+7
  lines), so the code reviewed here is unchanged.  The scratch directory was
  deleted, no `__pycache__` was left under `tools/leak-lab`, and
  `git status` is clean (this report is git-ignored).

## Verdict

- Every round-4 reproducer is fixed and was re-run with actual results:
  - GPT R4-I1;
  - Opus A I-1 on restart-docker, kill-wireguard, kill-container, stop-router,
    start-router and reboot-with-router-enabled;
  - Opus A M-1 and M-2;
  - Opus B B-1 and L-1.
- The sampler thread does not race the main thread on the client QGA socket.
  Its result is never PASS when it dies, gets stuck, is interrupted by SIGTERM
  or stops early.
- No window above 15 s, and no line written after the deadline, is ever
  credited.
- Four Minors remain (m-1..m-4).  None can produce a false PASS.

**PASS** (no Critical, no Important; Minors m-1, m-2, m-3, m-4)
