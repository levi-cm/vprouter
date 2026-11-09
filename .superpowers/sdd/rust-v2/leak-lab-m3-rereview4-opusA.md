# Leak-lab M3 — independent adversarial re-review, round 4 (Opus A)

Target: `rust/v2` @ `06baf40` (fix round 3 = `git diff 37bafc2..06baf40`), plus the
controller change already in that tree: hold samples call
`client_peer_is_active(..., require_online=False)` (`vm/run_phase.py:3097-3122`, `:4566-4571`).
Offline review only. No sudo, QEMU, tcpdump, ip, nft, iptables, docker, useradd or network
execution. Scratch: `/var/tmp/leaklab-m3r4-opusA` (deleted at the end). No subagents.
Report written incrementally.

## Test suites (run once each, from `tools/leak-lab`, `TMPDIR` in scratch)

- `python3 -B -W error -m unittest test_leak_lab`: **Ran 341 tests, OK** (14.7 s)
- `python3 -B -W error -m unittest vm.test_vm`: **Ran 291 tests, OK** (29.4 s). The fix report
  says 289; the two extra tests are the `require_online=False` controller change
  (`vm/test_vm.py:5852`).

## Reproducer harness

All phase reproducers run the real `run_phase.run_phase` through
`vm.test_vm.ClientRunPhaseTests._run` (fake router/client QGA, real `clientprobe`, real
`clientscan` over the crafted pcaps). Scratch scripts:

- `common.py` wraps `_run` and prints exit, result, errors, probe reasons, S_fault, S_end and
  every recorded hold sample as `(sequence, exit_sequence, stat_start, stat_end, exit_node_ok)`.
- `r3.py` / `r3b.py` port the round-3 reproducers. The old `read_client_probe_sequence` and the
  `cat` path no longer exist, so truncation uses the harness knob
  `truncate_next_read=(lines, exitcode)`, which truncates the next `head -c N` transfer. The
  backlog, burst and silence patterns are injected at the same points as in the round-3
  scripts.
- Note on the harness: a fake QGA exec takes zero fake time and the fake guest clock advances
  only with probes or `date`. So every silent-hold case also shows `probe_clock_stalled`. I
  checked that the host-window reason (`probe_hold_window_empty` or a missing S_fault) is
  present on its own in each case, so the INVALID does not depend on the guest clock.
- Stop numbering: stop 1 is the boot-time stale-unit stop and stop 2 ends the hold. My first
  run of `ghost_writer_after_stop=1` / `is_active_after_stop=(1, …)` hit the boot stop. `r3b.py`
  reruns them at stop 2.

## 1. Round-3 findings: re-verification

| ID | Reproducer (this round) | Result at 06baf40 | Status |
|---|---|---|---|
| GPT R3-C1 | stop-router 30 s, silent hold, frozen clock, two extra pairs after the gate (s=1..6). The S_fault `head -c N` returns 2 lines, **exit 1** | exit 2 INVALID; errors `probe_fault_sample_untrusted`, `probe_log_unreadable`, `probe_fault_sequence_missing`; S_fault `null`; probe reasons also include `probe_hold_samples_invalid`, `probe_hold_window_empty`, `probe_hold_short` | **fixed** |
| GPT R3-C1 | same, truncated transfer **exit 0** | exit 2 INVALID (`probe_log_truncated`, S_fault `null`) | **fixed** |
| Pi R3-I1 | idle 30 s, silent and frozen, two pairs written *inside* the action, first read after the action returns 1 line with exit 1 | exit 2 INVALID, S_fault `null` (the round-3 result was PASS with S_fault=1) | **fixed** |
| Pi R3-I1 control | same, complete boundary read | exit 2 INVALID, S_fault=6=S_end, `probe_post_fault_exit_missing`, `probe_hold_window_empty` | as expected |
| (variant) | "truncate S_fault transfer to 2 lines", healthy 1 Hz hold | exit 0 PASS, S_fault=2: the log held exactly 2 lines at that read, so the truncation removed nothing (no-op, see note below) | not a defect |
| GPT R3-C2 #1 | stop-router 30 s, 1 Hz loop writes only for hold offset ≤ 2 s, then silence (frozen and not frozen) | exit 2 INVALID, `probe_hold_window_empty`; samples `(2,1,0)`, `(6,5,10)`, `(6,5,20)`, `(6,5,30)` | **fixed** |
| GPT R3-C2 #2 | silent hold; two pairs written only inside the status call after S_end | exit 2 INVALID; S_end=2=S_fault; `probe_post_fault_exit_missing`, `probe_hold_window_empty`. The pairs after S_end are not credited | **fixed** |
| (variant) | 60 s hold, silence for offsets 20-50 s | exit 2 INVALID, `probe_hold_window_empty`; samples at 36 and 48 have the same sequence 42 | fixed |
| Opus R3-1 | `start_client_traffic` launches, appends a current-run `m:false`, then raises `QGAError` | exit 1 **LEAK**; `traffic_stop_proven=true`, leak persisted and latched | **fixed** |
| Opus R3-2 | every `head -c N` transfer exits 1 and carries `m:true` and a marker. The gate called directly returns `{'leak': False, 'mullvad': False, 'marker': False}` | phase exit 2 INVALID `client_not_routed`, `fault_epoch` null and no action command recorded: the fault never ran | **fixed** |
| Opus R3-3 | E7 (all `t=100`, S_fault=2, S_end=6, hold 30, no samples) through `evaluate_probe_log` | INVALID `probe_clock_stalled`, `probe_hold_samples_missing` | **fixed** |
| Opus R3-4 | `ExitNodeStatus.ID` = `other-exit` only at the second hold sample (away and back) | exit 2 INVALID `client_exit_node_lost`; that sample has `exit_node_ok=false` | **fixed** |
| Opus R3-4 prefs | `client_route_advertisement_problem`: `RouteAll:true` → `client_accepts_routes`; `ShieldsUp:false` → `client_shields_down`; through the phase, `RouteAll:true` is exit 2 INVALID before any traffic | **fixed** |
| Opus R3-4b / Pi R3-M2 | `python3 -I -c netplan._CLIENT_NEIGH_CHECK_CODE 10.251.0.2 vprlab1 <mac>`: the right entry on `vprlab1` plus the same dst with another MAC on `docker0` → 0; wrong MAC → 1; not permanent → 1 | **fixed** |
| Pi R3-M1 | `is-active` prints `unknown` at the end-of-hold stop, with and without a live writer | exit 2 INVALID `client_traffic_stop_failed`, snapshot untrusted. `deactivating`, empty and `active` give the same result. With the live writer the guest log holds a leak written after the untrusted read; the result is INVALID, not LEAK, but never PASS | **fixed** |
| Pi R3-M1 extras | writer keeps appending current-run leaks after stop 2 claims success | exit 1 **LEAK** (`client_writer_not_quiescent`, leak persisted) | fixed |
| | `MainPID` 4242 after the end stop | exit 2 INVALID `client_traffic_stop_failed` | fixed |
| Pi R3-M3 | docs: the design now documents the scoped `vprlab0` accepts and drops | text checked | fixed (docs) |
| Pi R3-M4 | `probe_clock_stop` is read right after the proven stop, before the 2 s quiescence wait (`vm/run_phase.py:4651`) | code read | partly fixed (false-INVALID only) |
| Pi R3-M5 | prefs without `AdvertiseRoutes` → `client_prefs_incomplete`; `null` → accepted | **fixed** |
| GPT round-3 controls | `stop_lies_at=2` → exit 2 INVALID (snapshot untrusted). Leak appended before the 1st or 2nd sample, then the final read fails → exit 1 **LEAK** (latched) | still hold |

Note on the "truncate S_fault transfer, healthy hold" row: I set the knob inside the action,
so the next transfer is S_fault's. It returned PASS with S_fault=2, which looked wrong, so I
checked it. The S_fault sample in that run is `(2, 1, 0.0)` and is trusted. In this phase the
fake log holds exactly 2 lines at the S_fault read (the fake loop does not write during the
action), so "truncate to 2 lines" removes nothing. The case is a no-op, not a bypass. The real
truncation cases above (backlog > 2 lines) are INVALID, and the repository test
`vm/test_vm.py:7362` covers a 1-line truncated boundary with healthy traffic (INVALID).

## 2. New false-PASS hunt

Scratch scripts: `r4.py` (H1-H6, sections below) and `r5.py` (the I-1 detail). All phase rows
are the real runner through the fake-QGA harness. Rows marked "unit" call the real function
with a scriptable fake guest.

### 2.1 `require_online=False` hold samples (H1): clean

stop-router 30 s with healthy traffic. From the S_fault sample on, every `tailscale status`
answer is rewritten as shown:

| Case | Result |
|---|---|
| H1a `ExitNodeStatus` same ID and IP, `Online:false` (the intended case) | exit 0 PASS |
| H1b another `ID` (`nOtherExit`), `Online:true` | exit 2 INVALID `client_exit_node_lost` |
| H1c same ID, other IP | exit 2 INVALID |
| H1d no `ExitNodeStatus` (no exit node selected) | exit 2 INVALID |
| H1e/f/g peer removed: `TailscaleIPs` `[]`, `null` or missing | exit 2 INVALID |
| H1h `ExitNodeStatus: null` | exit 2 INVALID |
| H1i status unparseable | exit 2 INVALID |
| H1k ID differs only in case | exit 2 INVALID |
| H1j `Peer` map empty but `ExitNodeStatus` kept | exit 0 PASS. Only `ExitNodeStatus` binds. Current tailscaled builds `ExitNodeStatus` from the netmap peer, so it cannot outlive the peer. Acceptable |
| unit `client_peer_is_active` | offline with `require_online=False` → True; the same document pre-fault → False; `TailscaleIPs` as a string → False; `100.64.0.9/32` → False |

A different exit node, a removed peer or no exit node can never pass a hold sample.
`require_online` is `False` only at `vm/run_phase.py:4570`; the pre-fault
`wait_client_exit_node` still uses the default `True` (`:3162`).

### 2.2 Exact prefix-read primitive (H2): clean, with one stated assumption

Unit tests of `read_client_probe_prefix` (`vm/run_phase.py:3385-3446`) with a fake guest that
changes the log before a given exec:

| Case | Result |
|---|---|
| H2a writer appends after `stat` and again after the digest | trusted, exactly the first N bytes (append-only prefix is stable) |
| H2b log shrinks before the digest and the transfer | `probe_log_truncated` |
| H2c log shrinks between the digest and the transfer | `probe_log_truncated` |
| H2e same-size rewrite between the digest and the transfer | `probe_log_hash_mismatch` |
| H2d same-size rewrite **before** the digest (not append-only) | **trusted**. These are not a prefix of what `stat` measured. This is the append-only assumption (§3) |
| H2f the size ends inside a line | trusted; the sample's `sequence`/`exit_sequence` count only complete lines (4/3) |
| H2g evaluator: the S_fault sample boundary is mid-line, the line is completed later | accepted. The completed line counts as new in the next window. It was written while the earlier sample ran, so the window rule still bounds it |
| H2h a sample claims a higher `sequence` than its prefix | `probe_hold_samples_invalid` |
| H2i a sample is larger than the evidence | `probe_hold_prefix_mismatch` |
| H2j the prefix shrinks between samples | `probe_hold_samples_invalid`, `probe_hold_window_empty` |

A guest that lies consistently in all three execs can only report a prefix that the final
evidence also starts with. Every sample hash is re-checked against the final bytes
(`clientprobe.py:322-336`). A stalled or stale guest therefore gives empty windows, not
coverage.

### 2.3 Host-sampled windows and timing (H3): clean

Every exec in the hold costs X s of fake host time (patched `read_client_probe_size` and
`read_client_status`):

| Case | Result |
|---|---|
| 1 s per exec | exit 0 PASS; samples `(4,3,0,1)`, `(24,23,10,11)`, `(44,43,20,21)`, `(64,63,30,31)` |
| 3 s per exec | exit 2 INVALID `probe_hold_deadline_late` (S_end size read ends at 33 > 30 + 2) |
| 5 s per exec | exit 2 INVALID `probe_hold_deadline_late` |
| one mid-hold status call stalls 16 s | exit 2 INVALID `probe_hold_window_late` (window from 10.0 to 26.0) |

Windows are measured from the earlier sample's size-read start to the later one's size-read
end (`clientprobe.py:344-349`). S_end's boundary is its size read, which runs before its
status call (`vm/run_phase.py:4553-4571`). The GPT R3-C2 #2 row in §1 shows that lines
written after S_end are not credited. The real QGA poll starts at 50 ms (`vm/qga.py`), so
the 2 s deadline slack is realistic.

### 2.4 Proven stop (H4): one Minor, M-1 below

`inactive`/`failed` plus `MainPID` 0 plus quiescence is enforced (§1 rows). The quiescence
window is weaker than it looks; see M-1.

### 2.5 Traffic started before launch and trusted pre-fault flags: clean

- `traffic_started = True` is set before the start call (`vm/run_phase.py:4460`). The Opus
  R3-1 row shows the leak is latched.
- `clear_client_probe_log` (`:3198-3214`) runs inside the start. A stale writer from an
  earlier phase would write a different `r` (`probe_run_mismatch`, INVALID; LEAK if
  `m:false`). `systemd-run` with the same unit name fails while a unit is active.
- The gate takes `mullvad`/`marker` only from trusted prefixes (Opus R3-2 row). The evaluator
  independently recomputes `pre_fault_mullvad`/`pre_fault_marker` from the final exact bytes
  (`clientprobe.py:487-504`).

## 3. Findings

### I-1 (Important): host-observed coverage starts after the fault action, so the fault itself is covered only by the guest clock in restart-docker, reboot-with-router-enabled and kill-wireguard

- **Where:**
  - `vm/run_phase.py:4488-4537`: `fault_epoch`, then the action and its postcondition
    (`run_router_fault`, or the reboot block), then `post_fault_epoch`.
  - `:4578-4583`: only then the S_fault sample, whose size read is `h0`.
  - `clientprobe.py:527-534`: the only check over `[fault_epoch, h0]` is the guest-clock
    `probe_gap`.
  - `probe_clock_stalled` (`:543-546`) starts at `post_fault_epoch`, so it does not cover
    the action either.
  - The design (`docs/rust-v2/leak-lab-m3-clients.md:26-28`, `:245-258`) defines the hold as
    `[h0, h0 + duration]`.
- **Why it matters:**
  - In stop-router and kill-container the fault persists into the hold, so the hold
    exercises it.
  - In the other phases the leak-relevant transition is entirely inside the action:
    - restart-docker: `systemctl restart docker`, then wait for the new docker PID and
      router ready (`:5035-5047`);
    - reboot-with-router-enabled: the whole reboot plus `wait_router_ready`;
    - kill-wireguard: `ip link del wg0`, "absent or recreated within one second", `:1186`.
  - By `h0` the router has recovered, so the host-sampled hold proves traffic through a
    healthy router.
  - For those phases, "the fault was exercised with client traffic" rests only on guest
    timestamps. That contradicts controller decision 2 ("coverage never depends on the guest
    clock"). It is the same stalled-loop and non-advancing-clock model as GPT R3-C2 and Opus
    R3-3, moved from the hold to the action.
- **Reproducer** (`r5.py`, real runner): the fault action takes 60 s of host time, the
  traffic loop writes nothing during it, and the 1 Hz loop resumes for the whole hold.

  | Phase | Guest clock does not advance during the action | Guest clock advances 60 s |
  |---|---|---|
  | restart-docker | **exit 0 PASS**, errors `[]` | exit 2 INVALID `probe_gap` |
  | kill-wireguard | **exit 0 PASS** | exit 2 INVALID `probe_gap` |
  | kill-container | **exit 0 PASS** | exit 2 INVALID `probe_gap` |
  | start-router | **exit 0 PASS** | exit 2 INVALID `probe_gap` |

  The "advances" column shows that the guest clock is the only thing that catches it. The
  harness cannot run reboot-with-router-enabled (its control is also a Refusal), but the
  code path is the same (`:4491-4530`).
- **Likelihood:** low. kvm-clock normally advances, so a stalled loop alone gives
  `probe_gap`. The realistic way to get both a silent loop and a clock that does not advance
  is a QEMU stop/cont of the client VM during the action. kvmclock is held across a pause
  (an `enospc` I/O-error pause that is then continued, or a manual `stop`). Nobody samples
  the client QGA during the action, so nothing on the host sees the pause.
- **Suggested fix:**
  - Take a trusted sample `S_pre` right after `fault_epoch`, before the action.
  - While the router action runs, sample the client from a helper thread. The client QGA
    is a separate socket that the main thread does not use during the action.
  - Apply the same rule from `S_pre` to S_fault: at most 15 s per window, a new exit attempt
    per window, and the exit-node binding with `require_online=False`.
  - Coverage then runs from `S_pre` through S_end. Keep `S_fault` as the "post-fault"
    sequence boundary.
  - If the controller prefers to accept this as a documented residual, state in the design
    that for restart-docker, reboot and kill-wireguard the transition is covered only by the
    guest-clock gap rule. That would downgrade this to Minor.

### M-1 (Minor): the 2 s writer-quiescence proof is shorter than the writer's normal inter-write gap

- **Where:** `CLIENT_STOP_QUIESCENCE_SECONDS = 2.0` (`vm/run_phase.py:148`), used at `:3338-3355`.
  - The guest loop (`vm/guest.py:997-1001`) writes after each curl. Each curl is `-m 3` with
    a 4 s subprocess timeout, followed by a 1 s sleep.
  - While an exit is down, consecutive writes are about 3-5 s apart. So a writer that
    survived a stop which `systemctl` reported as successful is missed most of the time.
- **Reproducer** (`r4.py quiesce`, real runner): `ghost_writer_after_stop=2`. `is-active`
  says `inactive` and `MainPID` is 0, but a writer appends a current-run `m:false` line every
  5 s, first 3 s after the stop.
  - Result: **exit 0 PASS**, `probe_log_read=exact`, `guest_leak=true`,
    `persisted_leak=false`, `latch=false`.
  - The existing 1 Hz ghost test (`vm/test_vm.py:7546`) is caught only because it writes
    faster than 2 s.
- **Impact:** this needs systemd to report a stopped unit with an empty `MainPID` while the
  writer process lives (escaped cgroup). That is not a realistic path, so it is defence in
  depth. A real leak packet would still have to pass the capture scanners. But a false PASS
  with a leak line in the guest log is exactly what the proof exists to prevent.
- **Suggested fix:** any one of these:
  - make the quiescence window ≥ 10 s (above `4 + 4 + 1`);
  - require an empty cgroup: `systemctl show -p ControlGroup` and an empty `cgroup.procs`,
    or no `vprlab-client-traffic` process;
  - cheapest: re-read the size once more just before the client VM is powered off (after the
    after-controls, several seconds later). Untrust the snapshot and parse the new tail for a
    LEAK if it grew.

### M-2 (Minor): the standalone evaluator ignores `exit_node_ok`, so a re-evaluation of evidence the runner judged INVALID says PASS

- **Where:**
  - `clientprobe._check_hold_samples` (`clientprobe.py:296-358`) and `_valid_sample`
    (`:276-293`) never read `exit_node_ok`.
  - Only the runner turns `exit_node_ok=false` into `client_exit_node_lost`
    (`vm/run_phase.py:4572-4574`).
- **Reproducer** (`r4.py cli`):
  - The exit node switches to another ID at the second hold sample. The runner gives exit 2
    INVALID `client_exit_node_lost`, with samples `exit_node_ok = [True, False, True, True]`.
  - The documented operator command, `clientprobe.py --probe-log … --hold-samples <that
    list>`, gives **exit 0, `"verdict":"PASS"`**.
- **Suggested fix:** in `_check_hold_samples`, require `sample.get("exit_node_ok") is True`
  for every sample (reason `client_exit_node_lost`). The evidence then carries the binding
  on its own.

### M-3 (Minor, evidence): a PASS record never says `traffic_stop_proven: true`

- **Where:** the success path proves the stop and quiescence (`vm/run_phase.py:4640-4659`)
  but never sets `record["client"]["traffic_stop_proven"] = True`. `finally` skips it because
  `probe_collected` is already set (`:4710`).
- **Reproducer:** every PASS row above (for example `control_healthy_stop_router_30s`, H1a,
  H3 1 s) has `stop_proven: null`. The design lists the field as part of `phase.json`
  (`docs/rust-v2/leak-lab-m3-clients.md:369`).
- **Suggested fix:** set it to `True` right after `client_probe_writer_quiescent` succeeds at
  `:4652`. A reader of a PASS record should not have to infer the stop proof from the absence
  of errors.

### M-4 (Minor, precision): what the host-only rule actually bounds

- **Exit-attempt spacing.** "A new exit attempt in every window of at most 15 s" bounds
  consecutive host-observed exit attempts only to about two windows.
  - Example: an attempt just after sample i-1 and the next just before sample i+1 gives up
    to about 28 s with 14 s windows.
  - The 15 s spacing is then enforced only by the guest-clock `probe_gap`.
  - To make the host bound 15 s, use windows ≤ 7.5 s, or require each pair of adjacent
    windows to be within 15 s of a new attempt. Otherwise, document the 2-window bound.
- **Exit-node sampling.** `ExitNodeStatus` is checked once per sample (10-14 s apart), so a
  switch away and back between samples is still invisible. Nothing in the lab triggers one;
  document it.

## 4. Residual guest trust (question 3)

What a buggy or stalled guest can no longer do (each reproduced above):

- turn a short, failed or altered transfer into coverage (untrusted, INVALID);
- certify a hold with a stalled or bursty loop (`probe_hold_window_empty`);
- certify lines written after the deadline;
- move S_fault backwards;
- give positive controls from a failed read;
- claim a stop with `unknown`, `deactivating`, an empty answer or a non-zero `MainPID`;
- keep a 1 Hz writer alive after the stop unnoticed.

The remaining assumptions, all about our own non-adversarial client VM:

1. **The probe log is the only evidence that the client attempted traffic.** The host
   binds every line by hash and host time, but it never checks that client packets actually
   left the client tap in each window. `clientscan.py` deliberately does not classify client
   WAN traffic (`clientscan.py:4-17`). A traffic script that writes lines without really
   sending would be believed. The script is ours and fixed (`vm/guest.py:896-1007`).
   Optional hardening: require at least one client-tap frame from `10.251.0.x` in each host
   window, using pcap host timestamps.
2. **`m:true` is curl's reading of am.i.mullvad.net inside the guest.** A LEAK can only be
   missed if the guest misreports. The cleartext-marker check is host-side and independent.
3. **Append-only log.** The prefix primitive assumes the first N bytes never change
   (H2d). Only `clear_client_probe_log` (before launch) and the script's own `O_TRUNC` at
   start truncate it. A later rewrite of earlier bytes is caught only through the hash chain
   against the final evidence.
4. **`stat`, `head` and `sha256sum` are honest.** Consistency is checked, but truth cannot
   be. A stale but consistent answer gives empty windows (INVALID); a fabricated one would
   also have to be in the final log.
5. **systemd's `is-active` and `MainPID` are honest.** The 2 s quiescence check is only a
   weak backstop (M-1).
6. **tailscaled's `ExitNodeStatus` is honest** and is sampled, not continuous (M-4).
7. **The guest clock** is still the only coverage over the fault action (I-1) and the only
   enforcement of the 15 s spacing inside the 2-window bound (M-4).

Assessment: 1-6 are acceptable for a VM we build and run, as long as a stalled guest cannot
give a PASS. That holds for the hold. It does **not** yet hold for the action interval: a
client VM paused and resumed (clock held) during a restart-docker/reboot/kill-wireguard action
PASSes (I-1). Fixing I-1 brings the action under the same host-sampled rule. M-1 should be
tightened so assumption 5 has a real backstop.

## Method notes

- No sudo, QEMU, tcpdump, ip, nft, iptables, docker, useradd or network command. No
  secret, key, `/etc/vprouter`, `/var/lib/vprouter`, `/var/lib/vprlab`, `/root` or `*.zip`
  read. I ran the embedded neighbour program only with `python3 -I` on crafted JSON.
- No repository file modified except this report; no git stage, commit or push.
- Reproducers: `common.py`, `r3.py`, `r3b.py`, `r4.py`, `r5.py` in
  `/var/tmp/leaklab-m3r4-opusA`, described above. The scratch directory is deleted at the end.

## Verdict

- All round-3 findings are fixed and reproduced as fixed: GPT R3-C1/C2, Opus R3-1..R3-4,
  Pi R3-I1, R3-M1/M2/M5, and R3-M3 in the docs. R3-M4 is partly addressed, and is
  false-INVALID only.
- The prefix primitive, host windows, deadline handling, proven stop and
  `require_online=False` hold samples showed no new false PASS.
- One Important remains. Host-observed coverage does not include the fault action, so in
  restart-docker, kill-wireguard and reboot the fault is "exercised with client traffic"
  only on the guest clock's word.

**FAIL** (1 Important: I-1; Minors M-1..M-4)
