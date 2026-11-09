# M3 adversarial re-review, round 3 (Opus)

Target: rust/v2 @ 37bafc2 (fix round 2 = `git diff 605cce8..37bafc2`).
Offline review only. No sudo/QEMU/tcpdump/ip/nft/iptables/docker/network execution.
Scratch: /var/tmp/leaklab-m3r3-opus (deleted at the end).
Report written incrementally.


## Reproducers (scratch, run by the reviewer)

- `/var/tmp/leaklab-m3r3-opus/repro_eval.py`: calls the real `clientprobe.evaluate_probe_log`
  on crafted logs (E1-E9).
- `/var/tmp/leaklab-m3r3-opus/repro_phase.py`: subclasses the repository harness
  `vm.test_vm.ClientRunPhaseTests` and runs the real `run_phase.run_phase` with the fake
  router/client QGA, the real `clientprobe` and the real `clientscan` (P0-P20). It injects
  faults with `mock.patch` on `run_phase` (here `run_phase = test_vm.run_phase`, so the
  patches act on the module the harness uses).
- `/var/tmp/leaklab-m3r3-opus/repro_plan.py`: renders `netplan.render_plan` and runs the
  generated shell only against a PATH stub harness (section 3).

## 1. Earlier findings: verification

Baseline: P0 `idle` 30 s, exit 0, PASS, read `exact`, `S_fault=2`, `S_end=62`. P19
`stop-router` 30 s, also PASS. So the harness is not broken by the fixes.

### GPT C1: unproven traffic stop (fixed)

- Code:
  - `stop_client_traffic` no longer masks errors. A separate `systemctl is-active` read must
    return `inactive`, `failed` or `unknown` (`vm/run_phase.py:3237-3263`).
  - If the end-of-hold stop fails, the phase raises with `traffic_stop_proven=False`
    (`:4480-4488`).
  - In `finally`, a proven `False` stays `False` (`:4551-4558`), so the snapshot is read
    with `trusted=False` (`:4562-4573`). That gives `probe_snapshot_untrusted` and never
    `exact` (`collect_client_probe`, `:3412-3436`).
- Reproducers (`repro_phase.py`):

| Case | Result |
|---|---|
| P1: GPT C1 rerun. First end-of-hold stop exits 1, leak is appended on the cleanup stop | exit 1 **LEAK**, `client_traffic_stop_failed`, `probe_snapshot_untrusted`, leak latched |
| P2: same, but the cleanup stop appends a benign `m:true` line | exit 2 INVALID, `probe_log_read_quality` |
| P3: stop exits 0 while the unit stays active | exit 2 INVALID |
| P4a / P4b: `is-active` says `deactivating` / empty at the end of the hold | exit 2 INVALID, snapshot untrusted |
| P4c: `deactivating`, plus a leak appended by the cleanup stop | exit 1 LEAK |
| P5a: the end-of-hold stop raises `QGAError`; the cleanup stop is proven | exit 2 INVALID (`phase_exception:QGAError`) |
| P5b: same, with a leak appended by the cleanup stop | exit 1 LEAK (the snapshot was taken after the proven stop) |
| P6: the stale-unit stop at boot is not proven (`is-active` = `active`) | exit 2 INVALID, refused before any traffic starts |

### GPT C2 and Pi I-1: same-second and frozen-clock post-fault coverage (fixed)

- Code:
  - `_is_post_fault_attempt` needs `t >= post_fault_epoch`, a matching `r`, and
    `S_fault < s <= S_end` (`clientprobe.py:274-285`).
  - The hold must contain at least `max(1, hold // 15)` exit attempts (`:381-384`).
  - The clocks must be ordered `clock_start <= fault_epoch <= post_fault_epoch <= clock_stop`
    (`:364-371`).
  - `S_fault` is read after the action and its postcondition (`vm/run_phase.py:4426-4435`).
    `S_end` is read at the end of the hold (`:4462-4471`).
- Evaluator reproducers (`repro_eval.py`):
  - E1, the GPT fixture: s=1/2 at t=100, `fault=post=100`, window 99..105, `S_fault=2`. Result
    INVALID (`probe_post_fault_exit_missing`, `probe_post_fault_marker_missing`,
    `probe_hold_coverage`).
  - E1b: the same fixture with `hold_seconds=5` is still INVALID.
  - E2, GPT's unordered fixture (`fault=103`, `post=100`): INVALID `probe_clock_order`.
  - E4 (`S_end < S_fault`) and E8 (`fault_sequence=None`) are INVALID.
- Phase reproducers:
  - P7 (frozen clock, silent active unit) and P8 (silent active unit): exit 2 INVALID,
    `S_fault == S_end == 2`.
  - P10a / P10b (the `S_fault` / `S_end` read fails): exit 2 INVALID
    (`probe_fault_sequence_missing` / `probe_end_sequence_missing`).

### GPT I1 and Opus N-1: a seen LEAK downgraded by a later read failure (fixed)

- Code:
  - The latched `probe_leak_observed` is set at the pre-fault wait (`vm/run_phase.py:4358`),
    at both sequence reads (`:4432`, `:4468`), on every persisted read
    (`collect_client_probe`, `:3426-3429`), and in the final evaluation (`:4724-4739`).
  - `combine_verdicts(..., leak_observed=True)` returns LEAK before any quality check
    (`:3724`).
  - A non-zero `cat` and a failed digest both keep their bounded bytes (`:3301-3304`,
    `:3343-3349`).
- Reproducers:
  - P11 (pre-fault leak, then the exact read returns `(None, unreadable)`): exit 1 **LEAK**.
    The probe sub-verdict is INVALID, but the combined result is LEAK.
  - P12 (`cat` exits 1 and returns a log with a leak): exit 1 LEAK.
  - P13 (`sha256sum` fails, the log has a leak): exit 1 LEAK.

### Opus N-2 to N-5 (fixed)

- N-2, end-of-hold exit-node re-check (`vm/run_phase.py:4451-4459`):
  - P16: `ExitNodeStatus.ID` switches to `some-other-exit` during the hold. Exit 2 INVALID,
    `client_exit_node_lost`.
  - P17 (my variant): the exit node goes `Online:false` at the end of the hold. Exit 2
    INVALID.
- N-3, minimum hold (`vm/run_phase.py:138`, `:3759-3762`): P18 `--duration 0` and `29` are
  both refused ("a --client phase needs --duration >= 30 seconds").
- N-4, unfiltered neighbour helpers: fixed; see section 3 (`netplan.py:1069-1076`).
- N-5, gap budget: `MAX_PROBE_GAP_SECONDS = 15` (`clientprobe.py:57`). This covers the worst
  case of about 9 s per loop plus QGA slack.

### Pi M-A, M-B, M-L, M-M (spot-checked)

- E9: `evaluate_probe_log(b"", run_id=None)` raises `ProbeError invalid_run_id`.
- The read-quality downgrade (`vm/run_phase.py:4740-4747`) shows in P2-P4: the probe object
  says INVALID `probe_log_read_quality`, never PASS.
- The route-advertisement refusal is covered by the repository test `test_vm.py:7013`, which
  is in the suite run below.

## 2. New false-PASS hunt in the fix diff

I found no new false-PASS path. Every trusted ("exact") snapshot on the success path is taken
after a proven stop. Every recognised non-Mullvad success is latched. Post-fault coverage is
bound to sequence numbers the runner read itself. The evaluator rejects
unordered, missing or contradictory boundaries (E1-E9, P1-P20 above). Other checks that came
out clean:

- E5 and P15: a non-Mullvad success with a foreign `r` is still LEAK.
- E6: `ok:true` with `m:null` is LEAK.
- P14: a leak written after `S_end` but before the stop is LEAK.
- E7b: with a working guest clock, a loop that stalls mid-hold is INVALID (`probe_gap`).
- The guest log cap (`MAX_LOG = 1 MiB`, `vm/guest.py:911-922`) equals
  `CLIENT_PROBE_READ_LIMIT` (`vm/run_phase.py:149`). The new `probe_log_oversized` early
  return cannot drop a log the script wrote.
- Router-only code: an AST comparison with `605cce8` shows `_run_phase_locked`,
  `scan_evidence`, `start_capture`, `stop_capture`, `run_phase`, `run_router_fault`,
  `wait_router_ready`, `emit_control`, `cleanup_guest_units` and `poweroff_vm` unchanged.
  `check_admission`, `login_phase_wait` and `combine_verdicts` changed only through
  keywords whose defaults keep the old behaviour.

The new Minor findings follow.

### R3-1 (Minor, LEAK shown as INVALID): a `start_client_traffic` exception after the unit started gives a trusted "exact" snapshot of a live writer

- Files:
  - `vm/run_phase.py:4343-4350`: `traffic_started = True` is set only after
    `start_client_traffic` returns.
  - `finally` (`:4542-4573`): with `traffic_started` False and `traffic_stop_proven` None,
    nothing is stopped, `trusted=True`, and the exact read runs against a unit that may be
    running.
- Reproducer (`repro_phase2.py`): wrap `start_client_traffic` so it runs the real start
  (the unit runs) and then raises `QGAError`, as if the QGA reply were lost after
  `systemd-run`.
  - S1: exit 2 INVALID, `probe_log_read=exact`, `trusted=True`, `traffic_stop_proven=None`.
  - S2: the same, plus a current-run `m:false` line written before the later stop in
    `cleanup_client_units`. Result: exit 2 **INVALID**, `leak_latched=False`. The leak line is
    not in the persisted log.
- Impact:
  - Never a false PASS: `phase_exception` forces INVALID.
  - It is the GPT C1 pattern (a snapshot certified before the writer is proven stopped) on an
    error path, so the rule "LEAK is never masked" does not fully hold. A pre-fault leak in
    that window would be reported as INVALID.
- Fix: set `traffic_started = True` (or a separate "start attempted" flag) before calling
  `start_client_traffic`. The `finally` stop then always runs and proves the unit stopped
  before any trusted read.

### R3-2 (Minor): the pre-fault gate accepts positive controls from failed reads at timeout

- Files: `vm/run_phase.py:3519-3529` (`wait_client_probe_control`).
  - `flags` is now computed from any returned bytes, including a `cat` that exited non-zero.
  - Inside the loop the function returns early only for a leak, or for positive controls
    from a clean read.
  - At the deadline it returns the last `flags` anyway. The caller (`:4352-4366`) then
    accepts `mullvad`/`marker` and runs the fault.
- Reproducer (`repro_gate.py`): a fake client whose every `cat` exits 1 with an `m:true`
  line and a marker line. Result: `{'leak': False, 'mullvad': True, 'marker': True}` after
  the full timeout.
- Impact:
  - Not a false PASS. `evaluate_probe_log` independently requires `pre_fault_mullvad` and
    `pre_fault_marker` from the exact final log, and the read-quality downgrade blocks a
    non-exact PASS.
  - It is a regression of the gate's intent. Before this round it only used clean reads.
    With it, the runner can run a destructive router fault without a clean pre-fault proof,
    and only waits the whole 90 s first.
- Fix: keep the leak flag from any read, but take `mullvad`/`marker` only from a read with
  `problem is None` (keep a separate `clean_flags`).

### R3-3 (Minor, residual of Pi I-1): hold coverage counts attempts but only the guest clock spreads them over the hold

- Files: `clientprobe.py:381-384`. It requires `max(1, hold // 15)` exit attempts in
  `(S_fault, S_end]`. How those attempts are spread over time is enforced only by the
  guest-clock gap check (`:351-361`).
- Reproducer `repro_eval.py` E7: frozen guest clock (every `t=100`), a pre-fault pair, then
  exactly 2 post-fault loops and nothing more, `hold=30`, `S_fault=2`, `S_end=6`. Result:
  **PASS**. With a working clock the same stall gives INVALID `probe_gap` (E7b).
- Impact: this needs a guest wall clock that does not advance while the guest still runs
  curl. I know of no real fault that does that (a paused VM also stops QGA). So it is defence
  in depth, not a reproduced live path. Pi I-1's silent-unit case itself is fixed (P7).
- Fix (cheap): have the runner check `probe_clock_stop - post_fault_epoch >= hold_seconds - 5`
  and make it a fixed INVALID reason, `probe_clock_stalled`. The guest clock must then advance
  at least as far as the host-monotonic hold it brackets. Optionally also require
  `S_end - S_fault >= 2 * hold // 15`.

### R3-4 (Minor, notes)

- **Login unit.**
  - `client-login` now starts `tailscale up --reset ...` as the transient unit
    `vprlab-client-login` (`vm/run_phase.py:4113-4133`).
  - `login_phase_wait` stops early once `BackendState` is `Running` (`:1773-1776`). The
    `finally` path then stops the login unit (`cleanup_client_units`, `:3533-3542`).
  - The CLI sends prefs on `Start` before the interactive login, so stopping the unit after
    `Running` should not lose `--shields-up` or `--accept-routes=false`. Only
    `AdvertiseRoutes` is re-verified (`:2917-2945`), not `RouteAll` or `ShieldsUp`. Reading
    `RouteAll == false` from the same `debug prefs` document would be cheap.
  - `read_client_status` in the polling loop is outside the `try`, so a QGA error there makes
    the login phase fail with an exception (INVALID). That is acceptable.
  - P20: the login fake blocks until it is authenticated. Exit 0, URL written, polled to
    `Running`.
- **The exit-node re-check is a single end-of-hold sample** (`:4451-4459`). A switch away and
  back during the hold is not seen. If the tailnet contains another exit node with Mullvad
  egress, probes would still say `m:true`. Nothing in the lab triggers a switch. Optionally
  sample `ExitNodeStatus` every few seconds inside the hold loop (`:4440-4446`).
- **`S_fault` taken from a failed tolerant read.** When `cat` exits non-zero but returns
  bytes, `read_client_probe_sequence` uses them and nothing is noted (`:3375-3385`). A lower
  `S_fault` makes the rule more lenient, but the `t >= post_fault_epoch` check still binds
  each attempt, so this is harmless. Consider noting the read problem anyway.

## 3. Host safety of the changed host plan

Rendered `netplan.render_plan('eth0')` (851 lines) and `render_plan('eth0', clients=(1,))`
(884 lines) into scratch. `sh -n` passes on both. I ran them only through the repository stub
harness (`test_leak_lab.NetplanTests._run_lab` with `_prepare_stub_lab`/`_STUB_SOURCE`).

### Rules and the objects they touch

- Every mutating command in both plans (listed with grep) targets only lab objects:
  - links `vprlab0`, `vprlab1`, `vprlab-tap0`, `vprlab-ctap1`;
  - neighbours `10.250.0.2` on `vprlab0` and `10.251.0.2` on `vprlab1`;
  - `sysctl` for `disable_ipv6` on those four links only;
  - table `inet vprlab` (create, and delete only after `table_owned`);
  - `DOCKER-USER` rules matching `-i/-o vprlab{0,1}` with the `$OWNER` comment (`-I`,
    `-C` then `-D`).
- There is no `nft flush ruleset`, no change to another table or chain, no global sysctl
  (`ip_forward` is untouched), no `docker`, `systemctl`, `tc` or `ip6tables`, and nothing that
  names `tailscale0`, `docker0`, `br-*` or a production container.
- New forward rules (plan line numbers):
  - `vprlab0`, lines 808-814:
    - `iif vprlab0 oif eth0 ip saddr 10.250.0.0/24 accept`
    - `iif eth0 oif vprlab0 ip daddr 10.250.0.0/24 ct state established,related accept`
    - `iif vprlab0 oif eth0 drop`
    - `iif eth0 oif vprlab0 drop`
  - `vprlab1`, lines 828-831: the same four rules for 10.251.0.0/24.
  - Each new drop matches only when the input or output interface is a lab bridge. In
    nftables a drop in our own base chain affects only packets that match it, and our
    accept never overrides Docker's `iptables-nft` FORWARD chain. So Docker, the production
    `max-vprouter` containers and the host's own `tailscaled` (INPUT/OUTPUT on `tailscale0`,
    or forwarding between `tailscale0` and `eth0`) cannot match any new rule.
- Ordering: the drops come after the IPv6 drops and the scoped accepts. The base chain's
  `policy accept` no longer applies to anything crossing a lab bridge and `eth0` (this
  closes Opus N-6 and Pi M-K).

### Neighbour parsing

- `client_neigh_ok` and `client_neigh_state` now read the unfiltered `ip -j neigh show`
  (`netplan.py:1069-1076`), the same as the router's `neigh_state`.
- Q10 runs the embedded programs (`netplan._INVENTORY_NEIGH_CODE`, `_NEIGH_CHECK_CODE`) with
  `python3 -I` on iproute2-shaped JSON: an unfiltered list with `dev`, an IPv6 entry with
  `"router":null`, and a `FAILED` entry with no `lladdr`.

| Input | Exit |
|---|---|
| Inventory `10.251.0.2`/`vprlab1`, present | 0 |
| Absent | 1 |
| Router `10.250.0.2`/`vprlab0` | 0 |
| Empty array | 1 |
| Empty stdin (`ip` failed) | 2, fail closed |
| The real debdev **filtered** shape (no `dev`), given to the inventory | 1 |
| Check: matching MAC, permanent | 0 |
| Check: wrong MAC | 1 |

- That filtered-shape row is the old N-4 failure. The helpers no longer use the filtered
  form, so it cannot occur.
- **R3-4b (Minor, fail-closed):** `client_neigh_ok` filters on `dst` only. Its `$2` (the
  device) is not passed (`netplan.py:1070-1071`, `_NEIGH_CHECK_CODE` at `:379`). So the same
  `dst` on a second device makes the check exit 1, and teardown is refused (Q10 "same dst on
  two devs" gives 1). The preflight refuses any 10.251.0.0/24 overlap, so this is unlikely
  and fails closed. Fix: pass the device and also match `dev` when the key is present.

### Teardown and refusal reproducers (`repro_plan.py`)

| Case | Result |
|---|---|
| Q1: `--client 1` setup / teardown | rc 0 / rc 0, everything removed, owner removed |
| Q2: no-client teardown of a client setup (owner lists the clients) | rc 0, everything removed |
| Q3: router-only setup / teardown (the live-host plan) | rc 0 / rc 0 |
| Q4: owner lists client 1, `vprlab1` already gone (old N-4 P4) | **rc 0**, fixed |
| Q5: old owner without `clients`, plus client residue | rc 1, "vprlab1 exists but no owner client inventory names it", "aborted without changes", state byte-identical, owner kept |
| Q6: only a stray `vprlab-ctap9` | rc 1, refused before any change |
| Q7 / Q8: `--client 1` setup fails at `link_add` / `tuntap_add` (old N-4 P7) | rc 1, the EXIT-trap teardown removes everything, owner removed (fixed) |
| Q9: no-client teardown, link inventory fails | rc 1, "retaining protection", nothing removed |

- The residue list (`netplan.py:1188`) covers `vprlab1` and `vprlab-ctap1..9`. That is exactly
  the valid range (`guest.validate_client_index`, 1..9).
- When the refusal fires on the live host it keeps `inet vprlab` and the `vprlab0`
  `DOCKER-USER` accepts. Those only match lab interfaces, so they do not affect production.
  Removing them needs a manual step, which is expected for fail-closed behaviour.

## 4. Live router VM traffic under the new forward rules

- **Outbound.** WireGuard/UDP, Tailscale and DNS from the VM (saddr 10.250.0.2, `iif
  vprlab0`, `oif eth0`) match `ip saddr 10.250.0.0/24 accept` whatever the ct state, and are
  masqueraded in `postrouting`. This is the same set the existing `DOCKER-USER -s
  10.250.0.0/24` accept already allowed.
- **Replies.** The conntrack reverse NAT rewrites the destination to 10.250.0.2. The packet
  is then forwarded `eth0 -> vprlab0` with ct state `established` and accepted. The
  `DOCKER-USER` return accept was already `--ctstate ESTABLISHED,RELATED`, so Docker's DROP
  policy imposed the same restriction before this round. The new nft rule adds no
  restriction for legitimate traffic.
- **The earlier live ICMP port-unreachable from the VM to the endpoint.**
  - The endpoint's UDP reaches the VM through the established mapping. The VM's ICMP error
    is `iif vprlab0`, `oif eth0`, saddr 10.250.0.2, so it matches the scoped outbound accept.
    Conntrack classifies it as `related` to the UDP entry and reverse-NATs the embedded
    header.
  - It is therefore still forwarded, exactly as before. Inbound ICMP errors toward the VM
    (for example frag-needed) are `related` and accepted.
- **What changes.** Only these are now dropped in `inet vprlab`:
  - unsolicited `new` or `invalid` packets from the WAN toward 10.250.0.0/24 or
    10.251.0.0/24. They were already dropped by Docker's FORWARD policy, and with masquerade
    they normally reach the host's INPUT, not FORWARD.
  - VM packets with a source outside the lab subnet.
- **If this were wrong, a live idle phase would show it as INVALID.**
  - `wait_router_ready` / `ROUTER_HANDSHAKE_TIMEOUT` would expire with no WireGuard handshake
    or Tailscale `Running`.
  - The router tap would show outbound handshake initiations and no responses.
  - It could never be a PASS, because the router must be ready before any verdict.
- Not verified live: the review rules forbid running the plan or QEMU.

## Test suites (run once each, from tools/leak-lab, TMPDIR in scratch)

- `python3 -B -W error -m unittest test_leak_lab`: **Ran 329 tests, OK** (14.3 s)
- `python3 -B -W error -m unittest vm.test_vm`: **Ran 266 tests, OK** (18.0 s)

## Method notes

- I ran no sudo, QEMU, tcpdump, ip, nft, iptables, docker, useradd or network command, and
  read no secret, key or configuration path. The generated shell ran only under the
  repository stub harness.
- I modified no repository file except this report. There was no git stage, commit or push.
- Scratch `/var/tmp/leaklab-m3r3-opus` was deleted at the end. The reproducer scripts are
  described above and can be rebuilt from the descriptions.

## Verdict

**PASS.** There is no Critical or Important finding.

- GPT C1, C2 and I1, Pi I-1, and my N-1 to N-5 are fixed. I re-verified each with the
  reproducers above, including variants not in the repository tests: P2, P4a-c, P5a-b, P6,
  P17 and E1b.
- The host plan touches only lab-named objects and its own table, and it keeps the router
  VM's existing traffic path.
- New Minors: R3-1 to R3-4. I recommend fixing R3-1 (set `traffic_started` before the start
  call) and R3-2 (positive controls only from clean reads) before live M3 runs. Both are
  one-line changes.
