# Leak-lab M3 — independent adversarial re-review (Pi)

Commit reviewed: `605cce870ab1b5bb7b2332750c2968c6bf2e2199` (`rust/v2`), the
fix round after `b849e3c`.  I reviewed an extracted `git archive 605cce8`
tree under `/var/tmp/leaklab-m3r-pi`; the working tree is clean and the branch
still points at the same commit.  Binding design: `docs/rust-v2/leak-lab-m3-clients.md`.
Earlier reports: `leak-lab-m3-review-pi.md`, `-gpt.md`, `-opus.md`; fix report:
`leak-lab-m3-fix-report.md`; controller decisions: last entry of `progress.md`.

Method: source read of every changed file and every earlier finding, then
independent reproducers using the committed `test_leak_lab` pcap/netplan stub
helpers, the fake-QGA `ClientRunPhaseTests`/`RunPhaseTests` harness, crafted
probe logs, and the real `clientscan` over crafted pcaps.  No file outside this
report and `/var/tmp/leaklab-m3r-pi` was modified; scratch was deleted at the
end.  No sudo, QEMU, tcpdump, `ip`, `nft`, `iptables`, Docker, useradd or
network execution was run; no restricted path was read.  All commands finished
in this turn.

## Test runs (as required)

From the extracted `605cce8` tree, `tools/leak-lab`:

- `python3 -B -W error -m unittest test_leak_lab` → **Ran 320 tests, OK** (12.9 s)
- `python3 -B -W error -m unittest vm.test_vm` → **Ran 252 tests, OK** (6.2 s)

Also: `git diff --check b849e3c..605cce8` clean; `py_compile` of the changed
Python files clean; `sh -n` on rendered no-client, `--client 1` and
`--client 1,2` plans rc 0.  The counts match the fix report.

## Bottom line

The fix round genuinely closes all four GPT Criticals, the four actionable GPT
Importants (GPT I5 is the accepted login-URL risk), Opus I-2, the normal-form
Opus I-1/C1 path, my C1/I1-I3, and my earlier Minors in the normal paths; the
stale-log, truncated-read, forged-control, exit-peer,
no-client-teardown and two-guest-admission reproducers that failed at
`b849e3c` now fail closed.  One **Important residual false-PASS boundary**
remains in the new post-fault-attempt check: a client phase whose hold is at
most 10 s can PASS with **zero probes during the hold**, and a frozen guest
clock makes the same hole independent of the hold length.  I reproduced it
both at the parser and at the fake-QGA phase level.  There are also several
Minors (test gaps, an unreachable old-owner teardown edge, a strictness gap,
and two unproven real-client functional risks).  Because the milestone treats
a false PASS as the critical failure, the verdict is **FAIL** until the
post-fault window is made strict.

---

## 1. Earlier Critical/Important findings — re-verified

All rows below were rerun against `605cce8`.  "Fixed" means the old passing
reproducer now returns INVALID/LEAK (or the old evidence loss is gone), not
merely that a new test exists.

| Earlier finding | Evidence at `605cce8` | Rerun result |
|---|---|---|
| **GPT C3 / Opus I-1 / Pi C1** — stale log or a traffic unit that never ran/exited certifies PASS | `run_phase.py:3125` `clear_client_probe_log`, `:3161` start, `:4227` `client_traffic_unit_active`; `clientprobe.py:212` run/sequence/window/gap/post checks | **Fixed for normal holds.** Fake harness: a unit that writes one pair and exits → `INVALID`, errors `client_traffic_unit_inactive`, `probe_post_fault_exit_missing`; a stale log with a foreign `r` → `INVALID`, `probe_run_mismatch`, `traffic_start` 0.  (Residual boundary in §2.) |
| **GPT C2** — a truncated QGA final read can omit a proven leak and PASS | `run_phase.py:3208-3250` exact `stat`/sha256/`cat`/newline; `:3253-3279` persist even rejected bytes | **Fixed.** Final `cat` truncation after a successful pre-fault control → `INVALID`, errors `probe_log_truncated`, probe evidence keeps the readable prefix; a leak inside the kept prefix → phase `LEAK`, evidence has `"m":false`. |
| **GPT C4 / Pi I1** — `Self.ExitNode` boolean bypasses exit-peer identity | `run_phase.py:2925-2955` `router_exit_identity`; `:2959-3013` `client_find_router_peer` (ID + HostName + ExitNodeOption + Online + expected IPv4); `:3029` `client_peer_is_active` (ExitNodeStatus ID/address/Online) | **Fixed.** Direct old repro `client_peer_is_active({ExitNodeStatus: production-exit, Self.ExitNode: true}, "test-router", ...)` → `False`.  Phase with no/wrong `ExitNodeStatus` + `Self.ExitNode: true` → `INVALID` (`client_exit_peer_missing`/refusal), no traffic start. |
| **GPT C1** — forged/reordered controls satisfy the client capture proof | `clientscan.py:63-118` exact Ethernet/IPv4/UDP tuple and payload; `:341` record/timestamp order; `:347` duplicate | **Fixed.** Matrix of raw-payload controls, wrong src/dst MAC/IP, wrong UDP port/length, MF, IP options, reversed records, reversed/equal timestamps, duplicate and missing controls → all `INVALID` with `client_control_wrong_tuple`/`client_control_order`/`client_control_duplicate`/`missing_client_controls`. |
| **GPT I1 / Opus M-6** — malformed tail masks an already seen LEAK | `clientprobe.py:150-205` `parse_probe_log_partial`; `:285-300` leak independent of quality | **Fixed.** `ok:true,m:false` line followed by `{`, no final newline, a foreign `r`, or an oversized tail → verdict `LEAK`; counts retained. |
| **GPT I2** — conflicting production HostName hidden by DNS fallback | `run_phase.py:2835-2868` `client_identity_problems` | **Fixed for string HostName.** `HostName=production-client` + valid test DNSName → refusal/INVALID.  Non-string HostName edge: Minor M-B. |
| **GPT I3** — pre-fault refusal discards a real-IP leak | `run_phase.py:4143-4160` returns a leak immediately; `:4279-4300` collect in `finally` | **Fixed.** Pre-fault-only `m:false` → phase `LEAK`, exit 1, log collected and contains `"m":false`; a runner exception after traffic start → log collected. |
| **GPT I4** — guest bytes in probe diagnostics | `clientprobe.py:61` `ProbeError(code,line)`; `:112-152` fixed codes; `run_phase.py:4443-4453` report | **Fixed.** Duplicate-key line carrying `198.51.100.77 tskey-auth-FAKEONLY https://login.tailscale.com/a/...` → `INVALID` with `problems=[{"code":"duplicate_key","line":5}]`; secret absent from `phase.json`, stdout and stderr.  (It is, by design, still in the raw root-only probe evidence the guest itself wrote.) |
| **GPT I5 / Opus M-9 / Pi M9** — login URL on stderr | `run_phase.py:1763` | **Accepted risk, not re-raised** per controller decision 12; documented exception in the design. |
| **Opus I-2 / Pi M8** — reversible 48-bit IP hash | `guest.py:895-1005` traffic script | **Fixed.** `guest.client_traffic_script_text()` has no `"h"`, `hashlib` or `sha256`; only booleans/r/s/t. |
| **Opus M-1** — client captures not attached to guards | `run_phase.py:3868-3869` `attach_capture` on each guard | **Fixed.** `client_capture_dead=True` → `INVALID`, `capture_ended_early`, `capture_ended_early_at` set; no PASS. |
| **Opus M-2 / Pi M2** — marker check vacuous | `clientprobe.py:212` `pre_fault_marker`; `run_phase.py:4150` `wait_client_probe_control` | **Fixed.** No pre-fault successful marker → `INVALID` (`client_marker_not_sent`); no pre-fault Mullvad success → `INVALID` (`client_not_routed`). |
| **Opus M-3 / Pi I2** — no-client teardown leaves `vprlab1`/tap/neighbour/DOCKER-USER while deleting the table/owner | `netplan.py:271` owner `clients`; `:594-604` read; `:1010-1027` union; `:1140-1207` dynamic verify/isolate/delete | **Fixed for the fixed tool's own state.** Client setup then no-client teardown with the same owner/state: `links_after=[]`, `neigh_after={}`, `rules_after=[]`, `table=null`, `owner_after=false`, rc 0.  Old-owner edge: Minor M-C. |
| **Opus M-4** — router peer chosen by first HostName match | `run_phase.py:2968-3013` | **Fixed.** Peer with a duplicate HostName, a wrong HostName, `Online:false` or a wrong Tailscale IP → `None`/refusal; peer is bound by the router's own `Self.ID`. |
| **Opus M-5** — dead role checks | `run_phase.py:2870-2895` uses `ExitNodeOption`/`ExitNode` and `PrimaryRoutes`/`AllowedIPs` | **Fixed.** Client with `ExitNodeOption:true` or `PrimaryRoutes:["0.0.0.0/0"]` → refusal strings. |
| **Opus M-7 / Pi M5** — controls matched anywhere | `clientscan.py:63-118` | **Fixed** (same matrix as GPT C1). |
| **Opus M-8** — overflow/`m:null`, tarball, clear race, unused nonces | `guest.py:926-947` overflow; `clientprobe.py:270` overflow INVALID; `provision.py:464-507` hash-copy-rehash; `run_phase.py:4012-4025` wait Running before clear | **Fixed/accepted.** Overflow → `INVALID`; `m:null` success → `LEAK`; staged wrong digest or a post-check swap → refusal, destination removed; wrong digest leaves no staged file; the code waits for `BackendState == Running` before `tailscale set`.  Unused nonces: harmless, accepted. |
| **Pi I3** — admission counts one capture/overlay | `run_phase.py:1881-1930` `capture_count`/`client_overlay`; `:3632-3639` client call | **Fixed.** 7 GiB−1 state → refused, 7 GiB → admitted; 5 GiB−1 evidence → refused, 5 GiB → admitted; old 3 GiB/5 GiB calls only admit when the caller explicitly asks for one capture/no client overlay. |
| **Pi M1** — forward accepts not source-scoped | `netplan.py:1120-1121` `ip saddr`/`ip daddr 10.251.0.0/24` | **Fixed text.** Both scoped accepts present.  Base-chain policy caveat: Minor M-K. |
| **Pi M2** — no-client plan blank lines/identity | `netplan.py:942-956` empty-block removal; `render_plan` | **Fixed.** Setup section (from `# --- 1.` to `# --- 5.`) is text-identical to `888f0d4`; capture section identical; no `@@`, no triple newline; only the intended dynamic teardown/helper text differs. |
| **Pi M3** — wrong probe-log path | `clientprobe.py:5` | **Fixed**: `/var/lib/vprlab/client-probe.jsonl`. |
| **Pi M4** — before-control order | `run_phase.py:4012-4047`: wait running → clear → wait cleared → before-control | **Fixed**; design `leak-lab-vm.md` updated. |
| **Pi M6** — snaplen not bound | `clientscan.py:268` `FULL_CAPTURE_SNAPLEN` | **Fixed**: snaplen 65535 → `INVALID` (`capture_snaplen_mismatch`); argv wrong interface/path → `capture_argv_mismatch`. |
| **Pi M7** — marker split across frames | design out of scope | Accepted false-negative; unchanged. |
| **Pi M10** — runtime host check does not verify client nft rules | `hostcheck.py:330-446`; `run_phase.py:2175-2245` | **Still open (Minor M-F)**: an older/modified plan with valid links/table/neighbours but missing client nft rules would pass `verify_host_lab`.  Deferred with a stated reason; not a false PASS by itself because the generated plan is reviewed and tested. |
| **Pi M11** — fake client scanner in orchestration | `vm/test_vm.py:6409-6450` runs the real `clientscan.scan_client_capture` over the crafted pcaps | **Fixed**; my run of the orchestration yields the real report (`client_packets=2`, stats captured 2, both controls seen). |
| **Pi M12** — CLI without epoch | `clientprobe.py:389-410` requires epoch/window/run-id | **Fixed for the CLI.** Library default `run_id=None`: Minor M-A. |

The shipped tests named in the fix report for these paths all pass (they are
inside the 320/252 counts).

---

## 2. New findings

### I-1 (Important) — post-fault attempts and the 10 s gap accept a same-second pre-fault probe, so a short client hold can PASS with zero probes during the hold

**Files**

- `tools/leak-lab/clientprobe.py:289-311` — a line counts as a post-fault
  attempt when `value >= int(post_fault_epoch)`; the same line can still be
  classified "before" by `value <= fault_epoch` at `:262-267`.
- `tools/leak-lab/clientprobe.py:320-333` — the gap check only measures
  `max(t[i+1]-t[i])` over `[clock_start, timestamps..., clock_stop]`.
- `tools/leak-lab/vm/run_phase.py:4163` (`fault_epoch`), `:4212`
  (`post_fault_epoch`), `:4227` (unit active), `:4234` (`probe_clock_stop`).
- The design's rule (`docs/rust-v2/leak-lab-m3-clients.md`, Probe verdict):
  "no post-fault exit/marker attempt … INVALID" and "gap above 10 s".

**What goes wrong.**  For an `idle` (or any fast) fault, `fault_epoch` and
`post_fault_epoch` can be the same guest second.  A probe written in that
second (before the fault action, or between the pre-fault control and the
action) satisfies both `phase == "before"` and the `value >= post_fault_epoch`
attempt count.  The hold then starts **after** that read.  If the hold is at
most `MAX_PROBE_GAP_SECONDS` (10 s), the last pre-fault probe is within 10 s of
`clock_stop`, so `probe_gap` is also satisfied, and the phase PASSes with no
probe at all during the hold.  This is reachable with a **healthy** script,
not only a hung one: after the fault the exit is gone and each failed
`curl`/`marker_probe` can take its 4 s subprocess timeout, so one loop can be
~9 s; a 5 s hold can fall entirely between probes.  With a frozen guest clock
(`clock_start == clock_stop == fault_epoch == post_fault_epoch`) the same hole
is independent of the hold length because the gap is zero.

**Reproducer A (parser, same-second boundary).**  Ran:

```python
import sys; sys.path.insert(0, "tools/leak-lab"); import clientprobe as P
RID = "a"*32
def line(k, s, t, ok, m):
    import json
    d = {"k":k,"r":RID,"s":s,"t":t}
    if k != "overflow": d["ok"] = ok
    if k == "exit": d["m"] = m
    return (json.dumps(d, sort_keys=True, separators=(",", ":"))+"\n").encode()
data = (line("exit",1,100,True,True) + line("marker",2,100,True,"unset"))
r = P.evaluate_probe_log(data, fault_epoch=100, post_fault_epoch=100,
                         clock_start=100, clock_stop=100, run_id=RID)
print(r["verdict"], r["invalid_reasons"],
      r["post_fault_exit_attempts"], r["post_fault_marker_attempts"])
# PASS [] 1 1
```

A 5 s version (probe pair at 1100, `fault_epoch=post=1100`,
`clock_stop=1105`, no later lines) also returns `PASS`; the same log with
`clock_stop=1111` returns `INVALID` (`probe_gap`).  Exact run:

```
1105 PASS []
1110 PASS []
1111 INVALID ['probe_gap']
```

**Reproducer B (phase level, fake-QGA `ClientRunPhaseTests`).**  The wrapper
below models a unit whose script is still running (`systemctl is-active`
true) but has not completed another probe during the hold, and a same-second
`idle` fault; `read_guest_clock` returns `T0-1, T0, T0, T0+duration` for the
four client clock reads:

```python
import contextlib, json, sys
from unittest import mock
sys.path[:0] = ["/var/tmp/leaklab-m3r-pi/tools/leak-lab",
                "/var/tmp/leaklab-m3r-pi/tools/leak-lab/vm"]
import guest, test_vm, run_phase
orig_start = run_phase.start_client_traffic
orig_clock = run_phase.read_guest_clock

def run(duration):
    case = test_vm.ClientRunPhaseTests(
        "test_client_idle_passes_with_both_captures_and_the_probe_log")
    case.setUp()
    try:
        def start(client, **kwargs):
            orig_start(client, **kwargs)      # one exit+marker pair at T0
            client.traffic_active = True      # unit stays active
        calls = {"n": 0}
        def clock(qga):
            if not hasattr(qga, "traffic_active"):
                return orig_clock(qga)        # router handshake clock
            t0 = qga.clock
            values = [t0-1, t0, t0, t0+duration]
            i = min(calls["n"], 3); calls["n"] += 1
            return values[i]
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(run_phase,
                "start_client_traffic", start))
            stack.enter_context(mock.patch.object(run_phase,
                "client_traffic_unit_active", lambda c: True))
            stack.enter_context(mock.patch.object(run_phase,
                "read_guest_clock", side_effect=clock))
            code, record, client, events, out, err, ev = case._run(
                "idle", duration)
        probe = record["client"]["probe"]
        print(duration, code, record["result"], probe["verdict"],
              probe["post_fault_exit_attempts"],
              probe["post_fault_marker_attempts"],
              [json.loads(x)["t"] for x in
               (ev / guest.CLIENT_PROBE_FILE).read_text().splitlines()])
    finally:
        case.doCleanups()

for d in (0.0, 1.0, 5.0, 10.0, 11.0):
    run(d)
```

Observed:

```
0.0  0 PASS PASS 1 1 [1700000000, 1700000000]
1.0  0 PASS PASS 1 1 [1700000000, 1700000000]
5.0  0 PASS PASS 1 1 [1700000000, 1700000000]
10.0 0 PASS PASS 1 1 [1700000000, 1700000000]
11.0 2 INVALID INVALID 1 1 [1700000000, 1700000000]   # probe_gap only
```

The phase log has exactly one pre-fault pair; no probe exists during the
hold; the phase still says `PASS` for every hold up to the gap limit.  A real
IP leak during that hold (the probe stream is what detects it; the client
scan does not classify normal TLS) would be certified PASS.

**Why the existing tests do not catch it.**  `test_leak_lab.py:5533`
(`test_post_fault_exit_and_marker_attempts_are_required`) uses the
`client_probe_log` fixture with `post_fault_epoch=105` and its "post" lines at
`t=105`, i.e. the same second as the fault; the orchestration fake's
`is-active` handler (`vm/test_vm.py:6296-6303`) writes a fresh pair on every
liveness poll, so it never models a slow loop or a hung unit.  This is a test
gap (Minor M-H) as well as a code boundary.

**Suggested fix.**  Make the post-fault control strict and the window
meaningful:

1. Count attempts only when `t > fault_epoch` (strictly after the pre-action
   clock), and require `post_fault_epoch > fault_epoch`; or require the last
   probe `t >= fault_epoch + MAX_PROBE_GAP_SECONDS` for a hold that short.
2. Reject `clock_stop <= clock_start` (and a zero elapsed window) in
   `evaluate_probe_log`, so a frozen guest clock cannot certify a hold.
3. Enforce a minimum client `--duration` of at least `2*MAX_PROBE_GAP_SECONDS`
   (or make a too-short hold INVALID), because a hold shorter than the probe
   cadence cannot be observed.
4. Add a harness test with a unit that is active but writes no probe during a
   5 s hold (and a parser test with a same-second `fault_epoch`/
   `post_fault_epoch`), and one with all timestamps equal.

---

### Minor findings

#### M-A (Minor) — `evaluate_probe_log` keeps `run_id=None` as a silent default

`tools/leak-lab/clientprobe.py:216`.  Calling
`evaluate_probe_log(valid_log, fault_epoch=..., ...)` without `run_id`
accepts a log whose `r` is any 32-hex value; the CLI and `run_phase` always
pass it, so this is a library-caller trap, not a phase false pass.  Reproducer:
the valid two-line log with `r="b"*32` and `run_id=None` → `PASS`.
Suggested fix: make `run_id` required (no default) or treat `None` as
`probe_run_id_missing` INVALID, as the other bindings already do.

#### M-B (Minor) — a present but non-string `Self.HostName` falls back to DNS

`tools/leak-lab/vm/run_phase.py:2849-2860`.  A status with
`Self.HostName=123` and the correct `DNSName` returns `[]` from
`client_readiness_problems`; only a **missing** HostName is documented to use
the DNS label.  Reproducer: direct call with `{"HostName":123,"DNSName":
"zz-vprclient-01-do-not-use.tailnet.ts.net."}` → no problems.  A real
`tailscale status --json` emits a string, so this is strictness; fix by
refusing a present non-string HostName.

#### M-C (Minor, host-safety edge) — an old owner.json without `clients` plus client residue repeats the old I2 fail-open

`tools/leak-lab/netplan.py:594-604` (`clients` defaults to `[]`), `:1010-1027`
(the union), `:1140-1207` (only recorded indexes are verified/isolated/deleted).
Reproducer (`repro_netplan.py`, stub shell): an owner.json in the pre-M3 format
(no `clients` key) and a state containing `vprlab1`, `vprlab-ctap1`, the
`10.251.0.2` neighbour and the two client `DOCKER-USER` accepts; a no-client
teardown → rc 0, `table=null`, owner removed, but

```
links_after  ['vprlab-ctap1', 'vprlab1']
neigh_after  ['10.251.0.2']
rules_after  [two DOCKER-USER accepts]
```

This is the old I2 symptom, but it is **not reachable from the fixed tool's
own state**: the fixed setup always writes `clients`, and `progress.md` says
M3 was never live and no client VM was provisioned.  It is an upgrade edge
from `b849e3c`, which is only a reviewed commit.  The compatibility case that
matters (an existing M2-era owner with router-only state) was rerun and
teardown succeeds (`links_after=[]`, `table=null`, owner removed).  Suggested
fail-closed hardening: if `CLIENT_INDEXES` is empty and `vprlab1` or any
`vprlab-ctapN` exists, refuse the teardown (or inventory and remove those
objects) before deleting the shared table and owner.

#### M-D (Minor, functional, unreproduced) — `client-login` runs a blocking `tailscale up` before it starts showing the login URL

`tools/leak-lab/vm/run_phase.py:3928-3949`: the client login executes
`tailscale up --reset … --shields-up --accept-routes=false` synchronously with
a 120 s QGA timeout, and only then calls `login_phase_wait` (which reads the
journal and prints/writes the URL).  A first interactive login normally prints
the URL and **waits** for authentication inside that command; the URL is in
the command's captured stderr, not shown to the operator, so the operator has
no URL during the 120 s window and the command can time out.  The fake
`ClientQGA` returns 0 immediately with the URL already in the journal, so
`test_client_login_boots_only_the_client_and_writes_the_url`
(`vm/test_vm.py:6813`) does not model it.  I could not run a real tailscaled
(no network/QEMU).  Suggested fix: start `tailscale up` in a transient unit /
background and poll the journal (as the router login phase does), or stream
and print the URL from the command while it waits; add a fake that blocks until
authenticated.

#### M-E (Minor, functional, unreproduced) — the real client exit underlay may appear on the router tap and the unchanged router scan would make the phase INVALID, not PASS

`docs/rust-v2/leak-lab-m3-clients.md:13` requires every `vprlab-tap0` frame to
be WireGuard to the declared Mullvad endpoint; `run_phase.py:472-540`
(`build_lab_policy`) allows exactly that flow.  The client's Tailscale packets
to the router exit node can take a **direct** underlay path (host NAT/hairpin)
and arrive on the router tap as Tailscale WireGuard to the router's port,
which the router scan will not allow; only a DERP-relayed path keeps the
router's underlay inside the Mullvad WireGuard.  The fake harness
(`vm/test_vm.py:6409`) fakes the router scan and writes a dummy router pcap,
so this is unproven.  If it happens the phase is INVALID (safe, but M3 cannot
PASS); it is not a false pass.  Suggested action: a real client phase on the
lab host, or an explicit documented policy/test for the exit underlay (do not
blindly widen the router scan).

#### M-F (Minor) — runtime host verification still does not check the client nft rules (my earlier M10)

`vm/hostcheck.py:330-446` verifies the client bridge/tap/address/neighbour/
ownership, and `run_phase.py:2175-2245` verifies the table exists and is
owned, but not the `vprlab1` input/forward/output drops, the two inter-bridge
drops or the scoped masquerade.  A modified/older plan with valid links and
table but missing rules would pass `verify_host_lab`; the generated-plan tests
are the only rule-level control.  Deferred in the fix report; still a Minor.

#### M-G (Minor, test gap) — the orchestration "final read truncation" test truncates from the initial cleanup stop, not the final read

`vm/test_vm.py:6659` sets `truncate_final_cat`, but the fake
`ClientQGA` arms `truncate_cat` on the **first** `systemctl stop`
(`vm/test_vm.py:6298-6306`), which is the cleanup stop before the silence
check; the pre-fault wait then reads a truncated log and the phase aborts
before the fault.  The test still asserts INVALID, but it does not exercise
the exact final read after a successful pre-fault control.  My independent
wrapper (arm the flag after the pre-fault control) gives `INVALID`
(`probe_log_truncated`), so the code is right; the test should arm the
truncation later.  Similarly, a leak in the **kept** prefix is `LEAK`, and a
leak in the omitted suffix is `INVALID` (never PASS), which I ran.

#### M-H (Minor, test gap) — the fake `is-active` writes a probe pair, so no orchestration test models a slow/hung active unit

`vm/test_vm.py:6296-6303`: every `systemctl is-active --quiet` call appends a
pair.  This is why the shipped `test_inactive_unit_at_the_end_of_the_hold_is_invalid`
covers only a **dead** unit and not the Important boundary above.  Add a
frozen-unit/slow-loop test.

#### M-I (Minor) — `client-login` over-reserves admission

`vm/run_phase.py:3632-3639`: the call is unconditional, so `client-login`
reserves two capture caps and both overlays (7 GiB state, 5 GiB evidence for
the default 2 GiB cap) although it starts no capture and no router VM.  This
is fail-safe (a false refusal), not a false pass; pass `capture_count=1` (or
0) and no router overlay for `login_only`, or use a dedicated login admission.

#### M-J (Minor, pre-existing from `b849e3c`) — the evidence-inside-state check covers only the client state

`vm/run_phase.py:3701-3709` compares `client_state` with the evidence root;
the router state (`router_state`) is also QEMU-owned and is checked in the
router-only path (`:4737-4741`), but not here.  An operator pointing
`--evidence-root` inside the router state would let the router VM write the
evidence.  Not reachable with the default paths; fix by checking both states.

#### M-K (Minor, defense in depth) — the scoped client forward accepts are not drops, and the lab base chains are `policy accept`

`tools/leak-lab/netplan.py:878-880` creates the `inet vprlab` chains with
`policy accept`; `:1120-1121` adds the source/dest-scoped accepts.  A spoofed
source `10.251.0.0/24`-outside frame from `vprlab1` out the WAN matches no
drop and is accepted by the base chain; the actual drop is Docker's
`FORWARD`/`DOCKER-USER` path (`check_name_collisions` reports the FORWARD
policy but does not require it to be `DROP`).  This mirrors the router plan and
is the M1 note's residual: the accept is now scoped, but the scope is not a
drop.  Suggested hardening: a `forward iifname "vprlab1" oifname "<wan>" ip
saddr != 10.251.0.0/24 drop` (and the symmetric return) or a preflight
requirement for the Docker FORWARD policy.

#### M-L (Minor, report consistency) — a read-quality problem can leave `client.probe.verdict == PASS` while the phase is INVALID

`vm/run_phase.py:3253-3279` notes a read problem in `errors` and persists the
data; `:4443-4453` evaluates the data without the read problem.  Reproducer:
patch `read_client_probe_log_exact` to return the full valid data plus
`probe_log_hash_mismatch`; the phase is `INVALID` (`errors:
["probe_log_hash_mismatch"]`) but `record["client"]["probe"]["verdict"]` is
`PASS`.  The phase result is correct (no false pass), but a downstream reader
of the probe object could be misled.  Fix: pass the read problem into the
evaluator or downgrade a PASS probe to INVALID when a read problem was noted
(LEAK still wins).

#### M-M (Minor, strictness) — role check does not use `AdvertisedRoutes`/prefs

`vm/run_phase.py:2870-2895` checks `PrimaryRoutes`/`AllowedIPs`, not the
client's advertised routes from `tailscale debug prefs`; a client advertising
`0.0.0.0/0` without being the primary route or an `ExitNodeOption` could pass
the role check.  The client is configured not to advertise and the exit/marker
controls remain; defense in depth only.  The old `Self.AdvertisedRoutes` check
was dead; this is a known limitation, not a new false pass.

#### M-N (Minor) — an observed pre-fault LEAK is downgraded to INVALID if the final exact read fails

`vm/run_phase.py:4143-4160` (`wait_client_probe_control` observes
`probe_flags["leak"]`, notes `client_real_ip` and raises) and
`:4279-4300`/`:3253-3279` (the `finally` exact read may fail, e.g. QGA
unreadable).  Reproducer: fake client with a pre-fault `m:false` line, and
`read_client_probe_log_exact` patched to return `(None, "probe_log_unreadable")`:

```
{"errors": ["client_real_ip", "phase_exception:Refusal",
            "probe_log_unreadable", "probe_fault_epoch_missing"],
 "probe": "INVALID", "result": "INVALID"}
```

The phase is fail-safe (not PASS) and the error names the leak, but the
observed LEAK verdict is not preserved and the prefix bytes seen by the
pre-fault read are not persisted.  Suggested fix: record a
`client.probe_leak_observed` flag (and the observed prefix bytes) when
`probe_prefix_flags` returns `leak`, and make the final result LEAK when that
flag is set even if the exact read later fails; the current normal path
(successful collection) correctly returns LEAK (verified).

#### Accepted/explicitly skipped (not re-raised)

- Login URL on stderr: accepted risk (controller decision 12), documented.
- Marker split across two frames: documented out of scope.
- `m: null` "dead rule": retained defense in depth; an unparseable answer is
  `ok:false`.
- Unused nonces in `client-login`: harmless.

---

## 3. Host-safety and secrecy checks (positives verified)

- **Production/tailscaled isolation.**  The client phase only runs QEMU/tcpdump
  and QGA commands inside the VMs; no host `tailscale`, Docker, `ip`, `nft` or
  `iptables` execution is added.  The netplan objects are `vprlab1`,
  `vprlab-ctapN`, the shared `inet vprlab` table and owner-tagged
  `DOCKER-USER` rules; nothing targets `max-vprouter` or the host's
  tailscaled.  The client and router QEMU argv keep `-nic none`, the explicit
  tap, `-serial none`, the sandbox, the fixed MAC and `setpriv --reuid/--regid
  --init-groups --no-new-privs --inh-caps=-all --bounding-set=-all` (source
  review; `start_vm` unchanged by the fix).
- **Client netplan.**  `vprlab1`/taps are created down with the owner ifalias;
  the input drop, both `vprlab0 <-> vprlab1` drops, the `oifname != wan` and
  `iifname != wan` drops, the IPv6 drops, the scoped forward accepts
  (`ip saddr`/`ip daddr 10.251.0.0/24`), the scoped masquerade and the scoped
  DOCKER-USER accepts are present before the links come up (plan tests and
  source).  The no-client setup/capture text is identical to `888f0d4`
  (verified by rendering both and comparing; 34 command lines).
- **Owner/teardown.**  `owner.json` now has `"clients"` and is 0600/exclusive;
  teardown reads it, unions with the plan, verifies every existing client
  tap/bridge/neighbour before any mutation, isolates the client taps, removes
  the client neighbours/DOCKER-USER rules, deletes the table/links and removes
  the owner last.  A foreign client tap/ifalias/neighbour aborts with no
  mutation and the owner retained (`repro_netplan.py` mismatch case).  An
  owner listing `[1,2]` with only client 1 created tears down cleanly; an old
  owner without `clients` works for router-only state.  The old-owner residue
  edge is M-C.
- **Collision preflight.**  `check_name_collisions` always inventories
  `vprlab1`, `vprlab-ctap1..9` and the `10.251.0.0/24` overlap, even for a
  no-client render; leftover client objects are visible to setup (test and
  source).
- **Admission.**  Two capture caps + 1 GiB on evidence and 4+2 GiB overlays +
  1 GiB on state; 256 MiB client memory added.  Boundary runs above.
- **Tarball staging.**  `provision._stage_client_payload` opens the source
  with `O_NOFOLLOW`, hashes while copying, re-hashes the staged copy and
  refuses/removes on a wrong digest or a post-check swap; wrong file, symlink
  and swapped file all refused; no staged destination left.
- **Exact probe read.**  `stat`/sha256/`cat`/final newline and exact length;
  truncation and hash mismatch are INVALID; a readable leak in the returned
  bytes is LEAK; the evidence file is 0600 and hashed in `phase.json`.
- **Exit peer.**  `router_exit_identity` reads the router's own `Self.ID` and
  IPv4s; `client_find_router_peer` requires exactly one peer with that ID,
  the exact test HostName, no HostName collision, `ExitNodeOption` and
  `Online`, and an expected IPv4; `client_peer_is_active` requires
  `ExitNodeStatus` with that ID, that address and `Online:true`; there is no
  `Self.ExitNode` fallback.  `wait_client_exit_cleared` requires no
  `ExitNodeStatus` and `Self.ExitNode` not true.
- **Client controls.**  Strict Ethernet II / IPv4 (no options/fragments) / UDP
  39001 from the client MAC+IPv4 to the bridge MAC+IPv4 with the exact
  payload; record and timestamp order; duplicates/missing/wrong tuples
  INVALID; controls on the router tap are a finding.
- **Capture guards.**  Both tcpdump processes are attached to their own
  guards; a dead client tcpdump → `capture_ended_early`, tap isolation, phase
  INVALID (my `client_capture_dead=True` run).
- **Secrecy.**  The traffic script records only booleans/`r`/`s`/`t`; no IP,
  location or hash; `phase.json`/`client-scan.json` contain fixed codes,
  counts, epochs, nonces, booleans and paths, not raw client status or guest
  text; the duplicate-key probe case keeps the guest bytes only in the
  root-only probe evidence file, not in `phase.json`, stdout or stderr.  The
  login URL stderr exception is accepted.

## 4. Router-only path (no `--client`)

- `run_phase.py:4595-4667` dispatches to `_run_phase_locked` when
  `getattr(arguments, "client", None)` is absent.  AST comparison against
  `888f0d4` shows `_run_phase_locked`, `scan_evidence`, `start_capture` and
  `stop_capture` are **identical**; `login_phase_wait` differs only by the
  optional `client_login` branch (the router branch is unchanged).
- `RunPhaseTests._run("idle")` with `_run_client_phase_locked` patched to
  raise → exit 0, `PASS`, no `client` record; the router branch was entered.
- The no-client netplan setup and capture sections are text-identical to
  `888f0d4`; the only added teardown text is the dynamic client inventory,
  which is a no-op for an owner with no clients (verified by teardown with an
  old-format owner).
- The full router/leak-lab suites (320 + 252) pass.

## 5. Docs vs code / report accuracy

- The design and `leak-lab-vm.md` match the fixed order (wait Running → clear
  → prove cleared → before-control) and the owner-record teardown, the
  `h` removal, the exact read and the strict controls.
- The fix report's line numbers are approximate in places (e.g.
  `clientprobe.py` line numbers shifted), but its claimed behaviours are
  present; the test-count claim (320/252) matches.
- "Setup and capture sections byte-identical" is true for the actual setup/
  capture text; a naive split before `# --- 4. teardown ---` also includes the
  new teardown helper definitions, so the claim should be read as the
  executed setup/capture sections.
- The design's "never record any non-Mullvad IP" is true for the script and
  diagnostics; the raw probe evidence can contain whatever the guest writes,
  which is expected for guest-produced evidence.

---

## Verdict

The previously reported Critical/Important false-PASS paths are fixed in their
normal forms, the host-network additions remain scoped and owner-verified, and
the router-only path is unchanged.  However, the new post-fault-attempt check
does not require a probe **after** the pre-action clock: a client phase with a
hold of at most 10 s (or a frozen guest clock) can still PASS with no probe
during the hold, and a real-IP leak in that window would be certified.  That is
an Important false-PASS residual, so this review does not clear M3.

Verdict:
FAIL
