# Leak-lab M3 — independent adversarial re-review, round 3 (Pi)

Target: `rust/v2` at `37bafc2ba28789834a1df1ecef599bf872c8c7ce` ("fix round 2").
Reviewed from an extracted `git archive 37bafc2` tree under
`/var/tmp/leaklab-m3r3-pi`; `HEAD` is that commit and the working tree is clean
(`git status --porcelain` empty, `git diff --check 605cce8..37bafc2` clean).
Binding design: `docs/rust-v2/leak-lab-m3-clients.md`.  Fix scope:
`git diff 605cce8..37bafc2` = `tools/leak-lab/{clientprobe,netplan,
test_leak_lab}.py`, `tools/leak-lab/vm/{guest,run_phase,test_vm}.py`,
`docs/rust-v2/{leak-lab-m3-clients,leak-lab-vm}.md`, reports/progress.

Method: full source read of the diff and of every earlier finding, then my own
reproducers (parser fixtures, the fake two-VM `ClientRunPhaseTests` harness,
crafted boundary-read injections, generated shell through the repository's
`test_leak_lab` stub `ip`/`nft`/`iptables` sandbox).  I modified no file except
this report, ran no sudo, QEMU, tcpdump, `ip`, `nft`, `iptables`, docker,
useradd or network command, and read no restricted path.  Generated shell was
only ever executed through the stub harness (plus `sh -n` parse checks).
Scratch was deleted at the end.

## Test runs (once each, as required)

From `tools/leak-lab` of the extracted tree:

- `python3 -B -W error -m unittest test_leak_lab` → **Ran 329 tests, OK**
  (14.07 s).  Matches the fix report's count.
- `python3 -B -W error -m unittest vm.test_vm` → **Ran 266 tests, OK**
  (5.71 s).  Matches the fix report's count.

Additional targeted evidence: `test_leak_lab.ClientScanTests ClientProbeTests
ClientNetplanTests ClientHostcheckTests` → 55 tests, OK; `py_compile` of the
six changed Python files OK; `sh -n` on the rendered no-client, `--client 1`
and `--client 1,2` plans rc 0.

## Summary

The round-2 fixes are real and I could not break any of them in its normal
path: the proven traffic stop (GPT C1), the sequence-bound post-fault coverage
(GPT C2 / my I-1), the latched LEAK (GPT I1 / Opus N-1 / my M-N), the
end-of-hold exit-node re-check (Opus N-2), the 30 s floor (Opus N-3), the
neighbour helpers and old-owner teardown refusal (Opus N-4 / my M-C), the 15 s
gap (Opus N-5), the non-blocking `client-login` (my M-D), the read-quality
downgrade (my M-L) and the `AdvertiseRoutes` check (my M-M).  The changed host
plan is scoped to `inet vprlab` + `DOCKER-USER`, and the router-only phase
runner is unchanged.

One **Important false-PASS residual remains** (R3-I1): the new fault-boundary
sequence number is taken from a *tolerant, length-unverified* read
(`read_client_probe_log`), so a partial `cat`/`stat` read (or a non-zero `cat`
whose stdout is a prefix) silently understates `S_fault` and promotes
pre-fault probe rows into the post-fault window.  Combined with a guest clock
that does not advance across the boundary (a frozen/broken RTC, which the fix
explicitly claims to handle) I reproduced an end-to-end phase **PASS for a 30 s
hold in which the traffic unit wrote no probe at all** (`fault_sequence=1`,
`hold_sequence_end=6`, `post_fault_exit_attempts=2`, log rows 1..6 all written
before the fault).  The same run with a complete boundary read is INVALID, so
the defect is the boundary read, not the evaluator.  There are also five Minors
(R3-M1..R3-M5), two of them document/report inconsistencies.

Because this milestone treats a false PASS as the critical failure, the
verdict is **FAIL** until the boundary read is made exact.

---

## 1. Earlier findings — re-verified against `37bafc2`

Each row was re-run with my own reproducer (not only the shipped test).
"Fixed" means the old passing evidence now ends in INVALID/LEAK or a refusal.

| Earlier finding | Evidence at `37bafc2` | Result |
|---|---|---|
| **Pi I-1** — same-second/frozen clock certifies a hold with no post-fault probe (`clientprobe.py:270-311`, `run_phase.py:4163/4212/4227`) | `clientprobe.py:274-285` `_is_post_fault_attempt` needs `s > S_fault`; `:381-383` requires `floor(hold/15)` exits; `run_phase.py:4427-4434` records `S_fault` after the action, `:4462-4470` `S_end` at the end of the hold; 30 s floor at `:3759-3765` | **Fixed in the normal path.** Parser: same-second pair with `fault_sequence=end_sequence=2`, `hold_seconds` 0/1/5/10/15, `clock_stop=fault` and the 4 s/11 s/16 s tails → all INVALID (`probe_post_fault_exit_missing`, `probe_hold_coverage`, `probe_gap`), 0 attempts; the same fixtures return **PASS** on `605cce8`.  Phase: my round-2 wrapper re-run verbatim now refuses 0/1/5/10/11 s (`a --client phase needs --duration >= 30 seconds`) and gives INVALID at 30 s (`fault_sequence=2`, `end_sequence=2`, 0 attempts).  **Residual: R3-I1.** |
| **Pi M-A** — `run_id=None` silent default | `clientprobe.py:217-219`, `:247-248` | **Fixed.** Omitting `run_id` → `TypeError`; `run_id=None`/`"zz"` → `ProbeError("invalid_run_id")`. |
| **Pi M-B** — non-string `HostName` falls back to DNS | `run_phase.py:2869-2881` | **Fixed.** `{"HostName":123,"DNSName":"zz-vprclient-01-do-not-use…"}` → `["the client name is not the expected client label"]`; missing HostName + valid DNS → `[]` (documented fallback); conflicting HostName → problem. |
| **Pi M-C** — old `owner.json` (no `clients`) + client residue tears down | `netplan.py:1185-1199` refusal block, before any mutation | **Fixed (fail closed).** Stub: rc 1, `vprlab1 exists but no owner client inventory names it` + `aborted without changes`, state byte-identical, owner preserved.  Pre-M3 owner + router-only state still tears down cleanly (rc 0, everything removed). |
| **Pi M-D** — blocking `tailscale up` hides the login URL | `run_phase.py:4113-4148` transient `vprlab-client-login` unit; `login_phase_wait(..., stop_when_running=True)` at `:1729/1773-1776` | **Fixed.** `client-login` (30 s) with a fake that blocks until authenticated → exit 0 PASS, `login_unit=started`, url written, no 120 s QGA call. |
| **Pi M-E** — direct client exit underlay vs the router scan | unchanged by this round | **Still a documented functional risk** (false INVALID, never PASS).  Not re-raised as a finding. |
| **Pi M-F** — runtime host check does not verify the client nft rules | `vm/hostcheck.py` untouched | **Still deferred** (controller decision 8).  My H2/H3 show the generated plan is the only rule-level control. |
| **Pi M-G** — truncation test armed at the wrong stop | `vm/test_vm.py:6449-6451` arms at `stop_count >= 2`; test asserts the pre-fault control succeeded | **Fixed.** |
| **Pi M-H** — no slow/hung active-unit test | `vm/test_vm.py:6935` (`silent_hold`), `:6949` (frozen) | **Fixed.** |
| **Pi M-I** — `client-login` over-reserves admission | `run_phase.py:3806-3808` (`capture_count=0`, `router_overlay=False`), `:1922-1940` | **Fixed.** |
| **Pi M-J** — evidence-inside-state checks only the client state | `run_phase.py:3868-3883` | **Fixed.** Both `client_state` and `router_state` are refused (`test_evidence_inside_either_state_directory_is_refused`). |
| **Pi M-K** — scoped accepts are not drops (policy-accept base chain) | `netplan.py:885-891` (vprlab0), `:1125-1130` (vprlab1) | **Fixed as text/behaviour.**  Scoped accept → conntrack return accept → two explicit drops, in that order (H1 log). |
| **Pi M-L** — PASS probe object with a read problem | `run_phase.py:4737-4747` | **Fixed.** Exact read forced to `probe_log_hash_mismatch` → phase INVALID and `probe.verdict=INVALID`, `probe.reason=probe_log_read_quality`. |
| **Pi M-M** — no advertised-routes check | `run_phase.py:2917-2948`, `:4150-4156`, `:4218-4224` | **Fixed.** `AdvertiseRoutes=["0.0.0.0/0"]` or `["10.0.0.0/8"]` or a string → `client_advertises_routes`, phase INVALID, traffic never starts; unreadable prefs → `client_prefs_unreadable`; `None`/`[]`/missing key → accepted. |
| **Pi M-N / GPT I1 / Opus N-1** — a seen LEAK downgraded by a later read failure | `run_phase.py:4358`, `:4432`, `:4468`, `:4725`, `:4738`, `combine_verdicts` `:3710-3728` | **Fixed.** Pre-fault leak + failed exact read → exit 1 **LEAK** (`client_real_ip`, `probe_leak_observed`); non-zero `cat` with a readable leak → LEAK and the bytes persisted; sha256 failure with a readable leak → LEAK. |
| **GPT C1** — a failed stop leaves a leak-bearing tail outside the snapshot | `run_phase.py:3236-3261` (no masked stop, `is-active` postcondition), `:4481-4491`, `:4540-4572` (sticky `traffic_stop_proven=False`), `:3278-3310` (partial bytes kept) | **Fixed.** End-of-hold stop fails, leak appended at the later cleanup stop → exit 1 **LEAK**, `client_traffic_stop_failed`, `probe_snapshot_trusted=False`, `m:false` in the evidence.  A stop that returns 0 while the unit stays active → INVALID. |
| **GPT C2** — a truncated final read can omit a leak and PASS | `run_phase.py:3311-3355` | **Fixed.** Final `cat` truncated → INVALID (`probe_log_truncated`, probe downgraded); a leak in the kept prefix → LEAK; a leak only in the omitted suffix → INVALID, never PASS. |
| **Opus N-1** (LEAK shown as INVALID) | see M-N/GPT I1 above | **Fixed.** |
| **Opus N-2** — exit node not re-verified at the end of the hold | `run_phase.py:4451-4460` | **Fixed.** Fake switching to `some-other-exit` while traffic is active → INVALID `client_exit_node_lost`. |
| **Opus N-3** — `--duration 0` PASSes | `run_phase.py:138`, `:3759-3765` | **Fixed.** 29.0 s and 29.999 s → Refusal "needs --duration >= 30"; 30.0 s passes the check.  Router-only phases still accept 0 s (client-only floor). |
| **Opus N-4** — dev-filtered `ip -j neigh show` helpers | `netplan.py:1069-1076` (unfiltered inventory), `test_leak_lab.py` stub models the real `dev` omission + `Cannot find device` | **Fixed.** Teardown with a missing `vprlab1` finishes rc 0 with no `Cannot find device`; a wrong client-neighbour MAC refuses before mutation. |
| **Opus N-5** — 10 s gap budget too tight | `clientprobe.py:57` (15 s) | **Fixed** (see R3-M4 for the residual latency note). |

The shipped tests named for these paths all pass inside the 329/266 counts; the
rows above were independently reproduced.

---

## 2. New finding — R3-I1 (Important): the fault-boundary sequence number is
taken from a partial read, so a truncated boundary `cat` promotes pre-fault
rows into the post-fault window and a 30 s hold can PASS with zero probes

### Where

- `tools/leak-lab/vm/run_phase.py:3360-3391` — `read_client_probe_sequence`
  derives `S_fault`/`S_end` from `read_client_probe_log`, the *tolerant* read.
  It returns `last` as soon as the bytes parse, and returns `read_problem`
  only as an aside; it never compares the received byte count with the
  guest-reported size and never requires the read to be clean.
- `tools/leak-lab/vm/run_phase.py:3278-3305` — `read_client_probe_log` runs
  `stat -c %s`, then `cat`, and **never compares `len(stdout)` with `size`**.
  A short `cat` (truncated QGA transfer) returns a prefix with `problem=None`;
  a `cat` that exits non-zero returns its partial stdout with
  `problem="probe_log_unreadable"` (`:3302-3304`).
- `tools/leak-lab/vm/run_phase.py:4427-4434` — the caller records
  `fault_sequence` and only calls `note(boundary_problem)` when the sequence
  is **missing**; a partial read that yields a number is silent.
- `tools/leak-lab/clientprobe.py:274-285` — `_is_post_fault_attempt` counts a
  row with `s > fault_sequence` and `t >= post_fault_epoch`;
  `:381-383` requires `floor(hold/15)` such exit rows.

### What goes wrong

The fix assumes `S_fault` is the true last complete sequence at the moment the
action and its postcondition finished ("A later read, a cleanup stop or a
same-second clock can never move it", fix report §Fix round 2).  It is not:
a partial boundary read moves it **backwards**.  Rows that were written
*before* the action but are dropped by the partial read then satisfy
`s > S_fault`.  They also satisfy `t >= post_fault_epoch` whenever the guest
clock did not advance across the boundary — a frozen/broken RTC, or a fast
action whose reads share the guest second with those rows.  With
`--duration 30` the evaluator only asks for `30//15 = 2` post-fault exits, so
two such pre-fault rows are enough for `probe_post_fault_exit_missing` and
`probe_hold_coverage` to pass, and every other check (pre-fault Mullvad,
pre-fault marker, `s` gap-free, timestamp monoticity, `clock_start <=
fault_epoch <= post_fault_epoch <= clock_stop`, `probe_gap`) is satisfied by
the same pre-fault rows.  The result is a certified PASS for a hold in which
no probe ran at all, which is exactly the round-2 Important (my I-1) that the
fix was meant to close.  The `probe_gap` safety net does not help: with a
frozen clock every timestamp is equal.

### Reproducer

`/var/tmp/leaklab-m3r3-pi/repro_phase.py` (fake-QGA `ClientRunPhaseTests`,
30 s hold, the guest writes only its pre-fault pair; two extra pairs model the
loop that keeps running while the fault action executes; the **first**
`read_client_probe_log` after the action returns only the first line, with
`probe_log_unreadable`, i.e. a `cat` that died mid-transfer):

```python
orig_fault = run_phase.run_router_fault
orig_read = run_phase.read_client_probe_log
def fault(router, phase, name, record, note):
    for _ in range(2):                      # the loop writes while it acts
        holder["client"].probe_pair()
    state["pending"] = True
    return orig_fault(router, phase, name, record, note)
def read(client):
    data, problem = orig_read(client)
    if state["pending"] and not state["truncated"]:
        state["truncated"] = True
        return data.splitlines(keepends=True)[0], "probe_log_unreadable"
    return data, problem
# patches: start_client_traffic (capture the client), run_router_fault, read_client_probe_log
case._run("idle", 30.0, client_kwargs={"silent_hold": True, "frozen_clock": True})
```

Observed (`P2` vs the control `P2b`, identical except the truncation):

```
P2  frozen+silent, 2 pre-action pairs, trunc  exit=0 result=PASS    probe=PASS
    fault_s=1 end_s=6 att=2 trusted=True read=exact
    evidence s=[1, 2, 3, 4, 5, 6]
P2b same, boundary read complete              exit=2 result=INVALID probe=INVALID
    fault_s=6 end_s=6 att=0   errors=['probe_post_fault_exit_missing']
threshold (rows in the dropped prefix): 0 -> INVALID, 1 -> INVALID
    (probe_hold_coverage), 2 -> PASS, 3 -> PASS
```

Rows 1..6 are all pre-fault (`t` identical, the hold wrote nothing); the phase
still says PASS and `record["result"]="PASS"`.  With a healthy 1 Hz loop
(P3) the same code PASSes with 30 attempts, so the defect is only reachable
through the boundary read, not the density rule.

### Impact

A real-IP leak during the hold produces no probe row in this state, so the
client scan (which does not classify normal TLS) and the probe verdict both
say PASS: a false PASS on the one claim that costs about 1 M EUR.  Conditions:
(1) the tolerant boundary read loses at least two exit rows, (2) the guest
clock does not advance across the boundary.  Each is plausible on its own —
the project itself rated a truncated *final* `cat` a Critical (GPT C2) and the
same reader feeds the boundary — but the two must coincide.

### Suggested fix

1. Make the boundary read length-exact like the final one: compare
   `len(stdout)` with the `stat -c %s` size in `read_client_probe_log` (or a
   dedicated boundary reader), retry within
   `CLIENT_SEQUENCE_READ_TIMEOUT`, and return `None` (→
   `probe_fault_sequence_missing`, INVALID) if no complete read is obtained.
   A non-zero `cat` must never yield a boundary sequence.
2. In `read_client_probe_sequence`, treat `read_problem is not None` as a
   failed attempt (retry) instead of returning `last` with the problem.
3. Cheap defence in depth: also require a post-fault attempt to have
   `t > fault_epoch` when `fault_epoch == post_fault_epoch`, or require at
   least one attempt whose `t > fault_epoch` for holds above 30 s.
4. Add a harness test that truncates only the fault-boundary read (a
   `truncate_boundary` knob next to `truncate_final_cat`) and asserts INVALID,
   and a parser test where `fault_sequence`/`end_sequence` leave pre-fault rows
   in the window.

---

## 3. Minors

### R3-M1 (Minor) — `stop_client_traffic` accepts `unknown` as proof of termination

`tools/leak-lab/vm/run_phase.py:3261` returns True for
`state in ("inactive", "failed", "unknown")`.  Every other word (including
`deactivating`, `maintenance`, `activating`) is untrusted, and `inactive` is
what `systemctl is-active` prints for a unit the manager does not know, so
`unknown` is not needed to cover "unit gone".  If systemd cannot determine the
state while the writer process still runs, the stop is treated as proven and
the snapshot is labelled exact (`collect_client_probe(trusted=True)`), so a
leak written after the read is not latched.

Reproducer (`repro_phase.py` P15): patch `client_traffic_unit_state` to return
`unknown` when the real state is `inactive`, and patch
`read_client_probe_log_exact` to append a `m:false` row after the original read
(a still-live writer leaking one frame after the snapshot):

```
P15 is-active 'unknown' with a live writer  exit=0 result=PASS probe=PASS
    trusted=True read=exact leak=False   m:false in evidence=False
```

The guest log then holds a leak that the phase never sees.  It needs systemd to
report `unknown` while a process lives (unproven, hence Minor), but the trust
decision has no test and no documentation.  Fix: drop `unknown` from the tuple
(or require a follow-up `is-active` plus a `kill -0`/cgroup check).

### R3-M2 (Minor) — `client_neigh_ok` no longer scopes the neighbour by device

`tools/leak-lab/netplan.py:1069-1072` pipes the complete inventory into
`_NEIGH_CHECK_CODE` (`:379-395`), which matches on `dst` only; the previous
form was `ip -j neigh show "$1" dev "$2"`.  `client_neigh_state`
(`:1073-1076`) still matches `dst` **and** `dev`, and it decides whether
`client_neigh_ok` runs, so the only effect is over-strictness: an entry for the
same client IPv4 on another device with the same MAC and PERMANENT makes
`len(entries) != 1` → "client neighbour … is not this run's fixed permanent
entry" → teardown refuses and leaves the lab installed.

Reproducer H6/H6b (`repro_plan.py`, stub harness): a foreign `10.99.0.9` on
`docker0` is ignored and the teardown succeeds; a client neighbour with the
wrong MAC aborts with the state unchanged.  The stub keys its neighbour table
by IP, so I could not model two entries with the same `dst`; the condition
`len(entries) != 1` shows that case would also refuse.  Fix: pass the device
to `_NEIGH_CHECK_CODE` and filter both fields, as `_INVENTORY_NEIGH_CODE`
already does.

### R3-M3 (Minor, docs) — the binding design still says the router-only plan is
unchanged

`docs/rust-v2/leak-lab-m3-clients.md:305-308` ("the router plan is unchanged
when no client is configured") contradicts decision 6 and the code.  The
rendered no-client plan now differs from `605cce8` in exactly three regions
(`repro_plan.py`, `difflib` of `netplan.render_plan("eth0")`): the two
neighbour-helper commands, the new teardown refusal block, and the forward
rules:

```
-nft add rule inet vprlab forward iifname "vprlab0" oifname "eth0" accept
-nft add rule inet vprlab forward iifname "eth0" oifname "vprlab0" accept
+nft add rule inet vprlab forward iifname "vprlab0" oifname "eth0" ip saddr 10.250.0.0/24 accept
+nft add rule inet vprlab forward iifname "eth0" oifname "vprlab0" ip daddr 10.250.0.0/24 ct state established,related accept
+nft add rule inet vprlab forward iifname "vprlab0" oifname "eth0" drop
+nft add rule inet vprlab forward iifname "eth0" oifname "vprlab0" drop
```

The change is safe (see §4) and the design's own bullet at `:69-71` documents
it, but the "Tests" bullet at `:308` is now false and should be updated (it is
the sentence an operator would cite to argue the router-only plan is
byte-stable).

### R3-M4 (Minor, carried) — the 15 s gap still includes the post-hold QGA
round trips

`clientprobe.py:57` now allows 15 s and the density rule uses the same number,
which covers the traffic script's worst case (`vm/guest.py:942-1001`: two
`curl -m 3` with a 4 s subprocess timeout plus a 1 s sleep ≈ 9 s).  The gap
still ends at `probe_clock_stop`, which is read *after* the exit-node re-check,
the end-of-hold sequence read (up to `CLIENT_SEQUENCE_READ_TIMEOUT = 10 s` of
retries on a bad guest), `is-active` and `systemctl stop`
(`run_phase.py:4481-4494`: the stop, then the clock, then the collect).  On a
slow guest the last row → `clock_stop` gap can approach the limit.  This is a false-INVALID risk only (never a false
PASS); reading `probe_clock_stop` before the is-active/stop calls, or allowing
`hold/15 + 2` attempts, would bound it.

### R3-M5 (Minor, strictness) — `AdvertiseRoutes` absent from `prefs` is accepted

`run_phase.py:2931-2948`: `routes is None` returns `None` (no problem), so a
`tailscale debug prefs` document without the key (or with `null`) passes the
role check.  `tailscale debug prefs` always emits the key on a running
daemon, and a non-empty or non-list value is refused, so this is fail-closed
adjacent only.  A missing key could be treated like `client_prefs_unreadable`.

### Accepted / explicitly not re-raised

- Login URL on stderr (`run_phase.py:1772`): accepted risk (controller
  decision 12).  Not re-raised.
- Marker split across two frames: documented out of scope.
- Runtime nft rule verification: deferred by controller decision 8 (my M-F).
- A leak that exists only in the *omitted tail* of a truncated final read is
  INVALID, not LEAK (bytes never reached the host).  Verified: final `cat`
  truncated after a successful pre-fault control → INVALID
  `probe_log_truncated`, probe downgraded; leak in the kept prefix → LEAK.
  This is the documented, fail-safe GPT C2 trade-off.
- The end-of-hold exit-node check is a single sample (`run_phase.py:4451`),
  not 1 Hz as Opus N-2 suggested; the probe stream is the primary detector of
  a lost exit (a cleared exit makes `am.i.mullvad.net` report
  `mullvad_exit_ip=false` → LEAK), so I did not treat it as a hole.
- `clientprobe.evaluate_probe_log` trusts the `fault_sequence`/
  `end_sequence` parameters; the CLI (`clientprobe.py:450-480`) lets an
  operator pass any values.  The certification path is `run_phase`; the
  evaluator cannot validate boundaries it did not observe.  R3-I1's fix
  covers the runner side.

---

## 4. Host safety of the changed host plan

The fix changes the plan for **both** the client and the router-only render
(§R3-M3 diff).  I ran the rendered shell only through the repository's stub
`ip`/`nft`/`iptables`/`sysctl`/`tcpdump` harness (`repro_plan.py`).

**Surface (H2, both plans).** The only nft table touched is `inet vprlab`;
the only iptables chain touched is `DOCKER-USER` (insert/check/delete), with
`$OWNER` comments.  There is no `flush`, no `-F`, no `-P FORWARD`, no
`docker`, `tailscaled`, `tailscale`, `systemctl`, `max-vprouter`, `pkill` or
`modprobe` line outside comments, every `ip link/addr/neigh/tuntap` mutation
names `vprlab0`/`vprlab1`/`vprlab-tap*`/`vprlab-ctap*`, and the only
`sysctl -w` writes are `net.ipv6.conf.vprlab*.disable_ipv6`.  Nothing can
match the production router, Docker's own containers, or the host tailscaled
(there is no tailscale command in the plan at all).

**New forward rules (H1/H3).** In order: scoped outbound accept
(`iifname vprlab{0,1} oifname <wan> ip saddr 10.250.0.0/24`|`10.251.0.0/24`),
conntrack-scoped return accept (`ip daddr … ct state established,related`),
then explicit `drop` for both directions of each bridge.  The four vprlab0
rules and the four vprlab1 rules appear exactly once, after the existing
isolate/IPv6 drops and before `postrouting masquerade`, and the accepts precede
the drops (`accept-before-drop order: True`).  This matters because the base
chains are `policy accept` (`netplan.py:878-880`, one shared template for
both plans): without the drops a spoofed source outside the lab subnet matched
nothing.  The router VM's
host-visible egress is `10.250.0.2`-sourced (it MASQUERADEs inside the guest,
`router.nft:24`), so the scoped accept covers it; return traffic is
conntrack-established.  The pre-existing `DOCKER-USER` return accept already
required `ESTABLISHED,RELATED`, and the plan documents Docker's FORWARD policy
as DROP, so on a Docker host the new nft drops change no effective lab
behaviour; on a host whose FORWARD policy is ACCEPT they only harden the lab
(`vprlab0`/`vprlab1` matches; production interfaces are never named).  The
preflight reports but does not require the DROP policy
(`netplan.py:1679-1685`), which is exactly why decision 6 is worth having.

**Setup / teardown (H1b, H3b).** Router-only and `--client 1` setup both end
rc 0 with the expected links, neighbours, `DOCKER-USER` accepts, table and
`owner.json` (`clients: []` / `[1]`); teardown then leaves
`links=[] neigh=[] rules=[] table=None owner=False` in both cases.  No
`vprlab*` object survives, and no production object is touched.

**Unfiltered `ip -j neigh` parsing (H6, stub models iproute2).**
`client_neigh_state` filters `dst` **and** `dev` in Python, so a neighbour on
another device cannot be mistaken for the client's, and a missing `vprlab1`
no longer aborts with `Cannot find device` (the old filtered form did).  A
foreign `10.99.0.9` on `docker0` is left untouched and does not block
teardown; the client's `10.251.0.2` neighbour is removed.  Both helpers are
read-only and emit only an exit status.  Residual: R3-M2 (dev not checked in
`client_neigh_ok`; over-refusal only).

**Teardown refusal on unattributed client residue (H4).** With an M2-era
`owner.json` (no `clients` key) and a state holding `vprlab1`,
`vprlab-ctap1`, the `10.251.0.2` neighbour and both client `DOCKER-USER`
accepts, the no-client teardown refuses **before any mutation**:

```
netplan: refusing teardown: vprlab1 exists but no owner client inventory names it
netplan: refusing teardown: vprlab-ctap1 exists but no owner client inventory names it
netplan: teardown aborted without changes; ownership verification failed
rc=1  state unchanged=True  owner preserved=True
```

The refusal lives inside `verify_ownership` (`netplan.py:1185-1199`), which is
called before `isolate_tap`/`delete_link`/`nft delete` (`:778-786`), so the
DROP table and the Docker accepts stay installed.  That is the intended
fail-closed behaviour for a residue the tool cannot attribute.  The
compatibility case that matters (M2-era owner, router-only state) still tears
down cleanly (H5: rc 0, everything removed).

**Not verified (out of scope, unchanged).** Whether the host's real
`iptables-nft` accepts the generated `ct state established,related` spelling
inside `inet` (it is the standard nftables syntax and the repo's own policy/
router tables use it), and the real-`ip` neighbour output shape beyond the
stub model the fix added (`test_leak_lab.py:5124`).  Review rules forbid
running `ip`/`nft`.

---

## 5. Router-only path — no regression

- AST comparison against `605cce8` (`repro_old.py`): the router-only functions
  `_run_phase_locked`, `scan_evidence`, `start_capture`, `stop_capture`,
  `run_phase`, `run_router_fault`, `wait_router_ready` are unchanged.  The
  changed names are `_run_client_phase_locked`, `check_admission`,
  `cleanup_client_units`, `client_identity_problems`, `collect_client_probe`,
  `combine_verdicts`, `login_phase_wait`, `read_client_probe_log`,
  `read_client_probe_log_exact`, `stop_client_traffic`,
  `wait_client_probe_control` plus five new helpers.
- `check_admission`: router path still calls it with the defaults
  (`capture_count=1`, `router_overlay=True`), so its budget is numerically
  identical; `max(0, …)` only affects the new `client-login` call.
- `login_phase_wait`: the new `stop_when_running` branch requires
  `client_login=True`, and the router call (`:5366-5374`) passes neither, so
  the router login behaviour is untouched.
- `combine_verdicts`: `leak_observed` defaults to False; the router path does
  not pass it.
- Harness: `RunPhaseTests._run("idle", duration=0.0)` with
  `_run_client_phase_locked` patched to raise → exit 0, `PASS`, no `client`
  key; duration 0 is still accepted for router-only phases.
- The *plan* is not unchanged (R3-M3), but as shown in §4 the difference is
  vprlab0-scoped only and behaviourally neutral on a Docker host.

---

## 6. Docs / fix-report accuracy

- Design and `leak-lab-vm.md` now match the code for the 15 s gap, the
  `s > S_fault`/`floor(hold/15)` rule, the unordered-clock check, the latched
  leak, the exact final read, the transient login unit, the 30 s floor, the
  fail-closed old-owner teardown, the unfiltered neighbour helpers and the
  decision-6 drops.  The `Setup and capture sections byte-identical` claim of
  earlier rounds no longer applies to the router plan (see R3-M3).
- `docs/rust-v2/leak-lab-m3-clients.md:308` is the one stale sentence
  (R3-M3).
- The fix report's statement that a partial/racy read "can never move"
  `S_fault` is the one behavioural claim that does not hold (R3-I1).
- Test counts (329/266) and the named new tests match what I ran.

---

## Verdict

The round-2 Criticals and Importants are genuinely fixed and I could not
reopen any of them in its normal path; the host-plan changes are scoped,
fail-closed and leave production objects, Docker and the host tailscaled
untouched; the router-only phase runner is unchanged.  But the fix anchors the
post-fault window to a sequence number read through a *tolerant, unverified*
boundary read: a partial boundary `cat` moves `S_fault` backwards, and with a
guest clock that does not advance across the boundary I reproduced an
end-to-end phase **PASS for a 30 s hold with no probe at all**, i.e. the same
false-PASS class as round 2.  That is an Important false PASS, so this review
does not clear M3; the fix is a length-verified boundary read (and refusing a
`cat` that did not complete).

Verdict: FAIL
