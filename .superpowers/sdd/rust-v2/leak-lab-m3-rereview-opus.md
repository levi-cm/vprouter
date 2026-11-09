# Leak-lab M3 re-review (Opus, independent, adversarial)

Scope: fix round `git diff b849e3c..605cce8` (branch rust/v2, commit 605cce8), binding design
`docs/rust-v2/leak-lab-m3-clients.md`. The reviewer modified no file except this report.
Scratch: /var/tmp/leaklab-m3r-opus (deleted at the end).

Status: complete.

## Reproducers (scratch, run by the reviewer)

- `repro_probe.py`: crafted probe logs against `clientprobe.evaluate_probe_log`.
- `repro_runphase.py`: subclass of the fake two-VM `vm.test_vm.ClientRunPhaseTests`,
  patching `test_vm.run_phase` (the module object the harness uses).
- `repro_gpt.py`: the GPT `orchestration.py`/`extra.py` cases adapted to the fixed
  function names (`wait_client_first_mullvad` no longer exists), plus the router-only check.
- `repro_scan.py`, `repro_plan.py`: crafted pcaps and stubbed generated shell (see below).

## 1. Earlier findings: verification

### Probe log and orchestration (Opus I-1, GPT C2/C3/I1/I3, Pi C1, Opus M-2, M-6)

| Case | Result at 605cce8 |
|---|---|
| Opus R1: unit "active" but silent after the fault (`client_traffic_unit_active` patched True, `stop-router`, 30 s) | INVALID, exit 2, `probe_post_fault_exit_missing`, `probe_post_fault_marker_missing` |
| Opus R2: stale earlier-phase line appended (`kill-container`) | INVALID (`probe_run_mismatch`, `probe_sequence_gap`, `probe_timestamp_regression`, `probe_timestamp_outside_window`, `probe_gap`) |
| GPT C3: `systemd-run` does nothing, stale same-run-id log pre-seeded | INVALID: the runner's `rm -f` empties it, then `client_not_routed` |
| GPT C2: `stat`/`sha256sum` full size, `cat` returns a prefix without the final leak line | INVALID (`probe_log_truncated`). The leak bytes never reached the host, so LEAK cannot be shown |
| Leak `ok:true,m:false` / `m:null` appended at the end of a `stop-router` hold | LEAK, exit 1 |
| Crafted logs: no post-fault probe; stale log; stale prefix + current; 11 s gap; all markers failed | all INVALID with the expected codes |
| Crafted logs: leak + malformed tail (Opus M-6, GPT I1); `ok` + `m:null`; leak with a foreign `r` | all LEAK |
| GPT I4: duplicate-key line with secret text | INVALID `probe_log_malformed`; secret absent from phase.json, stdout and stderr |

Fixed. The probe log is now bound to the run (`r`, gap-free `s`, window
`[probe_clock_start, probe_clock_stop]`, non-decreasing `t`, gap <= 10 s, at least one
post-fault exit and marker attempt, pre-fault marker success). The unit must be active at the
end of the hold (`run_phase.py:4226-4230`). The final read must be exact
(`run_phase.py:3208-3250`). The log is collected from `finally` (`run_phase.py:4287-4302`).
LEAK is computed independently of every quality flag (`clientprobe.py:279-290`).

### Exit-node identity (GPT C4/I2, Pi I1, Opus M-4/M-5)

| Case | Result |
|---|---|
| No exit node set, `Self.ExitNode: true` | INVALID (Refusal: no `ExitNodeStatus` for the router ID) |
| Wrong peer active (`ExitNodeStatus.ID` = other) | INVALID |
| Wrong `Self.HostName`, valid DNSName | INVALID |

Fixed. `client_find_router_peer` (`run_phase.py:2959-3012`) needs exactly one peer with the
router's own `Self.ID`, the exact HostName, no HostName collision, `ExitNodeOption`, online, and
an IPv4 from the router's own `TailscaleIPs`. `client_peer_is_active` (`run_phase.py:3029-3049`)
needs `ExitNodeStatus.ID` == router ID. The `Self.ExitNode` shortcut is gone.

### Secrecy (Opus I-2, Pi M8)

Fixed. `h`/`hashlib` are gone from the traffic script (`vm/guest.py:895-1000`), and
`clientprobe.parse_line` rejects any extra key (`unexpected_keys`).

### Client capture scanner (GPT C1, Opus M-7, Pi M5/M6, GPT M1)

`repro_scan.py`, crafted pcaps:

| Case | Result |
|---|---|
| good before/after controls | PASS |
| forged non-Ethernet control bytes; both nonces in one frame | INVALID (`client_control_wrong_tuple`, `missing_client_controls`) |
| reversed records with forged timestamps | INVALID (`capture_timestamp_regression`, `client_control_order`) |
| after-control inside a TCP frame to 198.51.100.99:80 (Opus M-7) | INVALID |
| control from the wrong source MAC | INVALID |
| duplicated before-control | INVALID (`client_control_duplicate`) |
| global snaplen 65535 (Pi M6) | INVALID (`capture_snaplen_mismatch`) |
| marker on the client tap / router tap; client control on the router tap | LEAK |
| kernel drops | INVALID |

Fixed (`clientscan.py:63-101`, `:262-269`, `:339-351`).

### Host plan, owner record and admission (Opus M-3, Pi I2/I3, Pi M1/M2)

`repro_plan.py` runs the generated shell through the repository's own stub harness
(`test_leak_lab._prepare_stub_lab`: PATH starts with stub `ip`, `nft`, `iptables`, `sysctl`,
`tcpdump`; `VPRLAB_RUN_DIR` in scratch):

| Case | Result |
|---|---|
| P0 `--client 1` setup, then no-client teardown | rc 0; `vprlab1`, `vprlab-ctap1`, both client DOCKER-USER rules and owner.json removed |
| P1 M2-era owner.json without a `"clients"` key, router-only lab, no-client teardown | rc 0; everything removed (`document.get("clients", [])`) |
| P2 same owner, teardown with a `--client 1` plan | rc 0; absent client objects are tolerated |

- The no-client setup and capture sections are byte-identical to 888f0d4 except for
  `"clients": []` in owner.json. I diffed `render_plan('enp1s0')` from both trees; only the
  dynamic client teardown text was added.
- `hostcheck.load_owner_token` (`vm/hostcheck.py:132-165`) ignores the extra key, so the M2
  runner still accepts the new owner record.
- `check_name_collisions` always inventories `vprlab1` and `vprlab-ctap1..9`
  (`netplan.py:1531-1536`).
- Admission (`run_phase.py:1881-1928`): the client call passes `capture_count=2` and
  `client_overlay=True`. The router path keeps the defaults, so its formula is unchanged.

Fixed. See N-4 for a residual teardown liveness defect that the repository stub cannot model.

### Router-only path (task item 3)

- AST comparison against 888f0d4 and b849e3c: `_run_phase_locked`, `scan_evidence`,
  `start_capture`, `stop_capture` and `poweroff_vm` are unchanged. Against b849e3c,
  `run_phase`, `CaptureGuard`, `run_router_fault`, `login_phase_wait` and `verify_host_lab`
  are also unchanged.
- `check_admission` changed only in the new keyword defaults and the message text.
- GPT's router-only harness case: `RunPhaseTests._run('idle')` with
  `_run_client_phase_locked` patched to raise → exit 0, PASS, no `client` key.
- A router-only setup and teardown (P1) works with both old and new owner records.

No regression found.

### Other earlier Minors

| ID | Status at 605cce8 |
|---|---|
| Opus M-1 (capture not attached to its guard) | Fixed (`run_phase.py:3867-3868`). Repro H6: dead client tcpdump → `capture_ended_early`, INVALID |
| Opus M-2 (vacuous marker) | Fixed. Crafted "all markers failed" gives `client_marker_not_sent`. The runner also waits for it |
| Opus M-5 (dead role checks) | Fixed (`run_phase.py:2864-2895`) |
| Opus M-8 overflow line | Fixed (`vm/guest.py` `emit`; `clientprobe.py:269-271`) |
| Opus M-8 tarball hash-then-copy | Fixed. One fd with `O_NOFOLLOW`, hashed while copying, and the staged copy is re-hashed against the pinned digest (`vm/provision.py:464-512`). The parent's ancestry is checked when running as root (`:839-845`) |
| Opus M-8 exit-node clear races tailscaled | Fixed. Order is wait Running → clear → prove cleared → before-control (`run_phase.py:4015-4033`) |
| Opus M-8 client nft rules not re-verified at runtime; unused nonces | Not fixed, by decision. Still Minor (see N-6) |
| Opus M-9 / Pi M3/M4 docs | Fixed. Docstring path, flow order and the secrecy paragraph now match the code |
| Pi M12 CLI without epochs | Fixed. All binding arguments are required |
| GPT M2 missing verdict | Fixed. `combine_verdicts` gives INVALID unless another side is LEAK |
| GPT I5 / Pi M9 login URL on stderr | Accepted risk. Not re-raised |

## 2. New findings in the fix diff

No Critical or Important finding. I found no new false-PASS path. Every path below ends in
INVALID or LEAK, or needs a client-side change that nothing in the lab makes.

### N-1 (Minor, LEAK shown as INVALID): a pre-fault leak the runner saw becomes INVALID if the final read fails

- Files:
  - `run_phase.py:4148-4152`: the tolerant pre-fault read sees `ok:true,m:false`, calls
    `note("client_real_ip")` and raises.
  - `run_phase.py:3253-3280` (`collect_client_probe`): on `probe_log_unreadable` (cat
    non-zero), `probe_log_oversized`, or an exception, it persists `b""`.
  - `run_phase.py:3545-3568` (`combine_verdicts`): only looks at verdict strings, so the
    `client_real_ip` error never becomes LEAK.
- Reproducer (`repro_runphase.py` H3/H4, `leak_only=True`):
  - `read_client_probe_log_exact` patched to return `(None, "probe_log_unreadable")`:
    exit 2, `result=INVALID`, errors `['client_real_ip', 'phase_exception:Refusal',
    'probe_log_unreadable', ...]`.
  - The same read raising `QGAError`: exit 2, INVALID, errors contain
    `probe_collection_failed`.
  - The bytes that proved the leak were read by the host and then dropped.
- Impact:
  - This is not a false PASS. The reason string still says `client_real_ip`.
  - It does break "LEAK is never masked" (decision: LEAK never masked). A leak is reported as
    exit 2 or INVALID, which operators usually re-run.
- Fix:
  - Keep the tolerant-read bytes that set `flags["leak"]`. Persist them, for example as
    `client-probe-prefault.jsonl` with its hash, whenever the exact read does not succeed.
  - Have `combine_verdicts` return LEAK when `client_real_ip` is in `errors`.

### N-2 (Minor, exit-node binding not re-proved): nothing checks after the fault that the client still uses the router's exit node

- Files: `run_phase.py:4216-4232`. After `wait_client_exit_node` (before the traffic
  starts), `ExitNodeStatus` is never read again. The hold ends with only
  `client_traffic_unit_active`, then stop and collect.
- Reproducer (`repro_runphase.py` H5): `stop-router`, 30 s. Just before the end-of-hold check,
  the fake client reports `ExitNodeStatus.ID = "some-other-exit"` (online). Result: exit 0,
  PASS.
- Impact:
  - If the client ever moved to another exit node with Mullvad egress, every check would
    still pass: probes `m:true`, the marker encrypted, the router tap clean.
  - Lab client traffic during the fault would then not have crossed the lab router.
  - Nothing in the lab triggers such a switch. `--exit-node=<IP>` has no failover, and no
    auto-exit-node policy is set. A cleared exit node sends traffic direct, which the probes
    report as LEAK. So this is defence in depth, not a reproduced live path.
- Fix:
  - Before `stop_client_traffic`, require `client_peer_is_active(status, router_id,
    exit_ipv4)` once more and make the phase INVALID otherwise.
  - Optionally sample it at about 1 Hz during the hold, as the guard already polls.

### N-3 (Minor): a client phase can PASS with `--duration 0`

- Files: `run_phase.py:3590` accepts any duration from 0 to 3600.
  `clientprobe.evaluate_probe_log` needs only one exit and one marker attempt at or after
  `post_fault_epoch`.
- Reproducers:
  - Harness H7: `stop-router --duration 0` gives PASS.
  - Crafted log D0 (`post=1021`, `stop=1023`, one post-fault loop) gives PASS.
- Impact:
  - The certificate "client traffic through test exit node" can rest on one post-fault probe
    loop, about 2 s of fault, even though the stopped-router state lasts for the hold.
  - This is an operator-choice weakness, not a leak path.
- Fix: for client phases other than idle, require `--duration` to be at least a few probe
  periods, for example `>= 30`. Or record `hold_seconds` and mark short holds
  non-certifying.

### N-4 (Minor, host residue, fail-closed; pre-existing for client plans, newly reachable from no-client teardown): dev-filtered `ip -j neigh show` helpers

- Files: `netplan.py:1064-1070` (`client_neigh_ok`, `client_neigh_state`), used by the
  dynamic `verify_ownership` and teardown blocks (`netplan.py:1140-1220`).
- Both helpers run `ip -j neigh show <ip> dev vprlab1`. As I understand iproute2's
  `ipneigh.c`:
  - with a device filter, it omits the `"dev"` key, so `client_neigh_state` always says
    "absent" and the client-neighbour ownership check is vacuous;
  - with a missing device, it prints `Cannot find device` and nothing on stdout, so
    `client_neigh_state` exits 2 and teardown refuses.
- The repository stub prints `"dev"` and never fails for a missing device, so the tests cannot
  see this.
- Reproducer (`repro_plan.py`, stub variant `REAL_NEIGH` modelling the behaviour above, no
  real `ip`):
  - P3: client setup, then no-client teardown → rc 0. The neighbour is reported "absent" but
    removed with the bridge.
  - P4: owner lists client 1 but `vprlab1` is already gone → rc 1, "teardown aborted without
    changes". `vprlab-tap0`, `vprlab0`, `vprlab-ctap1` and 4 DOCKER-USER accepts are left, and
    owner.json is kept.
  - P7: `--client 1` setup fails at `ip link add` (before `vprlab1` exists) → the EXIT-trap
    teardown refuses, and owner.json and `vprlab-tap0` are left. With the repository stub
    (P5/P6) both cases succeed.
- Not reproduced against a real `ip`: the review rules forbid running it.
- Impact:
  - It fails closed, so protections stay installed and nothing leaks.
  - It does leave lab residue and accepts on the production host, and needs manual cleanup.
  - Since this round, a no-client teardown also reaches it when owner.json lists clients.
- Fix:
  - Use the unfiltered `ip -j neigh show`, as the router `neigh_state` does, and filter `dst`
    and `dev` in Python.
  - When a complete link inventory proves `vprlab1` absent, treat its neighbours as absent.
  - Teach the stub iproute2's filtered-output shape.

### N-5 (Minor): the probe gap budget is tight against the script's worst-case loop

- Files:
  - `vm/guest.py:943-1000`: each loop runs two curls with `-m 3` and a subprocess timeout of
    4 s, then sleeps 1 s. Up to about 9 s plus process spawn on a 256 MiB, 1-vCPU guest.
  - `clientprobe.py:317-331`: the gap limit is 10 s, and it includes the last line to
    `probe_clock_stop`. That clock is read after the QGA `is-active` and `systemctl stop`
    round trips (`run_phase.py:4226-4233`).
- Impact: spurious INVALID during faults where both curls time out. It is never a false
  PASS. Not reproduced live.
- Fix: read `probe_clock_stop` before the is-active and stop calls, or allow
  `max_gap = loop worst case + QGA slack`, for example 15 s, and document it.

### N-6 (Minor, carried / notes)

- **Client nft rules still not re-verified at runtime.** Carried from Opus M-8 and Pi M10,
  skipped by decision.
- **The nft source scoping added for Pi M1 does nothing.**
  - `netplan.py:1120-1121` adds `ip saddr`/`ip daddr 10.251.0.0/24` to the client forward
    accepts. The forward chain is `policy accept` (`netplan.py:880`), so a packet from
    `vprlab1` to the WAN with a foreign source matches no rule and is still accepted by
    `inet vprlab`.
  - The real scoping is the DOCKER-USER `-s 10.251.0.0/24` accept followed by Docker's FORWARD
    DROP policy, the same as `vprlab0` in M2.
  - Not a regression. If source scoping is wanted, add
    `iifname "vprlab1" ip saddr != 10.251.0.0/24 drop`.
- **Router-only preflight is stricter.** `check_name_collisions` now refuses a no-client
  setup when any host address or route overlaps 10.251.0.0/24. This is conservative and
  intended, but it is a behaviour change for M2-only operators.
- **A truncated read leaves a misleading probe sub-verdict.** In the GPT C2 case the record
  shows `client.probe.verdict = PASS` (it was evaluated over the received prefix) while the
  phase is INVALID through `errors`. Consider forcing the probe sub-verdict to INVALID when
  `probe_log_read != "exact"`.
- **A leak past the 1 MiB parse cap is reported as INVALID** (crafted log BIG). The traffic
  script cannot produce such a log, so only a hostile guest could. Acceptable.
- **Secrecy.**
  - No guest bytes reach phase.json, stdout or stderr (GPT I4 rerun).
  - `client.probe_ips` holds only the host-resolved public service IPs.
  - No Tailscale IPs or status JSON are recorded.
  - The probe log holds only booleans, the run id, sequence numbers and guest times.

## Test suites (run once each, from tools/leak-lab)

- `python3 -B -W error -m unittest test_leak_lab`: **Ran 320 tests, OK**
- `python3 -B -W error -m unittest vm.test_vm`: **Ran 252 tests, OK**

## Method notes

- I ran no sudo, QEMU, tcpdump, ip, nft, iptables, docker, useradd or network command. The
  generated shell ran only against the stub harness in scratch.
- The first `repro_runphase.py` run patched `vm.run_phase` instead of the harness's
  `run_phase` module object, so its patches were inert. The results above come from the
  corrected run (`run_phase = test_vm.run_phase`).
- Scratch `/var/tmp/leaklab-m3r-opus` was deleted at the end.

## Verdict

PASS (no Critical, no Important). Every Critical and Important finding from the three earlier
reports is fixed and was re-verified with reproducers. My own earlier I-1 and I-2 are fixed,
and of my nine Minors all but the deliberately skipped ones are fixed. New Minors: N-1 to N-6.
N-1 (a seen pre-fault leak downgraded to INVALID) and N-2 (no end-of-hold exit-node
re-check) are the ones I recommend fixing before live M3 runs.
