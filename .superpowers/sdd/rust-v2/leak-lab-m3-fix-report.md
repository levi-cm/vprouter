# Leak-lab M3 fix round report

Milestone: M3 real client traffic through the test exit node — fix round for
three failed reviews (`b849e3c`).
Repository: `/DATA/AppData/vprouter-rust-v2` (branch `rust/v2`).
Date: 2026-11-09.

All work is in the working tree; nothing was staged, committed or pushed.  No
privileged command (sudo, QEMU, tcpdump, ip, nft, iptables, docker, useradd,
systemctl or network execution) was run.  Generated shell was exercised only
through the existing stub harness in a temporary directory.  Scratch
`/var/tmp/leaklab-m3-fix` (including an extracted `b849e3c` tree used to rerun
the review reproducers) was deleted at the end.

## Finding-to-fix map

Line numbers are from the fixed tree.

### GPT review

| ID | Fix |
|---|---|
| C1 forged/reordered controls | `clientscan.py:63` parses each control as Ethernet II / IPv4 (no options/fragments) / UDP 39001 from the client VM MAC+IPv4 to the bridge MAC+IPv4 with the exact payload; `:341` requires record order, timestamp order and rejects any capture timestamp regression (`:266`). Tests: `ClientScanTests.test_forged_non_ethernet_control_bytes_are_invalid`, `test_control_identity_and_udp_tuple_are_exact`, `test_reversed_records_with_forged_timestamps_are_invalid`. |
| I1 malformed suffix masks leak | `clientprobe.py:153` parses line by line and keeps every well-formed entry; `:212` computes LEAK independently of quality flags. Test: `test_malformed_tail_never_masks_a_real_ip_leak`. |
| C2 truncated QGA read | `run_phase.py:3208` requires guest `stat` size == bytes read, SHA-256 equal and a final newline; `:3253` persists even rejected bytes so a readable leak still wins. Tests: `test_truncated_final_probe_read_is_invalid_never_pass`, `ClientExitBindingTests.test_truncated_exact_read_keeps_readable_leak_evidence`. |
| C3 stale log / unit never ran | `run_phase.py:3125` deletes and proves absent the log before launch; `clientprobe.py:212` binds every line to `r`/`s`, launch/stop clock window, gap ≤ 10 s and post-action attempts; `run_phase.py:3317` makes RuntimeMaxSec cover the whole phase; `:4227` requires `systemctl is-active` at the end of the hold. Tests: `test_unit_that_exited_after_one_probe_is_invalid`, `test_inactive_unit_at_the_end_of_the_hold_is_invalid`, `ClientProbeTests.test_sequence_must_start_at_one_without_gaps`, `test_run_id_must_match_the_phase`, `test_timestamps_must_not_regress_or_leave_the_window`, `test_probe_gap_above_ten_seconds_is_invalid`, `test_post_fault_exit_and_marker_attempts_are_required`. |
| C4 `Self.ExitNode` bypass | `run_phase.py:2928` reads the router's own `Self.ID`/IPv4s through QGA; `:2959` requires exactly one peer with that ID, exact HostName, `ExitNodeOption` and online; `:3029` requires `ExitNodeStatus` with that ID, the selected IPv4 and `Online: true`. The boolean shortcut is gone. Tests: `ClientExitBindingTests` (all), `test_wrong_exit_peer_status_and_self_boolean_is_invalid`. |
| I2 HostName fallback | `run_phase.py:2835` makes `Self.HostName` authoritative and refuses a disagreeing `DNSName`; DNS is used only when HostName is missing. Test: `ClientExitBindingTests.test_client_identity_rejects_a_conflicting_hostname_and_dns`, `test_wrong_client_hostname_with_valid_dns_name_is_invalid`. |
| I3 pre-fault refusal discards leak | `run_phase.py:3345` returns a leak immediately from the pre-fault wait; `:4291` collects the log from `finally` before cleanup/poweroff. Tests: `test_pre_fault_real_ip_leak_returns_leak_and_collects_the_log`, `test_probe_log_is_collected_after_a_runner_exception`. |
| I4 guest bytes in diagnostics | `clientprobe.py:61` errors are fixed codes plus line numbers; `evaluate_probe_log` returns `problems: [{line, code}]`; no guest key/value is interpolated anywhere in `phase.json`, `client-scan.json`, stdout or stderr. Test: `test_duplicate_key_probe_line_never_copies_guest_bytes`. |
| I5 login URL on stderr | `skipped: accepted risk` per controller decision 12; retained router behaviour and recorded as an explicit exception in `docs/rust-v2/leak-lab-m3-clients.md` (Evidence section) and `docs/rust-v2/leak-lab-vm.md`. Test asserts the accepted behaviour: `test_client_login_boots_only_the_client_and_writes_the_url`. |
| M1 duplicate control LEAK | `clientscan.py:347` classifies duplicates as INVALID; a marker finding independently makes the verdict LEAK. Test: `test_replayed_control_is_invalid_unless_a_leak_is_also_seen`. |
| M2 missing verdict | `run_phase.py:3545` treats missing/unknown verdicts as INVALID unless another side is LEAK. Test: `CombinedVerdictTests.test_missing_or_unknown_verdict_is_invalid_unless_a_leak_exists`. |

### Opus review

| ID | Fix |
|---|---|
| I-1 traffic during the fault / stale log | Same as GPT C3: `run_phase.py:3125`, `:3317`, `:4227`, `clientprobe.py:212`. |
| I-2 reversible `h` field | Dropped from the script and parser; only booleans remain (`vm/guest.py:895`, `clientprobe.py` line schema). Test: `test_client_traffic_script_uses_curl_resolve_and_never_records_the_ip` asserts `"h"`/`hashlib` are absent. |
| M-1 capture guards | `run_phase.py:3868` attaches the client tcpdump to the client guard and the router tcpdump to the router guard. Test: `test_dead_client_capture_is_detected_by_its_guard`. |
| M-2 vacuous marker check | `clientprobe.py:212` requires a successful pre-fault marker probe (`client_marker_not_sent` otherwise); `run_phase.py:3345` waits for it. Tests: `test_successful_pre_fault_marker_is_required`, `ClientRunPhaseTests.test_marker_failure_before_the_fault_is_invalid`. |
| M-3 owner record / no-client teardown | `netplan.py:271` writes `"clients"` into `owner.json`; `:287`/`:594` read and validate it; `:1010` unions plan/owner indexes; dynamic verify/isolate/delete blocks remove the bridge, taps, neighbours and owned DOCKER-USER rules regardless of `--client`; `:1529` inventories `vprlab1`/`vprlab-ctap1..9` in the no-client collision check. Test: `test_no_client_teardown_removes_the_clients_recorded_in_owner` (plus updated collision test). |
| M-4 peer HostName first-match | `run_phase.py:2959` binds by ID and refuses duplicate IDs/HostName collisions. Tests: `ClientExitBindingTests.test_peer_is_bound_by_id_and_refuses_hostname_collisions`. |
| M-5 dead role checks | `run_phase.py:2875`/`:2856` use `ExitNodeOption`/`ExitNode` and `PrimaryRoutes`/`AllowedIPs` (the fields Tailscale emits). Test: `test_client_role_checks_use_real_route_and_exit_fields`. |
| M-6 malformed tail masks LEAK | Same as GPT I1. |
| M-7 controls matched anywhere | Same as GPT C1. |
| M-8 log cap can hide a line | `vm/guest.py:895` writes a final `{"k":"overflow"}` line; `clientprobe.py:270` makes it INVALID. Test: `test_overflow_line_is_invalid`. |
| M-8 `m: null` rule dead | `skipped: no behaviour change`; the rule stays as defence in depth, and an unparseable answer is still `ok:false`. |
| M-8 tarball hash-then-copy | `vm/provision.py:464` hashes while copying and re-hashes the staged copy against the pinned digest; `:841` validates the tarball ancestry when root. Test: `test_staged_tailscale_copy_is_rehashed_after_copy`. |
| M-8 exit-node clear races tailscaled | `run_phase.py:4020` waits for `BackendState == Running` first, then clears and waits until `ExitNodeStatus` is gone/`Self.ExitNode` false (`:3110`). Test: `test_tailscaled_is_running_before_the_exit_node_is_cleared`. |
| M-8 client nft rules not re-verified | `skipped: exact nft-JSON rule-expression inventory is not a cheap change`; plan-level tests and the generated-plan review cover the rule text, and the live check still verifies the table comment/chains. Also Pi M10. |
| M-8 unused nonces | `skipped: harmless`; no security effect. |
| M-9 docs vs code | `docs/rust-v2/leak-lab-vm.md` flow/secrecy/probe sections and `clientprobe.py` docstring updated; design updated. |

### Pi review

| ID | Fix |
|---|---|
| C1 no traffic during the fault | Same as GPT C3. |
| I1 `Self.ExitNode` fallback | Same as GPT C4. |
| I2 no-client teardown residue | Same as Opus M-3. |
| I3 admission | `run_phase.py:1881` accepts `capture_count`/`client_overlay`; the client call `:3632` reserves two capture caps and both overlays. Test: `ClientAdmissionTests.test_two_captures_and_two_overlays_are_reserved`. |
| M1 forward accepts not source-scoped | `netplan.py:1114-1115` adds `ip saddr`/`ip daddr 10.251.0.0/24`. Test updated in `test_client_plan_has_the_client_bridge_tap_rules_and_nat`. |
| M2 no-client plan blank lines | `netplan.py` `_substitute` removes the whole line of an empty block placeholder; the setup and capture sections of the no-client plan are now byte-identical to `888f0d4`, and no triple newline remains. Test: `test_router_plan_is_unchanged_without_clients`. The only added text is the decision-9 dynamic client teardown. |
| M3 wrong probe-log path | `clientprobe.py` docstring now says `/var/lib/vprlab/client-probe.jsonl`. |
| M4 before-control order | Code now waits for tailscaled, clears, proves cleared, then sends the before-control; docs updated (`docs/rust-v2/leak-lab-vm.md`, design step 3/4). |
| M5 raw-substring controls | Same as GPT C1. |
| M6 snaplen/argv binding | `clientscan.py:268` requires the pcap global snaplen to be the full-frame `262144` in addition to the exact `-s 0` argv. Test: `test_capture_snaplen_must_be_full_frame`. |
| M7 marker split across frames | `skipped: accepted design limitation`; documented out of scope, unchanged. |
| M8 reversible `h` | Same as Opus I-2. |
| M9 login URL on stderr | `skipped: accepted risk` (decision 12), documented exception. |
| M10 client nft rules not re-verified | `skipped: same reason as Opus M-8` (not a cheap exact check; deferred). |
| M11 fake client scanner in orchestration | `vm/test_vm.py` `ClientRunPhaseTests` now writes real pcap records/stats and `fake_run` calls the real `clientscan.scan_client_capture`; test `test_orchestration_runs_the_real_clientscan_over_crafted_pcaps` asserts the report. |
| M12 clientprobe CLI without epoch | `clientprobe.py:389` requires `--fault-epoch`, `--post-fault-epoch`, `--clock-start`, `--clock-stop` and `--run-id`. Test: `test_cli_requires_the_fault_epoch`. |

## Regression tests checked against `b849e3c`

An extracted `b849e3c` tree (`git archive`) was used to rerun the review
reproducers.  The old code produced the failures the reviews reported; the new
tests exercise the same paths and pass on the fixed tree:

| Reproducer | `b849e3c` result | Fixed result |
|---|---|---|
| Forged non-Ethernet controls | `PASS`, `invalid_reasons=[]` | `INVALID` (`client_control_wrong_tuple`, `missing_client_controls`) |
| Reversed records with forged timestamps | `PASS` | `INVALID` (`client_control_order`, `capture_timestamp_regression`) |
| Leak line followed by a malformed tail | `INVALID` `probe_log_malformed` | `LEAK` (plus `probe_log_malformed`) |
| Ancient success / missing final newline / out-of-order probe lines | `PASS` | `INVALID` (`probe_run_mismatch` / `probe_log_truncated` / `probe_timestamp_regression`) |
| Unit never runs, stale log | phase `PASS`, zero `traffic_start` events | `INVALID` (`probe_post_fault_*`, `probe_gap`, unit checks) |
| `cat` returns a prefix while `stat` reports full size | phase `PASS` | `INVALID` (`probe_log_truncated`); a readable leak in the prefix is `LEAK` |
| No exit node / wrong peer plus `Self.ExitNode: true` | phase `PASS` | `INVALID` |
| Conflicting `Self.HostName` with valid DNS | phase `PASS` | `INVALID` |
| Pre-fault real-IP leak | `INVALID`, log not collected | `LEAK`, log collected in `finally` |
| Duplicate-key guest line in diagnostics | secret text in `phase.json` | `INVALID`; secret absent from `phase.json`, stdout, stderr |
| No-client teardown after a client setup | bridge/tap/neighbour/DOCKER-USER left, owner removed | all recorded client objects removed; owner removed last |
| Two-guest admission at 3 GiB evidence / 5 GiB state | admitted | refused; 2 capture caps + 4+2 GiB overlays + headroom required |
| Client scanner in orchestration | synthetic `{"verdict":"PASS"}` | real scanner over crafted pcaps |
| No-client plan | placeholder blank lines | setup/capture sections byte-identical to `888f0d4`; no stray blank lines |

`client-login` still prints the login URL to stderr in both trees; this is the
accepted exception (decision 12), not a regression.

## Tests run (all pass)

From `tools/leak-lab`:

- `python3 -B -W error -m unittest test_leak_lab` — **320 tests, OK**
- `python3 -B -W error -m unittest vm.test_vm` — **252 tests, OK**
- `python3 -B -m py_compile` on `clientprobe.py`, `clientscan.py`,
  `netplan.py`, `vm/guest.py`, `vm/provision.py`, `vm/run_phase.py`,
  `vm/test_vm.py`, `test_leak_lab.py` — OK
- `sh -n` on rendered no-client, `--client 1` and `--client 1,2` plans — OK
- `git diff --check` — OK

New regression tests are the ones named in the tables above; the existing
router-only suites still pass and the router setup/capture sections of the
no-client plan are unchanged.  The only intended no-client plan change is the
dynamic teardown of client objects recorded in `owner.json` (controller
decision 9), which is a no-op when the owner record has no clients.

## Updated operator commands

Client provisioning and login are unchanged:

```sh
python3 -B tools/leak-lab/vm/provision.py --client --index 1 \
  --tailscale-tar /root/vprlab/tailscale_1.104.5_amd64.tgz

python3 -B tools/leak-lab/vm/run_phase.py \
  --phase client-login --client 1 --duration 900 \
  --used-nonces /root/leaklab-used-nonces.txt
```

A leak phase with the client is unchanged on the command line:

```sh
python3 -B tools/leak-lab/vm/run_phase.py \
  --phase idle --client 1 --duration 120 --index 1 \
  --profile-file /root/vprouter-lab.conf \
  --used-nonces /root/leaklab-used-nonces.txt
```

Host plan: `--client N` still creates the client objects; the collision
preflight now sees `vprlab1`/`vprlab-ctap1..9` and the client subnet even when
`--client` is omitted, and teardown reads the client list from `owner.json`:

```sh
python3 -B tools/leak-lab/netplan.py \
  --wan-interface <wan> --client 1 > /root/vprlab-lab.sh
sh /root/vprlab-lab.sh setup
# ... phases ...
sh /root/vprlab-lab.sh teardown   # removes recorded clients even without --client
```

The standalone probe-log tool now requires the full clock/binding arguments:

```sh
python3 -B tools/leak-lab/clientprobe.py --probe-log <file> \
  --fault-epoch <guest-sec> --post-fault-epoch <guest-sec> \
  --clock-start <guest-sec> --clock-stop <guest-sec> --run-id <32 hex>
```

## Skipped Minors (reasons)

- **Opus M-8 / Pi M10 — client nft rules not re-verified at runtime.**
  Exact rule-expression verification over `nft -j` is not a cheap change and
  is not in the controller's named cheap-Minor set; the generated-plan tests,
  teardown ownership checks and the live table/chain check remain. Deferred.
- **Opus M-8 — `m: null` rule is dead in practice.** The rule is retained as
  defence in depth; no script or verdict change is needed.
- **Opus M-8 — unused nonces in `client-login`.** Harmless; no security effect.
- **Pi M7 — marker split across two frames.** Explicitly out of scope in the
  binding design; unchanged accepted false-negative.
- **Pi M9 / GPT I5 — login URL on stderr.** Accepted risk (decision 12),
  documented rather than changed.

---

# Fix round 2

Milestone: M3 — fix round for the three re-reviews of `605cce8`
(`leak-lab-m3-rereview-gpt.md`, `-opus.md`, `-pi.md`).
Repository: `/DATA/AppData/vprouter-rust-v2` (branch `rust/v2`).
Date: 2026-11-09.

All work is in the working tree; nothing was staged, committed or pushed.  No
privileged command (sudo, QEMU, tcpdump, `ip`, `nft`, `iptables`, docker,
useradd, `systemctl` or network execution) was run.  Generated shell ran only
through the repository stub harness.  Scratch `/var/tmp/leaklab-m3-fix2`,
including an extracted `605cce8` tree used for the regression checks, was
deleted at the end.

## Finding-to-fix map

Line numbers are from the fixed working tree.

### New Criticals and Importants

| ID | Fix |
|---|---|
| GPT C1 — failed stop leaves a leak outside the snapshot | `stop_client_traffic` no longer masks the stop: the shell `|| true; ...; true` is gone, and the postcondition is a separate `systemctl is-active` read that must report `inactive`/`failed`/`unknown` before any exact read (`vm/run_phase.py:3236`, `:3225`).  The end-of-hold stop failure is a phase error (`:4481`); the finally path keeps `traffic_stop_proven=False` sticky so a later cleanup stop can never make the snapshot exact (`:4540-4578`); the boot-time stale-unit stop must also be proven (`:4086-4092`).  Tests: `test_vm.py:6850` (failed stop, leak appended on the later cleanup stop, result LEAK), `:6869` (stop returns 0 while active, INVALID). |
| GPT C2 / Pi I-1 — same-second or frozen clock certifies an unobserved hold | The runner records `S_fault` (last complete sequence after the action and its postcondition, `vm/run_phase.py:4426-4435`) and `S_end` (end of the hold, `:4462-4471`).  `evaluate_probe_log` counts a post-fault attempt only with `s > S_fault` (and `t >= post_fault_epoch`), requires at least one exit and one marker attempt, and requires `floor(hold / 15)` exit attempts with `S_fault < s <= S_end` (`clientprobe.py:270-290`, `:378-382`).  It also validates `clock_start <= fault_epoch <= post_fault_epoch <= clock_stop` (`:361-369`).  The gap allowance is 15 s (`clientprobe.py:57`).  A `--client` phase shorter than 30 s is refused (`vm/run_phase.py:138`, `:3762-3765`).  Tests: `test_leak_lab.py:5742`, `:5763`, `:5775`, `:5792` (parser); `test_vm.py:6949` (frozen clock, silent unit), `:6935` (active silent unit), `:6966` (duration refusal). |
| GPT I1 / Opus N-1 / Pi M-N — a seen LEAK is downgraded by a later read failure | A recognised non-Mullvad success is latched in `record["client"]["probe_leak_observed"]` whenever it is seen: pre-fault wait (`vm/run_phase.py:4358`), mid-phase boundary reads (`:4432`, `:4468`), tolerant/nonzero-`cat` bytes persisted by collection (`:3429`, `:4725`), and the final evaluation (`:4738`).  `combine_verdicts(..., leak_observed=True)` returns LEAK before every quality check (`:3707-3728`, call `:4768`).  `read_client_probe_log`/`read_client_probe_log_exact` keep the bounded stdout of a `cat` that exited non-zero (`:3278`, `:3308`), and the exact read still `cat`s and returns bounded bytes when the digest read failed (`:3330-3345`).  Tests: `test_vm.py:6880` (pre-fault leak + failed exact read), `:6896` (nonzero `cat` with a readable leak), `:6915` (sha256 failure still keeps the leak bytes). |
| Opus N-2 — exit node not re-verified at the end of the hold | Before stopping traffic, `ExitNodeStatus` must still name the router's own `Self.ID`, the selected IP and `Online`; otherwise `client_exit_node_lost` / INVALID (`vm/run_phase.py:4451-4459`).  Test: `test_vm.py:6912` (the fake switches to `some-other-exit` once traffic is active). |
| Opus N-3 — zero/short client hold PASSes | Minimum `--client` duration 30 s (`vm/run_phase.py:138`, `:3759`), plus the sequence-density requirement above.  Test: `test_vm.py:6966`. |
| Opus N-4 / Pi M-C — filtered `ip neigh` helpers, old-owner teardown edge | `client_neigh_ok`/`client_neigh_state` now read the complete unfiltered `ip -j neigh` inventory and filter `dst`/`dev` in Python, exactly like `neigh_state` (`netplan.py:1069-1076`).  The repository stub now models iproute2: the filtered form omits `dev` and a missing device exits 1 with `Cannot find device` (`test_leak_lab.py:5124`).  A no-client teardown refuses before mutation when `vprlab1` or any `vprlab-ctapN` exists without an owner/plan client inventory (`netplan.py:1185-1200`).  Tests: `test_leak_lab.py:4875` (helper shape), `:5080` (fail closed), `:5100` (missing bridge tolerated). |
| Opus N-5 — 10 s gap budget too tight | `MAX_PROBE_GAP_SECONDS = 15` and the hold density uses the same value (`clientprobe.py:57`, `:378`).  Test: `test_leak_lab.py:5792`. |
| Pi M-D — blocking `tailscale up` in `client-login` | `client-login` starts `tailscale up --reset ...` in the transient unit `vprlab-client-login` (`guest.py:87`, `vm/run_phase.py:4120-4135`) and `login_phase_wait` polls the URL and `BackendState` (`:1729-1778`), returning early once Running.  The fake blocks until authenticated and then releases (`test_vm.py:7004`). |
| Pi M-I — `client-login` over-reserves | `check_admission` gained `router_overlay` and allows `capture_count=0` (`vm/run_phase.py:1894-1941`); `client-login` passes 0 captures and no router overlay (`:3806-3808`).  Test: `test_vm.py:6023`. |

### Smaller items

| ID | Fix |
|---|---|
| Pi M-A — `evaluate_probe_log` silent `run_id=None` | `run_id` is a required keyword and is validated (`clientprobe.py:217-220`, `:247-248`).  Test: `test_leak_lab.py:5786`. |
| Pi M-B — present non-string HostName falls back to DNS | A present non-string `HostName` is refused (`vm/run_phase.py:2872-2875`); test added to `ClientExitBindingTests.test_client_identity_rejects_a_conflicting_hostname_and_dns`. |
| Pi M-G — truncation test armed at the wrong stop | The fake arms `truncate_cat` at the end-of-hold stop (`stop_count >= 2`), after the pre-fault control; the test asserts the control succeeded and the final read was truncated (`vm/test_vm.py:6817`). |
| Pi M-H — no slow/hung active-unit test | `silent_hold` models an active unit that writes nothing (`vm/test_vm.py:6935`); the frozen-clock variant is `:6949`. |
| Pi M-J — evidence-inside-state checks only the client | Both router and client state are checked (`vm/run_phase.py:3869-3881`).  Test: `test_vm.py:6971`. |
| Pi M-K — scoped accepts were not drops | After the scoped accepts, explicit drops for both bridges: `netplan.py:885-893` (vprlab0) and `:1126-1133` (vprlab1); the return accepts are conntrack-scoped.  Plan tests assert the ordering (`test_leak_lab.py:4820-4868`). |
| Pi M-L — PASS probe object with a read problem | A PASS probe report is downgraded to INVALID `probe_log_read_quality` when the final read was not exact; LEAK still wins (`vm/run_phase.py:4740-4747`).  Test: `test_vm.py:6977`. |
| Pi M-M — no `AdvertiseRoutes` check | `tailscale debug prefs` is read and a non-empty `AdvertiseRoutes` is refused (`vm/run_phase.py:2917-2948`), in both the traffic and login paths (`:4218`, `:4150`).  Test: `test_vm.py:6994`. |
| Pi M-F — runtime nft rule verification | **Skipped: deferred by controller decision 8**, consistent with the router path.  The generated-plan tests and the live table/chain/ownership checks remain; a modified plan is still caught by review and the plan tests. |
| Opus N-6 — nft source scoping did nothing | Addressed by decision 6: explicit drops after the scoped accepts for both bridges, so the `policy accept` base chain no longer accepts unscoped forwarded packets.  Runtime rule verification stays deferred (Pi M-F). |

### Interpretation notes

- The leak latch is keyed to the phase log, not to a matching `r`: a
  well-formed non-Mullvad success in this run's (cleared, launch-bound) log is
  LEAK even if its `r` is foreign.  A foreign `r` is additionally
  `probe_run_mismatch` / INVALID, but INVALID never masks the leak.  This is
  the conservative reading of "LEAK is never masked".
- The 30 s minimum applies to every `--client` invocation, including
  `client-login` (controller decision 2 wording), not only phases with a
  traffic hold.

## Regression checks against `605cce8`

An extracted `git archive 605cce8` tree was used to rerun the new phase-level
reproducers (new `vm/test_vm.py` against the old code; only the
`CLIENT_LOGIN_UNIT` constant was added so the shared fake imports, no behaviour
changed).  All six fail on `605cce8` and pass on the fixed tree:

| Reproducer | `605cce8` | Fixed |
|---|---|---|
| GPT C1 failed stop, leak on the later cleanup stop | exit 0 PASS | LEAK, `client_traffic_stop_failed`, snapshot untrusted |
| Stop returns 0 while the unit stays active | exit 0 PASS | INVALID, `client_traffic_stop_failed` |
| GPT I1/Opus N-1/Pi M-N pre-fault leak + failed final read | exit 2 INVALID | LEAK |
| GPT I1 nonzero `cat` with a readable leak | exit 2 INVALID | LEAK |
| Opus N-2 exit node switches at the end of the hold | exit 0 PASS | INVALID, `client_exit_node_lost` |
| Pi I-1 frozen clock + silent active unit | exit 0 PASS | INVALID, zero post-fault attempts |

Parser reproducer (old API): the same-second pair with
`fault_epoch=post_fault_epoch=100`, clock 99..105 returns **PASS** on
`605cce8`; the new sequence-bound evaluator returns INVALID.  The old
unordered-clock fixture (`fault_epoch=103`, `post_fault_epoch=100`) also
returns PASS on `605cce8`; the new evaluator returns `probe_clock_order`.
Host-safety reproducers: on `605cce8` the un-scoped plan has no decision-6
drops (`test_client_plan_...` fails), a no-client teardown with old-owner
client residue exits 0 (`test_teardown_refuses_...` fails), and a missing
`vprlab1` aborts teardown on `Cannot find device`
(`test_teardown_tolerates_...` fails).  All three pass on the fixed tree.

## Tests run (all pass)

From `tools/leak-lab`:

- `python3 -B -W error -m unittest test_leak_lab` — **329 tests, OK**
  (was 320)
- `python3 -B -W error -m unittest vm.test_vm` — **266 tests, OK**
  (was 252)
- `python3 -B -m py_compile` on `clientprobe.py`, `clientscan.py`,
  `netplan.py`, `vm/guest.py`, `vm/provision.py`, `vm/run_phase.py`,
  `vm/test_vm.py`, `test_leak_lab.py` — OK
- `sh -n` on rendered no-client and `--client 1` plans — OK
- `git diff --check` — OK

Router-only verification: AST comparison against `605cce8` shows
`_run_phase_locked`, `scan_evidence`, `start_capture`, `stop_capture`,
`run_phase`, `run_router_fault` and `wait_router_ready` unchanged;
`login_phase_wait`, `check_admission` and `combine_verdicts` changed only by
defaults/default-off keywords.  The host plan changes are the decision-6
scoped accepts/drops and the decision-6 teardown/neighbour helpers.

## Updated operator commands

The probe-log CLI now also requires the two sequence boundaries and the hold
length:

```sh
python3 -B tools/leak-lab/clientprobe.py --probe-log <file> \
  --fault-epoch <guest-sec> --post-fault-epoch <guest-sec> \
  --fault-sequence <s> --end-sequence <s> --hold-seconds <n> \
  --clock-start <guest-sec> --clock-stop <guest-sec> --run-id <32 hex>
```

A client phase (including `client-login`) needs at least 30 s:

```sh
python3 -B tools/leak-lab/vm/run_phase.py \
  --phase idle --client 1 --duration 120 --index 1 \
  --profile-file /root/vprouter-lab.conf \
  --used-nonces /root/leaklab-used-nonces.txt

python3 -B tools/leak-lab/vm/run_phase.py \
  --phase client-login --client 1 --duration 900 \
  --used-nonces /root/leaklab-used-nonces.txt
```

Host plan: `--client N` still creates the client objects; the forward chain
now has the decision-6 drops, and teardown refuses old-owner client residue:

```sh
python3 -B tools/leak-lab/netplan.py \
  --wan-interface <wan> --client 1 > /root/vprlab-lab.sh
sh /root/vprlab-lab.sh setup
# ... phases ...
sh /root/vprlab-lab.sh teardown
```

---

# Fix round 3

Milestone: M3 — fix round for the three round-3 re-reviews of `37bafc2`
(`leak-lab-m3-rereview3-gpt.md` FAIL, `-opus.md` PASS with Minors,
`-pi.md` FAIL).  Repository: `/DATA/AppData/vprouter-rust-v2` (branch
`rust/v2`, HEAD `37bafc2`).  Date: 2026-11-09.

All work is in the working tree; nothing was staged, committed or pushed.  No
privileged command (sudo, QEMU, tcpdump, `ip`, `nft`, `iptables`, docker,
useradd, `systemctl` or network execution) was run.  Generated shell was only
parsed (`sh -n`) or run through the repository stub harness.  Scratch
`/var/tmp/leaklab-m3-fix3`, including the extracted `git archive 37bafc2` tree
used for the regression check, was deleted at the end.

## Design (controller decisions 1-5)

- **One exact prefix-read primitive** (`vm/run_phase.py:3380`,
  `ProbeLogRead` `:3357`).  N = `stat -c %s` (exit status kept, no `|| true`),
  then `head -c N | sha256sum` and `head -c N` as separate bounded QGA execs.
  Trusted only if every exec exited 0, `len(bytes) == N` and the host SHA-256
  equals the guest's.  Untrusted reads still return their bytes for tolerant
  LEAK parsing.  Used by the pre-fault gate, the S_fault sample, every hold
  sample, the deadline sample and the final snapshot
  (`read_client_probe_log_exact` `:3450` adds non-empty + final newline).
  Sequence numbers come only from complete lines of a trusted prefix
  (`clientprobe.prefix_observation` `clientprobe.py:230`,
  `complete_lines` `:217`; `take_client_probe_sample` `run_phase.py:3469`).
  The old tolerant `read_client_probe_sequence` with its 10 s retry is gone:
  an untrusted read never sets S_fault, a sample or S_end and makes the phase
  INVALID (`probe_{fault,hold,end}_sample_untrusted` + the read problem).
- **Host-observed hold coverage** replaces `floor(hold/15)`.  The S_fault
  sample's size read is the hold base `h0`; the hold is split into
  `k = ceil(duration/14)` equal windows (`CLIENT_HOLD_SAMPLE_TARGET`,
  `run_phase.py:145`; 10-14 s for every hold >= 30 s, above the traffic loop's
  worst-case exit spacing and below the 15 s limit); a trusted sample is taken
  at each boundary and at the deadline (`run_phase.py:4538-4612`).  Each
  sample's prefix boundary is its size read, which precedes its
  `ExitNodeStatus` re-check, so S_end is fixed before any end-of-hold status
  call.  The record carries `hold_samples` (sequence, exit_sequence, size,
  prefix sha256, host stat_start/stat_end relative to h0, exit_node_ok) and
  `hold_windows`.  `evaluate_probe_log(..., hold_samples=)` re-derives every
  sample from the evidence bytes (prefix SHA-256 must match, recorded
  sequence/exit_sequence must equal the prefix's) and requires: first = S_fault,
  last = S_end; each window <= 15 s from the earlier size-read start to the
  later size-read end; a new exit attempt (`exit_sequence_i > sequence_{i-1}`)
  in every window; deadline reached and the deadline read finished within 2 s
  (`clientprobe.py:296-358`, `:557`).  Guest-clock checks stay as extra
  INVALID conditions, plus `probe_clock_stalled` (`:546`, Opus R3-3's cheap
  check).  At least one exit and one marker attempt with `s > S_fault` are
  still required.  CLI: `--hold-samples <json>` (`clientprobe.py:642`).
- **Proven stop** (`stop_client_traffic` `run_phase.py:3271`): `is-active`
  must print exactly `inactive`/`failed` (`:3299`), and
  `systemctl show -p MainPID --value` must print `0` (`:3253`).  Then writer
  quiescence: two trusted size reads >= 2 s of host time apart must match
  (`client_probe_writer_quiescent` `:3333`), on the end-of-hold path (`:4644`)
  and in `finally` before a trusted collection (`:4710`).  `clock_stop` is read
  right after the proven stop, before the 2 s wait (`:4643`; also narrows Pi
  R3-M4's tail gap).

## Finding-to-fix map

Line numbers are from the fixed working tree.

| ID | Fix |
|---|---|
| GPT R3-C1 / Pi R3-I1 — partial boundary read understates S_fault | Exact prefix primitive (`vm/run_phase.py:3380`); S_fault only from a trusted sample (`:4574`), no retry, no partial fallback; an untrusted boundary read is `probe_fault_sample_untrusted` → INVALID even with healthy traffic.  Tests `vm/test_vm.py:7309` (GPT backlog after the wait, exit 1 and exit 0; Pi backlog during the action, one line kept), `:7343` (healthy hold), `:7357` (untrusted hold sample), `:7653`/`:7679` (primitive). |
| GPT R3-C2 — total count does not prove coverage over the hold | Host-scheduled trusted samples and per-window coverage (`vm/run_phase.py:4583-4612`, `clientprobe.py:296-358`); S_end sampled before the status call.  Tests `vm/test_vm.py:7376` (1 Hz burst at +1/+2 s then 28 s silence), `:7391` (probes only during the end status call), `:7427` (30 s silent window inside a 60 s hold), `:7443` (healthy positive control, windows/samples asserted); evaluator `test_leak_lab.py:5895`, `:5922`, `:5933`, `:5951`, `:5973`, `:5992`, `:6006`. |
| Opus R3-1 — start that raises after launch gives a trusted live snapshot | `traffic_started = True` before `start_client_traffic` (`vm/run_phase.py:4455`); `finally` stops, proves and quiesces before collecting.  Test `vm/test_vm.py:7535` (LEAK). |
| Opus R3-2 — positive controls from failed reads | `wait_client_probe_control` (`vm/run_phase.py:3605`) takes `mullvad`/`marker` only from trusted prefixes; LEAK from any bytes.  Tests `vm/test_vm.py:7749` (function), `:7553` (phase: the destructive fault never runs). |
| Opus R3-3 — coverage relied on the guest clock | Superseded by host samples; plus `probe_clock_stalled` (`clientprobe.py:546`).  Tests `test_leak_lab.py:5882` (the E7 fixture without samples), `:6032`. |
| Opus R3-4 — single end-of-hold exit check; RouteAll/ShieldsUp unchecked | Every sample re-checks `ExitNodeStatus` (`vm/run_phase.py:4560-4566`); prefs require `RouteAll` false and `ShieldsUp` true (`:2938`).  Tests `vm/test_vm.py:7465` (switch away and back mid-hold), `:7567`, `:7776`. |
| Opus R3-4b / Pi R3-M2 — `client_neigh_ok` not scoped by device | New `_CLIENT_NEIGH_CHECK_CODE` matches `dst` and `dev` (`netplan.py:403`), called with the device (`:1097`); the router `neigh_ok` and its check are unchanged.  Test `test_leak_lab.py:4888`. |
| Pi R3-M1 — `unknown` accepted as a proven stop | Only `inactive`/`failed` + `MainPID` 0 + quiescence (`vm/run_phase.py:3271-3300`, `:3333`).  Tests `vm/test_vm.py:7488` (`unknown` with a live writer), `:7505` (writer keeps appending after a claimed stop → LEAK), `:7518` (non-zero MainPID), `:7702`, `:7721`. |
| Pi R3-M3 — design said the router-only plan was unchanged | Design Network section documents the decision-6 `vprlab0` scoped accepts + drops and why; the Tests bullet now says the no-client plan is not byte-identical (`docs/rust-v2/leak-lab-m3-clients.md`). |
| Pi R3-M4 — post-hold QGA calls widen the tail gap | Partly addressed: `clock_stop` is read right after the proven stop, before the 2 s quiescence wait.  The guest gap rule itself is unchanged (false-INVALID only). |
| Pi R3-M5 — missing `AdvertiseRoutes` accepted | Missing key → `client_prefs_incomplete`; `[]` or JSON `null` (Go's empty slice) accepted (`vm/run_phase.py:2938`).  Tests `vm/test_vm.py:7567`, `:7776`. |
| Opus "S_fault from a failed tolerant read" note | Covered by decision 1 (no S_fault from an untrusted read). |

## Regression check against `37bafc2`

An extracted `git archive 37bafc2` tree received the new `test_leak_lab.py`
and `vm/test_vm.py` unchanged (the fake answers both the old `cat`/`sha256sum`
and the new `head -c` reads; the hooks only patch functions that exist on
both trees).  Outcomes of the phase reproducers through the real runner,
real `clientprobe` and real `clientscan`:

| Reproducer | `37bafc2` | Fixed |
|---|---|---|
| GPT R3-C1 truncated boundary, backlog, `cat` exit 1 | exit 0 PASS, S_fault=2 | exit 2 INVALID, S_fault none |
| GPT R3-C1 same, exit 0 | exit 0 PASS, S_fault=2 | exit 2 INVALID |
| Pi R3-I1 one line kept, backlog during the action | exit 0 PASS, S_fault=1 | exit 2 INVALID |
| Truncated boundary, healthy hold | exit 0 PASS | exit 2 INVALID |
| GPT R3-C2 burst then silence | exit 0 PASS | exit 2 INVALID `probe_hold_window_empty` |
| GPT R3-C2 probes only during the end status call | exit 0 PASS | exit 2 INVALID, S_end = S_fault |
| Silent window in the middle of a 60 s hold | exit 0 PASS | exit 2 INVALID |
| Exit-node switch mid-hold (Opus R3-4) | exit 0 PASS | exit 2 INVALID `client_exit_node_lost` |
| Pi R3-M1 `unknown` + live writer | exit 0 PASS (leak in guest log) | exit 2 INVALID, snapshot untrusted |
| Writer keeps appending after a claimed stop | exit 0 PASS (leak in guest log) | exit 1 LEAK |
| Opus R3-1 start raises after launch, leak before stop | exit 2 INVALID | exit 1 LEAK |
| Opus R3-2 every transfer exits 1 | fault ran, INVALID late | refused before the fault |
| Control: healthy stop-router 30 s | exit 0 PASS | exit 0 PASS |

Unittest run on the old tree: all 14 new regression tests (the 11 phase
tests, `ClientProbeReadTests.test_opus_r3_2_...`,
`ClientProbeTests.test_opus_r3_3_...`, `ClientNetplanTests.test_client_neighbour_check_is_scoped_by_device`)
**fail by assertion** (19 failures counting subtests; no import or attribute
error), and all pass on the fixed tree.  The old evaluator returns **PASS**
for the Opus R3-3 fixture.

## Tests run (all pass)

From `tools/leak-lab`:

- `python3 -B -W error -m unittest test_leak_lab` — **341 tests, OK** (was 329)
- `python3 -B -W error -m unittest vm.test_vm` — **289 tests, OK** (was 266)
- `py_compile` of `clientprobe.py`, `clientscan.py`, `netplan.py`,
  `vm/guest.py`, `vm/provision.py`, `vm/run_phase.py`, `vm/test_vm.py`,
  `test_leak_lab.py` — OK
- `sh -n` on the rendered no-client, `--client 1` and `--client 1,2` plans — OK
- `git diff --check` — OK

Router-only verification: an AST comparison with `37bafc2` shows
`_run_phase_locked`, `scan_evidence`, `start_capture`, `stop_capture`,
`run_phase`, `run_router_fault`, `wait_router_ready`, `emit_control`,
`cleanup_guest_units`, `poweroff_vm`, `check_admission`, `login_phase_wait`,
`combine_verdicts` and `main` unchanged.  The rendered no-client plan differs
from `37bafc2` only inside the `client_neigh_ok` helper, which runs only when
`owner.json` records clients.

## Open risk to verify live (not a false PASS)

Decision 2 requires `ExitNodeStatus.Online` at **every** sample.  In
`stop-router` and `kill-container` the router's Tailscale is down for the
hold, so the client will likely report the peer offline within seconds and
those phases would be INVALID `client_exit_node_lost`.  Round 2 already had
the same check at the end of the hold; sampling makes it certain.  If live
runs confirm this, the controller may want ID+IP (not `Online`) during the
hold for those phases.  It can only cause a false INVALID.

## Updated operator commands

The probe-log CLI now also needs the recorded hold samples (the
`client.hold_samples` list of `phase.json`, saved as JSON):

```sh
python3 -B tools/leak-lab/clientprobe.py --probe-log <file> \
  --fault-epoch <guest-sec> --post-fault-epoch <guest-sec> \
  --fault-sequence <s> --end-sequence <s> --hold-seconds <n> \
  --clock-start <guest-sec> --clock-stop <guest-sec> --run-id <32 hex> \
  --hold-samples <hold-samples.json>
```

`run_phase.py` and `netplan.py` invocations are unchanged.
