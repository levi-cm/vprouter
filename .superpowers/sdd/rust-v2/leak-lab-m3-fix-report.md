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
