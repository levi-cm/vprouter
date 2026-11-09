# Leak-lab M3 review (Opus, independent, adversarial)

Scope: `git diff 888f0d4..b849e3c` (branch rust/v2, commit b849e3c), binding design
`docs/rust-v2/leak-lab-m3-clients.md`. Reviewer modified no file except this report.
Scratch: /var/tmp/leaklab-m3-opus (deleted at the end).

Status: complete.

## Findings

### I-1 (Important, FALSE PASS): the probe verdict does not prove client traffic ran during the fault, and it accepts a stale probe log from an earlier phase

Files:
- `tools/leak-lab/clientprobe.py:139-205`: `evaluate_probe_log` needs only one `ok && m==true` line with `t <= fault_epoch`. It never requires any probe after the fault. It never checks that a line belongs to this phase: there is no marker or nonce in the line and no lower bound on `t`.
- `tools/leak-lab/vm/run_phase.py:3096` defines `client_traffic_unit_active`, but nothing calls it (`grep -n client_traffic_unit_active vm/*.py` finds only the definition). Nothing checks that the unit was still active at the end of the hold.
- `tools/leak-lab/vm/run_phase.py` (client flow, after `start_client_traffic`): the runner never removes `/var/lib/vprlab/client-probe.jsonl` before it starts the unit (`grep` finds no `rm` or `unlink`). The file persists in the client overlay between phases. `wait_client_first_mullvad` (run_phase.py, around line 3105) accepts the first `m:true` line it reads. That line can be a stale line read before the new script truncates the file, or a stale line that remains because the script exited before its `O_TRUNC`.
- `RuntimeMaxSec = duration + 120` (`client_runtime_seconds`) starts before the pre-fault wait, which can take up to 90 s, and before the fault action. The reboot and restart-docker actions also wait for router READY. So systemd can kill the unit before the hold ends without anyone noticing.

Reproducer (run): `/var/tmp/leaklab-m3-opus/repro_runphase.py`. It subclasses the existing fake two-VM `ClientRunPhaseTests` harness.
- R1: `stop-router --client 1` returns `PASS`, exit 0. The probe counts show `exit.after.total == 0` and `marker.after.total == 0`: not a single client probe ran after the fault. (The shipped `test_client_idle_passes_...` already asserts PASS for such a log.)
- R2: `kill-container --client 1`. `start_client_traffic` "succeeds" but writes nothing, which models a script that dies before `O_TRUNC`. The probe log read back is the previous phase's file, with `t = 1600000000` against a `fault_epoch` of `1700000000`. Result: `PASS`, exit 0, probe verdict `PASS`. The client sent no probe or marker in this phase.

Impact: an M3 phase can be certified "client traffic through test exit node" while the client sent nothing during the fault, which is exactly the window under test. The marker check is then vacuous as well (see M-2).

Suggested fix:
- Bind every probe line to the phase. The script can write a header line `{"k":"start","marker":<marker>}` or carry the marker hash on each line. The runner should also `rm -f` the log before `systemd-run`.
- Reject `t` values earlier than the client clock read just before `start_client_traffic`.
- Require at least one exit probe and one marker probe attempt after `fault_epoch`, and attempts that cover the hold, for example the last attempt within a few seconds of the hold end.
- Call `client_traffic_unit_active` before `stop_client_traffic` and make the phase INVALID if the unit is not active.
- Set `RuntimeMaxSec` from the remaining phase budget plus the action timeouts, not from `duration + 120`.

### I-2 (Important, SECRECY): the `h` field stores the host's real IP in a form that is reversible in about one core-hour

Files:
- `tools/leak-lab/vm/guest.py`, client traffic script `exit_probe` (diff lines about 247-251): it writes `h = sha256(ip)[:12]` for every parsed answer, including `mullvad_exit_ip: false`. That answer's IP is the host's real public IP.
- The line is copied verbatim into the evidence file `client-probe.jsonl`.
- `clientprobe.py:23-25` and `leak-lab-vm.md` call this "never recording a non-Mullvad IP".

Reproducer (run): `/var/tmp/leaklab-m3-opus/repro_scan.py`, case H1. It hashes the documentation address `203.0.113.77` and enumerates `203.0.0.0/16`. It recovers the address uniquely in 0.06 s, at about 1.1 M IPs/s with pure-Python `hashlib`, which is roughly 1.1 core-hours for the whole IPv4 space. 48 bits of an unsalted hash over a 32-bit domain is not a one-way function.

Impact:
- A LEAK line, the very case where `h` matters, records the host's real IP in recoverable form inside evidence that people review, copy and archive.
- The design's own two sentences conflict: "Never record … any non-Mullvad IP" against "at most the first 12 hex characters of the IP's sha256".

Suggested fix: drop `h` entirely, or write it only when `m is true`. If correlation is needed, use an HMAC with a per-phase key that is never stored. Amend the design text to match.

### M-1 (Minor): client phases never attach the tcpdump processes to the CaptureGuards, so a dead capture no longer isolates the taps

- `tools/leak-lab/vm/run_phase.py:3574-3640`. The client flow creates `router_guard` and `client_guard` and calls `attach_qemu`, but never calls `attach_capture`. The only call is at `run_phase.py:4522`, in the router-only path.
- So `CaptureGuard._capture_liveness` (`run_phase.py` around line 2036) returns `None` for the whole client phase.
- In M2, a dead tcpdump trips `_breach("capture_ended_early")`, which takes the tap down at once (`run_phase.py:2050-2060`). In M3, both guests keep sending traffic that nobody captures until the hold ends, which can be up to 3600 s.
- The final `capture_alive_before_stop` check (`run_phase.py:4077`) still makes the phase INVALID, so this is not a false PASS. It does lose a reviewed M2 safety property.
- Reproduced by inspection: `grep -n attach_capture vm/run_phase.py` returns only lines 1978 and 4522.
- Fix: after each `start_capture`, call `guard.attach_capture(...)`: both captures on both guards, or each capture on its own guard and the cross-capture on the other. Add a harness test where the client's fake tcpdump `poll()` returns 1 during the hold.

### M-2 (Minor, related to I-1): the plaintext-marker check can be vacuous

- `clientscan.py` reports PASS when the marker never appears anywhere (repro_scan S1: `verdict=PASS`).
- `clientprobe.py` never requires a successful marker probe (repro_scan P2: every marker probe failed, verdict `PASS`).
- If the HTTP probe never completes a TCP handshake, for example because the `example.com` IP is unreachable through Mullvad, design point 3 is never exercised, and nothing records that.
- Fix: require at least one pre-fault `marker ok:true` and marker attempts after the fault (see I-1). Record `marker.ok` counts as a positive control.

### M-3 (Minor, HOST SAFETY): the owner record does not bind the planned client set

The owner record (`netplan.py` `READ_OWNER`/owner writer) stores only the token. Reproducer (run): `/var/tmp/leaklab-m3-opus/repro_plan.py` plus an inline `check_name_collisions` call.
- A no-client plan's `verify_ownership` and `do_teardown` never mention `vprlab1`. Its teardown still deletes `inet vprlab`, which holds the `vprlab1` input drop, the inter-bridge drops and the client forward scoping. It also deletes `owner.json`.
- `check_name_collisions` without `--client` returns `[]` while `vprlab1`, `vprlab-ctap1` and a `vprlab-owned:` DOCKER-USER accept for `vprlab1` exist. With `--client 1` it reports all three.

A client setup torn down with an older or regenerated M2 plan therefore leaves an UP `vprlab1` holding `10.251.0.1/24`, a QEMU-user-owned tap, and DOCKER-USER ACCEPTs. Nothing can verify or remove them afterwards. The run lock prevents a running client VM during teardown, so this is residue on the production host rather than a live exposure.

Fix: record `clients` in `owner.json` and make teardown refuse on a mismatch, or have every plan inventory `vprlab1`/`vprlab-ctap[1-9]` and refuse if they exist but are unplanned. Also have the no-client preflight flag `vprlab1`.

### M-4 (Minor, exit-node selection): the router peer is chosen by self-reported HostName and the first match wins

`run_phase.py` `client_find_router_peer` (around line 2870). Reproducer (run, inline): a status with two online `ExitNodeOption` peers both named `zz-vprtest-01-do-not-use` returns the first one in dict order. Here that is `impostor` with DNSName `other-host…`, with no ambiguity refusal. `HostName` is chosen by each node. If another online exit node with that HostName (and a Mullvad egress) exists in the tailnet, client traffic would skip the lab router and still PASS.

Fix:
- Refuse if more than one peer matches.
- Bind the peer to the router's own identity: the runner already reads the router's `tailscale status --json`, so compare `Self.ID` or `PublicKey` with the peer `ID` or key.
- Check `DNSName`'s first label as well.

### M-5 (Minor): dead or over-broad role checks

Repro (run, inline):
- `client_readiness_problems` looks for `Self.AdvertisedRoutes`, a key that `tailscale status --json` does not emit. A self status with `PrimaryRoutes: ["0.0.0.0/0","::/0"]` returns no problem.
- `client_peer_is_active` returns True for any peer when `Self.ExitNode is True`. That field describes peers, not the selected exit node.

Neither leads to a false PASS on its own, because the pre-fault `m:true` gate remains. Fix: drop the `Self.ExitNode` shortcut. Check `PrimaryRoutes`/`AllowedIPs` for default routes, or read the prefs with `tailscale debug prefs` to get `AdvertiseRoutes`.

### M-6 (Minor): a malformed tail line masks a LEAK line as INVALID

`clientprobe.evaluate_probe_log` (`clientprobe.py:150-160`) returns INVALID `probe_log_malformed` before it looks at any parsed line. Repro P1: a valid `ok:true,m:false` line followed by a truncated line gives `INVALID`, not `LEAK`. This contradicts LEAK > INVALID. Fix: parse line by line, keep LEAK if any well-formed line is a leak, and otherwise INVALID.

### M-7 (Minor): client controls are matched anywhere in any frame

`clientscan._scan_raw` (`clientscan.py:74-85`) counts any frame that contains `VPRLEAKCTL1:<nonce>`. It does not check the source, the destination (10.251.0.1), UDP/39001 or the frame shape. Repro S2: the after-control embedded in a TCP frame to `198.51.100.99:80` is accepted, and the result is `PASS`. Only the client knows the nonce, so this matters only for a hostile guest. Fix: reuse `control.py`/`pcapscan`'s exact control-datagram parser.

### M-8 (Minor, notes not reproduced live)

- **Traffic script log cap.** The script silently skips lines once the log reaches 1 MiB (guest.py `append`). That is not reachable at the 3600 s maximum, at about 95-111 B/s. A dropped line could hide `m:false`, though, so write a final `"k":"overflow"` line and treat it as INVALID.
- **`m: null` rule is dead.** The script records an unparsed answer as `ok:false`, so the "`ok` with `m` null is LEAK" rule never fires in practice. This matches the design. An HTTP 4xx/5xx or rate-limit page on a real-IP egress counts as a failure, not a LEAK, and only the marker or router tap would catch that path.
- **Tarball hash-then-copy race.** `provision.verify_tailscale_tarball` hashes the path, then `_stage_client_payload` copies it by path again. The guest re-verifies with `sha256sum -c` before extracting, so a swap is caught. Even so, hash and copy from one fd. The tarball path also gets no `rootfs.validate_ancestry` check, unlike the base image.
- **Exit-node clear can race tailscaled.** `clear_client_exit_node` runs right after QGA becomes ready. `tailscale set` can fail before tailscaled's socket accepts connections, which gives a flaky INVALID rather than a false PASS. Retry until `wait_client_running`, or clear after it.
- **Client nft rules not re-verified.** `verify_host_lab` checks the client links and neighbours but not the client nft rules (inter-bridge drops, client forward scope). Only the chains are checked, the same as M2.
- **Unused nonces.** `client-login` allocates and spends three unused nonces. This is harmless.

### M-9 (Minor, docs vs code)

- `clientprobe.py:5` says the log is at `/var/lib/vprouter/client-probe.jsonl`. The code uses `/var/lib/vprlab/client-probe.jsonl` (guest.py `CLIENT_PROBE_LOG`).
- `leak-lab-vm.md` "Running a phase with a client" lists `set --exit-node=` → before-control → require Running. The code runs clear → wait Running → before-control. That is safe, but the doc and the design's step order differ.
- `leak-lab-vm.md`'s secrecy paragraph says no non-Mullvad IP is recorded. See I-2.
- The impl report's "client capture/guard" suggests the guard watches the client capture. See M-1.
- The impl report's deviation 1 is reasonable, but it is the reason I-1 matters. Once the unit starts before the pre-fault gate, nothing proves it is still running when the fault happens.

## Areas checked with no finding

- **Combined verdict.** `combine_verdicts` (`run_phase.py` around line 3303) gives LEAK > INVALID > PASS. Errors and missing verdicts give INVALID. The client-scan report is bound to the hashes of both pcaps, the stats file, the argv file and both nonces, and they are re-hashed after the scan.
- **Ordering.** The harness asserts, and the code confirms, the following order. The exit node is cleared before both client controls. Both captures start before either VM. Both QEMUs exit before either capture stops (`run_phase.py` finally block). The after-controls are awaited in the pcaps before `QUIET_SECONDS`.
- **Client QEMU test boot.** Printed argv: `-m 256 -smp 1 -nic none`, an explicit `vprlab-ctap1` netdev, MAC `52:54:00:76:71:02`, `-serial none`, QGA over virtio-serial, `-sandbox on,…spawn=deny…`, launched with `setpriv --reuid … --no-new-privs --inh-caps=-all --bounding-set=-all`. It is the same builder as the router. Provisioning uses user-mode netdev only.
- **Admission.** It requires 1536 MiB + 256 MiB and records `mem_available`. `refuse_if_qemu_running` runs before either boot.
- **netplan client plan.** `vprlab1` and the taps are created DOWN with the owner ifalias. The input drop, both inter-bridge drops, the `!= wan` scoping, the IPv6 drops, the output drop and the masquerade are all scoped to `10.251.0.0/24` with `iifname vprlab1 oifname <wan>`. The DOCKER-USER accepts are `-i vprlab1 -o wan -s 10.251.0.0/24` and the conntrack ESTABLISHED,RELATED return path. Teardown verifies before mutating and isolates the client taps before it removes protections. The plan touches no other nft table and no production object. The no-client plan contains no client text (test plus the repro_plan output).
- **Router-only path.** `run_phase` dispatches to the unchanged `_run_phase_locked` when `--client` is absent. The old `_STATS_BANNER_RE` is equivalent to `stats_banner_re("vprlab-tap0")` (printed both). The `CaptureGuard` list change keeps router semantics, with a single `attach_capture`. All pre-existing `RunPhaseTests` pass.
- **Secrecy, apart from I-2.** Client status JSON, peer Tailscale IPs, `tailscale up` output and login URLs are not recorded. `login-url.txt` is mode 0600. Errors record only class names.

## Test suites (run once each, from tools/leak-lab)

- `python3 -B -W error -m unittest test_leak_lab`: **Ran 301 tests, OK**
- `python3 -B -W error -m unittest vm.test_vm`: **Ran 227 tests, OK**

## Reproducers

These are scratch files only and were deleted at the end of the review:
- `repro_runphase.py`: R1 and R2 through the fake two-VM harness.
- `repro_scan.py`: S0-S2, P1-P2 and H1, using crafted pcaps and probe logs.
- `repro_plan.py`: renders the client and no-client plans and runs the collision check.
- Inline runs for M-4 and M-5.

No sudo, QEMU, tcpdump, ip, nft, iptables, docker or network command was run.

## Verdict

FAIL: 2 Important findings (I-1, a FALSE PASS where the probe log need not prove traffic during the fault and may be stale; I-2, a secrecy leak where `h` makes the host's real IP recoverable), 0 Critical, 9 Minor.
