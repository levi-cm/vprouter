# Leak lab — combined adversarial review (monitor round 4 + runner round 2), Opus, 2026-11-09

## Scope

**Commit:** `e1535b8` (`rust/v2`).

**Files reviewed:**
- **Monitor:** `tools/leak-lab/{pcapscan,policy,netplan,control,tsnames}.py`, `policy.schema.json`, `test_leak_lab.py`, `docs/rust-v2/leak-lab.md`.
- **Runner:** `tools/leak-lab/vm/*.py`, `docs/rust-v2/leak-lab-vm.md`.
- **Release, read-only:** `/opt/vprouter/current/{docker-compose.yaml,host/orchestrate.py,host/vprouter@.service}`.

**Method:**
- Re-ran the round-3 monitor and round-1 runner reproducers.
- Rendered the host plan with `netplan.py --wan-interface eno1 --tap-user opsec`, then ran `sh -n` on it and read it in full.
- Wrote new offline probes:
  - monitor probes, via `test_leak_lab` helpers;
  - runner probes that subclass `test_vm.RunPhaseTests`, so the real `run_phase()` decision logic runs with fake QGA, process and scan;
  - cross-checks of the host JSON contract between `netplan.py` and `hostcheck.py`.

**Limits:**
- No sudo, QEMU, tcpdump, ip, nft, iptables, docker or network command was run.
- I read no secrets or key files.
- Host metadata I read: directory modes, `/dev/kvm` ACL, `id opsec`, `ptrace_scope`, `free`, `/proc` mount options.
- Scratch `/var/tmp/leaklab-comb-opus` was deleted at the end.

## Test suites

```
python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py
Ran 239 tests in 5.830s   OK
python3 -B -W error -m unittest discover -s tools/leak-lab/vm -p 'test_*.py'
Ran 96 tests in 1.767s    OK
```

- Total: 335 tests. 0 failures, 0 errors, 0 skips.
- The VM doc's count of 96 is correct.

## Verdict: **FAIL** — 0 Critical, 3 Important, 9 Minor

**What is fixed:**
- Every round-3 monitor Critical/Important reproducer now behaves correctly (§1).
- Every round-1 runner Critical/Important finding is fixed in the runner logic (§1).
- The controller order is now AFTER → router stop → poweroff → QEMU exit → AFTER-in-pcap → 2 s quiet → SIGINT → scan. Probes confirmed it.
- Failed setup, action, postcondition, cleanup and forced poweroff can no longer certify PASS.

**What remains Important:**
- **I-1:** an integration break. The runner refuses every phase on a host built by the current `netplan.py` plan.
- **I-2:** the root-only evidence tree sits under an opsec-owned ancestor and is re-read by path. An opsec process, or an escaped QEMU, can substitute a forged capture and obtain PASS.
- **I-3:** `login` and every fault phase certify PASS on a node that never logged in to Tailscale or reached exit-node READY. The exit-node data path the lab exists to test is never exercised.

---

## 1. Previous-round closure (reproducers re-run)

### Monitor (m1-rereview3-*)

| Finding | Reproducer | Result now |
|---|---|---|
| opus I-1: `alias` vs `ifalias` | generated `link_owned()` | reads `entry.get("ifalias")`, plus `info_kind` `tun`/`bridge` and `info_data.type == "tap"` ✔ |
| pi I-1: one-line summary discarded | multi-line 4/4/0 + one-line `4 captured, 100 received` | INVALID `unread_capture_tail` ✔ |
| | one-line `100 captured, 100 received` | INVALID `stats_packet_count_mismatch` ✔ |
| gpt I1: incomplete fragment outside window | unfinished allowed first fragment before A, after B, and inside | LEAK `fragment_incomplete` in all three ✔ |
| gpt I2: ownership checked after mutation; fixed tag | generated script | per-run 32-hex token in `owner.json` (O_EXCL, 0600); `vprlab-owned:<token>` on both ifaliases, the table comment and both DOCKER-USER comments; `verify_ownership()` runs before any mutation and aborts with no change ✔ |
| gpt I3: isolation failure does not gate removal | generated script | `isolate_tap()` stops on `down`/`nomaster` failure and requires readback (`operstate down`, no master) before any protection is removed; failures aggregate to a nonzero exit; `owner.json` is kept ✔ |
| opus M-1: Ctrl-C skips teardown | | `trap cleanup INT TERM HUP EXIT` ✔ |
| opus M-2: forgeable inbound evidence | inbound with VM src MAC; VLAN-tagged inbound | LEAK `allowed_tuple_wrong_l2` + INVALID `tunnel_not_observed` ✔ |
| opus M-4/M-5: teardown/setup order | | links stay DOWN until the nft table, DOCKER-USER accepts and neighbour exist ✔ |
| opus M-6: API default `any` | | `expect_tunnel` is a required keyword (TypeError when omitted) ✔ |
| opus M-7: `-w` / banner | `-w /dev/null` with `pcap_path` | `capture_argv_mismatch` ✔ |
| | banner twice | `capture_banner_mismatch` ✔ |
| opus M-8: bridge MAC changes per run | | `ip link set vprlab0 address 52:54:00:76:70:01` runs before enslaving ✔ |

### Runner (m2-review-*)

| Finding | Result now |
|---|---|
| C1: non-raising setup/action failure → PASS | `setup_failed`, `router_not_ready`, `action_failed` and `postcondition_failed` are all errors, and errors force INVALID. Behavioural tests drive `run_phase()` (`test_vm.py:1675-1933`) ✔ |
| C2: capture stopped before teardown | `run_phase.py:1682-1730` keeps the capture alive through guest cleanup, poweroff and QEMU exit, then the AFTER-in-pcap check, then the 2 s quiet. Probe event order confirmed ✔ |
| I1 (opus/pi): silence check broken on Debian 13 | `ip -4 -o neigh show dev`; DHCP-off from the `.network` file, the lease file and `networkctl` ✔ |
| I2: `--expect-tunnel` not tied to phase | fixed `PHASE_EXPECTATIONS` table, all `up`; fault effect proven by an in-guest postcondition ✔ |
| I3/I6: signals, orphaned processes, finally robustness | SIGTERM/HUP/INT handlers; each finally step guarded; `main` never returns 1 for a crash ✔. Residual: m-3 |
| I4/I9 (pi): root path writes | evidence moved out of the state directory; `O_NOFOLLOW` writes; `qemu-img info` runs as opsec. **Residual is I-2 below** |
| I5/I7: login_url vs QGA | runner polls the URL itself; `login_url.py` refuses while the lock is held ✔ |
| gpt I1: reboot spec in `/run` | spec moved to `/var/lib/vprlab`, bound to a boot token ✔ |
| gpt I2: tap JSON shape | `tun` + `info_data.type == "tap"`, `master == vprlab0` required ✔ |
| gpt I4 / opus M1: no global lock | `flock` on `/run/vprlab/run.lock` across the whole lifecycle ✔ |
| gpt I5 / pi I11: QEMU as uid 0 | refused in `resolve_unprivileged_user` and `build_setpriv_argv` ✔ |
| gpt I9: policy allows extra endpoints | policy is built from the profile Endpoint only; `len(allowed) == 1` ✔ |
| gpt I10: guest error text | bounded to 200 printable characters; `run_phase` never prints it. Residual: m-6 |
| pi I12 / opus M3: QMP socket | removed; `-nodefaults -no-user-config -nic none` ✔ |

---

## 2. Important

### I-1. `hostcheck` compares the table comment with the fixed `vprlab-leak-lab-m1`, but `netplan.py` now writes `vprlab-owned:<token>`, so every phase is refused

**Locations:**
- `tools/leak-lab/vm/hostcheck.py:26` (`OWNER_TAG = "vprlab-leak-lab-m1"`)
- `hostcheck.py:170` and `:272` (`elif table.get("comment") != owner_tag`)
- `run_phase.py:1126-1134`: calls `verify_host_network(..., owner_token=token)` without `owner_tag`
- the generated plan: `nft create table inet vprlab "{ comment \"$OWNER\"; }"`, where `$OWNER` is `vprlab-owned:<token>` (`lab.sh:411`)

**Why the tests miss it:** the unit fixture uses the stale tag (`test_vm.py:802`, `"comment": hostcheck.OWNER_TAG`), so the hostcheck tests pass against a shape the real host never produces. This is the same pattern as last round's `alias`/`ifalias` defect.

**Reproducer** (fixture from `HostcheckTests._valid_documents`, comment replaced with exactly what `lab.sh` writes):

```python
table["nftables"][0]["table"]["comment"] = netplan.OWNER_PREFIX + "e"*32
hostcheck.verify_host_network(links, table, neighbor, owner_token="e"*32)
# -> ['nft table inet vprlab does not carry the ownership tag']
```

**Effect:**
- `verify_host_lab` raises `Refusal`, so `run_phase` exits 2 before any capture, on every phase, on a correctly built host.
- It fails closed (no exposure), but M2 cannot run at all.
- The doc (`leak-lab-vm.md:58-66`) says the table must carry "its ownership comment" without naming which one.

**Fix:**
- Compare the table comment with `OWNER_IFALIAS_PREFIX + owner_token`, and make `owner_token` mandatory in the runner.
- Delete `OWNER_TAG`.
- Build the hostcheck fixtures from one shared constant with netplan, so the two sides cannot drift.
- Better still, add one test that feeds documents shaped like the rendered plan's objects into `verify_host_network`.

### I-2. Evidence is still substitutable: the root-only evidence tree hangs under opsec-owned `/DATA/vprouter-lab` and is re-read by path, giving a false PASS

**Locations:**
- `run_phase.py:113` (`EVIDENCE_ROOT = /DATA/vprouter-lab/leaklab/evidence`)
- `run_phase.py:653-675` (`ensure_root_directory`: `mkdir(parents=True)` follows intermediate symlinks; only the last component is opened `O_NOFOLLOW` and owner-checked)
- `run_phase.py:1316-1321`
- path-based re-reads at `:1737-1808`: scan argv `--pcap/--tcpdump-stats/--capture-argv-file/--policy`, `scan.json`, and all hashes
- `run_phase.py:1710`: the AFTER-in-pcap check, also by path
- doc claims: `leak-lab-vm.md:88-90` ("an opsec process (or an escaped guest) cannot substitute it between capture and scan") and `:464-465`

**Host facts:**
- `/DATA/vprouter-lab` is `drwx------ opsec opsec`.
- `leaklab/` is created by root (`provision.py:286`, 0711).
- Linux `rename(2)` of a directory inside the same parent needs write permission only on the parent, not on the directory (`vfs_rename` checks `MAY_WRITE` on the source only when the parent changes). So opsec can `mv /DATA/vprouter-lab/leaklab leaklab.x` and create its own `leaklab/evidence/<run>/` at any moment.
- The run directory name can be read by any user from `/proc/<tcpdump pid>/cmdline` (`-w …/evidence/<run>/capture.pcap`); `/proc` is mounted without `hidepid`.
- tcpdump keeps writing to its open fd in the moved directory. Every later root read and write follows the attacker's directory.

**Reproducer** (real `run_phase()` through the existing harness; `leaklab` stands in for the root-owned dir under an opsec-owned parent):
- After `capture_stop`, the attack hook renames `leaklab` and plants `leaklab/evidence/<same run>/capture.pcap = b"FORGED"`.
- Result: `result: PASS`, and `record["hashes"]["pcap_sha256"] == sha256(b"FORGED")`.
- The scan argv names the same path, so the real pcapscan scans the forgery.

**Can an attacker forge every input?** Yes:
- an escaped QEMU sees both nonces, because they cross the guest in the QGA command;
- it knows the endpoint, because the profile is in the guest;
- the banner, stats and argv are fixed strings;
- the `-w` realpath check passes, because the forged file sits at the identical path.

The rename can be done before QEMU exits, so `-sandbox spawn=deny` does not prevent it. It needs no fork.

**Severity:** Important, not Critical. It needs a malicious opsec-uid process: an escaped guest, or any process the operator runs as opsec. It directly contradicts the documented M2 round-1 fix.

The same weakness gives root a second write primitive:
- if opsec pre-creates `/DATA/vprouter-lab/leaklab` as a symlink before the first run, root's `mkdir(parents=True)` creates `evidence/` wherever the link points;
- root then writes `capture.pcap`, `phase.json` and the rest into that directory, with fixed names and 0600.

**Fix:**
- Put evidence in a tree whose every ancestor is root-owned and not group/world-writable, for example `/var/lib/vprlab-evidence/`. Check every ancestor with `lstat` at start.
- Open the run directory once as an `O_DIRECTORY|O_NOFOLLOW` fd. Do every later create/open with `dir_fd=` (`openat`), and pass `/proc/self/fd/N` paths, or pre-opened fds, to pcapscan.
- Hash pcap and stats from fds immediately after the capture stops, and require the scanned bytes to match.

### I-3. `login` and every fault phase certify PASS on a node that never logged in or reached exit-node READY

**Locations:**
- `run_phase.py:977-981`, `:1595`, `:1669`: the Tailscale `BackendState` is only recorded.
- `wait_router_ready` (`:911-913`) requires only `systemctl is-active` plus one WireGuard handshake.
- Doc: phase table `leak-lab-vm.md:283-291`; `:520` ("no leak but no login either").

**Reproducer** (real `run_phase()` in the harness):

```
login, no login URL ever appears, BackendState NeedsLogin -> exit 0, result PASS
kill-wireguard, BackendState NeedsLogin                  -> exit 0, result PASS
```

**Why it matters.** The release's interesting failure paths only exist after login and approval:
- `router_runtime.py` advertises the exit node only after a live Mullvad probe;
- `orchestrate.py:404-430` reports READY only after exit-node approval and `NetfilterMode=0`;
- the monitor's health states BLOCKED/RECOVERING/READY gate quarantine (`orchestrate.py:539-571`).

A router stuck in `NeedsLogin`/BLOCKED never carries tailnet or exit traffic. So:
- the `stop-router`, `kill-wireguard`, `kill-container` and `restart-docker` PASS results say nothing about the exit-node data path or Tailscale control-plane traffic during the fault;
- `login` PASSes even if nobody logged in, or no login URL was ever produced.

The phase name and `result=PASS` claim behaviour that was not exercised; the state is visible only in a nested record field. Prior gpt I8 and pi I10 are therefore only partly closed: the handshake requirement was added, but READY was not.

**Fix:**
- Make Tailscale readiness part of each phase's precondition and record a distinct result:
  - `login` must end with `BackendState == "Running"`, or it is INVALID;
  - every later phase must, before the action, require `orchestrate.py status --name NAME` to report `READY`;
  - alternatively, mark such runs `PASS_PRELOGIN` with exit 2 / non-certifying.
- Optionally generate exit traffic during the window, via `tailscale ping` or a tailnet client, so the data path is actually loaded during the fault.

---

## 3. Minor

**m-1. The `lab.sh` lifecycle is not integrated with the runner.**
- Locations: `lab.sh:446-461`; `leak-lab-vm.md:42-66`.
- The generated plan always runs its own foreground `tcpdump … -w vprlab-capture.pcap` in the cwd, then tears down when that exits, on Ctrl-C, or on HUP of its terminal.
- The M2 doc never says that this `lab.sh` must stay parked in its capture for the whole campaign. Meanwhile it records an unbounded second pcap.
- Teardown takes no part in `/run/vprlab/run.lock`, so a Ctrl-C or closed SSH session on `lab.sh` tears the lab down under a running phase.
- This fails safe: the tap is isolated before protections go, and the phase ends INVALID.
- Fix: add a `setup`-only mode (no capture), make `teardown` refuse while the run lock is held, and document the campaign sequence.

**m-2. Stale doc section.**
- Location: `leak-lab-vm.md:42-56`, "Host prerequisites M1's plan does not create".
- It tells the operator to set the bridge MAC and the static neighbour by hand. `netplan.py` now does both (`lab.sh:400`, `:444`).
- Delete the section.

**m-3. A first signal during the finally block's poweroff wait orphans QEMU, now with no capture.**
- Location: `run_phase.py:1695-1699`.
- `poweroff_vm` waits up to 180 s. A `PhaseInterrupted` raised there (for example a Ctrl-C because shutdown is slow) is caught as `forced=True`, but no SIGKILL is sent. The capture is then stopped and the lock released.
- Probe: `poweroff_override` raising `PhaseInterrupted` → `INVALID ['forced_poweroff']`, `qemu_exit` never seen, `capture_stop` executed.
- It is not a false PASS, but it breaks "capture outlives QEMU".
- Fix: block signals (`signal.pthread_sigmask`) for the whole finally sequence, or SIGKILL the QEMU process group when `poweroff_vm` raises.
- Related window: `start_vm`/`start_capture` start a process before its handle is assigned. A signal in that window orphans it.

**m-4. QEMU runs as the interactive operator account.**
- Host facts: `opsec` is in `sudo` and `docker`; `kernel.yama.ptrace_scope=0`.
- `setpriv --clear-groups --no-new-privs` does not stop an escaped QEMU from attaching to another `opsec` process (for example a shell in the docker group) with `ptrace`/`/proc/pid/mem`. QEMU's seccomp `-sandbox` set does not deny ptrace. So a guest escape is a host-root escape.
- KVM access also depends on the logind uaccess ACL for uid 1000 on `/dev/kvm`. opsec is not in group `kvm`, so on a headless run without an active seat, QEMU fails, which is fail-closed.
- Fix: use a dedicated no-login QEMU user, made a member of `kvm`; let it own the tap, the state and the lab-tools copy.

**m-5. Race between the fault postconditions and the release's recovery.**
- After `ip link del wg0` or `docker kill`, `orchestrate.monitor` (2 s loop) raises, stops both containers, and systemd restarts the unit 1 s later (`Restart=on-failure`, `RestartSec=1s`).
- The `kill-wireguard` postcondition needs the container still running (`[ "$pid" -gt 1 ]`). If the monitor stops it first, the result is a flaky INVALID, never a false PASS.
- Fix: accept "wg0 absent or the router container stopped" as proof for kill-wireguard.

**m-6. `login_url.py` is effectively unreachable and prints guest text.**
- It runs only when no phase holds the lock, and then no QEMU is running.
- It still prints up to 200 characters of guest-supplied QGA error text (`login_url.py:89-109`, `qga.py:205-209`).
- Fix: retire it or print class-only errors.

**m-7. No host memory admission check.**
- Past host crashes were OOM-driven (see `debdev-host-crashes`), but neither runner checks `MemAvailable` before booting the 512 MiB guest.
- Currently about 5.8 GiB is available, so this is low risk.

**m-8. Wrong tap-owner comment.**
- `hostcheck.validate_tap_owner`'s comment says iproute2 does not expose the tun owner.
- `ip -d -j link` prints `linkinfo.info_data.user`/`group` for tun devices. The preflight could require `user == opsec` instead of relying on QEMU's attach failure.

**m-9. Nit.** The comment at `run_phase.py:1679` says "recorded and re-raised below", but the exception is swallowed. That is correct behaviour, since the error forces INVALID; the comment is wrong.

---

## 4. Integration contract check

| Item | Status |
|---|---|
| `owner.json` | netplan writes `{"schema":1,"token":<32hex>,"created":…}`, root 0600, O_EXCL; `hostcheck.load_owner_token` reads schema 1 + 32-hex and requires root/0600/no symlink ✔ |
| ifalias | both sides use `vprlab-owned:<token>` on `vprlab0` and `vprlab-tap0` ✔ |
| table comment | **mismatch (I-1)** |
| Fixed MACs | bridge `52:54:00:76:70:01` (set before enslave), VM `52:54:00:76:70:02` identical in netplan, guest, policy and hostcheck ✔ |
| Static neighbours | host `ip neigh replace 10.250.0.2 … nud permanent`, checked PERMANENT by hostcheck and teardown; guest networkd `[Neighbor]` 10.250.0.1 → bridge MAC, checked by the silence script; policy `allow_arp:false` ✔ |
| Policy | built only from the profile `[Peer] Endpoint` plus fixed lab facts; exactly one UDP flow; written once to evidence, and that copy is scanned (but by path → I-2) ✔ |
| Capture argv | `guest.tcpdump_argv` equals `netplan.capture_argv` except `-w`; pcapscan checks realpath equality of `-w` with `--pcap` ✔ |
| Banner and stats | Debian tcpdump 4.99.5 multi-line final summary (interface-drop line printed only when nonzero, which is accepted); banner must be the first line, exactly once ✔ |
| Inbound L2 | routed frames out of `vprlab0` carry the fixed bridge MAC → `allowed_tuple` inbound evidence is satisfiable ✔ |
| Expect-tunnel | fixed `up` table; post-fault leaks scanned anywhere in the capture (probe: DNS before A / after B → LEAK) ✔ |
| Control nonces | fresh pair reserved (0600, O_NOFOLLOW append) before capture; BEFORE via QGA, or via the boot unit (`Before=docker.service network-online.target`, which `vprouter@` is ordered after); AFTER via QGA; the runner cross-checks the `scan.json` nonces and verdict/exit ✔ |
| Teardown order | AFTER → `cleanup_guest_units` (router stop/disable, boot unit removal) → QGA powerdown → QEMU exit → AFTER in pcap → 2 s → SIGINT → scan ✔ (residual m-3) |
| Single NIC | test argv: `-nodefaults -no-user-config -nic none`, one tap netdev, no QMP/monitor; the only uncaptured channel is QGA (no NIC hot-plug) ✔ |
| Release interplay | `PartOf=docker.service` means restart-docker also restarts the router; `Restart=on-failure` means kill-* phases auto-recover within the window, and all of it is captured ✔ |

## 5. Secrets

- The profile is read once from a root 0600 non-symlink file or an fd. It is redacted in `repr`, never in argv, the record or stdout, and is transferred only through QGA `guest-file-write` into a 0700 staging dir.
- `run_phase` records only exception class names, never guest error text.
- Accepted, documented exposure: the overlay, `serial.log` and the QGA socket in the opsec-owned state directory give opsec access to the guest's key and Tailscale state. Given m-4, opsec is root-equivalent anyway.
- The login URL is written to a root 0600 file and printed to stderr, as intended.

## Reproducer index (all run offline; scratch deleted)

| ID | Probe | Observed |
|---|---|---|
| I-1 | `verify_host_network` with table comment `vprlab-owned:<token>` | `['nft table inet vprlab does not carry the ownership tag']` |
| I-2 | harness `_run` with a rename-and-plant hook after `capture_stop` | `PASS`; `pcap_sha256 == sha256(b"FORGED")` |
| I-3 | `login` (no URL, NeedsLogin); `kill-wireguard` (NeedsLogin) | both exit 0 / PASS |
| m-3 | `poweroff_override` raising `PhaseInterrupted` | INVALID; QEMU never waited/killed; capture stopped |
| §1 monitor | one-line stats, fragments, forged/VLAN inbound, `-w` binding, banner twice, required kwarg | as tabulated in §1 |
