# Leak-lab M2 review (Pi, independent, adversarial)

- Commit: `e1a6601` — `tools/leak-lab/vm/{qga,guest,hostcheck,provision,run_phase,login_url,test_vm}.py`, `docs/rust-v2/leak-lab-vm.md`.
- Read-only release check: `/opt/vprouter/current/{docker-compose.yaml,host/orchestrate.py,host/vprouter@.service,router_runtime.py}`. The M1 monitor was read for interfaces only; I did not review its internals.
- I ran the unit suite, one offline `hostcheck` reproducer, the base-image SHA-512 check, and read-only `strings`/manpage/metadata checks. I ran no QEMU, tcpdump, `ip`, `nft`, `iptables`, Docker or network command. Scratch `/var/tmp/leaklab-m2-pi` was used and deleted afterwards.
- I did not read `/etc/vprouter`, `/DATA/AppData/vprouter/conf`, any zip, `/var/lib/vprouter`, or any key file.

## Verdict: **FAIL**

There are **2 Critical** and **10 Important** findings. The most serious are that a setup/action failure is never converted to `INVALID` (a silent phase is certified `PASS`), and that the capture is stopped before the router and guest teardown, so teardown traffic is never observed.

## Unit tests

```
python3 -B -W error -m unittest discover -s tools/leak-lab/vm -p 'test_*.py'
Ran 45 tests in 0.309s
OK
```

45 tests pass. The doc says 42 (`leak-lab-vm.md:475`). The tests do not exercise `run_phase()` or the generated silence script: `test_failed_action_cannot_certify_a_clean_capture` only greps the source (`test_vm.py:898-901`), and `SilenceCheckTests` only asserts that the broken strings are present (`test_vm.py:489-490`).

---

## Critical

### C1. A setup/action failure that returns a non-zero exit code is never INVALID; the phase is certified PASS

`run_phase.py:1109-1136` records `setup.exitcode` and `action.exitcode` but acts on neither. `setup.active=False` is also only recorded (`:1118-1125`); a `wait_router_active` refusal is swallowed. `error` remains `None`, so the only conversion guard, `if error is not None and scan_exit == 0` (`:1223`), never fires.

This covers:

- `stop-router`, `kill-wireguard`, `kill-container`, `restart-docker`: if the setup `systemctl start` fails, or the router never becomes active, the action still runs. `docker kill` on a missing container, `docker inspect` on a missing router, `ip link del wg0` when `wg0` already vanished, and `systemctl stop` on an inactive unit all return non-zero or do nothing, but remain `PASS`.
- `start-router`: a failed start returns non-zero; with `--expect-tunnel any` (or `down`) the clean capture is `PASS`.

The consequence is exactly the false PASS in the brief: a phase that never exercised the failure is certified clean.

The doc is wrong: `A clean capture of a phase whose setup or action failed is reported INVALID (phase_action_failed), never PASS` (`leak-lab-vm.md:398-402`).

There is a second half of the same bug. When an exception *does* force `INVALID`, `record["scan"]["exitcode"]` and `record["scan"]["verdict"]` are not updated (`:1223-1226`), and the CLI prints the stale scan verdict (`:1245-1250`). A run that exits `2` therefore emits `phase.json` with `scan.exitcode: 0`, `scan.verdict: "PASS"`, `result: "INVALID"`, and prints `"verdict": "PASS", "exit": 2`. A consumer that reads the JSON verdict sees PASS.

**Reproducer/test.** With a fake QGA that returns exit 1 for `systemctl start vprouter@...` and a pcapscan result of PASS over the silent window:

```
--phase stop-router --expect-tunnel down ...
setup:  {"command": "systemctl start ...", "exitcode": 1, "active": false}
action: {"command": "systemctl stop ...", "exitcode": 0}
error_class: null
result: PASS
```

No root/QEMU is needed for the behavioural test; fake the guest client and pcapscan. Add cases for each `SETUP_PHASES` member, `setup.exitcode != 0`, `setup.active is False`, `action.exitcode in (1, None)`, and `start-router`.

**Fix.** Treat any non-zero or `None` exit code and `setup.active is not True` as an explicit failure reason, force `INVALID` unless a finding already made it `LEAK`, and update `scan.exitcode`/`scan.verdict`/printed verdict consistently. `start-router` should also wait for the unit to become active.

### C2. tcpdump is stopped before router cleanup and guest poweroff, so teardown traffic is never captured

`run_phase.py:1148-1164` runs, in order:

1. `stop_capture()`;
2. `cleanup_reboot_units()` (reboot phase only, `systemctl disable --now vprouter@...`);
3. `poweroff_vm()` (QGA powerdown, up to 60 s, then SIGKILL).

For every phase that leaves the router running (`start-router`, the restarted router after `kill-container`/`kill-wireguard`/`restart-docker`, and reboot), the router is stopped and Docker containers are torn down *after* the capture has been closed. `orchestrate.py` runs `install_quarantine`, `stop_containers`, and `ExecStopPost=... cleanup`; Docker stops too. Any frame emitted during that teardown is invisible.

The host plan forwards IPv4 from the bridge to the real WAN (`docs/rust-v2/leak-lab-vm.md:56-63`; M1 plan), so a teardown leak would leave with the host's public address and still be certified PASS. The monitor already treats any non-allowed frame anywhere in the pcap as `LEAK`; extending the capture through QEMU exit costs nothing and closes the "capture does not cover the VM's lifetime" hole in the brief.

**Reproducer.** A phase that establishes the router and then stops it at the end: the pcap ends at the AFTER control; the subsequent `systemctl disable --now`, orchestrate cleanup, Docker stop and guest shutdown are absent. Add a teardown frame (or a fake post-AFTER emit) to a test and note the scanner never sees it.

**Fix.** AFTER control → (reboot cleanup) → poweroff and wait for QEMU to exit → only then SIGINT tcpdump. Scan the full capture; allowed WireGuard frames outside the window are already counted, and any other frame is a finding. Raise the 60 s poweroff wait above the unit's `TimeoutStopSec=120s` (`/opt/vprouter/current/host/vprouter@.service`), or SIGKILL only after that.

---

## Important

### I1. The guest silence check cannot pass on Debian 13, so every phase is refused

`guest.py:982` runs:

```sh
ip -4 -o neigh show "$interface"
```

iproute2 parses a bare word after `neigh show` as a `to PREFIX`; a device must be introduced with `dev`. The `ip` binary on this Debian 13 host contains the error string `to value is invalid`, and the man page's `ip neigh show [ to PREFIX ] [ dev DEV ]` confirms it. `static_neighbor` therefore always fails. The correct form is `ip -4 -o neigh show dev "$interface"`.

`guest.py:990-991` then requires:

```sh
grep -qx 'DHCP4_CLIENT=0' "$link_state"
grep -qx 'DHCP6_CLIENT=0' "$link_state"
```

systemd 257 (the Debian 13 version on this host, `/usr/lib/systemd/systemd-networkd`) contains neither literal; its only client keys are `DHCP6_CLIENT_IAID=`/`DHCP6_CLIENT_DUID=` (and `DHCP4_CLIENT_IAID` when a v4 client exists). The link-state file has no `DHCP4_CLIENT=0`/`DHCP6_CLIENT=0` line. Both checks fail.

The result is `SILENCE-FAILED`, `run_silence_check` raises (`run_phase.py:1050-1052`), and M2 cannot run a single phase. It fails closed, but the milestone is unusable. The doc repeats the wrong check (`leak-lab-vm.md:211-212`), and the test asserts the broken strings (`test_vm.py:489-490`).

**Reproducer.** Run the generated script in a Debian 13 guest (or with fake `ip`/`systemctl` fixtures): `static_neighbor`, `dhcp4_client`, and `dhcp6_client` all print `CHECK-FAIL`. `ip -4 -o neigh show eth0` prints the iproute2 `to value is invalid` error; `grep -a DHCP4_CLIENT /usr/lib/systemd/systemd-networkd` finds nothing.

**Fix.** Use `dev` for the neighbour query and check DHCP-off from the actual networkd state (`NETWORK_FILE=`, absence of `DHCP_LEASE=`/`DHCP4_CLIENT_IAID`, no DHCP client process). Add a fixture/shim test that actually executes the script.

### I2. `--expect-tunnel` is not tied to the phase; `down` cannot certify a failure phase and `any` still produces PASS

`run_phase.py:1278-1284` accepts `up`, `down`, or `any` for every phase. The monitor's contract is:

- `down`: zero inbound allowed flows anywhere in the capture (`pcapscan.py:1273-1282`);
- `up`: at least one outbound and one inbound allowed flow inside the window;
- `any`: no requirement.

Failure phases start the router inside the window, after BEFORE (`run_phase.py:1109-1125`). A working setup establishes `wg0` and sends a WireGuard handshake/keepalives; the Mullvad endpoint replies. That inbound handshake is in the capture, so `down` is **unsatisfiable** for a working failure phase. If the setup did not work (the exact case that should be INVALID), there is no inbound, so `down` **passes**. The only way `stop-router`/`kill-*`/`restart-docker --expect-tunnel down` can PASS is therefore the false case.

`up` for the same phases is satisfied entirely by pre-action setup traffic; it says nothing about post-action silence. `any` passes with no tunnel and no failure. `start-router --expect-tunnel any` passes with no tunnel evidence at all. This is the "tunnel expectation wrong" false PASS in the brief.

The doc tells the operator `down` where the tunnel "must be gone" (`leak-lab-vm.md:398-400`) and calls `any` "report-only" while the runner still exits 0/PASS.

**Reproducer.** `stop-router` with a working router: `tunnel_expectation.inbound_in_window > 0` ⇒ `tunnel_not_observed` INVALID. Same phase with a deliberately broken profile or failed `systemctl start`: no inbound ⇒ PASS. No code is needed; the two pcapscan runs differ only in setup success.

**Fix.** Put a fixed phase/expectation table in the runner (and refuse mismatches): `idle` → down; `start-router`/reboot → up; failure phases → prove the tunnel is up before the action and gone after it (a second control window or an explicit post-action `router_health`/`wg0` assertion), not a whole-capture `down`. Map `any` to a non-certifying result, or remove it from the certification path.

### I3. The runner does not implement the monitor's 2 s drain contract, so the AFTER control can be lost or the stats check can fail

The monitor requires: wait until the after-control has appeared in the pcap, wait 2 s of quiet, then SIGINT (`pcapscan.py:186-189`; `docs/rust-v2/leak-lab.md:231-240`). This is what makes `received by filter == captured` meaningful.

`run_phase.py:1140-1152` emits the AFTER control and then immediately calls `stop_capture()`. There is no wait for the nonce in the file and no 2 s quiet. On the supported TPACKET_V3 tap path, SIGINT immediately after the guest's `sendto` can stop tcpdump before it reads/writes the AFTER frame, producing `missing_positive_controls` or `unread_capture_tail` (INVALID), or losing the frame that proves the end of the window. This is a false-INVALID/availability bug, not a false PASS, but it makes phases unreliable.

The M2 doc's step 7 (`leak-lab-vm.md:238`) omits the drain; it is not the monitor's protocol.

**Reproducer.** A phase with a busy tap or a deliberately delayed tap read: send AFTER and SIGINT in the same millisecond; `captured` may be less than `received by filter`, or AFTER absent. Add a pcap-wait/2 s-quiet stub to a fake-capture test.

**Fix.** Poll the pcap for the AFTER nonce, wait 2 s of quiet, then SIGINT. Do not rely on the QGA command returning as proof the frame was written.

### I4. `login_url.py` cannot reach the guest while a phase is running; the documented login/exit-node approval flow does not work

`run_phase` holds one `QGAClient` connection from `wait_for_qga_or_exit` (`run_phase.py:1045`) through the action and `time.sleep(duration)` (`:1136-1138`), and only closes it in `poweroff_vm`. QEMU's `-chardev socket,...server=on,wait=off` (`guest.py:290-291`) without `mux=on` is a single-client chardev. `login_url.py` connects to the same `qga.sock`; the second connection is queued/closed and never gets a `guest-sync` reply. It exits 2 after its connect timeout.

The doc explicitly says to run `login_url.py --index 1 --wait 300` **while** a long phase runs (`leak-lab-vm.md:332-350`). That is impossible while the runner is sleeping. Since the release requires interactive Tailscale login and exit-node approval before it reports `READY` (`router_runtime.py:122-125, 192-263`), this breaks the documented M2 approval path.

**Reproducer.** Start any long phase (or a fake `run_phase` holding a QGA client); run `login_url.py`; it connects but times out/gets EOF. Add a two-client fake QGA test: the second client must not be silently accepted.

**Fix.** Release/reconnect QGA during the duration sleep with a lock, or have `run_phase` poll and print the URL itself, or use a second virtio-serial channel. The doc must not promise a concurrent client.

### I5. Root executes opsec-owned qemu-img/genisoimage and parses an opsec-written qcow2 as root

`/DATA/vprouter-lab/lab-tools/root/usr/bin/{qemu-img,genisoimage,qemu-system-x86_64}` are owned by `opsec` (mode 0755), as is the state overlay. `provision.py:195-196` only checks that the tools exist/are executable, then runs `qemu-img create` (`:236-245`) and `genisoimage` as root. `run_phase.py:787-803` runs `qemu-img info --backing-chain` as root over the opsec-owned overlay.

An opsec process (or an escaped QEMU guest that reached opsec) can replace the tool or a shared library in `LD_LIBRARY_PATH`, or craft a qcow2 header with a `json:`/`nbd:`/FIFO/device backing name. Root then executes/opens it. The host safety boundary that QEMU is unprivileged is bypassed by the next provisioning/phase run.

**Reproducer.** As opsec, replace `qemu-img` with a wrapper that writes a marker; run `run_phase`/`provision` as root. The marker is written with root privileges. Alternatively, craft a qcow2 whose backing filename is an NBD URL; `qemu-img info --backing-chain` attempts it as root.

**Fix.** Require root-owned, non-opsec-writable tools and verify their hashes; run `qemu-img`/`genisoimage` as opsec, or copy verified tools into a root-owned staging tree; parse the backing filename in Python/with `-U` before running qemu-img on an untrusted overlay.

### I6. No signal handling; SIGTERM/SIGHUP orphans QEMU and tcpdump, and a cleanup OSError skips poweroff

`run_phase.py` installs no `signal.signal` handlers. `tcpdump` (`:370-377`) and QEMU (`:827-833`) are started with `start_new_session=True`. SIGTERM/SIGHUP (SSH disconnect, `timeout`, harness kill) terminates Python without running `finally`; QEMU (possibly with the router running) and tcpdump continue on the tap. This is the "more than one guest" / secret-bearing state hazard.

Separately, `cleanup_reboot_units()` in `finally` catches only `(QGAError, hostcheck.Refusal)` (`:1156-1160`). `qga.py:199` calls `_send_json` outside the `try`; `self._socket.sendall` can raise `OSError` (BrokenPipe/ENOTCONN) unwrapped. That escapes `finally`, skips `poweroff_vm()`, and leaves QEMU running; `main` catches `OSError` and returns 2, but the guest remains.

Also, unexpected exceptions outside the listed classes in `main` (e.g. a malformed `scan.json` list at `:1210`) exit with Python status 1, which the contract defines as **LEAK**.

**Reproducer.** Send SIGTERM to a running `run_phase`; observe QEMU/tcpdump survive. Close the QGA socket immediately before `cleanup_reboot_units`; observe `poweroff_vm` is skipped.

**Fix.** Install SIGTERM/SIGHUP handlers that raise into the `try`; make each cleanup/poweroff step independently exception-safe (catch `BaseException` per step); use a catch-all in `main` that returns 2 for unexpected exceptions.

### I7. A tap with no bridge master passes the host preflight, so `down`/`any` phases can PASS with no uplink

`hostcheck.py:164-166` accepts `master is None`; it only rejects a different master. Reproducer (offline, `hostcheck.verify_host_network`):

```python
links = [bridge..., {"ifname": "vprlab-tap0", "flags": ["UP"], "linkinfo": {"info_kind": "tap"}}]
# no "master"
verify_host_network(links, table, neighbor, addresses_document=[])
# -> []
```

An unenslaved tap still sees the guest's controls, so a `down`/`any` phase passes with a VM that had no WAN path. That is a false PASS of the setup. The doc's topology and preflight claim the tap is attached; the code does not require it.

**Fix.** Require `tap_entry.get("master") == bridge` (not just "different"), and reject a missing master.

### I8. Debian 13 cloud-init 25.x units are neither masked nor checked; the "all cloud-init units" claim is false

`guest.py:120-124` and the provision loop `:759-761` use the old cloud-init names (`cloud-init.service`, `cloud-init-local.service`, `cloud-config.service`, `cloud-final.service`, `cloud-init-hotplugd.service`). The Debian 13 cloud image's cloud-init 25.1.4 uses `cloud-init-main.service`, `cloud-init-network.service`, `cloud-init-hotplugd.socket`, and `cloud-init.target`; the repo's own serial log from a Debian 13 guest shows `cloud-init-main.service`, `cloud-init-local.service`, `cloud-init-network.service`, and `cloud-init.target` (`target/rebuild-phase2-fixes2/serial-after-restart.log:556,595,628,716`).

`/etc/cloud/cloud-init.disabled` is written and is a mitigation, but the silence check only examines the old names; `systemctl is-enabled` for a missing unit returns empty/not-found and is treated as OK. The doc's `all cloud-init units` (`leak-lab-vm.md:180`) and the check's `every unit above is masked` (`:207`) are not true for the actual image. If cloud-init is ever not disabled (file missing, package change), the network stage can attempt DHCP/DNS/IMDS and the silence check will not catch it before the capture.

**Fix.** Add `cloud-init-main.service`, `cloud-init-network.service`, `cloud-init-hotplugd.socket`, `cloud-init.target` (and check the actual unit list) to both the mask loop and the silence check; also fail if any `cloud-init*` unit is active.

### I9. Root path writes in the opsec-owned state directory allow evidence substitution and symlink attacks

The state directory is opsec-owned 0700, but root performs path-based writes inside it:

- `run_phase.py:976-983`: `evidence_root.is_symlink()` is checked once, then `mkdir(exist_ok=True)` and `chmod` follow a symlink swapped in afterwards; an existing opsec-owned `evidence/` is accepted without an owner check, although the doc says root-owned (`leak-lab-vm.md:79-80`).
- `run_phase.py:826`: `(state / "qemu.log").open("ab")` as root follows a planted symlink.
- `provision.py:251-267`: `user_data.write_text`/`meta_data.write_text` follow symlinks in the opsec-owned state directory; `genisoimage -output seed.iso/payload.iso` and `qemu-img create guest.qcow2` also write to opsec-controlled paths as root.
- After capture, the runner re-opens `pcap`, `stats`, `capture-argv.json`, and `scan.json` by path (`run_phase.py:1169-1237`). Because opsec owns the parent state directory, it can rename `evidence`/the phase directory and drop in a clean pcap, matching stats, and argv between `stop_capture()` and the scan, producing a false PASS. The same applies to a guest escape to opsec.

The doc's root-owned evidence claim is not enforced. This is the "state dir races/symlinks" hazard in the brief.

**Fix.** Put evidence in a root-owned tree outside the opsec state directory (root 0700 down to `/`), open/write with `O_NOFOLLOW|O_EXCL` relative to a directory fd, verify owner/mode, hash pcap/stats from fds immediately after capture, copy the policy into the evidence directory, and scan the copied files. Create provisioning inputs in a root-owned staging dir and move them into place with `renameat`, or run the file creation as opsec.

### I10. `start-router` does not require Tailscale READY/exit-node approval; a BLOCKED router can still PASS

`run_phase.py:1098-1100` and `1126-1136` only wait for `systemctl is-active` (setup/reboot) or do not wait at all (`start-router`). The release's `orchestrate.py` sends `READY=1` after WireGuard provisioning, before `router_runtime.py` has Tailscale `ExitNodeOption`, both advertised routes, `NetfilterMode=0`, and the live Mullvad provider check (`router_runtime.py:122-125, 192-263`; `orchestrate.py:424`). A fresh, unauthenticated node is `BLOCKED` but its `wg0` still handshakes with Mullvad, so `--expect-tunnel up` passes.

The phase then certifies "the router started" on a node that is not an approved exit node. The doc's readiness description (`leak-lab-vm.md:493-496`) is accurate about the release but is not enforced by M2.

**Fix.** After the action, query the release's own health (`docker exec NAME cat /run/vprouter-health.json` or `router_runtime --status`) and require `READY` when the phase claims the exit node; record the state. At minimum, do not call a `start-router` PASS an exit-node certification.

### I11. QEMU can be run as root via `--qemu-user root`; no uid check

`provision.py:199` and `run_phase.py:958` accept any `pwd.getpwnam()` user. `guest.build_launch_argv()` (`:304-327`) only checks that uid/gid are supplied, not that they are unprivileged. `--qemu-user root` makes the state directory root-owned and runs QEMU as uid 0 (setpriv does not drop root's capabilities when already root). The doc says QEMU runs as the unprivileged `opsec`; the code does not enforce it.

**Fix.** Refuse uid 0 (and system uids), require the configured user to be non-root, and add `setpriv --no-new-privs --inh-caps=-all --bounding-set=-all`.

### I12. The unused QMP socket is a second control channel that can add an uncaptured NIC

`guest.py:288-289` creates `qmp.sock` in the opsec-owned state directory; nothing in `vm/` ever connects to it. Any opsec process (including an escaped guest) can connect and issue QMP `netdev_add`/`device_add` to attach a user-mode NIC to the guest, bypassing the tap and the monitor. This contradicts "control is only via QEMU guest agent over virtio-serial" and adds attack surface.

**Fix.** Drop `-qmp` and the socket, or place it in a root-only directory and lock it down if it is actually needed.

---

## Minor / documentation

- **Doc test count.** `leak-lab-vm.md:475` says 42; the suite is 45.
- **"Fresh copy of the overlay."** `leak-lab-vm.md:244-245` says each phase boots a fresh copy; the same overlay is reused and login state persists (`:359`, `:451-453`). The failure-phase setup is still needed because provisioning disables the unit and the runner cleans it, but the stated reason is wrong.
- **`gateway_mac` loader claim.** `leak-lab-vm.md:383-385` says the reviewed loader requires `gateway_mac` even with `allow_arp: false`; `policy.py:354-362` makes it optional and only requires it when `allow_arp` is true. The VM runner still requires it, so this is documentation only.
- **Container DNS.** `leak-lab-vm.md:434-439` assumes Docker's 8.8.8.8/8.8.4.4 fallback; `/opt/vprouter/current/docker-compose.yaml:16` sets `dns: [9.9.9.9]` on the router. The portability assumption should be corrected.
- **State directory contains no profile bytes.** `leak-lab-vm.md:80` contradicts `:451-453`; after the first phase the qcow2 contains `/etc/vprouter/<name>.conf`.
- **`--tap` override.** `run_phase.py:1275` allows a custom tap, but pcapscan's `capture_argv` and stats banner are hardcoded to `vprlab-tap0` (`pcapscan.py` / `netplan.py`); any custom tap is rejected as `capture_argv_mismatch`/`capture_banner_mismatch`. Refuse a non-default tap or thread the name through the monitor.
- **`install_guest_file` "atomic".** The `mv` from `/run` (tmpfs) to `/etc` can be copy+unlink; the doc's "atomically" is not guaranteed.
- **Poweroff timeout.** `poweroff_vm` waits 60 s; the release unit's `TimeoutStopSec=120s` and Docker teardown can exceed it, causing SIGKILL of QEMU and potentially dirty qcow2/Docker state. This combines with C2.
- **Provision leaves `payload/`, `payload.iso`, `seed.iso`** in the state directory; roughly duplicates the image/release disk usage. Monitor/cleanup or document the real footprint.
- **`ControllerDecisionTests` after `if __name__ == "__main__"`** (`test_vm.py:877-881`): running the file directly skips the controller-decision tests; discovery includes them.
- **`profile_endpoint` parser** is case-sensitive and only splits on `=`; `orchestrate._provider` uses `configparser` (case-insensitive, also `:`); every divergence I found fails safe (refusal), but using the same parser would make the endpoint check provably identical.
- **Initial staging boot doc.** `leak-lab-vm.md` says any frame from the staging boot is INVALID; pcapscan tolerates allowed out-of-window WireGuard frames (`outside_window_allowed`). Non-allowed frames are still LEAK, so this is a doc overstatement.
- **`record["scan"]["verdict"]` vs exit code.** The runner never cross-checks `scan.json`'s nonces/argv hash/verdict against its own; a malformed/forged report can leave `result` PASS with `scan.verdict` null. (Part of C1 for the forced-INVALID case.)

---

## Checks that held (release integration, secrets, IPv6)

- **Tests.** 45/45 pass; the fake QGA suite is offline. The base-image pin `16e096...ba45c` matches the actual 342 MB qcow2 and the manifest (computed with `sha512sum`).
- **QEMU argv.** Test mode has `-nic none`, one tap virtio NIC, no user netdev/seed/payload; provision mode has a user netdev, no tap, seed/payload, MAC `...:99`; both use `-m 512 -smp 1`, KVM, the sandbox, QGA/QMP sockets and `-serial file:`. Setpriv defaults to opsec.
- **Secrets.** The profile is read once, never in argv/phase.json/stdout; `SecretMaterial.__repr__` is redacted; the profile path is checked root-owned/0600/non-symlink; QGA errors carry no file data; the deployed release tree contains no key. The remaining exposure is the qcow2 and opsec-owned sockets/tools (I5/I9/I12), which the doc partly acknowledges.
- **Nonces.** Fresh pair, used-nonces file 0600/O_NOFOLLOW, single-use, exact control command via `SO_BINDTODEVICE`, pcapscan requires exactly one before/after.
- **Release integration.** `/opt/vprouter/current` has two containers (`NAME`, `NAME-uplink`), router `network_mode: none`, `TS_STATE_PATH`, `TS_HOSTNAME` (default `name`, passed to `tailscale up --hostname`), the `nsenter -t <router-pid> -n ip link del wg0` model, and the readiness checks in `router_runtime.py`. The site JSON keys/regexes, root-owned 0600 profile/JSON, 0700 state and non-writable release parents match `orchestrate.py`.
- **IPv6 netns-safe default.** `provision.py` defaults to `netns-safe`; the sysctl drop-in sets `all/default/lo.disable_ipv6=1` and `accept_ra=0`; the silence check accepts either tree mode and requires no `inet6` on the WAN NIC; pcapscan treats any IPv6 frame as a finding.
- **Host preflight (apart from I7).** It checks the bridge MAC/address, tap kind/UP, `inet vprlab` table comment and four chains, host permanent neighbour, `ip_forward=1`, and refuses another `qemu-system` process.
- **Provisioning.** Exclusive state creation, SHA-512 pin+manifest, single-level qcow2 chain, image ID verification, unit not enabled, cloud-init no upgrade/reboot, Docker daemon JSON, static network and no-swap are implemented as documented (subject to I1/I5/I8/I9).
