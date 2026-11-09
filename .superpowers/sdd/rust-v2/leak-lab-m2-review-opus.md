# Leak-lab M2 review (Opus, independent, adversarial)

- Commit: `e1a6601` (`rust/v2`), files `tools/leak-lab/vm/{qga,guest,hostcheck,provision,run_phase,login_url,test_vm}.py`, `docs/rust-v2/leak-lab-vm.md`.
- Release checked read-only: `/opt/vprouter/current/{docker-compose.yaml,host/orchestrate.py,host/vprouter@.service,router_runtime.py}`.
- I executed nothing beyond the unit suite and one offline reproducer with fakes (scratch `/var/tmp/leaklab-m2-opus`, deleted afterwards). I ran no QEMU, tcpdump, ip, nft, docker or network commands. I read no secrets.
- I did not read the other M2 review, so this one is independent of it.

## Verdict: **FAIL**

There are 2 Critical and 5 Important findings. The most serious is the controller decision "failed action ⇒ INVALID", which is not implemented for any non-exception failure. A failure phase whose router never started is certified **PASS**; I reproduced this below.

## Unit tests

```
python3 -B -W error -m unittest discover -s tools/leak-lab/vm -p 'test_*.py'
Ran 45 tests in 0.308s
OK
```

That is 45 tests, all passing. The doc says 42. No test runs `run_phase.run_phase()`: the controller-decision test only greps the source text for the string `phase_action_failed` (`test_vm.py:898-901`).

---

## Critical

### C1. A setup or action that fails without raising never makes the phase INVALID, so a phase that never happened is certified PASS

`run_phase.py:1109-1135`. The setup and action exit codes are recorded but never acted on:

- `setup.exitcode != 0` sets only `record["setup"]["active"] = False`.
- If `wait_router_active` raises `Refusal`, the exception is swallowed (`:1119-1123`).
- `action.exitcode` is stored, with any value including `None` for a signal death, and nothing else happens.

`error` stays `None`. The guard at `:1223` (`if error is not None and scan_exit == 0`) only covers exceptions.

**Reproducer.** Offline, everything faked. The guest returns exit 1 for `systemctl start vprouter@…`, and pcapscan returns PASS on the silent window:

```
--phase stop-router --expect-tunnel down ...
exit 0
result PASS reason None
setup  {'active': False, 'command': 'systemctl start vprouter@zz-vprtest-01-do-not-use.service', 'exitcode': 1}
action {'command': 'systemctl stop vprouter@zz-vprtest-01-do-not-use.service', 'exitcode': 0}
error_class None
```

The same happens in these cases:

- `kill-container`: `docker kill NAME` exits 1 because there is no container.
- `kill-wireguard`: `docker inspect` fails, or `wg0` is already gone.
- `start-router`: `systemctl start` fails (Type=notify, so it fails if orchestrate never reaches `READY=1`).
- `restart-docker`: fails.

**This combines with C1b and makes it worse.** pcapscan's `--expect-tunnel down` means "no inbound allowed flow anywhere in the capture" (`pcapscan.py:1275-1278`). For every `SETUP_PHASES` phase, the router is started *inside* the window. A working setup therefore always produces inbound WireGuard, so `down` is unsatisfiable. The doc tells the operator to use `down` "where it must be gone" (`leak-lab-vm.md:398-400`). With that choice, a stop-router, kill-* or restart-docker phase can only PASS when the setup failed.

The doc's claim "A clean capture of a phase whose setup or action failed is reported INVALID (`phase_action_failed`), never PASS" (`leak-lab-vm.md:400-402`) is false.

**Fix:**
- Make every non-zero or `None` exit code, and `setup.active is not True`, set an explicit failure reason (`setup_failed`, `action_failed`, `router_not_active`). That forces INVALID; LEAK still wins.
- Treat the `start-router` action like setup: require `wait_router_active`.
- Add a behavioural test that runs `run_phase()` with fakes, along the lines of the reproducer, for each phase and each failure point.

### C2. tcpdump is stopped before the VM is torn down, so the router teardown and guest shutdown are never captured, while the host forwards everything to the real WAN

`run_phase.py:1148-1164`. The `finally` block runs in this order:

1. `stop_capture()`
2. `cleanup_reboot_units()` (reboot phase), which runs `systemctl disable --now vprouter@NAME`
3. `poweroff_vm()`: QGA powerdown, up to 60 s, then SIGKILL

In every phase that leaves the router running (start-router, the restarted router after kill-container, kill-wireguard and restart-docker, and reboot), the guest's shutdown path runs with **no capture**:

- systemd stops `vprouter@`;
- `orchestrate.py` runs its `finally` (`install_quarantine`, `stop_containers`);
- `ExecStopPost=orchestrate.py cleanup` runs;
- docker stops.

`netplan.py:324` accepts all IPv4 forwarding from `vprlab0` to the WAN and masquerades it (`:331`). Any teardown leak therefore leaves debdev with the host's public IP and is never seen, and the phase is still PASS. This is precisely "capture does not cover the VM's lifetime".

pcapscan already tolerates this: after-window allowed WireGuard frames are only counted (`outside_window_allowed`), and any non-allowed frame is still LEAK (`pcapscan.py:22-24, 1252-1262`). Reordering costs nothing.

**Fix:**
- Order the teardown as: AFTER control → (reboot cleanup) → poweroff, confirming QEMU has exited (`process.wait`, then SIGKILL) → only then SIGINT tcpdump.
- If teardown frames must stay outside certification, record them as a separate post-AFTER segment, but they must be captured and scanned for findings.
- Also raise the poweroff wait above the unit's `TimeoutStopSec=120s` (`vprouter@.service`). The current 60 s routinely SIGKILLs QEMU mid-teardown, which also risks the qcow2 and Docker state.

---

## Important

### I1. The guest silence check cannot pass on Debian 13, so every phase is refused (fail-closed, but the milestone cannot run)

`guest.py:982` runs `ip -4 -o neigh show "$interface"`. iproute2 reads a bare word as the `to` prefix, so this fails with "to value is invalid":
- the error string is present in `/usr/bin/ip`;
- the correct form is `ip -4 neigh show dev "$interface"`.

The result is that `static_neighbor` is always `CHECK-FAIL`.

`guest.py:990-991` greps the networkd link state for `DHCP4_CLIENT=0` and `DHCP6_CLIENT=0`. systemd 257, the same version as Debian 13's guest, writes neither key. The only `*CLIENT*=` keys in `/usr/lib/systemd/systemd-networkd` are `DHCP6_CLIENT_IAID=`, `DHCP6_CLIENT_DUID=` and `CLIENTID=`, plus `DHCP_LEASE=`. So `dhcp4_client` and `dhcp6_client` always fail too.

The fake-agent tests never execute this script.

**Fix:**
- Use `dev`.
- Check DHCP-off from the network file (`networkctl status` / `NETWORK_FILE=` equals `10-vprlab-wan.network`) and from the absence of `DHCP_LEASE=`, with no DHCP client process.
- Run the script against a fixture once, for example with fake `ip`/`systemctl` shims, so syntax errors are caught.

### I2. `--expect-tunnel` is required but not tied to the phase, and `any` still produces PASS

`run_phase.py:1278-1284` accepts any of the three values for any phase. The problems:

- `start-router --expect-tunnel any` PASSes with no tunnel evidence.
- For the failure phases, `up` is satisfied entirely by traffic from before the failure (setup handshake and keepalives), so it says nothing about the post-failure behaviour.
- `down` is unsatisfiable when setup succeeds (see C1).
- The doc calls `any` "report-only", yet the runner still exits 0 / `PASS`.

**Fix:**
- Put a fixed table in `run_phase`: idle → `down`; start-router and reboot → `up`; failure phases → `up` plus a post-action check. That check is either a second window (BEFORE / MID / AFTER) or an explicit "router not active / wg0 absent" guest assertion after the action.
- Refuse a mismatching operator value.
- Map `any` to a distinct non-certifying result (for example `REPORT_ONLY`, exit 2).

### I3. The VM and tcpdump can be orphaned on the tap with nobody observing

- No signal handling: there is no `signal.signal` anywhere in `vm/`.
- QEMU and tcpdump are started with `start_new_session=True` (`run_phase.py:376, 833`).

So SIGTERM or SIGHUP to `run_phase.py` kills only Python, and no `finally` runs. Realistic triggers: an SSH disconnect during the documented 900 s login phase, `timeout`, or an agent harness kill. QEMU (with the router possibly running) and tcpdump keep running. Separately:

- `cleanup_reboot_units` in `finally` catches only `(QGAError, Refusal)` (`:1159`). An `OSError` from `QGAClient._send_json`/`sendall`, which is not wrapped (`qga.py:113-117`), escapes and skips `poweroff_vm` entirely.
- Unexpected exception types in `main` (anything outside the listed classes, for example an `AttributeError` if `scan.json` is a list, `:1210`) exit with Python's status 1, which the contract defines as **LEAK**.

**Fix:**
- Install SIGTERM/SIGHUP handlers that raise into the `try`.
- Make each `finally` step independent, with its own `try` for each step and a catch-all.
- Use a catch-all in `main` that returns 2.

### I4. Root does path-based writes in directories owned by the unprivileged user, which allows evidence substitution and arbitrary file chmod/chown

`/DATA/vprouter-lab` is `opsec` 0700, `lab-images` is `opsec` 0775, and `vm-NNN/` is chowned to `opsec` (`provision.py:94`). Root then does the following in those directories:

- **provision.py:**
  - `qemu-img create` writes `guest.qcow2`, then `os.chmod` and `os.chown(overlay, uid, gid)` follow symlinks (`:236-245`). A planted `guest.qcow2 -> /etc/…` symlink gets truncated and **chowned to opsec**.
  - `user_data.write_text` and `meta_data.write_text` follow symlinks (`:251-265`).
  - `leaklab/` itself is created inside an opsec-owned parent, so opsec can rename it and swap it out after `mkdir`.
- **run_phase.py:**
  - `(state/qemu.log).open("ab")` as root follows symlinks (`:826`).
  - `evidence_root.mkdir(exist_ok=True)` followed by `os.chmod(evidence_root, 0o700)` follows a symlink swapped in after the `is_symlink()` check (`:977-980`).
  - An existing opsec-owned `evidence/` is accepted without checking its owner, although the doc says `evidence/` is root-owned 0700.
- **Evidence path re-reads.** `pcap`, `stats`, `capture-argv.json` and `scan.json` are re-opened **by path** for pcapscan and hashing (`:1169-1237`). The owner of the parent directory, opsec, can rename `evidence` (or the phase directory) and drop in a clean pcap, stats file and argv between `stop_capture` and the scan. That is a false **PASS** by any opsec process or by an escaped QEMU, which runs as opsec.
- **Untrusted qcow2 parsed as root.** `verify_state` runs `qemu-img info --backing-chain` as root over a qcow2 written by QEMU running as opsec (`:787-803`). A crafted backing name (a `json:`/`nbd:` protocol, a FIFO or a device) makes root-run qemu-img open or connect to it.

**Fix:**
- Keep evidence in a root-owned tree outside the state directory, for example `/DATA/vprouter-lab/leaklab-evidence/vm-NNN/`, root 0700 down to `/`.
- Open everything with `O_NOFOLLOW|O_EXCL` relative to a directory fd.
- Hash the pcap and stats files from fds right after the capture stops, and pass those fds or hashes to pcapscan.
- Do the provisioning file creation as opsec via `setpriv`, or create the files in a root-owned staging directory and move them in. Use `os.chown(..., follow_symlinks=False)` or `fchown`.
- Run qemu-img as opsec with `-U`, or parse the qcow2 header's backing filename in Python first.

### I5. `login_url.py` cannot reach the guest agent during a phase, so the documented login and exit-node approval flow does not work

`run_phase` holds one `QGAClient` connection from `wait_for_qga_or_exit` until `poweroff_vm`, including `time.sleep(duration)` (`run_phase.py:1045-1162`). QEMU's socket chardev serves one client at a time: it stops accepting while a client is connected, with a listen backlog of 1. `login_url.py`, run "while it runs" (`leak-lab-vm.md:340-350`), connects into the backlog, never gets a sync reply, and exits 2 after `--connect-timeout` (10 s).

**Fix:** pick one of:
- `run_phase` releases the QGA connection during the duration sleep and reconnects afterwards, with a file lock to serialise clients;
- `run_phase` itself polls and prints the login URL (a `--print-login-url` option);
- a second, separate virtio-serial agent channel.

---

## Minor

- **M1. No lock and a race in the single-guest check.** `refuse_if_qemu_running` runs before a multi-second base-image SHA-512 and the host checks (`run_phase.py:936-965`). Two `run_phase` runs, or a `provision` plus a `run_phase`, can both pass it. The tap's EBUSY and the qcow2 locks are the only backstop, and a provisioning VM on a user netdev would not be stopped by them. Add an `flock` on a root-owned lock file held for the whole run.
- **M2.**
  - `--qemu-user root` is not refused in either runner, so QEMU can run as uid 0. Refuse uid 0 and system uids.
  - `setpriv` lacks `--no-new-privs`, `--inh-caps=-all` and `--bounding-set=-all`.
  - Root's whole environment is passed through to QEMU (`guest.qemu_env(dict(os.environ))`). Pass a minimal environment.
- **M3. QEMU argv and control sockets** (`guest.py:236-300`).
  - The argv lacks `-nodefaults -no-user-config`.
  - The QMP socket is unused by the code, yet any opsec process can `netdev_add user` plus `device_add` a second NIC, giving the guest an **uncaptured** path that bypasses the tap. Drop `-qmp`.
  - The QGA socket gives any opsec process root in the guest and lets it read `/etc/vprouter/NAME.conf`. This is documented only indirectly ("state directory is secret-bearing").
- **M4. Gaps in the silence list.**
  - Debian 13's cloud-init 25.x units (`cloud-init-main.service`, `cloud-init-network.service`, `cloud-init-hotplugd.socket`) are neither masked nor checked; the old names report `not-found` and are treated as OK. `cloud-init.disabled` mitigates this.
  - `chrony`, `ntpsec` and `openntpd` are not checked.
  - `ifup@.service` (the ifupdown hotplug path) is not masked; only `networking.service` is.
  - This is low risk with no DNS and no lease, but the check should fail on presence.
- **M5. A tap with no bridge passes the host check.** `hostcheck.py`: `master is None` is accepted for the tap. On an unbridged tap, the controls are still seen on the tap, so `down`/`any` phases PASS with a VM that had no uplink. Require `master == bridge`.
- **M6. Policy and report integrity.**
  - The policy is re-read by path at scan time, possibly much later; only the start-time hash is recorded. Copy it into the evidence directory and scan the copy.
  - The runner does not cross-check that `scan.json`'s verdict, nonces and argv hash match its own values, nor that the verdict agrees with the exit code.
- **M7. Doc inaccuracies.**
  - The suite has 45 tests, not 42.
  - "each phase boots a fresh copy of the overlay" (`:243-244`) is false: the overlay persists and there is no `-snapshot`. The doc itself says elsewhere that login state persists.
  - The DNS paragraph (`:434-439`) assumes Docker's 8.8.8.8 fallback, but compose sets `dns: [9.9.9.9]` on the router.
  - "atomically" in `install_guest_file` is false: `mv` from tmpfs `/run` to `/etc` is copy plus unlink.
  - The `ipv6_mode` defaults in `guest.provision_script`, `build_user_data` and `grub_dropin_text` are still `kernel-disable`; only the CLI default changed.
- **M8. Some tests are skipped when the file is run directly.** `ControllerDecisionTests` is defined after `if __name__ == "__main__": unittest.main()` (`test_vm.py:877-881`), so running `python3 test_vm.py` skips it. Discovery does include it.
- **M9. QGA replies are not matched by id.** After a `QGATimeout`, a late reply is attributed to the next command, for example a stale `guest-exec-status exited 0`. pcapscan still demands the nonces, so this cannot by itself cause a false PASS, but recorded exit codes can be wrong. Reconnect (re-sync) after any timeout.
- **M10. `profile_endpoint` parses differently from the release.** It is case-sensitive and only splits on `=`. `orchestrate._provider` uses `configparser`, which is case-insensitive and also splits on `:`. Every divergence I found fails safe (refusal). Using `configparser` with the same options would make the endpoint check provably identical.
- **M11. Provisioning leaves large files behind.** `payload/` (a release copy plus a hard-linked image tar), `payload.iso` and `seed.iso` stay in the state directory after provisioning, roughly doubling disk use.

## Checks that held (release integration and secrets)

- **Release integration.**
  - There are two containers: router `NAME` (`network_mode: none`, `restart: "no"`) and transport `NAME-uplink` (`compose --project-name NAME`).
  - `kill-wireguard`'s `nsenter -t <router pid> -n ip link del wg0` matches `orchestrate.provision_wireguard`, which creates `wg0` in the transport namespace and moves it into the router namespace.
  - `TS_HOSTNAME` = `tailscale_hostname or name` (`compose_env`), and the release's runtime uses it as `--hostname=`.
  - The site JSON's keys and regexes match `load_site`.
  - The 0600/0700 rules, root ownership and non-writable parents match `assert_host_ownership`, including `/etc/vprouter` and `/var/lib/vprouter` at 0755.
  - `READY=1` comes after the WireGuard provisioning, so `systemctl start` returns before Tailscale approval.
  - The host guard and quarantine tables touch only `br-vpr-uplink`, so the root-namespace controls still reach `10.250.0.1`.
- **Secrets.**
  - The profile is never in an argv, the record, stdout or QGA error messages.
  - `SecretMaterial` is redacted, and the profile file is checked for root ownership, 0600 and no symlink.
  - The deployed release tree contains no key material.
  - The remaining exposure is that opsec can read the qcow2 and both sockets (see I4 and M3).
- **The netns-safe IPv6 default is sound.** Debian 13 networkd with `LinkLocalAddressing=no` does not re-enable `disable_ipv6`, and `all.disable_ipv6=1` propagates to existing links.
