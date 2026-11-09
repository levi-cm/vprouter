# Leak lab — combined adversarial re-review (round 2), Opus, 2026-11-09

## Scope

**Commit:** `545fb95` (`rust/v2`). The working tree was clean before and after the review.

**Files reviewed:**
- **Monitor:** `tools/leak-lab/{pcapscan,policy,netplan,control,tsnames}.py`, `test_leak_lab.py`, `docs/rust-v2/leak-lab.md`.
- **Runner:** `tools/leak-lab/vm/*.py`, including the new `rootfs.py` and `hostsetup.py`, plus `docs/rust-v2/leak-lab-vm.md`.
- **Release, read-only:** `/opt/vprouter/current/{host/orchestrate.py,router_runtime.py,docker-compose.yaml}`.

**Method:**
- Re-ran every Important reproducer from `leak-lab-combined-review-{gpt,opus,pi}.md`.
- Wrote new offline probes. Runner probes subclass `test_vm.RunPhaseTests`, so the real `run_phase()` decision logic runs with fake QGA, process and scan layers.
- Rendered the M1 plan (`netplan.py --wan-interface eno1`) and checked it with `sh -n`.
- Extracted the generated hostsetup `copy_tools` function and ran it in scratch with harmless tools (`cp`, `find`, `sha256sum`).
- Read the Debian tcpdump changelog and AppArmor profile.

**Limits:**
- No sudo, QEMU, tcpdump, ip, nft, iptables, docker, useradd or network command was run.
- I read no secrets, `/etc/vprouter`, conf, zip, `/var/lib/vprouter` or key files.
- Scratch `/var/tmp/leaklab-crr-opus` was deleted at the end.

## Test suites

```
TMPDIR=/var/tmp/leaklab-crr-opus/tmp python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py
Ran 246 tests in 7.567s   OK
TMPDIR=... python3 -B -W error -m unittest discover -s tools/leak-lab/vm -p 'test_*.py'
Ran 133 tests in 4.740s   OK
```

- Total: 379 tests. 0 failures, 0 errors, 0 skips.
- The doc's count of 133 is correct.

## Verdict: **FAIL** — 0 Critical, 2 Important, 9 Minor

**What is fixed:**
- Every Important finding from the three previous combined reports is closed by its original reproducer (§1). That includes the table-comment mismatch, evidence substitution, readiness, QGA text, the setpriv loader, source chmod, lifecycle orphaning, inventory-failure teardown and scanner memory.
- The descriptor-anchored evidence design holds. A rename-and-plant attack after AFTER no longer changes what is scanned or hashed.
- Readiness now consumes the real release contract (`orchestrate.py status` READY plus a Tailscale exit-node check). That works inside the guest as implemented (§4).

**What remains Important:**
- **I-1, integration blocker:** the new `hostsetup.py` pre-creates `/var/lib/vprlab/vm-001`, and `provision.py` refuses an existing state directory. The documented sequence (hostsetup → provision) therefore cannot provision.
- **I-2, host safety:** the "bounded" claims do not hold against an untrusted guest.
  - The 2 GiB capture cap is checked only inside the phase window. A phase can PASS with a pcap far above the cap.
  - The root runner's QGA receive buffer has no bound at all.

---

## 1. Previous-round closure (reproducers re-run)

| Previous finding | Reproducer re-run | Result now |
|---|---|---|
| opus I-1 / gpt I1 / pi I-1: table comment vs fixed tag | `verify_host_network(...)`, table comment `vprlab-owned:`+`e`*32, `owner_token="e"*32` | `[]` ✔. The fixture now uses the token comment (`test_vm.py:903`) |
| opus I-2 / gpt I3 / pi I-2: evidence under opsec ancestor, re-read by path | (a) harness `stop-router`; after AFTER, the finally-cleanup hook renames `evidence/` and plants `capture.pcap=b"FORGED"` plus stats/argv/policy at the identical path | `PASS`; `pcap_sha256 != sha256(b"FORGED")`; `phase.json` written into the original (moved) directory ✔. Writes, scan and hashes go through the retained fd |
| | (b) `rootfs.open_directory(anc/link/evidence, create=True)` with `link` a symlink | `PathError` ✔ |
| | (c) `rootfs.validate_ancestry(<opsec path under /var/tmp>, expected_uid=0)` | refused (`/var/tmp is group/other writable`) ✔ |
| opus I-3 / gpt I5: PASS without login/READY | `login`, NeedsLogin, no URL | exit 2 INVALID `login_not_running` ✔ |
| | `kill-wireguard`, NeedsLogin | INVALID `router_not_ready` ✔ |
| | `idle`, NeedsLogin | INVALID `router_not_ready` ✔ |
| | `restart-docker` with `orchestrate.py status` never 0 | INVALID `router_not_ready` ✔ |
| | `start-router`, NeedsLogin | PASS, by documented design; `certifies: server_side_no_client_traffic` |
| gpt I2: setpriv loads libraries from opsec dir | `build_launch_argv` / `start_vm` / `provision` | `/usr/bin/setpriv … --init-groups --no-new-privs --inh-caps=-all --bounding-set=-all -- /usr/bin/env -i LD_LIBRARY_PATH=/opt/vprlab-tools/… QEMU_MODULE_DIR=… qemu`. Popen `env=` is `{PATH,LANG,LC_ALL}` at all four launch sites (`run_phase.py:1581,1637`, `provision.py:131,420`) ✔ |
| gpt I4 / pi I-3: QGA `desc`/`class` rendered | buffer `{"error":{"class":"PrivateKey = AAAA…=","desc":"PRIVATE-KEY-SENTINEL"}}` | `guest agent error guest_error`; no sentinel or key bytes ✔. `desc` is discarded, and `class` is allowlisted (`qga.py:37-59`) |
| gpt I6: forced poweroff leaves QEMU; provision lacks handlers | real `poweroff_vm` with QGA `shutdown` raising `OSError`, live child with matching pidfile and cmdline | `(-9, forced=True, survived=False)`; child reaped ✔ |
| | same, pidfile removed | `survived=True`, tap isolated, lock retained (`run_phase.py:1890-1898`); see m-3 |
| | provision | `install_signal_handlers()` at `provision.py:503`; `test_self_signal_during_provision_reaps_the_qemu_child` passes ✔ |
| gpt I7: hardlinked tar chmod | real `_stage_payload` with a 0600 source | source stays `0o600` ✔ (`shutil.copyfile`, `provision.py:198-201`) |
| gpt I8: failed link inventory treated as absence | `test_leak_lab.NetplanTests.test_gpt_i8_failed_link_inventory_is_never_absence` (generated script, stubs, `link_inventory` / `link_inventory_json` ENOBUFS) re-run | no neighbour/table/rule/link deletion, owner kept, nonzero ✔ |
| gpt I9: scanner retains a tuple per packet | `_Scanner.parse_frame(wg_outbound)` ×10 000 / ×20 000 under tracemalloc | 33 667 B / 32 756 B retained (was 1.52 MB / 3.05 MB); index list capped at 1000 ✔. Capture-side bound: see I-2 |
| opus m-1: lab.sh capture/lock | rendered plan | `setup` mode exits before tcpdump; teardown checks the run lock (but see m-5) ✔ |
| opus m-2 / gpt M1 / pi M-5: stale prerequisite doc | | section replaced ✔ |
| opus m-3: signal during poweroff | `poweroff_vm` catches `BaseException` in the wait and falls back to kill / isolate; `block_termination_signals()` around Popen | ✔ |
| opus m-4: QEMU as the operator | dedicated `vprlab-qemu`, kvm only, `--init-groups` | ✔ |
| pi M-1: reboot postcondition | `postcondition_failed` now noted | ✔ |
| pi M-2: non-dict `scan.json` | `scan_report_invalid` | ✔ |
| pi M-6: default capture path is the cwd | default is now `$RUN_DIR/manual-capture.pcap` | ✔ |
| pi M-7: report not bound to files | pre-scan hashes compared with the report `capture_meta` and with post-scan hashes | ✔ |
| pi M-9: `login_url` check-then-release | lock now held across the connection | ✔ |

---

## 2. Important

### I-1. `hostsetup.py` pre-creates `vm-NNN`, so the documented `provision.py --index 1` always refuses

**Locations:**
- `tools/leak-lab/vm/hostsetup.py:433-437`, unconditional for `INDICES` (default `1`):
  ```sh
  install -d -m 0700 -o "$QEMU_USER" -g "$QEMU_GROUP" "$STATE_ROOT/vm-$suffix"
  ```
- `tools/leak-lab/vm/provision.py:312-315`:
  ```python
  create_state_directory(state)  # → FileExistsError
  raise hostcheck.Refusal("state directory already exists: …")
  ```
- `provision.py:164-168` (`path.mkdir(mode=0o700)`).
- Documented order: `docs/rust-v2/leak-lab-vm.md:660-666` ("once, root: … hostsetup", then "once, online … refuses an existing state directory"). Also `:65` and `:127-128`.

**Why the tests miss it:**
- `HostsetupTests` checks a rendered script and an inventory that *expects* `vm-001` (`test_vm.py:3026`).
- `ProvisionPipelineTests` creates its state under a fresh temporary root.
- No test runs the two in the documented order. This is the same cross-component drift class as last round's I-1.

**Reproducer:**
```python
script = hostsetup.render_setup_script()
'install -d -m 0700 -o "$QEMU_USER" -g "$QEMU_GROUP"' in script        # True
provision.create_state_directory(<dir already created 0700>)           # FileExistsError
# → _provision_locked raises Refusal("state directory already exists")
```

**Effect:**
- On a host built exactly as documented, provisioning exits 2, and `run_phase` then has no overlay to boot.
- It fails closed, with no exposure, but M2 cannot be brought up without an undocumented `rmdir`.
- The `--check` inventory requires `vm-001` to exist, so a reader cannot tell that it must be absent before provisioning.

**Fix:**
- Either let hostsetup create only `/var/lib/vprlab` (root 0755) and leave `vm-NNN` to provision's exclusive create, then hand-over;
- or let provision accept an *empty*, QEMU-owned, 0700 `vm-NNN` that hostsetup created (verified empty via an fd), and still refuse a non-empty one.
- Add one test that runs the rendered hostsetup (stubbed `install`/`useradd`) and then `provision` against the same scratch root.

### I-2. The resource bounds are not enforced as documented: the capture cap holds only inside the phase window, and the root runner's QGA buffer is unbounded

The doc (`leak-lab-vm.md:633-641`) says:

> The default capture cap is 2 GiB; exceeding it stops the phase and makes it INVALID.

**Part (a): the capture cap.**

**Locations:**
- The cap is checked only in `wait_capture_room` (`run_phase.py:1440-1460`, called at `:2271`) and in `login_phase_wait` (`:1291-1294`).
- No check runs during QGA boot (≤180 s), the initial silence/secrets steps, setup (`systemctl start` ≤360 s plus readiness ≤180 + 120 + 180 + 120 s), the action and postcondition (≤360 s each), the finally cleanup (≤180 s) or the poweroff wait (≤180 s).
- The admission check (`:1409-1433`) reserves only cap + 1 GiB on `/` (`/var/lib/vprlab` is on `/dev/sda4`; 173 GiB free today).

**Reproducer** (real `run_phase()` through the harness): `stop-router`, `capture_size_cap=1000`. An override on the finally-block `systemctl stop 'vprouter@…'` appends 50 000 bytes to the pcap.

```
cap=1000, pcap grows in teardown -> exit 0  PASS  []  pcap bytes 50068
```

The cap is exceeded 50-fold and the run still certifies PASS. The real scanner counts allowed WireGuard frames after AFTER only as `outside_window_allowed`, not as a finding. So a flood of allowed-tuple frames during teardown is a PASS with an arbitrarily large pcap.

A guest (documented as untrusted) can write at virtio-net/tap speed for several minutes outside the window. At ~300 MB/s, the 180 s poweroff wait alone is ~54 GB on the host root filesystem. tcpdump writes it with root's reserved blocks.

**Part (b): the QGA receive buffer.**

**Locations:**
- `qga.py:146-161`: `_fill` appends with `self._buffer += chunk` and has no limit.
- `_read_response` (`qga.py:196`) and `_handshake` (`:179-191`) search the *whole* buffer for `\n` / `\xff` on every chunk, which is O(n²) CPU.

The only bound is the per-call deadline, which is up to `ACTION_TIMEOUT` = 360 s. A guest root can stop `qemu-ga` and stream to `/dev/virtio-ports/org.qemu.guest_agent.0`, and so can a compromised QEMU, which owns the chardev.

**Reproducer:** a fake socket returning 64 KiB chunks with no newline, fed to `_read_response`, retains **104 857 600 bytes** after 1600 chunks with no error. The root runner has no `RLIMIT_AS` of its own (only the scanner child gets one).

**Why Important:**
- Previous gpt I9 asked to "enforce disk/capture bounds and mark the run INVALID when reached" and to keep the guest from harming non-lab services.
- The scanner half is genuinely fixed (§1). But both the disk path and the root runner's memory path stay unbounded and guest-driven.
- Host OOM is this machine's recorded crash cause (debdev host crashes, 2026-11-04).
- The doc's claim is stronger than the code, so a reader will trust a bound that does not exist.

**Fix:**
- Enforce the cap from a watchdog for the whole capture lifetime: a thread or a `poll` loop on the evidence fd's `fstat`. When it is reached, mark `capture_size_cap`, SIGKILL QEMU (verified), isolate the tap, then stop tcpdump.
- Alternatively, put tcpdump in a cgroup/`RLIMIT_FSIZE`-bounded wrapper. A truncated record then becomes INVALID through the existing structural check.
- Cap `QGAClient._buffer` (for example 32 MiB, comfortably above `guest-exec` output limits). Exceeding it should raise `QGAProtocolError` and close the socket. Search only the newly appended tail.
- Optionally set `RLIMIT_AS` on the runner itself.

---

## 3. Minor

**m-1. hostsetup's "verified copy" follows symlinks swapped in after `find`, and then publishes images world-readable.**
- Location: `hostsetup.py:276-300` (`copy_tools`), `:449-458`.
- The source trees are opsec-owned (`/DATA/vprouter-lab/lab-{tools,images}`). Root runs `find . -type f` once, then for each name runs `cp -p "$src" "$dst"`, which dereferences a source symlink.
- The manifest is computed from the destination after the copy. So it proves only copy == source-at-copy-time, never provenance (only the base image has a pinned digest).
- The images tree is then `chmod 0644`.
- Reproducer (scratch, harmless tools): a HASHER wrapper swaps `src/zz` for a symlink to a 0600 `secret.conf` while the loop hashes an earlier file. Result: `dst/zz` = `TOP-SECRET-PRIVATE-KEY`, `verify_manifest … OK`, exit 0. In the real script, the next step would make it 0644 under the world-traversable `/var/lib/vprlab/images`.
- An opsec process can trigger this deterministically with inotify on the qcow2 copy. It could target `/etc/shadow` or a production WireGuard profile (the rule "prod key never in lab").
- **Why Minor, not Important:** the only actor is an opsec-uid process. That actor is already root-equivalent here: root executes the lab code from the opsec checkout (m-2), opsec is in `sudo`, and `ptrace_scope=0`. It is still a real hygiene defect in a root script.
- Fix:
  - copy only the named files (base image, `SHA512SUMS`, a fixed tool list);
  - open each source `O_NOFOLLOW` and require `S_ISREG`;
  - hash the opened fd, compare with a pinned or pre-recorded manifest, and write from the same fd;
  - never `chmod` a file whose type was not checked.

**m-2. The root boundary holds only against `vprlab-qemu`, not against opsec.**
- Location: `run_phase.py:2393` executes `str(_LEAK_LAB_DIR / "pcapscan.py")` from the opsec-owned checkout at *scan time*, after the capture. The runner itself, `policy.py` and `netplan.py` are opsec-owned too.
- An opsec process can replace `pcapscan.py` mid-phase with one that prints a PASS report carrying the correct pre-hashes.
- The doc's evidence claim is scoped to "an escaped guest", which is correct. It should say explicitly that the operator account is trusted. Alternatively, install the lab code into `/opt/vprlab-tools` (root-owned, already ancestry-checked) and run it from there.

**m-3. The QEMU kill depends on QEMU-controlled proof.**
- Location: `run_phase.py:1669-1718`.
- `kill_qemu` refuses to signal unless the QEMU-owned `qemu.pid` and `/proc/<pid>/cmdline` match. An unreaped `Popen` child's pid cannot be reused, so the check adds nothing. Meanwhile a compromised QEMU can evade SIGKILL by deleting the pidfile or rewriting its argv.
- Probe: pidfile removed → `(None, forced=True, survived=True)`, tap isolated, child still alive.
- It fails safe (tap down, lock retained), but leaves a live guest process. Kill the process group when `process.poll() is None`, without the pidfile check.

**m-4. Root connects to `qga.sock` by path inside the QEMU-owned state directory.**
- Location: `qga.py:111-115`.
- `AF_UNIX connect` follows symlinks. A compromised QEMU can point `qga.sock` at any host socket. The root runner then sends QGA JSON, including `guest-file-write` with the profile, with root peer credentials.
- The profile is already visible to QEMU, and the line-JSON is unlikely to drive another protocol, so this is low impact.
- Fix: `lstat` via the state dir fd and require `S_ISSOCK` with the QEMU uid, or hand QEMU a pre-created listening fd (`-chardev socket,fd=N`).

**m-5. Teardown "refuses while a phase holds the lock" is a probe, not exclusion.**
- Locations: `netplan.py:412-420` (`flock -n "$RUN_LOCK" true`) and `hostsetup.py:376-381`.
- Both take and immediately release the lock, so a phase can start during teardown.
- It fails safe (the tap is isolated before protections go, and the phase ends INVALID).
- Fix: hold it for the whole teardown (`exec 9>"$RUN_LOCK"; flock -n 9 || exit 1`).

**m-6. hostsetup teardown silently deletes all evidence.**
- Location: `hostsetup.py:386`.
- `rm -rf "$EVIDENCE_ROOT"` removes every phase's pcap/scan/phase.json. Teardown also does not check for a still-present persistent tap owned by the uid it `userdel`s; if that uid is later reused, the new account can open `vprlab-tap0`.
- Fix: keep or archive evidence (or require `--delete-evidence`), and refuse teardown while `vprlab-tap0` exists.

**m-7. `rootfs.ancestry_records` always crashes.**
- Location: `rootfs.py:298`.
- `reversed(target.parents) + [target]` raises `TypeError: unsupported operand type(s) for +: 'generator' and 'list'`.
- It is dead code (tests feed synthetic records to `ancestry_problems`). Fix it, or delete it with its docstring reference to `--check` tools.

**m-8. A scanner crash is reported as LEAK.**
- Location: `run_phase.py:2482-2484`.
- An uncaught pcapscan exception (for example `MemoryError` under the new 1 GiB `RLIMIT_AS`, possible with a flood of replayed controls, since `control_sightings` is unbounded) exits 1. The runner maps any `scan_exit == 1` to LEAK, even when `scan_report_invalid` was noted.
- This fails closed, but the label is wrong. Require a parseable report with `verdict == "LEAK"` for LEAK, and map anything else to INVALID.

**m-9. Doc nits.**
- `leak-lab-vm.md:134` says "The root `tcpdump` writes the pcap". Debian's tcpdump drops to user `tcpdump` (see §5).
- `:66-67` says the tools are "verified against a written `SHA256SUMS`", which is self-referential (m-1).
- The `Self.AdvertisedRoutes` branch in `tailscale_readiness_problems` (`run_phase.py:1194-1197`) reads a field that `tailscale status --json` does not emit. It is harmless, because the release-READY gate is the binding one; drop it, or use `ExitNodeOption` only, as `router_runtime.tailscale_ready` does.

---

## 4. Requested deep checks

**rootfs descriptor anchoring.**
- `open_directory` walks from `/` with `O_DIRECTORY|O_NOFOLLOW`. Every component is checked uid 0 and not g/o-writable, `mkdir` uses `dir_fd`, and the final directory gets `fchmod`.
- `make_run_directory` uses exclusive `mkdir` plus an fd. All evidence I/O (`write_bytes_at`, `read_bytes_at`, `hash_file_at`) is `dir_fd`-relative `O_NOFOLLOW`.
- No security-relevant path re-resolution is left. The display-path uses (`start_capture` readiness `pcap.is_file()`, `wait_capture_room` stat) are under a root-only ancestry, so they cannot be redirected.
- `validate_ancestry` (base image, used-nonces, owner file, tools, state parent) is lstat-then-open-by-path. That is acceptable because every ancestor is root-owned and not writable.
- Offline tests skip ownership checks when euid ≠ 0 (`rootfs.py:47-51`). I verified the uid-0 branch directly (§1).

**`/proc/self/fd` across subprocess boundaries.**
- tcpdump gets `-w /proc/self/fd/N/capture.pcap` with `pass_fds=(N,)`. The scanner gets the same N with `pass_fds`.
- In each child, `/proc/self` is the child, and fd N is inherited at the same number. So the `-w` realpath equals the `--pcap` realpath (both `/var/lib/vprlab/evidence/<run>/capture.pcap`), and pcapscan's argv binding holds.
- `/proc/self/fd` access survives a uid change (`proc_fd_permission` same-thread-group rule).
- The recorded `capture-argv.json` names an fd path, not the run directory. That is cosmetic.

**setpriv / `env -i` boundary.** Correct:
- trusted setpriv runs with a 3-variable environment;
- the staged loader variables are set only by `/usr/bin/env -i` after the drop;
- `--init-groups` gives exactly `vprlab-qemu` plus `kvm`;
- capabilities are cleared and the bounding set emptied, with `no_new_privs`.

**QGA secrecy.** Guest `desc` is never read into a message, and `class` is allowlisted. `run_phase` records only exception class names, and `wait_for_qga`'s `last_error` now carries only local strings. Residual: the login URL regex permits any `[A-Za-z0-9/_-]+` path, so a compromised guest can still put text on the operator's terminal through the URL. That is accepted by design.

**Readiness vs the real release.** Would `orchestrate.py status` and `tailscale status` work inside the VM as implemented? Yes:
- `release_status_command` → `exec python3 /opt/vprouter/current/host/orchestrate.py status --name <name>`, run as root through QGA.
- The guest installs the release at that path (`guest.py:853-862`).
- `main()` prints `router_health(name)` = `{"name","state":"READY","heartbeat"}` on success and exits 1 on `SiteError` (`orchestrate.py:588-598,616-622`). The runner requires exit 0, `state == "READY"` and `name == name`.
- READY already implies `tailscale_ready()`: `BackendState Running`, `Online`, `ExitNodeOption`, advertised routes and `NetfilterMode=0` (`router_runtime.py:118-125`).
- `docker exec <name> tailscale status --json` uses the container name, which equals `ROUTER_NAME = site.name` (`orchestrate.py:175`, compose `container_name`), and the default socket on the container's `/run` tmpfs. That is the same call the runtime itself makes.
- Side effect to know about: `router_health` can `install_quarantine()` when the guard snapshot changed. That is identical to the release monitor's own behaviour, so it is not a lab artefact.
- The gating is consistent with the docs:
  - `login` must end Running;
  - `start-router` deliberately requires only active + fresh handshake (≤180 s, guest clock);
  - every setup, fault and reboot phase requires release READY plus the Tailscale exit-node check before the action;
  - `restart-docker` requires READY again afterwards.

**Lifecycle kill and isolation.**
- AFTER → unit cleanup → powerdown → wait, then on any exception or signal a verified SIGKILL. If the process survives, the tap is brought down, `qemu_still_running` is noted and the lock is retained.
- After that: AFTER-in-pcap via the fd → 2 s → SIGINT → scan.
- Process handles are created with termination signals blocked. Residual: m-3.

**Streaming scanner.**
- Online window classification, under the existing `non_monotonic_timestamps` → INVALID rule, is equivalent to the old post-hoc `before_ts < ts < after_ts`. The one difference is a frame with ts == after_ts that precedes AFTER in file order, which now counts in-window; that is legitimate.
- `fragment_table_overflow` is excluded from `leak_findings_total` but always adds INVALID, and it skips `finalize_fragments`. So overflow can downgrade a fragment-borne LEAK to INVALID, but never yields PASS.
- Eviction drops only completed associations.
- The streaming `source_sha256` covers the consumed bytes. On a structural truncation it covers a prefix, which mismatches the runner's pre-hash → `scan_report_mismatch` → INVALID.
- **No new false PASS was found in the scanner.**

**hostsetup on Debian 13.**
- `groupadd --system`, `useradd --system --no-create-home --shell /usr/sbin/nologin` and `usermod -aG kvm` are fine (`kvm` comes from systemd-sysusers).
- `check_account` correctly refuses extra groups. Ancestry checks run before and after `install -d`.
- Defects: I-1, m-1, m-5, m-6.
- Small notes:
  - `check_ancestry "/opt"` never checks `/` itself (its loop starts below `/`).
  - Re-runs never delete stale tool files.
  - Teardown `userdel` relies on Debian's `USERGROUPS_ENAB` to drop the `vprlab-qemu` group.
- The M1 plan creates `vprlab-tap0` with `user vprlab-qemu`, so the account must exist before `lab.sh setup`. The documented order satisfies that.

## 5. Runtime gate (not counted as a finding)

Debian's tcpdump 4.99.5 is configured `--with-user=tcpdump` (changelog: "Drop root privileges by default"). Its binary does not link `libcap-ng` (readelf `NEEDED`: libpcap, libcrypto, libc). The changelog adds a Fedora patch "to drop root privileges *after* opening the savefile when possible".

The runner pre-creates `capture.pcap` root 0600 inside a root 0700 run directory and passes `/proc/self/fd/N/capture.pcap`. That works only if the savefile is opened before the drop. If the drop happens first in this build, tcpdump (uid `tcpdump`) gets EACCES and every phase refuses with "tcpdump exited before listening". That fails closed. I could not confirm offline which applies to 4.99.5-2, and the same was true at the previous commit.

The AppArmor profile allows `/**.pcap rw`, and the fd path resolves to `…/capture.pcap`, so AppArmor is not a blocker. Qualify on the host before relying on it. If needed, add `-Z root` to both `guest.tcpdump_argv` and `netplan.capture_argv`; pcapscan binds the argv, so both must change together.

## 6. Secrets and host safety summary

- **Profile:** read from a root 0600 file or fd; reaches the guest only via QGA `guest-file-write`; never in argv, records or stdout.
- **QGA error text:** closed.
- **qcow2:** the secret-bearing qcow2 is now owned by `vprlab-qemu`, not the operator.
- **Exposure channels found:** m-1, which needs an opsec racer, and none from the guest side.
- **Host safety:** I-2 (disk and memory) is the open issue. The fail-safe isolation paths hold, but m-3 and m-5 are residuals.

## Reproducer index (all offline; scratch deleted)

| ID | Probe | Observed |
|---|---|---|
| I-1 | `render_setup_script()` contains the `vm-NNN` install; `provision.create_state_directory(existing)` | `True`; `FileExistsError` → Refusal |
| I-2a | harness `stop-router`, `capture_size_cap=1000`, +50 000 B during finally cleanup | exit 0, PASS, pcap 50 068 B |
| I-2b | `QGAClient._read_response` fed 1600 × 64 KiB with no newline | 104 857 600 B buffered, no error |
| m-1 | extracted `copy_tools` with a swap-on-first-hash HASHER | secret copied, manifest OK, exit 0 |
| m-3 | real `poweroff_vm`, shutdown raising `OSError`, pidfile absent | `(None, True, True)`, tap isolated, child alive |
| m-7 | `rootfs.ancestry_records(path)` | `TypeError` |
| §1 | rename-and-plant, NeedsLogin phases, QGA sentinel, launch argv/env, `_stage_payload` mode, scanner tracemalloc, inventory-failure test | all closed as tabulated |
