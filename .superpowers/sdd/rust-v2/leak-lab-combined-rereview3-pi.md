# Leak-lab combined adversarial re-review, round 3 (pi)

- **Reviewed commit:** `79a5bd5286db538625d846de51859f7d77c9de7b`
  (`fix(leak-lab): combined r2 — exact-byte hashes with real-scanner integration test,
  symlink-faithful tool copy, lifetime capture guard, bounded QGA`). The worktree was
  clean before and after; the only repository file written is this report.
- **Scope:** the whole leak lab at that commit —
  `tools/leak-lab/{pcapscan,policy,netplan,control,tsnames}.py`,
  `policy.schema.json`, `test_leak_lab.py`, `docs/rust-v2/leak-lab.md`, and
  `tools/leak-lab/vm/{qga,guest,hostcheck,hostcopy,hostsetup,provision,run_phase,login_url,runlock,rootfs}.py`,
  `test_vm.py`, `docs/rust-v2/leak-lab-vm.md`.
- **Previous reports re-audited:** `leak-lab-combined-rereview-{gpt,opus,pi}.md`. GPT's
  report was partial, so its three Important items (§3 there) were treated as findings
  too. Every unique Important from all three was re-run (§2).
- **Constraints honoured:** no sudo, QEMU, tcpdump, ip, nft, iptables, docker, useradd or
  network execution. The generated hostsetup shell was executed only by the suite's
  stubbed harness (every privileged command stubbed, temp cwd) and by `sh -n`. I read no
  `/etc/vprouter`, `/DATA/AppData/vprouter/conf`, `*.zip`, `/var/lib/vprouter` or key
  material. I listed `/DATA/vprouter-lab/lab-tools/root` (metadata only) and read
  `/opt/vprouter/current` read-only. Scratch `/var/tmp/leaklab-crr3-pi` was deleted at
  the end.

## Test suites (fresh, run three times, identical)

```
$ TMPDIR=/var/tmp/leaklab-crr3-pi/tmp PYTHONDONTWRITEBYTECODE=1 \
  python3 -B -W error -m unittest discover -s tools/leak-lab -p test_leak_lab.py
Ran 249 tests in 7.687s
OK
$ TMPDIR=... PYTHONDONTWRITEBYTECODE=1 \
  python3 -B -W error -m unittest discover -s tools/leak-lab/vm -p 'test_*.py'
Ran 161 tests in 4.550s
OK
```

**249/249 M1 and 161/161 M2, no skips.** The fix-round claim (249 + 161) is accurate.

## Verdict: **FAIL — 0 Critical, 1 Important SAFETY (S-1), 3 Minor SAFETY**

All six Important findings from the previous round are closed by their original
reproducers (§2). The remaining Important is new: the guest has a second, unbounded,
guest-controlled write path into the host filesystem (`serial.log`, and the same class
of QEMU stderr log) that the new capture guard does not measure or stop. It is not a
false PASS and not a leak-hiding path; it is a host-availability/safety hole of exactly
the class the round-2 findings asked to close. The capture cap itself is now correctly
enforced for the whole lifetime.

AVAILABILITY items are listed separately in §4; the live bring-up will reveal them
immediately and each fails closed.

---

## 1. Method and fresh validation

- Re-ran every previously reported Important reproducer against the real components:
  the real `run_phase()` decision path through `test_vm.RunPhaseTests`, the real
  `pcapscan.py` CLI through the real `scan_evidence()`, the real `rootfs` writers and
  the real `hostcopy.copy_tree`/`verify_tree`.
- Re-ran the `hostsetup` stubbed host-plan test end to end (rendered shell → stubbed
  setup → real `provision` path) and re-read the rendered script.
- Probes used a real `AF_UNIX` fake QGA agent, a real guard thread over a real evidence
  fd, and a live writer thread.
- Read the release's `orchestrate.py` status/health contract from `/opt/vprouter/current`
  read-only (unchanged by this fix; readiness consumption is unchanged).
- The previous round's differential scanner fuzz is not invalidated by this commit: the
  `pcapscan` diff changes only hash plumbing (`capture_argv_sha256` now covers the
  argv file bytes, plus a separate canonical field) and the CLI's argv read; no
  classification code changed. The real-scanner end-to-end PASS/LEAK probe below
  confirms the new contract agrees with the runner.

## 2. Previous-round Important closure (reproducers re-run)

The round-2 reports' own Importants are GPT I1-I3, Opus I-1, Opus I-2a/I-2b and
pi I-1/I-2 (overlapping). The table also includes the earlier combined-review
items those reports had re-audited, because that is what the fix round claimed to
close; every row below was re-run at `79a5bd5`.

| Prior finding | Reproducer re-run at `79a5bd5` | Status |
|---|---|---|
| **GPT I1** — controller hashes indented argv JSON; scanner hashes compact JSON, so every clean scan gets `scan_report_mismatch` | Real writers (`rootfs.write_json_at`) + real `pcapscan.py` CLI via `scan_evidence()` over 4 records: `exit 0 verdict PASS problems []`; argv file SHA-256 `66d70975…f407ca` equals the scanner's `capture_argv_sha256`; the canonical re-encoding is `0084942c…8e92cf` and is separate. `source`/`stats`/`policy` hashes also equal. A DNS-leak variant exits 1/LEAK with no mismatch. `test_vm.RealScannerIntegrationTests` runs the real CLI, so the fake-scanner test gap is closed. | **fixed** |
| **GPT I2 / Opus I-1** — `hostsetup` pre-creates `vm-NNN`, so documented `setup → provision` always refuses | Rendered script contains no `install -d … vm-NNN`; it says "The plan deliberately does not create vm-NNN". The stubbed setup + real `provision` test (`HostsetupTests.test_generated_plan_runs_with_stubbed_privileges_and_keeps_evidence`) passes and reaches `provision.create_state_directory` successfully. `check_layout` accepts an absent `vm-NNN` and still refuses a present one that is not QEMU 0700. | **fixed** |
| **GPT I3** — tool tree copied with `find -type f`, so SONAME/firmware symlinks are silently dropped | `hostcopy.copy_tree` copies confined relative links as links, records them in `SYMLINKS.json`, and `verify_tree` checks them. Independent probe: `libx.so.0 -> libx.so.0.1` survives as a link, manifests verify, an absolute link and a `../../outside` link are refused, a FIFO is refused, a destination directory that is a symlink is refused, and a source file swapped for a symlink after listing is refused. On the **real** source tree (read-only): 1 857 regular files, 157 symlinks, 382 dirs; all 157 link targets resolve inside the tree; 0 problems. | **fixed** |
| **GPT I4 / pi I-3 / Opus** — QGA `desc`/`class` rendered; printable key in errors | Unchanged good code (`qga.py` allowlist/discard); suite sentinel tests pass. See A-1 for a new, unrelated QGA framing regression. | **fixed** |
| **GPT I5 / Opus I-3** — PASS on a node that never logged in / reached READY | `kill-wireguard`/`stop-router` with `NeedsLogin` → INVALID `router_not_ready`; `login` NeedsLogin → INVALID `login_not_running`; `login` Running → PASS; `restart-docker` requires READY after the new PID; `release status` non-READY → INVALID; stale handshake → INVALID. `start-router` keeps the documented pre-login exception. | **fixed** |
| **GPT I6** — lifecycle failure leaves an unobserved VM; provision has no handlers | `kill_qemu` now verifies the `Popen` pid via `/proc/<pid>/exe` + argv[0] (not the QEMU-owned pidfile); survival isolates the tap and retains the lock; provision's second signal is ignored during the reaper (`_signal_seen`). Suite's survival/second-signal tests pass. | **fixed** |
| **GPT I7** — payload staging chmods the operator's hard-linked image tar | `_stage_payload` still `shutil.copyfile`s; suite's 0600-source test passes. | **fixed** |
| **GPT I8** — failed link inventory read as absence | `link_state`/`neigh_state` 0/1/2 contract and `iptables -C` status handling unchanged and tested; stubbed M1 teardown refuses to delete on inventory failure. | **fixed** |
| **GPT I9 / Opus** — unbounded scanner/capture/QGA resources | Scanner streaming bound and 1 GiB `RLIMIT_AS` unchanged and passing. QGA reply buffer now capped at 16 MiB and exec output at 4 MiB; independent fake-agent flood of 64 KiB chunks: `QGAProtocolError reply_too_large` after 0.386 s, buffer discarded. Capture cap now enforced for the whole lifetime (the pcap half; see S-1 for a different guest write path that remains unbounded). | **fixed for the scanner/QGA half** |
| **pi I-2** — guest `BackendState` written verbatim into `phase.json`; whole key fits | `start-router` with `BackendState = "PrivateKey=" + "A"*43 + "="`: `exit 0 PASS`, `phase.json` `tailscale.backend_state = "unrecognized"`, sentinel absent. `login` with the sentinel → INVALID `login_not_running`; `login` with `Running` → PASS/Running. Fixed vocabulary is `NoState/NeedsLogin/NeedsMachineAuth/Stopped/Starting/Running/unrecognized`. | **fixed** |
| **Opus I-2a / pi I-1** — capture cap enforced only inside the duration wait | *Real guard thread*: 0 B clean, 5 000 B → `capture_size_cap` + `isolate_tap`; a continuous 4 KiB/5 ms writer is caught at 8 192 B while the main thread only waits. *Real `run_phase()`*: `stop-router`, cap 1 000, +50 000 B injected during setup/readiness → exit 2 INVALID `capture_size_cap`, one `isolate_tap`, still scans; +50 000 B injected during final cleanup → INVALID `capture_size_cap`, `isolate_tap` before `capture_stop`. `guard.stop()` re-checks before stopping, and the final `note_capture_guard()` covers the stop wait. | **fixed** |
| **Opus I-2b** — root QGA receive buffer unbounded | See I9/QGA above: capped, closed, `QGAProtocolError`; tests added. | **fixed** |

Every prior Minor claimed fixed in the commit was re-checked in the diff and the suites:
`--check` executable modes, setup lock/QEMU guard, missing `pgrep`/`userdel` failure,
spawn-close reaper, stale M1 capture path, display argv, symlink copy, second provision
signal, scanner crash → INVALID, removed `qemu_env`, absolute `ip`/`nft`, held M1
teardown lock, `ancestry_records` crash. Remaining prior minors: QGA socket connect by
path inside the QEMU-owned state dir (opus m-4) and no persistent-tap check in
`hostsetup` teardown (opus m-6) — both unchanged, both listed in §3.1 (S-4).

## 3. Findings

### 3.1 SAFETY

#### S-1 — **Important SAFETY: the guest can grow host files without any bound (`serial.log`, and the same class of `qemu.log`), outside the new capture guard**

**Files:** `tools/leak-lab/vm/guest.py:79` (`SERIAL_FILE = "serial.log"`),
`:329-330` (`-serial`, `file:{state}/serial.log`; emitted for **both** provision and
test boots); `tools/leak-lab/vm/run_phase.py:1914-1955` (`start_vm`; no `preexec_fn`,
no `RLIMIT_FSIZE`), `:1674-1690` (`CaptureGuard.measure` stats only the evidence pcap
fd), `:1687-1695` (`_breach` only `isolate_tap`), `:1592-1616` (`check_admission` sees
only `--evidence-root`); `tools/leak-lab/vm/provision.py:351` / `guest.py:491` (4G
overlay).

The phase VM is documented as **untrusted**. Its QEMU command always redirects the
first serial port to a file in the QEMU-owned state directory:

```
$ python3 -B p7_unbounded.py
argv: ['-serial', 'file:/var/lib/vprlab/vm-001/serial.log']
SERIAL_FILE: serial.log state path /var/lib/vprlab/vm-001/serial.log
start_vm has preexec/rlimit: False
admission formula: int(capture_size_cap) + DISK_HEADROOM
overlay create argv: [... 'qemu-img', 'create', ... '4G']
```

The guest provisioning scripts themselves write to `/dev/ttyS0`
(`guest.py:793,972`), so the port exists and is guest-writable. A compromised guest
(root in the VM; exactly the compromise the lab is meant to survive) can write to
`/dev/ttyS0` at the rate the emulated UART and host filesystem accept (QEMU's 16550
backend is not paced by the nominal baud rate in the default configuration), and the
file is neither rate-limited nor rotated.  Even a modest sustained rate over a 3600 s
phase is tens of megabytes to gigabytes; the bound is time, not bytes. `serial.log` is not evidence, is never read by `run_phase` (only
`provision._wait_for_marker` reads it), and no code truncates or caps it. The capture
guard measures the **pcap** only. If the evidence and state roots are on the same
filesystem (the default `/var`), the guard's 1 GiB free-disk floor does eventually
record `capture_disk_low` and isolate the tap — but it **does not stop QEMU or the
serial writer**, so the guest can keep filling the host while the runner waits for
poweroff (up to 180 s) and the current guest command (up to 360 s). If
`--evidence-root` is on another filesystem, the state filesystem is not measured at
all. `qemu.log` (the evidence-side QEMU stderr, `run_phase.py:2461`, `open_append` at
`:924`) has the same absence of a bound, though its rate is less clearly
guest-controlled.

**Impact:** a hostile or simply runaway guest can fill the host's `/var` (shared with
production Docker/`/var/lib/vprouter`), causing unrelated services to fail. It is not a
false PASS (the phase is INVALID whenever the guard notices; a leak in the pcap is
still LEAK), but it is the "harm the host/other services" SAFETY class, and it is the
same class the previous round's pcap finding was rated Important for.

**Why the tests miss it:** no test looks at `serial.log`; the guard tests only grow the
pcap. The deployable fix is small: use `-serial null` (or a bounded socket/pipe sink)
for **test** boots, because nothing in `run_phase` reads the file; keep `-serial file:`
for provision (which needs the marker) but bound/rotate it there; and make the guard's
disk breach a hard stop (SIGKILL the QEMU we own, or set `RLIMIT_FSIZE` on the QEMU
child) instead of only bringing the tap down. Include the state filesystem in
admission.

#### S-2 — **Minor SAFETY: admission reserves `cap + 1 GiB`, but the guest's own 4G overlay (and the state filesystem, if evidence is elsewhere) is outside the reservation; a disk breach does not stop QEMU**

**Files:** `run_phase.py:1592-1616` (`required = cap + DISK_HEADROOM`, measured on
`evidence_root`), `guest.py:491` (4G virtual overlay), `CaptureGuard._breach`
(`isolate_tap` only), docs `leak-lab-vm.md:654-655` (the 4G disk is acknowledged as an
operator sizing concern).

The overlay can grow to 4G, the pcap to the cap, and the serial log without bound (S-1).
With admission free space of only `cap + 1 GiB` (3 GiB at the default cap), a guest
filling its own filesystem (no network needed) consumes the 1 GiB headroom and reaches
the filesystem-full point while the guard has already isolated the tap but cannot stop
the local writes. On this host (`/var` has ~173 GiB free) it is not reachable today, and
it is bounded at ~4G, hence Minor. Fix: reserve `cap + overlay virtual size + headroom`
on **both** the evidence and state filesystems, and make `capture_disk_low` a hard stop
(kill our verified QEMU) rather than a passive tap-down.

#### S-3 — **Minor SAFETY (root-script hygiene): `hostcopy`/`hostsetup` copy from an operator-owned tree without anchoring the source root/ancestors; hardlinks are copied as content; `verify_tree` ignores extra destination files**

**Files:** `hostcopy.py:281-395` (`_collect` walks by path; `_copy_regular` opens the
final leaf `O_NOFOLLOW` and checks dev/ino but re-resolves the parent path),
`:632-690` (`verify_tree` reports only manifest-listed paths), `hostsetup.py` setup
(copy from `/DATA/vprouter-lab/lab-tools/root`, which is opsec-owned; `/DATA/vprouter-lab`
is `opsec 0700`).

The leaf-level O_NOFOLLOW/inode check closes the previous m-1 swap-at-leaf attack, and
absolute/escaping links are refused. Remaining gaps: a directory component (or the
source root) can be replaced by a symlink between the `isdir/islink` check and the walk,
and hardlinks (for example an operator-owned file hardlinked into the source tree) are
copied as regular content and published under root-owned `/opt` or world-readable
`/var/lib/vprlab/images`. `verify_tree` does not report extra files left in a
destination from an earlier copy. The only actor is the opsec uid, which is already
root-equivalent here (`sudo`, `docker` groups; `protected_hardlinks=1` blocks hardlinks
to root-only secrets), so this is **Minor**, not a new privilege boundary — but a root
script should not re-resolve an operator-owned source path. Fix: open the source root
and each directory with `O_DIRECTORY|O_NOFOLLOW` from a validated anchor, refuse
`st_nlink > 1` (or document the hardlink copy), and have `verify_tree` report
destination entries not present in either manifest.

#### S-4 — **Minor SAFETY residuals (unchanged from round 2): QGA socket path inside the QEMU-owned state dir; `hostsetup` teardown does not check a persistent `vprlab-tap0` before `userdel`**

`qga.py:124-128` still connects to `qga.sock` by path inside the QEMU-owned state dir;
a compromised QEMU can point it at another host socket, and the root runner then sends
QGA JSON (including the profile via `guest-file-write`) with root peer credentials. The
profile is already visible to QEMU, so impact is low. `hostsetup.py` teardown removes
the account without checking whether the persistent tap still exists; a later account
with the reused uid could open it (the M1 teardown does remove the tap, so the
documented order is safe). Both are pre-existing; both were Minor in round 2 and remain
so.

### 3.2 AVAILABILITY

**A-1 — Minor: the new QGA `_scan_from` optimisation can miss a handshake delimiter
that arrives split after the `0xFF`.** `qga.py:193-214`: when a `0xFF` marker is found
without a following newline, `_scan_from` is set to `len(buffer) - 1` instead of the
marker position. If the next chunk completes the frame but the marker is earlier than
that index, the marker is never rescanned and the connection times out. Reproducer with
a real fake agent that writes `b'\xff{"r'`, sleeps, then writes `b'eturn": 2}\n'`:

```
split error: QGATimeout timed out waiting for the guest agent elapsed 1.001
```

The normal one-chunk frame (and the `\xff`-as-last-byte split) works. This is
fail-closed: `wait_for_qga` retries with a new connection for up to 180 s, and the
`_read_response` newline scan is unaffected. Fix: remember the marker offset (or reset
`_scan_from` to the marker) when a marker is seen without a terminator. Add a split
test.

**A-2 — Minor (test fidelity): the suite patches `run_phase.CAPTURE_WATCH_INTERVAL` to
0.01 s, but `CaptureGuard.__init__`'s `interval` default is bound at definition time
(`run_phase.py:1650`), so the tests run the watcher at 0.1 s.** No product defect (the
synchronous `guard_check()`/`note_capture_guard()` still makes the verdicts correct),
but the test comments imply a faster guard than actually runs, and the teardown-growth
test passes largely via the synchronous final check. Pass `interval=` explicitly in
`_run_phase_locked` (or patch after construction) and assert the thread path.

**A-3 — Live gate (unchanged): Debian's tcpdump build drops privileges, with a patch
that is supposed to do so after opening the savefile "when possible"; it is
unconfirmed which order applies to this build.  The runner pre-creates a root 0600 pcap
and passes `/proc/self/fd/N/capture.pcap`.** If this build drops before opening,
tcpdump gets EACCES, `start_capture` refuses, and every phase is INVALID. Fails closed; confirm on
the host (and qualify AppArmor) before the first phase. No change in this commit.

**A-4 — Live gate: `hostcopy.check_elf_deps` must find every direct `DT_NEEDED` of the
staged `qemu-system-x86_64`, `qemu-img` and `genisoimage` in the copied library dir (or
the fixed host-base list).** The real tree contains the expected SONAME symlinks, but I
did not read the staged binaries (constraint: list-only), so this first host-setup step
is unverified; it fails closed at setup. `hostcopy` was exercised on synthetic ELF
images only.

**A-5 — Live gate: QEMU 2G/4G, KVM/tap, Docker/Tailscale login/READY, provisioning
completion, and the `-serial`/`qemu.log` behaviour are not run here.** All conclusions
are offline/source-level, as the M2 doc itself states.

**A-6 — Live gate (minor): the generated `hostsetup` teardown cannot `rmdir
/run/vprlab` because setup creates `run.lock` there; `rmdir … || true` leaves the
directory and lock (root 0700/0600).** Harmless; the module docstring's "exact
removal" is about tools/images/state. Adjust the wording or remove the lock on
teardown.

### 3.3 DOC

**D-1 — the resource-bound section is stronger than the code.** `leak-lab-vm.md:689-700`
describes the capture guard as enforcing the whole lifetime and does not mention
`serial.log`, `qemu.log`, or the 4G overlay as host-write paths; "it immediately brings
the tap down, records INVALID" is true for the tap but the INVALID reason is recorded at
the next checkpoint/finally, and a disk breach does not stop QEMU. The QGA sentence
"the buffer search only scans newly appended bytes" is the optimisation that A-1 shows
can skip an earlier handshake marker. Fix the wording together with S-1/A-1.

**D-2 — `hostcopy`/`hostsetup` provenance wording.** The doc now honestly says the
manifest is copy-fidelity, not pinned provenance, and only the base image has a pinned
digest (`leak-lab-vm.md:57-83`); the code matches. The remaining wording "every source
leaf is opened O_NOFOLLOW" should also say that directory components are not anchored
(S-3), and the `--allow-repo-scanner` developer override should carry a one-line warning
that it runs the operator-owned working-tree scanner as root.

**D-3 — prior minor doc nits:** the M1 capture path is now `/run/vprlab/…` and matches
`netplan.DEFAULT_CAPTURE`; the tcpdump drop-priv/AppArmor paragraph was added; the
`SHA256SUMS` "verified" wording is now scoped; the stale `Self.AdvertisedRoutes` branch
is gone. No remaining M1 doc reversal found.

## 4. False-PASS hunt (no new false PASS found)

- **Real scanner contract:** the controller and scanner now agree on exact bytes; a
  clean 4-record capture is PASS with `problems == []`, and a DNS leak is LEAK, both
  through the real CLI and the real `scan_evidence()`. The old fake-scanner-only test
  gap is closed by `RealScannerIntegrationTests`.
- **Capture guard cannot hide a leak:** on a `capture_size_cap`/`capture_disk_low`
  breach the runner still scans the retained pcap and `scan_verdict == "LEAK"` keeps
  precedence over the error list; a breach can only turn a would-be PASS into INVALID.
  The guard re-checks at `stop()` and after the stop wait, and `PASS` requires an empty
  `errors` list.
- **Evidence substitution:** every evidence read/write/hash is still `dir_fd`-relative
  with `O_NOFOLLOW|O_EXCL`, and the scanner is now executed from the root-owned
  `/opt/vprlab-tools/leaklab` copy whose `SHA256SUMS` is verified and compared with the
  repository copy (the previous rename-and-plant path remains closed).
- **Guest strings:** the only new guest string channel found last round
  (`BackendState`) is now mapped to a fixed vocabulary; the sentinel probe never reaches
  `phase.json`. `wan_device`, boot IDs, Docker PIDs, login URL and QGA error text remain
  bounded/allowed as before.
- **Scanner semantics:** the `pcapscan` diff is hash/report plumbing only; the
  round-2 differential (96 624 sequences, 0 LEAK→non-LEAK) remains applicable, and this
  round's real-scanner probe exercises the new bytes contract.
- **Residual:** no false PASS was found. S-1/S-2 are host-harm paths that produce
  INVALID, not PASS.

## 5. Final verification

- `git status --porcelain` was empty before the review and after all probes; `HEAD`
  remained `79a5bd5286db538625d846de51859f7d77c9de7b`. The only repository file written
  is this report.
- No prohibited command was executed. The generated host shell ran only under the test
  suite's stubs inside a temp directory; no QEMU/tcpdump/ip/nft/iptables/docker/useradd
  or network command was run.
- Scratch `/var/tmp/leaklab-crr3-pi` (probes, fake sockets, evidence fixtures) was
  removed after the probes.
- Passing suites do not certify runtime behaviour; the closure claims above are scoped
  to the re-run offline reproducers and the named code paths. S-1 is a source-level
  host-write bound, not a false-PASS claim.

## 6. Reproducer index (all offline; scratch deleted)

| ID | Probe | Observed |
|---|---|---|
| GPT I1 | real writers + real `pcapscan.py` CLI via `scan_evidence()` | `PASS []`; argv-file SHA-256 == `capture_meta.capture_argv_sha256`; canonical field separate |
| GPT I2 / Opus I-1 | rendered script + stubbed setup + real `provision` | no `vm-NNN` creation; provision reaches exclusive create; `check_layout` accepts absence |
| GPT I3 | `hostcopy.copy_tree` on synthetic tree + `_collect` on real tree | links preserved/verified; abs/escape/fifo/dir-symlink refused; 157/157 real links confined |
| Opus I-2b (QGA half; GPT I9 scanner half unchanged) | fake AF_UNIX agent, 64 KiB chunks forever | `QGAProtocolError reply_too_large`, closed at 16 MiB, 0.386 s |
| pi I-2 | `start-router` with key-shaped `BackendState` | `PASS`, `phase.json` = `unrecognized`, sentinel absent |
| Opus I-2a / pi I-1 | real guard thread + continuous writer; harness setup/cleanup growth | `capture_size_cap`, `isolate_tap`, INVALID, pcap above cap, still scanned |
| S-1 | `guest.build_qemu_argv("test")`, `inspect.getsource(start_vm)`, `check_admission` | `-serial file:<state>/serial.log`; no preexec/rlimit; admission `cap + 1 GiB`; overlay 4G |
| A-1 | fake agent writes `\xff{"r` then the rest | `QGATimeout` (split marker missed); one-chunk frame works |
| A-2 | `inspect.signature(CaptureGuard.__init__)` before/after patching the module constant | `interval=0.1` both times; the test patch 0.01 has no effect |
