# Leak lab — combined adversarial re-review (round 3), Opus, 2026-11-09

## Scope

**Commit:** `79a5bd5` (`rust/v2`). The working tree was clean before the review; only this report was added.

**Files reviewed:**
- **Monitor:** `tools/leak-lab/{pcapscan,policy,netplan,control,tsnames}.py` and `docs/rust-v2/leak-lab.md`.
- **Runner:** `tools/leak-lab/vm/*.py`, with emphasis on the new `hostcopy.py` and on the changes to `run_phase.py` (CaptureGuard, scanner resolution, `scan_evidence`, kill proof, runner rlimit), `qga.py`, `hostsetup.py` and `provision.py`. Also `docs/rust-v2/leak-lab-vm.md`.
- **Previous round:** the reports `leak-lab-combined-rereview-{gpt,opus,pi}.md` (gpt is partial).

**Method:** every probe is offline.
- Runner probes subclass `test_vm.RunPhaseTests`, so the real `run_phase()` decision logic runs.
- One probe swaps the fake scanner for the **real `pcapscan.py` subprocess**. It runs over a real pcap, through the inherited evidence fd and an installed-style scanner copy.
- Real child processes were used for the signal and kill probes (`/usr/bin/sleep`, `python3`).
- The rendered hostsetup and M1 scripts were checked with `sh -n`.

**Limits:**
- No sudo, QEMU, tcpdump, ip, nft, iptables, docker, useradd or network command was run.
- I ran `readelf --dyn-syms` on `/usr/bin/tcpdump` and libpcap. I also ran **one `ldd`** on `/usr/bin/tcpdump` to find libpcap. That is a loader trace, and no tcpdump code ran; I disclose it because it is borderline.
- I read no `/etc/vprouter`, conf, zip, `/var/lib/vprouter` or key files.
- Scratch `/var/tmp/leaklab-crr3-opus` was deleted at the end.

## Test suites

```
TMPDIR=/var/tmp/leaklab-crr3-opus/tmp python3 -B -W error -m unittest discover -s tools/leak-lab    -p test_leak_lab.py
Ran 249 tests in 8.031s   OK
TMPDIR=...                            python3 -B -W error -m unittest discover -s tools/leak-lab/vm -p 'test_*.py'
Ran 161 tests in 4.625s   OK
```

- Total: 410 tests. 0 failures, 0 errors, 0 skips.
- The doc's count of 161 is correct.

## Verdict: **PASS** — 0 Critical and 0 Important SAFETY findings

| Category | Critical | Important | Minor |
|---|---|---|---|
| SAFETY | 0 | 0 | 7 |
| AVAILABILITY | 0 | 1 | 3 |
| DOC | — | — | 5 |

**What is fixed:**
- Every Important finding from the three round-2 reports is closed by its reproducer (§1). That includes the real-scanner argv-hash contract, now proven end to end through `run_phase()` with the real scanner subprocess.
- No false-PASS path, secret channel or guest-driven host-resource path at Important level was found.

**What to fix before the supervised bring-up:** fix **A-1** first, although it is allowed to be deferred.
- Every tcpdump the runner starts inherits SIGINT/SIGTERM/SIGHUP **blocked**. The graceful stop therefore never works, and every live phase will end INVALID after a 20 s forced kill with no stats summary.
- It fails closed, but it would waste the first live phase.
- The same spawn helper is the right place to fix S-1 (the guard thread bypasses the signal mask) and A-3 (the inherited 2 GiB `RLIMIT_AS`).

---

## 1. Previous-round closure (reproducers re-run)

| Previous finding | Reproducer re-run at 79a5bd5 | Result |
|---|---|---|
| **gpt I1**: argv exact-byte vs canonical hash, so a clean phase can never PASS | (a) Real `run_phase()` for `idle`, with only `subprocess.run` for `pcapscan.py` routed to the **real** scanner. A real 4-frame pcap and stats are written after AFTER. The scanner is an installed-style copy (`pcapscan/netplan/policy/control/tsnames` + `SHA256SUMS`). (b) The same run plus one DNS frame. | (a) exit 0 **PASS**, `errors []`, scanner `PASS`, `pcapscan_argv[2]` = the installed copy. (b) exit 1 **LEAK**, `errors []`. `capture_meta.capture_argv_sha256` is now the exact file-bytes hash. The canonical hash is kept separately as `capture_argv_canonical_sha256`. ✔ |
| **gpt I2 / opus I-1**: hostsetup pre-creates `vm-NNN`, so provision refuses | `render_setup_script()`; `provision.create_state_directory(<absent vm-001>)` | The script has no `install … -o "$QEMU_USER"` for `vm-NNN` (the only `vm-$suffix` left is the teardown `rm`). Provision creates the directory. `--check` accepts its absence. ✔ |
| **gpt I3 / pi M-7**: symlinks dropped from the tool tree | `hostcopy.copy_tree` over `libx.so.0 -> libx.so.0.4.0` | The link is recreated, recorded in `SYMLINKS.json`, and `verify_tree` returns `[]` ✔. See S-3 for a residual. |
| **opus I-2a / pi I-1**: capture cap enforced only during the window | (a) My round-2 reproducer: `stop-router`, cap 1000, +50 000 B on each finally-cleanup `systemctl stop`. (b) New: growth during the setup `systemctl start`; the fake guest blocks until it sees `isolate_tap`. | (a) exit 2 INVALID `capture_size_cap`, `isolate_tap` is called. (b) INVALID `capture_size_cap`, and the tap was isolated **while the QGA call was still running** (the watchdog thread works) ✔ |
| **opus I-2b**: unbounded QGA buffer | 1600 × 64 KiB with no newline into `_read_response` | `QGAProtocolError: reply_too_large`; the socket is closed and the buffer is 0 ✔. The O(n²) rescan is gone. See A-2 for a regression this introduced. |
| **pi I-2**: guest `BackendState` stored verbatim | `start-router`, `BackendState = "PrivateKey=" + "A"*43 + "="` | PASS with `backend_state: "unrecognized"`; the sentinel is absent from `phase.json` ✔ |
| opus m-1: hostsetup copy follows a swapped symlink | Swap a listed file for a symlink to a 0600 secret after listing; also rename-over replacement | Refused (`O_NOFOLLOW` → `ELOOP`, and dev/ino mismatch → "changed while it was being copied"). Images are copied 0600 and made 0644 only after the pinned digest verifies ✔ |
| opus m-2: scanner run from the opsec checkout at scan time | `resolve_pcapscan` | It runs from root-owned `/opt/vprlab-tools/leaklab` after its manifest verifies, and `pcapscan.py` must equal the repo copy ✔. Residuals: S-2 and D-4. |
| opus m-3: kill gated on the QEMU pidfile | Real child that `execv`s another binary | Partly fixed: the pidfile is no longer used, but `/proc/<pid>/exe` and `cmdline` are still QEMU-controlled. See S-5. |
| opus m-4: `qga.sock` connected by path | Code read | Unchanged (S-6). |
| opus m-5 / pi M-2 / pi M-3: lock probe only, setup unguarded, pgrep optional, userdel ignored | Rendered scripts | `exec 9>>lock; flock -n 9` is held for the whole teardown/setup in both `netplan.py` and `hostsetup.py`. Setup now takes the lock plus a QEMU guard. A missing `pgrep` refuses. A failed `userdel` returns 1. Both scripts pass `sh -n` ✔ |
| opus m-6: teardown deletes evidence | Rendered teardown | Evidence is retained, with a message ✔ |
| opus m-7: `ancestry_records` TypeError | Code | Fixed ✔ |
| opus m-8 / pi M-9: scanner crash reported as LEAK | Code: `final_result` | LEAK now requires a parseable report with `verdict == "LEAK"` ✔ |
| opus m-9: doc nits | Doc and code | `AdvertisedRoutes` dropped (`ExitNodeOption` only, as in `router_runtime`) ✔. tcpdump doc rewritten, but see D-3. |
| pi M-1: `--check` rejects 0755 tools | Code | The mask is now `0o6022`, and `/` no longer has to be exactly 0755 ✔ |
| pi M-4: `with` close after Popen | Code | `reap_after_setup_failure` ✔. But see S-1: the signal mask no longer protects this window. |
| pi M-5 / M-6 / M-8 / M-10 / M-11 | Code and doc | Doc path fixed; display argv recorded; provision ignores a second signal; `qemu_env` deleted; absolute `/usr/sbin/ip` and `/usr/sbin/nft` (both exist on this host, `ip` as a link to `../bin/ip`) ✔ |

---

## 2. SAFETY findings (all Minor)

### S-1. The CaptureGuard thread defeats `block_termination_signals()` (regression of the round-2 m-3 fix)

**Locations:**
- `run_phase.py:2510-2519`: `capture_guard.start()` runs *before* `with block_termination_signals(): start_capture(…)`.
- `:2527`: the same block around `start_vm`.
- `:2117-2127`: `pthread_sigmask` blocks only the calling (main) thread.

**Mechanism:** the kernel delivers a process-directed SIGTERM/SIGINT/SIGHUP to any thread that does not block it, which here is the guard thread. CPython then runs the Python handler in the main thread at its next eval-breaker check, regardless of the main thread's mask.

**Probes** (external `kill -TERM`, real handler):

```
guard thread running: False -> ['handler_ran_after_block']
guard thread running: True  -> ['handler_ran_inside_block']
```

With the real `start_capture` and a real child (`sleep 30`, new session): the handler raises `PhaseInterrupted` inside `start_capture`, the capture handle is `None`, and the **child is still alive**.

**Effect:**
- A signal during the tcpdump readiness loop orphans tcpdump in its own session. The finally block has no handle, and later phases' tap traffic would be appended, unbounded, to the old run's pcap.
- A signal between `start_vm` returning and the tuple assignment orphans QEMU with the tap up. `lifecycle.qemu_alive` is false, so the lock is released. The next run's `refuse_if_qemu_running` refuses.
- No false PASS: the phase is INVALID.

**Why Minor:** it needs an operator or systemd signal inside a short window. The readiness loop ends as soon as tcpdump writes the 24-byte header; the QEMU window is a few bytecodes.

**Fix:**
- Start the guard thread *inside* a blocked region, because threads inherit the creator's mask. Alternatively, call `pthread_sigmask(SIG_BLOCK, …)` at the top of `CaptureGuard._run`.
- Add a test that sends a real signal with the guard running.

### S-2. Only `pcapscan.py` is bound to the repository; the scanner's imports (`netplan.py`, `policy.py`) can be stale without any check

**Locations:** `run_phase.py:135-169` (`resolve_pcapscan` compares `digests["pcapscan.py"]` only) and `pcapscan.py:60-61` (`import netplan`, `import policy`, resolved from `sys.path[0]` = `/opt/vprlab-tools/leaklab`).

**Probe:**
- Installed `pcapscan.py` equal to the repo, installed `netplan.py` changed, manifest rewritten.
- `resolve_pcapscan` accepts and returns the installed path.

**Effect:**
- Suppose a verdict-relevant fix lands in `policy.py` or `netplan.py` (for example `check_capture_argv`), and hostsetup is not re-run.
- Certification runs then silently use the old logic. The doc says "compares its hash with the repository copy".
- `phase.json` records the scanner path only implicitly, through `pcapscan_argv`, and records no module digests.
- This is a false-PASS path only for a regression fixed in those modules, so Minor.

**Fix:**
- Compare every file in the scanner's import closure (`pcapscan.py`, `netplan.py`, `policy.py`; or simply all `LEAK_LAB_FILES`) with the repo.
- Record `scanner: {path, installed|repo_override, manifest_sha256}` in `phase.json`, and make `--allow-repo-scanner` an explicit `certifiable: false`.
- Consider `-I` instead of `-B` alone for the scanner.

### S-3. `hostcopy`'s "confined relative symlink" check is lexical; chained links escape the tree

**Location:** `hostcopy.py:251-269` (`_resolve_link`), used by `_collect` and `verify_tree`.

**Probe:**
- Source tree with `a/b/s -> ../../top` (lexically `top`) and `a/b/k -> s/../..` (lexically `a`).
- `copy_tree` and `verify_tree` both return `[]`.
- After the copy, `realpath(dst/a/b/k)` is the **parent of the destination**, and `dst/a/b/k/OUTSIDE-MARKER` is readable.

**Effect:**
- The doc (`leak-lab-vm.md:59-61`) and the module docstring say links "must resolve inside the copied tree"; that is false.
- In `/opt/vprlab-tools`, such a link can point the unprivileged loader (`LD_LIBRARY_PATH`) at arbitrary host paths: a fidelity break, not an exposure.
- Root's own `chown -R` and `find -type f -exec chmod` do not follow links.
- `elfcheck` uses `realpath` and correctly refuses an escaping `DT_NEEDED`.
- A provision run reads only the pinned-digest base image.
- The actor is the operator-owned source tree, so Minor.

**Fix:** after recreating the links, check each one with `os.path.realpath` against the destination root. Or refuse a link whose target path traverses another symlink.

### S-4. The M1 foreground capture defaults to `/run/vprlab` (tmpfs, 1.2 GiB here), so a capture can fill `/run` for every host service

**Locations:** `netplan.py:58` (`DEFAULT_CAPTURE = "$RUN_DIR/manual-capture.pcap"`) and `:761` (unbounded foreground tcpdump in the non-`setup` mode). The docs (`leak-lab.md:417,705-721`) were updated to this path in this commit.

**Effect:**
- `/run` holds containerd/docker state, systemd runtime files, and the production router's runtime on debdev.
- At line rate, 1.2 GiB fills in about 10 s, and other services then fail to create runtime files.
- The documented M2 path uses `lab.sh setup`, which never starts this capture, so the next step is unaffected. Minor.

**Fix:** default the manual capture to a run directory under `/var/lib/vprlab/evidence`, and bound it with `ulimit -f` / `RLIMIT_FSIZE`. A truncated record then becomes INVALID through the existing structural check. Or refuse a tmpfs target.

### S-5. QEMU kill is still gated on QEMU-controlled state (carried from opus m-3, partly fixed)

**Location:** `run_phase.py:1981-2001` (`qemu_process_is_ours`: `/proc/<pid>/exe` and `cmdline` argv[0]).

**Probe:**
- Real child; `guest.QEMU` patched to the interpreter.
- A plain child is `ours=True` and is killed.
- A child that `execv`s `/usr/bin/sleep` gives `ours=False` and `kill_qemu=False`, and **it stays alive**.

A compromised QEMU can `execve` (`no_new_privs` does not stop that) or rewrite its argv to dodge the kill.

**Why Minor:** the fail-safe isolation holds (tap down, `qemu_still_running`, lock retained). Our unreaped `Popen` pid cannot be reused, so the proof adds nothing and should not veto `killpg` while `process.poll() is None`.

### S-6. Root connects to `qga.sock` by path inside the QEMU-owned state directory (carried from opus m-4, unchanged)

**Location:** `qga.py:120-128`. A compromised QEMU can swap the path for a symlink to another host socket. The impact is low (line-JSON from a root peer); `lstat` via a dir fd plus `S_ISSOCK`/uid checks, or a pre-opened listening fd, would close it.

### S-7. The guard bounds only the pcap; guest-driven serial output and the QEMU log are unbounded, and a breach does not stop QEMU

**Locations:**
- `guest.py:329-330`: `-serial file:<state>/serial.log` is guest-writable through the emulated UART.
- `run_phase.py` CaptureGuard: `capture_disk_low` isolates the tap but leaves QEMU writing until the main thread reaches its next checkpoint, which can be after a 360 s QGA call.

**Effect:** bounded in practice by phase length and serial throughput against 173 GiB free.

**Fix:** on any guard breach, also SIGKILL our QEMU (as suggested last round). Alternatively, give QEMU `RLIMIT_FSIZE` and the serial chardev `logfile` a size bound, or watch `serial.log` too.

---

## 3. AVAILABILITY findings (fail closed; may be deferred to live bring-up)

### A-1 (Important). tcpdump and QEMU are spawned with SIGHUP/SIGINT/SIGTERM blocked, so `stop_capture`'s SIGINT never works and every live phase ends INVALID

**Locations:** `run_phase.py:2515-2519` and `:2527-2535`. `start_capture`/`start_vm` run `Popen` inside `block_termination_signals()`. A signal mask survives `fork`+`execve`; CPython does not reset it, and neither `setpriv` nor `env -i` do.

**Probe** (real child spawned inside the block):

```
child SigBlk: 0000000000004003   (HUP|INT|TERM)
SIGINT did NOT stop the child (pending, blocked)
```

**Evidence that tcpdump will not undo the mask:** `/usr/bin/tcpdump` imports `sigaction` only. Neither it nor `libpcap.so.0.8` imports `sigprocmask` or `pthread_sigmask` (`readelf --dyn-syms`).

**Effect** (`stop_capture`, `:714-737`):
- SIGINT stays pending. After 20 s the runner falls back to `killpg(SIGKILL)` and sets `tcpdump_forced_stop`.
- tcpdump never writes its exit summary, so the scanner reports `stats_incomplete`/`stats_unparseable`.
- `tcpdump_exit_status` is -9, which is noted.
- Result: **every real phase is INVALID**. It fails closed, and the first live phase will show it.
- The harness uses fake processes, so 161 green tests miss it. It has existed since `545fb95`.

**Fix:**
- Spawn the children with `os.posix_spawn(…, setsigmask=(), setsid=True)`, or restore the mask in the child.
- Keep the handle-orphan protection through a deferred-flag handler instead of a mask.
- Add a test that reads `/proc/<child>/status` `SigBlk` for both spawn paths.

### A-2 (Minor). QGA handshake regression: a sync frame split after `\xff` is never found

**Location:** `qga.py:199-214`. When `\xff` is found but no `\n` follows yet, `_scan_from = len(buffer) - 1` moves *past* the marker. The next search for `\xff` then skips it.

**Probe:**
- `\xff{"return": <id>}` arrives in one recv and `\n` in the next: `QGATimeout`.
- The same bytes in one chunk work.
- `\xff` alone in the first chunk still works, because the marker is the last byte.

**Effect:** rare; `wait_for_qga` retries with a new connection. Fix: when a marker is found without a newline, keep `_scan_from = marker`.

### A-3 (Minor). The 2 GiB runner `RLIMIT_AS` is inherited by QEMU, tcpdump and the other children

**Location:** `run_phase.py:157-169` sets only the soft limit, before any spawn.

**Effect:**
- QEMU's virtual size (guest RAM, per-thread glibc arenas, thread stacks, the AIO worker pool) can approach or exceed 2 GiB.
- An `mmap` ENOMEM aborts QEMU mid-phase, so the phase is INVALID.
- It is not verifiable offline. Check QEMU's `VmPeak` during bring-up, or restore the soft limit to the hard limit in the children (same spawn hook as A-1).

### A-4 (Minor). The scanner still uses `preexec_fn` while the guard thread may still be alive

**Location:** `scan_evidence` uses `preexec_fn=set_scan_limits`. `CaptureGuard.stop()` joins with a 1 s timeout, while `_breach → isolate_tap` can take up to 15 s.

**Effect:** `preexec_fn` with a live thread risks a child deadlock, which would be a 300 s scan timeout and then INVALID. Use `posix_spawn` with `resource` limits through a wrapper, or join the guard unconditionally before scanning.

---

## 4. DOC findings (Minor)

- **D-1.** `leak-lab-vm.md:76-79`: the doc says the runner "compares its hash with the repository copy", but only `pcapscan.py` is compared (S-2). The scanner provenance that ends up in `phase.json` is not documented.
- **D-2.** `leak-lab-vm.md:59-61` and the `hostcopy.py` docstring say links "must resolve inside the copied tree". The check is lexical only (S-3).
- **D-3.** `leak-lab-vm.md:124-127` and `leak-lab.md:695-698` now state as fact that Debian's tcpdump "starts as root, opens the savefile, then drops". That is still the unverified runtime gate from round 2 §5; keep it marked as "qualify on host". The doc should also say the runner stops tcpdump with SIGINT, which is what A-1 breaks.
- **D-4.** The operator-account trust boundary is still implicit. Only the scanner moved to the root-owned copy. `run_phase.py`, `hostcheck.py`, `rootfs.py`, `qga.py` and `provision.py` still run as root from the operator-owned checkout (the documented commands use `tools/leak-lab/vm/run_phase.py`), and the root environment (`PYTHONPATH`) is inherited by the scanner. Say explicitly that the operator account is trusted. Or document running the installed `/opt/vprlab-tools/leaklab/vm/run_phase.py`, which hostsetup already installs.
- **D-5.** `leak-lab-vm.md:698-699` describes the runner's `RLIMIT_AS` 2 GiB as bounding "the root runner itself". It does not mention that QEMU and tcpdump inherit it (A-3).

## 5. Deep checks that held (no finding)

- **CaptureGuard coverage:**
  - It starts before tcpdump and opens the pcap via the evidence dir fd.
  - It polls every 100 ms with `fstat` and `fstatvfs`, so a rename-and-plant cannot evade it.
  - The breach reason is noted at finally entry, after poweroff and after `stop()`. Every breach therefore becomes INVALID even when the main thread was blocked in a long QGA call (probe P2b).
  - After `stop()`, tcpdump has exited, so no further growth is possible.
- **Real scanner contract:**
  - The runner's exact-byte pre-hashes, the scanner's `capture_meta` hashes and the post-scan re-hashes agree on a clean run.
  - The `/proc/self/fd/N/…` paths resolve identically in tcpdump, the runner and the scanner.
  - `display_argv` is display-only.
- **Final-result mapping:**
  - PASS needs `scan_exit == 0`, `verdict == "PASS"`, a report and no noted errors.
  - LEAK needs a parseable LEAK report.
  - Everything else is INVALID.
- **QGA bounds:**
  - The 16 MiB reply cap and 4 MiB exec-output cap close the socket on violation.
  - A desynchronised stream is never reused.
- **hostcopy copy integrity:**
  - The source leaf is opened `O_NOFOLLOW` and must have the dev/ino recorded at listing time. Bytes are hashed while written, the temp file is re-hashed, then `os.replace`.
  - Modes are masked with `0o755`, so setuid is dropped.
  - `fs.protected_hardlinks=1` on this host, so a hardlinked root-only file cannot be planted in the source.
- **Setup/teardown scripts:**
  - The lock is held via fd 9 for the whole script (`flock(2)` on both sides, compatible with `runlock.flock`).
  - The runlock re-`fchmod`s 0600, so a lock file created by the shell is harmless.

## Reproducer index (all offline; scratch deleted)

| ID | Probe | Observed |
|---|---|---|
| P1/P1b | real `run_phase()` + real scanner subprocess, clean / +DNS | PASS `[]` / LEAK `[]` |
| P1c | stale installed `netplan.py`, manifest rewritten | accepted (S-2) |
| P2/P2b | growth in finally cleanup / during setup call | INVALID `capture_size_cap`; isolated during the call |
| P3 | 55-char key-shaped `BackendState` | `unrecognized`, sentinel absent |
| Q1 | 100 MiB with no newline | `reply_too_large`, buffer 0 |
| Q2 | `\xff{json}` + `\n` split | `QGATimeout` (A-2) |
| L1 | rendered hostsetup; provision create | no `vm-NNN` install; create OK |
| H1/H2/H2b/H3 | link copy; symlink swap; rename-over; chained-link escape | OK; refused; refused; **escapes** (S-3) |
| K1/K2 | kill plain child / child after `execv` | killed / not killed, alive (S-5) |
| SIG | external SIGTERM inside `block_termination_signals` with/without guard | handler deferred / **runs inside block**; real `start_capture` child orphaned (S-1) |
| MASK | child spawned inside the block | `SigBlk 0x4003`, SIGINT ignored (A-1) |
