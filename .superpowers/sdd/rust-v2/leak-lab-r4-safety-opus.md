# Leak lab — round-4 focused SAFETY gate (Opus), 2026-11-09

## Scope and limits

- **Commit:** `0097e78` (`rust/v2`). The worktree was clean before and after the review. This report is the only file added (`.superpowers/` is git-ignored).
- **Code reviewed:** `tools/leak-lab/**` and `docs/rust-v2/leak-lab*.md`, with emphasis on the fix diff:
  - `run_phase.py`: deferred signals, `apply_child_limits`, CaptureGuard liveness and QEMU kill, scanner wrapper, admission;
  - `provision.py`, `guest.py` (`-serial none`), `pcapscan.py` (WireGuard shape check), `login_url.py`, `qga.py`, `hostcopy.py`;
  - `hostsetup.py` and `netplan.py` (generator quoting).
- **Method:** everything was offline.
  - Real `start_capture`/`stop_capture`/`CaptureGuard`/`kill_qemu` were run against **real child processes**: a fake tcpdump written in Python that handles SIGINT, and `python3`/`sleep` children. I read `/proc/<pid>/status` and `/proc/<pid>/limits` directly.
  - `isolate_tap` was monkey-patched to a recorder, so no `ip` command ran.
  - The real `run_phase()` was driven through `test_vm.RunPhaseTests`, and the real scanner through `test_leak_lab.scan`.
- **Not run:** sudo, QEMU, tcpdump, ip, nft, iptables, docker, useradd or any network command.
  - I read package metadata (`dpkg-query`) and `/proc/sys/kernel/core_pattern` only.
  - I read no `/etc/vprouter`, conf, zip, `/var/lib/vprouter` or key files.
- **Cleanup:** scratch `/var/tmp/leaklab-r4-opus` was deleted.
  - A `sleep 30` process seen afterwards belongs to an unrelated `hourly-recovery.sh` (ppid 1201), not to this review. It was left alone.

## Test suites

```
TMPDIR=/var/tmp/leaklab-r4-opus/tmp python3 -B -W error -m unittest discover -s tools/leak-lab    -p test_leak_lab.py
Ran 254 tests in 8.158s   OK
TMPDIR=...                          python3 -B -W error -m unittest discover -s tools/leak-lab/vm -p 'test_*.py'
Ran 188 tests in 9.058s   OK
```

- Total: **442** tests (up from 410). 0 failures, 0 errors, 0 skips.

## Verdict: **PASS** — 0 Critical and 0 Important SAFETY findings

**Fix before the live bring-up: A-N1 (Important AVAILABILITY).**
- The new WireGuard shape check rejects real WireGuard transport packets whose padding was clamped to the tunnel MTU.
- At MTU 1420 (the wg-quick default on a 1500-byte WAN) or 1380, **any full-size inner packet makes the phase `LEAK`**.
- Tailscale's TLS/Noise traffic through the tunnel will almost certainly produce such packets. Every tunnel-up phase is therefore likely to report a **false LEAK**: the scanner reports a product leak that does not exist.
- That is fail-closed for certification, but it is worse than last round's A-1. A-1 produced INVALID; this produces a misleading LEAK.

| Category | Critical | Important | Minor |
|---|---|---|---|
| SAFETY (new) | 0 | 0 | 4 |
| SAFETY (carried, documented skips) | 0 | 0 | 3 |
| AVAILABILITY | 0 | **1** | 3 (+1 nit) |
| DOC | — | — | 6 |

---

## 1. Round-3 closure (reproducers re-run at 0097e78)

### Opus round-3 findings

| Finding | Reproducer | Result |
|---|---|---|
| **A-1** children inherit blocked HUP/INT/TERM | The probe process **blocked INT/TERM/HUP first** (a caller-supplied mask), then ran `install_signal_handlers()` + `set_runner_limits()`. A real child was spawned via `start_capture` (fake tcpdump). | Runner `SigBlk 0`; child `SigBlk 0000000000000000`, `SigCgt 0x4002` (INT, TERM). `stop_capture` → rc 0, `forced_stop False`, summary written. **Closed**, but see **A-N2**: the graceful window is now 0.5 s. |
| **S-1** guard thread bypasses the mask | SIGTERM at 0.3 s while `start_capture` waits for the pcap header (the fake writes it at 2 s). A real `CaptureGuard` thread is running. | `PhaseInterrupted: received signal 15` is raised from the readiness loop. The child is stopped and reaped: **0 live children**. **Closed.** |
| **S-2** only `pcapscan.py` bound to the repo | Installed-style copy of all `LEAK_LAB_FILES`; `netplan.py` changed and `SHA256SUMS` rewritten | Refused: `installed netplan.py differs from the repository copy`. `phase.json` now records `scanner.{path,source,certifiable,manifest_sha256}`. **Closed.** |
| **S-3** chained-link escape | `a/b/s -> ../../top`, `a/b/k -> s/../..` | `a/b/k resolves outside the copied tree`. **Closed.** |
| **S-4** M1 manual capture on `/run` | `netplan.DEFAULT_CAPTURE` | Still `$RUN_DIR/manual-capture.pcap` with no size bound. **Open; documented skip** (the M2 path never starts it). |
| **S-5** kill proof uses QEMU-controlled `/proc` | Child `execv`s `/usr/bin/sleep` | `kill_qemu → False`, child alive. **Open; documented skip.** The guard's new kill inherits the same proof. The RLIMIT_FSIZE hard limit now bounds guest-driven writes even then: it survives `execve`, and `-sandbox resourcecontrol=deny` prevents QEMU from changing it. |
| **S-6** `qga.sock` connected by path | Code | Unchanged. **Open; documented skip.** |
| **S-7** serial/QEMU log unbounded; breach does not stop QEMU | `build_qemu_argv("test")`; real guard with a real "QEMU" child (`guest.QEMU` patched to the interpreter), pcap 5000 B > cap 1000 | `-serial none` for test boots. The guard breach `capture_size_cap` → `isolate_tap` + **QEMU SIGKILLed** (rc -9), `kill_error None`. QEMU has `RLIMIT_FSIZE` 6 GiB. **Closed.** |
| **A-2** QGA sync frame split after `\xff` | Real AF_UNIX fake agent: `\xff{"return": id}`, a 0.3 s pause, then `\n` | Handshake OK. **Closed.** |
| **A-3** inherited 2 GiB `RLIMIT_AS` | `/proc/<child>/limits` after `start_capture` under the runner limit | `Max address space unlimited unlimited`. QEMU uses the same helper (not executed). **Closed.** |
| **A-4** `preexec_fn` with the guard thread live | `scanner_launch_argv` run on a child that prints its limits | No `preexec_fn`. The child has `RLIMIT_AS 1073741824/1073741824`, argv preserved (`$0=ARG0`), and the wrapper itself runs `-I`. **Closed.** |

### GPT round-3 findings

| Finding | Reproducer (GPT's script, adapted to new signatures) | Result |
|---|---|---|
| **S1** capture exits cleanly after AFTER → PASS | Same harness: the fake capture's `poll()` returns 0 after AFTER, real scanner in-process | `exit 2 INVALID`, `errors ["capture_ended_early"]`, `capture_alive_before_stop false`; scan still `PASS`. Separately, a real guard with a real fake-tcpdump that dies on its own records `capture_ended_early` within 100 ms and isolates the tap. **Closed.** |
| **S2** login URL as a secret channel | `AuthURL = /a/<base64 of 32 bytes>` | Nothing written, nothing on stderr. `login_url_unrecognized` is noted, so INVALID. A valid `/a/1f6d5b3a3c4d8` is still written. **Closed** to a bounded residual (S-N4). |
| **S3** host disk exhaustion | Code and probes above | `-serial none` (test). Provision: serial capped at 64 MiB with a kill, QEMU and provision process under `RLIMIT_FSIZE` 8 GiB, 8 GiB state admission. Phase: state-filesystem admission is 4 GiB overlay + 1 GiB (probe: 3 GiB free is refused); a guard breach kills QEMU. **Closed.** |
| **S4** arbitrary UDP payload on the tuple → PASS | GPT's plaintext frames | `LEAK`, 2 × `allowed_tuple_not_wireguard`. **Closed** for non-WireGuard-shaped payloads. Type-4-shaped plaintext still passes (probe: PASS); that is the **inherent limit of a shape check** and is not counted as new. |
| **S5** shell injection via generator file names | `base_image_name="x'; printf …"`, `capture_file='$RUN_DIR/$(printf …).pcap'`, `'/tmp/a b.pcap'`, `'$RUN_DIR/../x.pcap'` | All refused (`LayoutError` / `NetplanError`). A valid `$RUN_DIR/ok.pcap` renders as `"$RUN_DIR"/'ok.pcap'`. Every assignment in hostsetup is `shlex.quote`d. **Closed.** |

### Pi round-3 finding

| Finding | Result |
|---|---|
| **S-1** guest-driven `serial.log` / QEMU log growth | Test boots use `-serial none` (verified in argv). `qemu.log` sits on the evidence filesystem, which the guard's free-disk floor watches (and that breach now kills QEMU); QEMU also has `RLIMIT_FSIZE` 6 GiB. **Closed.** |

---

## 2. New-code review: specific questions

### Deferred signals: any window that leaves QEMU or tcpdump running without a handle?

**In `run_phase.py`, no.**
- The handler only sets a flag. `Popen` therefore always returns and is assigned, and `apply_child_limits` runs before the first `check_interrupt()`.
- The readiness loop stops and reaps tcpdump on `PhaseInterrupted` (probe above).
- Signals delivered to the guard thread cannot raise anywhere.
- The ordered `finally` keeps tcpdump alive until QEMU has exited.
- A signal that arrives during cleanup makes `poweroff_vm`'s `wait_process` raise once, which falls through to a verified SIGKILL. The phase is INVALID (`forced_poweroff`), which is acceptable.

**The trade-off is latency** (A-N3 / S-N1). `provision.py` was not converted (S-N2).

### Does tcpdump get an empty mask and stop on SIGINT?

**Yes.**
- The runner clears its own mask in `install_signal_handlers()`. The probe proved this even when the caller handed it a blocked mask.
- CPython's vfork path restores the parent thread's (empty) mask in the child.
- Python-installed handlers reset to `SIG_DFL` on exec.
- The child shows `SigBlk 0`, and SIGINT produces a clean exit with the summary.
- Real tcpdump 4.99.5 always installs a SIGINT `cleanup` handler that calls `pcap_breakloop`. libpcap 1.10.5 wakes its `poll` through the break-loop eventfd, so the real exit should take milliseconds (qualify on the host).
- **However**, `stop_capture` now waits only 0.5 s before SIGKILL (A-N2).

### Capture liveness

- Correct.
  - The guard polls tcpdump every 100 ms and isolates the tap on an early exit.
  - The final pre-stop `poll()` notes `capture_ended_early`.
  - `mark_capture_stopping()` is set after that check and before SIGINT, so the normal stop is not misreported.
  - The guard's `poll()` can reap tcpdump first; `stop_capture` then sees a `returncode` and sends **no** signal (probe: returns 0, `forced False`).
- A liveness breach does not kill QEMU. That is deliberate and fine: the tap is down.

### `-serial none`, `RLIMIT_FSIZE` and `prlimit`

- **No util-linux `prlimit` binary is used.** The code calls Python's `resource.prlimit()`, which is the `prlimit64` syscall and is available in CPython 3.13 on Linux.
- For reference, `/usr/bin/prlimit` does exist on this Debian 13 host (util-linux 2.41.5-0+deb13u1).
- Root (`CAP_SYS_RESOURCE`) may raise and lower a child's hard limits after `setpriv` has changed its uid.
- The limits are applied after `Popen` returns, so QEMU briefly starts under the runner's 2 GiB AS soft limit. That is harmless: guest RAM is 512 MiB, and the AS limit is checked per `mmap`.
- Failures are swallowed silently (S-N5).
- `-serial none` affects only test boots. The guest's `/dev/ttyS0` writes are provision-only and guarded by `[ -w /dev/ttyS0 ]`.

### Can the guard's SIGKILL hit a non-QEMU process?

**No practical path.**
- `kill_qemu` first calls `poll()`. Once either thread has reaped QEMU, it returns True **without signalling** (probe: `kill_qemu(reaped) → True`).
- The only gap is CPython's `_internal_poll` returning `None` while the other thread holds `_waitpid_lock`.
- Even then, `/proc/<pid>/exe` must resolve to the staged QEMU binary. Only one such process exists under the run lock, and a pid would have to wrap within microseconds.
- Nit: `os.killpg(os.getpgid(pid))` could be replaced by `os.pidfd_open` at spawn plus `signal.pidfd_send_signal`, which removes the class entirely.

### WireGuard shape check

- Types and fixed lengths 148/92/64 are correct, keepalive (32) passes, and fragments fail closed.
- **The type-4 alignment rule is wrong for MTU-clamped packets** (A-N1).
- Type-4-shaped plaintext passing is an inherent limit, not a finding.

### Injection-safe generators

- Closed (see §1).
- Paths in hostsetup and netplan are restricted to `[A-Za-z0-9._-]` components, with no `.`/`..`, and every shell word is quoted. `$RUN_DIR` is composed as `"$RUN_DIR"/'name'`.

### Scanner wrapper

- Correct.
  - `python3 -I -c <fixed text> <limit> <scan argv…>` → `setrlimit(AS, 1 GiB)` → `execv`. argv and `pass_fds` are preserved through exec.
  - The scan timeout kills the same pid.
- Note: the scanner itself still runs with `-B` and not `-I` (round-3 D-4 residual; `sudo` `env_reset` strips `PYTHONPATH`).
- `phase.json` records the inner `scan_argv`, not the wrapper (D-5).

---

## 3. AVAILABILITY

### A-N1 (Important). The type-4 rule `(len-16) % 16 == 0` rejects real WireGuard packets whose padding was clamped to the MTU; the result is a false `LEAK`

**Locations:**
- `pcapscan.py:176-185` (`wireguard_length_problem`);
- `test_leak_lab.py:4456` (the case "data not 16n" asserts LEAK);
- `docs/rust-v2/leak-lab.md:805`.

**Mechanism:**
- Both the kernel (`drivers/net/wireguard/send.c: calculate_skb_padding`) and wireguard-go (`calculatePaddingSize`) compute `padded = min(mtu, ALIGN(len, 16))`.
- An inner packet within 15 bytes of the tunnel MTU is therefore padded to exactly the MTU.
- The resulting message length `32 + MTU` violates the rule whenever `MTU % 16 != 0`.

**Probe** (real scanner; random ciphertext, valid header, keepalive in the reverse direction):

```
wg MTU 1280 inner 1280 -> msg 1312 B: PASS
wg MTU 1380 inner 1380 -> msg 1412 B: LEAK findings=1
wg MTU 1420 inner 1420 -> msg 1452 B: LEAK findings=1
wg MTU 1440 inner 1440 -> msg 1472 B: PASS
```

**Effect:**
- A WireGuard interface on a 1500-byte WAN gets MTU 1420 from wg-quick unless the profile sets one, and the lab VM's WAN is 1500. Any full-MSS TCP segment through the tunnel then becomes `allowed_tuple_not_wireguard` and the phase is `LEAK`.
- Such segments are routine: Tailscale's TLS/Noise traffic, a post-quantum ClientHello, and netmap or DERP payloads.
- I could not confirm the guest's `wg0` MTU (that would mean reading the profile or the guest). Expect this on every tunnel-up phase until qualified.
- It fails safe (no false PASS), but it would waste the bring-up and point at a non-existent product leak.

**Fix** (choose one):
- (a) For type 4, require only `len >= 32`. Alignment adds nothing against type-4-shaped plaintext, which passes anyway.
- (b) Accept `(len-32) % 16 == 0` **or** `len-32 == tunnel_mtu`, with `tunnel_mtu` as a policy field taken from the profile or from the guest `wg0` MTU recorded by the runner.

In either case, replace the "data not 16n" test with an MTU-clamp test (1420 and 1380 must PASS), and fix the doc sentence.

### A-N2 (Minor; regression). `stop_capture` waits 0.5 s, not 20 s, before SIGKILL

**Location:** `run_phase.py:789-803`. The `while` loop's `process.wait(timeout=min(0.5, remaining))` raises `TimeoutExpired`, and that exception is caught **outside** the loop. The first 0.5 s slice therefore goes straight to SIGKILL.

**Probe** (fake tcpdump that needs *d* seconds after SIGINT):

| *d* | Result |
|---|---|
| 0.05 s, 0.4 s | rc 0, summary written |
| 0.8 s, 3.0 s | rc -9, `forced_stop True`, **empty stats**, after 0.50 s |

**Effect:**
- Any tcpdump that needs more than 0.5 s to stop — host under memory pressure (debdev's OOM history) or slow I/O — ends INVALID (`tcpdump_exit_status`, stats incomplete).
- Real tcpdump normally exits in milliseconds, so the failure is intermittent, not every phase.
- No test catches it, because the harness uses fake processes.

**Fix:** catch `TimeoutExpired` inside the loop and `continue`. Add a real-child test with an exit delay of about 1 s.

### A-N3 (Minor). Deferred signals can wait for minutes

- `QGAClient.execute` polls with its own sleeps and never calls `check_interrupt()`.
  - PEP 475 retries an interrupted `recv`/`sleep` after a non-raising handler. Probe: a SIGINT at 0.2 s did not end a 3 s `recv`; the flag was raised afterwards.
  - A SIGINT/SIGTERM therefore takes effect only after the current guest command: up to `ACTION_TIMEOUT` 360 s, `SILENCE_TIMEOUT` 180 s, or the cleanup command's 180 s.
- After the first raise, `poweroff_vm` waits its full 180 s.
- A second signal is ignored, and nothing tells the operator.
- In normal operation the delay is at most about 30 s; a hung or hostile guest makes it minutes.
- Last round, the raising handler interrupted the call at once.
- **Fix:**
  - Let the handler `os.write(2, …)` a one-line notice ("signal N received; finishing current guest command (≤360 s), then ordered cleanup — do not SIGKILL").
  - Pass an interrupt callback into `execute`'s poll loop.
- See S-N1 for the safety side.

### A-N4 (Minor; qualify on host). The login-URL allowlist may reject real output

- `LOGIN_URL_RE = /a/[0-9a-f]{8,16}`. Observed Tailscale auth paths are 12–14 lowercase hex characters, so the regex is probably right; confirm on the first login phase.
- Log candidates are cut at whitespace or quotes only. Trailing punctuation (`…/a/abcd1234.` or `)`), or any other `login.tailscale.com/...` link in the last 400 log lines, flags `login_url_unrecognized` when the status JSON has no `AuthURL`. The login phase is then INVALID.
- **Fix:** strip trailing punctuation, and only consider log candidates under `/a/`.

### Nit

`main()` and `run_phase()` both call `install_signal_handlers()`, which resets `_signal_seen`. A signal that arrives between the two calls is dropped.

A signal during the pre-capture work (base-image digest, admission) is first observed only after tcpdump has been spawned. tcpdump is then stopped at once, which is harmless but pointless. Add a `check_interrupt()` before `start_capture`, and install the handlers once.

---

## 4. SAFETY (all Minor)

### S-N1. The longer signal latency makes SIGKILL escalation more likely, and a SIGKILLed runner leaves an **unbounded** tcpdump

- tcpdump and QEMU run in their own sessions. If the root runner is SIGKILLed — by an operator who sees Ctrl-C "ignored" (A-N3), or by a supervisor timeout — the guard thread dies with it.
- tcpdump keeps appending to the evidence pcap on `/var` with **no `RLIMIT_FSIZE`**. Only QEMU got one.
- QEMU keeps running with the tap up.
- SIGKILL orphaning existed before. What is new is that deferral makes the escalation likelier.
- **Fix:**
  - Give tcpdump `RLIMIT_FSIZE = capture cap + 64 KiB` through the same `apply_child_limits` call. A truncated pcap is already INVALID, and with no runner the bound still holds.
  - Consider `setpriv --pdeathsig KILL` for QEMU. Qualify first whether a parent-death signal set *after* the uid change survives into QEMU.
  - Combine with the A-N3 notice.

### S-N2. `provision.py` still raises from its signal handler; the deferred model was applied only to `run_phase.py`

- **Location:** `provision.py:55-68` and `:505-516`. A SIGTERM or SIGINT that lands between fork and the `process = subprocess.Popen(…)` assignment raises inside `Popen.__init__`. That covers, for example, the errpipe `os.read` or a later bytecode in `__init__`.
- The child has been created but no handle is returned.
- `finally: if process is not None` then skips `_terminate`, and the run lock is released.
- The provisioning QEMU keeps running with slirp user networking, bounded only by `RLIMIT_FSIZE` 8 GiB, because the serial-cap loop is gone with the runner.
- `provision.py` also does not clear an inherited mask. This is the round-3 S-1 class.
- The window is tiny, and the provisioning guest is the pinned base image, so Minor.
- **Fix:** reuse the flag/`check_interrupt` model from `run_phase.py`.

### S-N3. Residual login-URL channel (inherent, accept)

The allowlist still lets a hostile guest choose up to 16 hex characters (64 bits) of URL once per login phase, plus a 1-bit "unrecognized" flag. A key needs four or more phases, the URL goes only to root-only evidence and the operator's stderr, and the operator already holds the profile. Document it; no change needed.

### S-N4. `apply_child_limits` swallows every failure

- If `prlimit` fails, QEMU runs without the file-size bound and nothing is recorded. This should not happen as root.
- **Fix:** read back `/proc/<pid>/limits` (AS and FSIZE) into `phase.json` and note an error if the read-back differs.

### Carried (documented skips, still Minor)

S-4 (M1 `/run` capture), S-5 (kill proof uses QEMU-controlled `/proc`), S-6 (`qga.sock` by path). See §1.

---

## 5. DOC (Minor)

- **D-1.** `leak-lab-vm.md:379` ("SIGINT tcpdump and wait for its summary") and the `timeout=20.0` default overstate the graceful window: the real window is 0.5 s (A-N2).
- **D-2.** `leak-lab-vm.md:737-749` says "Every blocking wait/loop calls `check_interrupt()`". This is not true for `QGAClient.execute` (up to 360 s), the scanner run (up to 300 s), or the waits after the first raise. Document the worst-case latency and the "do not SIGKILL" instruction (A-N3 / S-N1).
- **D-3.** `leak-lab-vm.md:723-724`: say `resource.prlimit()` (syscall), not "`prlimit`". No util-linux binary is involved.
- **D-4.** `leak-lab.md:805` states the wrong type-4 rule (A-N1). Also state explicitly that type-4-shaped plaintext on the tuple passes; that is the inherent limit.
- **D-5.** `phase.json` `pcapscan_argv` is the inner scanner argv. Mention that the scanner runs under the 1 GiB `-I` wrapper, or record the wrapper argv.
- **D-6.** `leak-lab-vm.md:700-702` (provision handlers "route into terminate+reap") omits the raise-during-spawn window (S-N2).

## 6. Reproducer index (offline; scratch deleted)

| ID | Probe | Observed |
|---|---|---|
| MASK | caller-blocked mask → `install_signal_handlers` → real `start_capture` child | runner and child `SigBlk 0`; SIGINT → rc 0 with summary |
| STOP | fake tcpdump exit delay 0.05/0.4/0.8/3.0 s | 0/0/**-9 forced**/**-9 forced** at 0.50 s (A-N2) |
| LIM | `/proc/<child>/limits` | AS unlimited; scanner wrapper AS 1 GiB, argv kept |
| SIG | SIGTERM during readiness, guard running | `PhaseInterrupted`, 0 live children |
| LAT | SIGINT during a 3 s `recv` | returned at 3.00 s; raised afterwards (A-N3) |
| GKILL | guard size breach with a verified "QEMU" | tap isolated (recorded), QEMU rc -9 |
| REAPED | `kill_qemu` on a reaped Popen | True, no signal |
| LIVE | fake tcpdump dies early | `capture_ended_early`, tap isolated, QEMU kept; `stop_capture` sends nothing |
| GPT-S1/S2/S4/S5 | GPT scripts adapted | INVALID `capture_ended_early` / no URL write + `login_url_unrecognized` / LEAK `allowed_tuple_not_wireguard` / all refused |
| R3-S2/S3/S5/A2 | stale netplan / chain link / execv child / split QGA frame | refused / refused / not killed (carry) / OK |
| ADM | state filesystem with 3 GiB free | refused |
| MTU | type-4 with MTU-clamped padding, MTU 1280/1380/1420/1440 | PASS / **LEAK** / **LEAK** / PASS (A-N1) |
