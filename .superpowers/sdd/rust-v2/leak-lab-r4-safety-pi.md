# Leak-lab round-4 focused SAFETY gate review (pi)

- **Commit:** `0097e78059ffc44cee8c925ab1f950acc43b48a5`
  (`fix(leak-lab): combined r3 — deferred signals, capture liveness, WireGuard shape check, no test-boot serial file, injection-safe generators`).
  The worktree was clean before and after; the only repository file written is this
  report (`.superpowers/` is Git-ignored).
- **Scope:** `tools/leak-lab/**` and `docs/rust-v2/leak-lab*.md` at that commit,
  with emphasis on the fix diff, plus re-runs of every Important finding in
  `.superpowers/sdd/rust-v2/leak-lab-combined-rereview3-{pi,gpt,opus}.md`.
- **Method:** offline only. Real `run_phase()` through the suite harness, real
  `pcapscan`/`policy` code, real `hostcopy`/`rootfs` writer code, real child
  processes (`sleep`, Python) for `/proc`, signal, limit and kill probes.
  I decompressed the loaded kernel's `wireguard.ko` into scratch and read its
  disassembly (no code executed) to settle the padding question. I read
  `/opt/vprouter/current/host/orchestrate.py` read-only (the release, not
  configuration or keys).
- **Constraints honoured:** no sudo, QEMU, tcpdump, `ip`, `nft`, `iptables`,
  docker, useradd or network execution. I read no `/etc/vprouter`,
  `/DATA/AppData/vprouter/conf`, `*.zip`, `/var/lib/vprouter` or key material.
  `/DATA/vprouter-lab/lab-tools/root` was listed/read as a tool tree (metadata
  and file paths only). Scratch `/var/tmp/leaklab-r4-pi` was deleted after the
  probes.

## Test suites

```
$ TMPDIR=/var/tmp/leaklab-r4-pi/tmp PYTHONDONTWRITEBYTECODE=1 \
  python3 -B -W error -m unittest discover -s tools/leak-lab -p test_leak_lab.py
Ran 254 tests in 7.800s   OK
$ TMPDIR=... PYTHONDONTWRITEBYTECODE=1 \
  python3 -B -W error -m unittest discover -s tools/leak-lab/vm -p 'test_*.py'
Ran 188 tests in 5.506s   OK
```

**254/254 M1 and 188/188 M2, 442 total, no failures/errors/skips.** Both suites
were run twice (start and end of the review) with identical results. A PASS here
is still not runtime evidence (see §2.8).

## Verdict

**PASS on the SAFETY gate — 0 Critical, 0 Important SAFETY.** All round-3
Important findings are closed by their reproducers. No new false-PASS, secret
exfiltration or guest-driven host-resource path at Important level was found.

**But this is not a green light for the supervised bring-up.** Two **Important
AVAILABILITY** items will waste or block it, and both are new in this commit:

| ID | Class | Severity | Effect |
|---|---|---|---|
| **A-0** | false `LEAK` from the new WireGuard type-4 length rule when padding is clamped to the tunnel MTU | Important AVAILABILITY | every tunnel-up phase that carries a full-size inner packet reports a product leak that does not exist |
| **A-1** | `hostcopy.verify_tree`'s new extra-destination-entry check vs. the nested `LEAKLAB_ROOT` | Important AVAILABILITY | a second `hostsetup.py setup` (and therefore the re-install this commit requires) fails; every live phase then refuses on the stale installed scanner |

Neither is a safety defect (both fail closed), so the SAFETY verdict is PASS; but
A-0 and A-1 must be resolved or explicitly worked around before the first phase.
The remaining items are Minor SAFETY / AVAILABILITY / DOC.

| Category | Critical | Important | Minor |
|---|---|---|---|
| SAFETY | 0 | 0 | 8 (2 new/residual, 6 carried/documented) |
| AVAILABILITY | 0 | **2** (A-0, A-1) | 5 |
| DOC | — | — | 8 |

---

## 1. Round-3 finding closure (reproducers re-run at `0097e78`)

### 1.1 pi round-3

| Prior finding | Reproducer re-run | Result |
|---|---|---|
| **S-1** guest-driven `serial.log` growth on test boots | `guest.build_qemu_argv("test", "/s")`; `build_qemu_argv("provision", ...)`; `apply_child_limits` on a real child | `-serial none` for test boots, `file:/s/serial.log` for provision only; `serial.log` never appears in a test argv; QEMU child gets `Max file size 6442450944`. **CLOSED** (provision residuals §2.7/§3.6). |
| **S-2** admission ignores the state filesystem / overlay | `check_admission(..., state_root=...)` with `state_free_bytes` below/at 4 GiB + 1 GiB | refused below, accepted at the floor; `state.parent` is passed from `_run_phase_locked`. **CLOSED**. |
| **S-3** `hostcopy` hardlinks / unanchored walk / extra destination entries | real `hostcopy.copy_tree`/`verify_tree` | hardlinked source copied as independent inode (`st_nlink 2 -> 1`); chained link `a/b/s -> ../../top`, `a/b/k -> s/../..` refused on **source and destination**; extra file reported; empty dir not misreported. Path walk still by path — **documented skip** (unchanged). |
| **S-4** `qga.sock` by path; teardown tap check | code read | unchanged, **documented skip** (round-3 S-4). |
| **A-1** QGA `_scan_from` skips a split `0xFF` marker | real `FakeQGAServer(sync_split_at=cut)` for **every** cut 0..15 | all splits OK. **CLOSED**. |
| **A-2** suite patched `CAPTURE_WATCH_INTERVAL`, default bound at definition time | `CaptureGuard(...)` under a 0.01 module patch | `guard.interval == 0.01`. **CLOSED**. |
| **A-3/A-4/A-5** live gates (tcpdump drop-priv, `check_elf_deps`, QEMU/KVM/tap) | not runnable offline | unchanged, **live gates** (§2.8). |

### 1.2 GPT round-3 (S1-S5)

| Prior finding | Reproducer | Result |
|---|---|---|
| **S1** capture can exit before QEMU poweroff and still PASS | real `run_phase()` harness: capture dies during the setup QGA call; also a capture that dies after QEMU exit | `exit 2`, `INVALID`, `errors ["capture_ended_early"]`, `capture_alive_before_stop false`, `capture_ended_early_at` recorded, `isolate_tap` called, scan still runs. **CLOSED**. |
| **S2** login URL is an arbitrary secret channel | real `login_phase_wait` with `AuthURL = /a/<key-shaped>`; 4-phase chunk probe | invalid shape: nothing written, `login_url_unrecognized`, INVALID, nothing on stderr. Full 32-byte key needs 4 phases of 16 hex — residual channel §3.5. **CLOSED to a bounded residual**. |
| **S3** host disk exhaustion from serial/overlay/logs | argv, admission, real-child limits, guard kill | test serial gone; state admission 5 GiB; evidence admission 3 GiB; QEMU fsize 6 GiB; guard breach SIGKILLs our QEMU (real child, rc -9) and leaves a bystander alive. **CLOSED for the phase runner**; provision residuals §2.7/§3.6. |
| **S4** arbitrary UDP payload on the allowed tuple certified PASS | 401 fixed-length cases × 3 types, 197 type-4 lengths, fragment cases, fragments of a valid message | plaintext → `LEAK allowed_tuple_not_wireguard` (both directions); types 1/2/3 exact lengths 148/92/64 pass; type-4 `>=32, (len-16)%16==0` pass; bad type/reserved/length fail; fragmented plaintext and bad-length fail; genuine 148 fragmented pass; 8-byte-first fragment fails closed. **CLOSED for non-WireGuard-shaped payloads**; the inherent type-4-shaped-plaintext limit remains, and a *new* false-LEAK bug in the same rule is A-0. |
| **S5** filename arguments become shell code | the original two payloads plus `;`, backtick, `..`, trailing quote, whitespace on both generators | all refused (`LayoutError`/`NetplanError`); rendered scripts pass `sh -n`; valid capture line is `-w "$RUN_DIR"/'manual-capture.pcap'`. **CLOSED**. |

### 1.3 Opus round-3 (A-1..A-4, S-1..S-7)

| Prior finding | Reproducer | Result |
|---|---|---|
| **A-1** children inherit a blocked SIGINT/SIGTERM/SIGHUP mask | real child spawned after `install_signal_handlers()` | `SigBlk 0000000000000000`, no terminal signals in `SigIgn`, `SIGINT` → exit -2. **CLOSED**. |
| **A-2** QGA split marker (same as pi A-1) | all cut positions | **CLOSED**. |
| **A-3** runner `RLIMIT_AS` 2 GiB inherited by children | real child with runner AS set to 2 GiB, then `apply_child_limits` | before: `2147483648`; after: `unlimited`; fsize `6442450944`. **CLOSED**. |
| **A-4** `preexec_fn` while the guard thread lives | `scan_evidence` spy | scanner launched as `python -I -c <wrapper> <limit> …`, **no `preexec_fn`**, inner argv preserved, child `RLIMIT_AS` 1 GiB, real 4-record scan PASS with matching hashes. **CLOSED**. |
| **S-1** guard thread defeats `block_termination_signals()` | real guard thread + external SIGTERM; deterministic signal *inside* the `popen()` wrapper | handler only sets a flag (`guard` still alive, no raise in the thread); main thread raises at the first checkpoint; **no orphaned child** (the round-3 failure) — the capture handle is assigned and `stop_capture` reaps it. **CLOSED**. |
| **S-2** only `pcapscan.py` was bound to the repo | installed copy with a stale listed `netplan.py` | refused: `installed netplan.py differs from the repository copy`; `phase.json` records `scanner.{path,source,certifiable,manifest_sha256}`. A **stale module omitted from the manifest is still accepted** (§4 D-4). **CLOSED for the installed manifest**; residual Minor. |
| **S-3** lexical-only link confinement | chained links | refused with `… resolves outside the copied tree`; real source tree: 1 857 files, 157 links, **0** realpath escapes. **CLOSED**. |
| **S-5** kill proof uses QEMU-controlled `/proc` | real child, `execv` to `sleep` | `kill_qemu → False`, child stays alive; verified child → killed (rc -9). Carried, **documented skip**; the guard's new kill inherits the proof (with the concurrent-reap nit §3.3). |
| **S-6** `qga.sock` by path | code read | unchanged, **documented skip**. |
| **S-7** serial/qemu.log unbounded, breach does not stop QEMU | `-serial none`; real guard + real "QEMU" | test serial `none`; breach (`capture_size_cap`) → `isolate_tap` + verified QEMU SIGKILL (rc -9), `kill_error None`, bystander untouched. **CLOSED** for the phase runner. |

Also re-checked: `hostsetup` no longer creates `vm-NNN`; the stubbed setup→`provision.create_state_directory` path passes; a `capture_size_cap` still scans and keeps LEAK precedence; QGA 16 MiB/4 MiB caps; `BackendState` fixed vocabulary; tcpdump argv/stats binding; real-scanner argv hash (`capture_argv_sha256` equals the file bytes' SHA-256, canonical hash separate).

---

## 2. New-code review (the fix round)

### 2.1 A-0 — Important AVAILABILITY: the type-4 rule rejects real MTU-clamped WireGuard packets, producing a false `LEAK`

**Files:** `tools/leak-lab/pcapscan.py:196-205` (`wireguard_length_problem`),
`:1222-1245` and `:1050-1070` (fragment completion), `docs/rust-v2/leak-lab.md:801-810`.

**Why the rule is wrong:** WireGuard pads the plaintext to 16 bytes **only up to
the tunnel MTU**. The kernel computes
`padded = min(ALIGN(len, 16), mtu)`; when the inner packet is within 15 bytes of
the MTU, the message length is `16 + 16 + mtu`, which is not 16-aligned whenever
`mtu % 16 != 0`. I settled this from the loaded `wireguard.ko` (6.12.107,
read-only, decompressed to scratch):

- `encrypt_packet` @0x4d00: `lea 0xf(%rdx),%ebp; and $0xfffffff0,%ebp;
  cmp %ecx,%ebp; cmova %ecx,%ebp; sub %edx,%ebp` → `padding = min(ALIGN(len,16), mtu) - len`.
- the `mtu` stored in the skb is `dev->mtu`: `wg_xmit` @0x2ec3
  `mov 0x38(%dev),%r15d` → @0x2f5a `mov %r15d,0x3c(%skb)`, read back at
  `encrypt_packet` @0x4d55 `mov 0x3c(%rbx),%ecx`; `wg_packet_send_keepalive`
  @0x5f2f/0x5f32 does the same for the keepalive skb. The kernel BTF confirms
  `net_device.mtu` is at 0x38 (BTF: `net_device` size 2560, `mtu` byte 0x38;
  `sk_buff` size 232, `cb` byte 0x28), so skb+0x3c is the MTU carried in the cb.
- wireguard-go's `CalculatePaddingSize` has the same `if paddedSize > mtu` clamp.
  The outer IP packet can exceed the WAN MTU, in which case the kernel fragments
  it (upstream passes `df=0`); the scanner reassembles it and applies the length
  rule to the reassembled UDP payload — my fragmented probe below reproduces
  exactly that.

**The lab's outer interface is 1500, not a multiple of 16.** The release creates
it as `in_netns(transport_pid, "ip", "link", "add", "wg0", "type", "wireguard")`
(`/opt/vprouter/current/host/orchestrate.py:341`) and never sets an MTU; a kernel
WireGuard device defaults to `ETH_DATA_LEN` 1500. `wg setconf` does not set the
link MTU. A 1420 profile (wg-quick default) has the same problem; only a
multiple of 16 (e.g. Tailscale's own 1280 tun) is safe.

**Reproducer (real `pcapscan` code, `make_policy(allow_arp=False)`):**

```
mtu 1280: inner 1280 -> msg 1312 -> PASS
mtu 1380: inner 1380 -> msg 1412 -> LEAK
mtu 1420: inner 1420 -> msg 1452 -> LEAK
mtu 1420: inner 1419 / 1412 -> 1452 -> LEAK
mtu 1420: inner 1405 -> padded 1408 -> 1440 -> PASS
mtu 1500: inner 1500 -> msg 1532 -> LEAK
mtu 1500: inner 1499 / 1492 -> 1532 -> LEAK
mtu 1500: inner 1485 -> padded 1488 -> 1520 -> PASS
fragmented 1532-byte transport message (first fragment 1480) -> LEAK
```

Only lengths in `[mtu-15, mtu]` fail, and a full-size TCP segment is exactly
`mtu`, so one full-size inner packet through the outer tunnel is enough. This
will be reported as `allowed_tuple_not_wireguard` and the phase as **LEAK** —
not INVALID, and not a real product leak. It is fail-closed (no false PASS), but
it would waste the supervised bring-up and point at a non-existent leak.

**Suggested fix:** for type 4, accept `len >= 32 && (len - 32) % 16 == 0 ||
len <= 32 + tunnel_mtu` (with the MTU as a policy field or the lab's fixed WAN
MTU). At minimum: `len >= 32` and the type/reserved bytes; alignment adds
nothing against type-4-shaped plaintext, which passes anyway. Add tests at 1380,
1420, 1500 and the fragmented form; the current suite only covers 32/48/64-byte
messages. Fix the doc sentence at `leak-lab.md:805`.

### 2.2 A-1 — Important AVAILABILITY: a second `hostsetup.py setup` fails, so the re-install this commit requires cannot be done

**Files:** `tools/leak-lab/vm/hostcopy.py:690-714` (new extra-destination-entry
check), `tools/leak-lab/vm/hostsetup.py:456` ("Re-running setup is safe"),
`:464/:570` (`LEAKLAB_ROOT = "$TOOLS_ROOT/leaklab"` created *inside* the tools
root), `:584-587` (tools copy + `verify_manifest`), `:595-598` (leaklab copy).

**Mechanism:** `verify_tree` now walks the whole destination and reports any
file that neither manifest lists. The tools destination `/opt/vprlab-tools`
contains the separately installed `/opt/vprlab-tools/leaklab/**` tree from the
previous run. Those files are not in the **tools** manifest, so the second
run's tools verification reports `leaklab/vm/runlock.py is an extra destination
entry` (sorted order varies) and `set -eu` aborts — before the leaklab copy
refreshes anything.

**Reproducer (rendered plan, stubbed privileges, completed tool tree):**

```
run 1: rc=0  vprlab: host layout ready; provision.py creates vm-NNN as the QEMU user
run 2: rc=1  vprlab: leaklab/vm/runlock.py is an extra destination entry
        # documented teardown, then setup again
        rc=0  host layout ready
run 3: rc=1  vprlab: leaklab/vm/runlock.py is an extra destination entry
```

Differential: the **same probe at the parent commit `79a5bd5`** (old
`hostsetup.py`/`hostcopy.py`, same source tree) runs 1/2/3 all `rc=0`. The
regression is the new extra-entry check, not the stub harness.

**Why it blocks the bring-up:** this commit's `resolve_pcapscan` now compares
**every** installed manifest file with the repository
(`run_phase.py:295-344`). On a host where hostsetup ran before this commit, the
installed `vm/run_phase.py` etc. differ, so every phase refuses
(`installed vm/run_phase.py differs from the repository copy`) until setup is
re-run. Setup is now the thing that fails. Workaround: the documented
`sh /root/vprlab-hostsetup.sh teardown` first (it removes `$TOOLS_ROOT`
entirely; the test suite verifies that) and then setup. `hostsetup.py --check`
does not detect this, because it inspects the layout inventory, not the copy
manifests.

**Suggested fix:** in the generated setup script, `rm -rf -- "$LEAKLAB_ROOT"`
before the tools copy/verify (after the ancestry checks and under the lock), or
teach `verify_tree`/the tools verify an `ignore` root (`$LEAKLAB_ROOT`). A
`__pycache__` left under the installed leaklab tree (e.g. running the installed
modules without `-B`) is reported the same way and is worth ignoring explicitly.

### 2.3 A-2 — Minor AVAILABILITY (regression): `stop_capture(timeout=20)` SIGKILLs tcpdump after 0.5 s

`run_phase.py:791-809`: `process.wait(timeout=min(0.5, remaining))` raises
`TimeoutExpired`, which is caught **outside** the loop, so the first 0.5 s slice
goes straight to `killpg(SIGKILL)`; the 20 s deadline never applies. Reproducer
with a real Python "tcpdump" that sleeps `d` after SIGINT:

```
d=0.05 -> rc 0, forced False, 0.06 s
d=0.4  -> rc 0, forced False, 0.41 s
d=0.8  -> rc -9, forced True, 0.50 s
d=1.5  -> rc -9, forced True, 0.50 s
```

Real tcpdump normally exits in milliseconds, so this is Minor, but on a loaded
host it turns a clean stop into `tcpdump_exit_status -9` and an empty stats file
→ INVALID. Fix: catch `TimeoutExpired` inside the loop and continue (or just
`process.wait(timeout=timeout)`), and add a real-child test with a ~1 s exit
delay.

### 2.4 A-3 — Minor AVAILABILITY: a deferred signal can take minutes

The handler only sets a flag, and `QGAClient.execute` polls its own socket
without `check_interrupt()`; PEP 475 retries the interrupted syscall after the
non-raising handler. A SIGINT/SIGTERM during a guest command is observed only
after it returns: up to 360 s (`ACTION_TIMEOUT`), 180 s (`SILENCE_TIMEOUT`) or
the 180 s poweroff wait. The documentation says "Every blocking wait/loop calls
`check_interrupt()`" — true at loop granularity, not for a single QGA call.
A second signal is ignored by design; the operator gets no notice and may
escalate to SIGKILL (see §3.2). Consider a one-line stderr notice from the
handler ("signal N received; finishing the current guest command (≤360 s),
then ordered cleanup — do not SIGKILL") and/or an interrupt callback in
`execute`'s poll loop.

### 2.5 A-4 — Minor AVAILABILITY: one startup signal can be swallowed

`main()` installs the handlers (`run_phase.py:3290`), then `run_phase()` calls
`install_signal_handlers()` again (`:2552`), which resets `_signal_seen`. A
SIGTERM in that window (through `set_runner_limits()` and the argument checks)
is recorded and then forgotten; the phase proceeds for up to an hour. The next
signal works. Fix: install once, or only reset the flags at process start.

### 2.6 A-5 — Minor AVAILABILITY: `_valid_path` is stricter than the CLI suggests

`hostsetup._valid_path` accepts only `[A-Za-z0-9._-]` components, and rejects a
trailing slash (`/opt/vprlab-tools/` → empty component → `LayoutError`) even
though `tools_root.rstrip("/")` is done immediately afterwards. A checkout or
source path containing `+` or a space now fails setup. The defaults are safe
(`/DATA/vprouter-lab/...`, `/opt/vprlab-tools`), so this is a portability nit;
document the restriction or normalise/allow a trailing slash.

### 2.7 A-6 — Minor AVAILABILITY: provision serial cap is only polled until the marker

`provision.py:294-339` checks `SERIAL_SIZE_CAP` (64 MiB) only inside
`_wait_for_marker`; after the marker, `process.wait(timeout=180)`
(`:525-529`) has no serial or free-space monitor. An untrusted/broken base
image that prints the marker early and then floods the console can write up to
the 8 GiB `RLIMIT_FSIZE` (`:43-44`, `_apply_qemu_limits`) and fill the
8 GiB-admitted state filesystem (`PROVISION_DISK_REQUIRED`). The phase runner is
not affected. Poll the serial size during the poweroff wait too (and/or admit on
aggregate staging bytes; see §3.6).

### 2.8 Live gates (qualify on debdev, unchanged or new)

1. **Guest `wg0` MTU.** `ip link add wg0 type wireguard` without an MTU → 1500
   (or a 1420 profile) → A-0. Confirm the MTU on the first boot **and** fix the
   rule.
2. **`-serial none`.** Test boots no longer expose `ttyS0`. The guest scripts
   only write it in provision mode and guard with `[ -w /dev/ttyS0 ]`, but the
   base image's boot/GRUB/getty behaviour without a serial device is unverified
   offline. Confirm a test boot reaches QGA.
3. **Login URL shape.** `[0-9a-f]{8,16}` (12-14 hex is the observed Tailscale
   form). Log candidates are cut only at whitespace/quotes, so trailing
   punctuation or an unrelated `login.tailscale.com` link can make the login
   phase INVALID via `login_url_unrecognized`.
4. **Re-run hostsetup after this commit** (A-1 workaround/teardown), otherwise
   `resolve_pcapscan` refuses every phase on a stale install.
5. Debian tcpdump drop-priv/AppArmor order; `hostcopy.check_elf_deps` on the
   real staged binaries; QEMU/KVM/tap; Docker/Tailscale READY/exit-node —
   unchanged round-3/4 live gates.

---

## 3. SAFETY (all Minor; nothing Critical/Important)

### 3.1 S-1 — `provision.py` still has the raising signal handler (pre-existing; not converted by this round)

`provision.install_signal_handlers` (`:55-68`) raises `ProvisionInterrupted`
from the handler, while the QEMU `Popen` (`:507`) is inline in the `try` whose
`finally` only reaps when `process is not None`. A signal that lands inside
`Popen` (errpipe read, later `__init__` bytecodes) raises before the handle is
assigned; the child is orphaned and the run lock is released. I reproduced the
**code shape** deterministically (signal sent from inside a `popen()` wrapper:
`handle None`, `orphaned [pid]`), while the same shape in `run_phase` is closed
by the deferred model (no orphan). The provisioning guest is the pinned base
image with slirp-only networking and an 8 GiB fsize bound, so the host impact is
bounded; the window is tiny. Minor / pre-existing. Fix: reuse the
flag/`check_interrupt` model in provision.

### 3.2 S-2 — a SIGKILLed runner leaves tcpdump unbounded (newly more likely)

`start_capture` applies only `address_space=RLIM_INFINITY`
(`run_phase.py:741-743`); tcpdump never gets `RLIMIT_FSIZE` (verified: a
tcpdump-like child shows `Max file size unlimited`). tcpdump runs in its own
session, so if the runner is SIGKILLed the guard dies and tcpdump keeps
appending to the evidence pcap with no byte bound. The pcap cap is only enforced
by the guard thread. This hole predates the commit, but the deferred signals
(§2.4) make an operator SIGKILL — or a supervisor timeout — much more likely
when Ctrl-C appears ignored. Fix (cheap, worth doing before the bring-up):
pass `file_size = capture_size_cap + 64 KiB` to `apply_child_limits` in
`start_capture` (a `SIGXFSZ`/truncated pcap is already INVALID), and consider
`--pdeathsig`/cgroup handling for QEMU.

### 3.3 S-3 — guard SIGKILL: no practical non-QEMU target; the only gap is a PID-reuse TOCTOU after a concurrent reap

Direct answer to the question: **it cannot kill an unrelated process in normal
operation.**

- `kill_qemu` signals only `process.pid` and its process group; `process` is our
  own unreaped `Popen`. QEMU was spawned with `start_new_session=True`, so its
  pgid is its own pid; `setpgid` cannot join another session, so `killpg` is
  confined to QEMU and its own descendants.
- It returns before any signal when `poll()` says the child is gone; a process
  whose `/proc/<pid>/exe` is not the staged `guest.QEMU` is never signalled
  (`kill-other-binary → False, alive True`; `kill-bystander-still-alive: True`).
- The verified child is killed (`rc -9`) and the guard's breach does exactly
  that; a reaped `Popen` returns `True` without signalling.

Residual: GPT's r4 N1 interleaving is real at the code level — between the
`/proc/<pid>` identity read and `os.getpgid(pid)`, the main thread can reap the
child, and a **reused** pid would make `getpgid`/`killpg` name an unrelated
group. GPT's probe mocks `getpgid` to model the recycle; it does not show
reachability. On this host `pid_max = 4194304`, and the window is a few
microseconds, so a wrap to that exact pid in that window is not practically
reachable; if the pid is reaped and *not* recycled, `getpgid` gets `ESRCH` and
no signal is sent. I therefore rate GPT's Important N1 **Minor** (harden with a
retained `pidfd_open` at spawn + `pidfd_send_signal`, or a lock serialising
reap/identity/signal). The same binary-path proof caveat (a QEMU that
`execve`s another binary escapes the guard kill) is the round-3 S-5 documented
skip.

### 3.4 S-4 — `apply_child_limits` / `_apply_qemu_limits` swallow every failure

`run_phase.py:182-211` catches `(OSError, ValueError)` and continues; a failed
`resource.prlimit` (no `CAP_SYS_RESOURCE`, externally lower hard limit) silently
leaves QEMU without the new file-size bound, and nothing is recorded.
`provision._apply_qemu_limits` returns on the first `PermissionError`, skipping
the fsize operation. As root this is implausible, but a mandatory safety bound
should not disappear silently: read back `/proc/<pid>/limits` into `phase.json`
and note `limits_not_applied` if AS/FSIZE differ from the requested values.

### 3.5 S-5 — residual login-URL channel: 64 guest-selected bits per login phase

The fixed shape accepts any 16 hex characters (`login_url.py:30-52`), and
`login_phase_wait` writes and prints them (`run_phase.py:1570-1576`). Four
synthetic login phases with `0001020304050607`, `08090a0b0c0d0e0f`, … recover
`bytes(range(32))` from both `login-url.txt` in four evidence dirs and the
four stderr lines. This is the guest's *own* key, the URLs are visually
anomalous, the file is root-only 0600, and the host operator already holds the
profile, so I rate it **Minor** (GPT rates it Important). It is nevertheless a
real, bounded declassification: the doc's "stops a guest from using the URL path
as an arbitrary secret-encoding channel" should say "bounded to one 64-bit
token per login phase" and the gate owner should explicitly accept it (or stop
forwarding unauthenticated guest URLs). No single-URL/full-key channel remains.

### 3.6 S-6 — aggregate provisioning disk use (GPT r4-S3)

`provision` admits a fixed 8 GiB (`:147-157`) and bounds each file at 8 GiB, not
their sum: staging image + release copies, payload ISO, 4 GiB overlay,
`serial.log` (see §2.7), `qemu.log` and seed ISO can exceed the admitted free
space. The provisioning guest is the operator-pinned base image with a
user-mode netdev, so I rate this **Minor** rather than GPT's Important; the
untrusted router guest is only run by the phase runner, whose bounds are
admitted separately. Fix: admit on `staged bytes + ISO + overlay + log budgets`
and add a continuous free-space/serial guard through QEMU exit.

### 3.7 S-7 — qemu.log can transiently exceed the evidence admission; a failed guard kill is not retried

Test QEMU has `RLIMIT_FSIZE 6 GiB`, but the evidence filesystem is admitted for
`capture_cap + 1 GiB` (3 GiB default) and `qemu.log` lives there. The binding
bound is the guard's 1 GiB free floor + the new SIGKILL, so the evidence
filesystem is not exhausted permanently, but a hostile QEMU can drive it down to
the floor (poll lag) before dying. Also, `kill_qemu` returns `False` when the
proof fails (e.g. the first microseconds before `setpriv` execs, or a QEMU that
`execve`d away) and `_breach` neither records nor retries that: the guard never
re-attempts, so QEMU keeps writing until the main thread's next checkpoint /
`poweroff_vm`. Minuscule window, already INVALID; record the failed kill and
retry at the next guard tick.

### 3.8 S-8 — carried documented Minors (unchanged)

QEMU kill proof reads QEMU-controlled `/proc` (execve escape); guard kill during
the `setpriv` pre-exec window returns False; `qga.sock` connected by path in the
QEMU-owned state dir; `hostcopy` walks the operator-owned source by path without
`openat` anchoring (leaf swaps, link chains, hardlinks and extra entries are now
covered); M1 manual capture still defaults under `/run/vprlab` with no bound
(M2 never starts it). All fail closed and are listed in the docs' "Skipped
Minors".

**Not counted as new (inherent limit, per the review brief):** a plaintext
payload that starts with `0x04 00 00 00` and has a valid type-4 length passes
(`32/48/64/192-byte` bodies → PASS). The monitor cannot authenticate ciphertext.
The doc should state this explicitly next to the failed "stops a plaintext
payload" sentence.

---

## 4. DOC

- **D-1 (important).** `docs/rust-v2/leak-lab.md:801-810`: the type-4 rule
  `(length - 16) % 16 == 0` is **wrong** for MTU-clamped WireGuard (A-0). State
  the clamp and the accepted lengths.
- **D-2 (important).** `hostsetup.py:456` / the generated script's
  "Re-running setup is safe" is false after this commit (A-1). Also document
  that `--check` does not run the copy manifests.
- **D-3.** `leak-lab-vm.md:716-719`: `serial.log` is "capped at 64 MiB in
  provision (kill QEMU and fail)" — the cap is only polled during the marker
  wait; afterwards the 8 GiB per-file limit is the bound (§2.7).
- **D-4.** `leak-lab-vm.md:84`: "compares every manifest-listed file (the
  scanner and all modules it can import)" — the comparison is manifest-driven;
  an installed module omitted from the manifest is accepted (probe:
  stale-unlisted `netplan.py` → ACCEPTED). After a normal hostsetup the manifest
  lists all `LEAK_LAB_FILES`, so this is a doc precision issue.
- **D-5.** `leak-lab-vm.md:737-749`: "Every blocking wait/loop calls
  `check_interrupt()`" — a single `QGAClient.execute` (up to 360 s), the
  scanner run (300 s) and the waits after the first raise are not checkpoints
  (§2.4). Document the latency and the "do not SIGKILL" instruction.
- **D-6.** `hostcopy.py` docstring/`verify_tree`: "reports any destination entry
  that neither manifest lists" — plain empty directories are not reported
  (verified). Say "file or symlinked directory".
- **D-7.** `phase.json` `pcapscan_argv` is the inner scanner argv; the `-I`
  wrapper/1 GiB limit is not recorded (§1.3 A-4).
- **D-8.** `leak-lab-vm.md:744-749` ("subsequent signals during cleanup are
  ignored") needs the "do not SIGKILL; the guard/children are still bounded by
  X" caveat (§3.2); and `_valid_path`'s `[A-Za-z0-9._-]`, ≤64-char component
  restriction (no trailing slash, spaces or `+`) is undocumented (§2.6).

---

## 5. What held (no finding)

- **Signal model:** handler sets a flag only; `SigBlk` is 0 in the main thread,
  the guard thread and a spawned tcpdump-like child; SIGINT terminates the child
  (-2); a deterministic signal inside the `popen()` wrapper leaves no orphan;
  `check_interrupt` raises once, cleanup checkpoints stay silent; `wait_process`
  honours signals in 0.5 s slices.
- **Capture liveness:** guard detects a mid-phase capture exit within its poll
  interval, records `capture_ended_early_at`, isolates the tap and does not kill
  QEMU; the end-of-phase `capture_alive_before_stop` catches a post-QEMU exit;
  `mark_capture_stopping` prevents a false positive on the normal SIGINT stop.
- **`-serial none`, admission, fsize:** test argv has no serial file; provision
  uses the file; state admission 4 GiB + 1 GiB (below refused, floor accepted);
  evidence admission cap + 1 GiB; QEMU fsize 6 GiB; provision 8 GiB.
- **Guard SIGKILL scope:** verified child killed (rc -9), different-binary child
  not killed, bystander alive, reaped handle returns without signalling.
- **WireGuard shape:** 3 × 201 fixed-length cases and 197 type-4 lengths have no
  anomalies other than A-0; controls on the separate sink tuple are unaffected;
  fragments fail closed on missing header/length.
- **Injection-safe generators:** all six hostsetup and six netplan payloads in the probe
  refused; valid scripts `sh -n` clean; `-w "$RUN_DIR"/'manual-capture.pcap'`.
- **Scanner wrapper:** `python -I -c <fixed> <1 GiB> <argv…>` → `execv`, argv and
  `pass_fds` preserved, no `preexec_fn`, real scan PASS with all four hashes
  matching.
- **hostcopy:** chained-link escape refused on source and destination; confined
  link preserved/verified; hardlink independent; extra file reported; empty dir
  not misreported; real tool tree 157/157 links confined.
- **QGA:** every sync-marker split position works; 16 MiB reply/4 MiB exec caps
  and the error-class allowlist are unchanged and tested.
- **Real scanner contract:** 4-record clean capture → exit 0/PASS/`problems []`
  with `capture_argv_sha256` equal to the argv file's SHA-256 and a separate
  canonical hash; DNS frame → exit 1/LEAK.

## 6. Reproducer index (offline; scratch `/var/tmp/leaklab-r4-pi` deleted)

| ID | Probe | Observed |
|---|---|---|
| A-0 | `pcapscan` type-4 lengths for MTU 1280/1380/1420/1500; fragmented 1532 | PASS / LEAK / LEAK / LEAK; fragmented LEAK |
| A-0 kernel | `wireguard.ko` 6.12.107 disassembly `encrypt_packet`/`wg_packet_send_keepalive`; `/opt/vprouter/current/host/orchestrate.py:341` | `padding = min(ALIGN(len,16), dev->mtu) - len`; `ip link add wg0 type wireguard` without MTU |
| A-1 | rendered hostsetup, stubbed privileges, complete tree, 3 runs; teardown between; parent commit differential | run 1 rc 0; run 2 rc 1 `leaklab/vm/runlock.py is an extra destination entry`; teardown+setup rc 0; next rc 1; `79a5bd5` all rc 0 |
| A-2 | real Python "tcpdump" with SIGINT delay 0.05/0.4/0.8/1.5 s, `stop_capture(timeout=20)` | 0 / 0 / -9 forced at 0.50 s / -9 forced at 0.50 s |
| A-3 | SIGINT during a 3 s `recv` | handler flag set, return at 3.0 s, raise afterwards |
| A-4 | two `install_signal_handlers()` calls | `_signal_seen` reset |
| A-5 | `render_setup_script(tools_root="/opt/vprlab-tools/")`, `tools_source="/tmp/a+b"` | `LayoutError` |
| A-6 | `provision._wait_for_marker` source | cap only in the marker loop |
| S-1 | signal inside a `popen()` wrapper, deferred vs raising handler | no orphan / orphaned child |
| S-2 | tcpdump-like child limits; `pid_max` | `Max file size unlimited`; `4194304` |
| S-3 | real `kill_qemu`; GPT interleaving review | other binary False/alive; ours -9; bystander alive; mocked recycle only |
| S-5 | four `login_phase_wait` calls with 16-hex chunks | 32-byte value recovered from files and stderr |
| pi A-2 | `CaptureGuard` under patched interval | 0.01 |
| GPT S1 | real `run_phase()` capture dies mid-phase | INVALID `capture_ended_early`, tap isolated |
| GPT S4 / pi S-1 | shape table; `-serial none` | LEAK / no serial file in test argv |
| QGA A-2 | split 0..15 | all OK |

## 7. Completion

`HEAD` remains `0097e78059ffc44cee8c925ab1f950acc43b48a5`; `git status --porcelain`
is empty (this report is Git-ignored). All probes were offline; no prohibited
command was executed. Scratch `/var/tmp/leaklab-r4-pi` was removed after the
probes. Passing suites are not runtime evidence; A-0 and A-1 are source-level
findings and the live gates in §2.8 remain unqualified.
