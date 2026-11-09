# Round-4 focused SAFETY gate review

Target: `0097e78059ffc44cee8c925ab1f950acc43b48a5`; initial worktree clean. Review scope: `tools/leak-lab/**`, `docs/rust-v2/leak-lab*.md`, and prior S1-S5 report. Local offline code/fixtures only; no privileged/network execution or prohibited state/config/key/archive reads. Only this report is changed in the repository. Scratch: `/var/tmp/leaklab-r4-gpt` (removed at completion).

## Incremental observations

- S1 now has capture-process polling and a mandatory alive-before-stop check after QEMU poweroff/drain; original synthetic early-exit probe is being rerun.
- S2 now accepts only `/a/[0-9a-f]{8,16}`; original full synthetic key encoding is being rerun. This restricts, but cannot authenticate, guest-selected URL tokens.
- S3 removes test serial output and adds admission and per-file limits. Reviewing whether the limits cover cumulative disk use and are installed before guest-controlled writes.
- S4 adds WireGuard type/reserved/length checks; ciphertext authentication remains inherently outside this monitor, including type-4-shaped plaintext. This is not a new safety finding.
- S5 validates shell-inserted path components and quotes assignments; original malicious filename probes are being rerun.

## Fresh suite results (each ran exactly once)

With `TMPDIR=/var/tmp/leaklab-r4-gpt/tmp`:

- `python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py`: **254 tests, OK**, 8.086 s.
- `python3 -B -W error -m unittest discover -s tools/leak-lab/vm -p 'test_*.py'`: **188 tests, OK**, 8.620 s.
- **442 total; zero failures/errors/skips reported.** Tests use synthetic processes/command stubs, including harmless sleep/Python children; no real QEMU, capture, firewall, account or network operation was run.

## S1-S5 initial rerun results

The executable round-3 harness was extracted into scratch. Only scanner argv unwrapping was adapted for the new wrapper, and the S2 observation handles the now-absent evidence text.

- S1 original run: `capture_ended_early` is now recorded. Because its original packet fixture is also S4 plaintext, scanner LEAK takes precedence (`exit=1, result=LEAK, scan=LEAK, errors=[capture_ended_early]`). A separate shape-valid fixture below isolates the capture verdict. No false PASS.
- S2 original full 32-byte synthetic base64 key: recoverable from stderr **false**, recoverable from file **false**.
- S3 original test-serial path: `build_qemu_argv(test, ...)` now uses `-serial none`. The broader host-disk finding is **not fully closed**; details below. No exhaustion experiment.
- S4 original `CLEAR_TEXT_NOT_WIREGUARD`/`CLEAR_REPLY` tuple probe: **LEAK, 2 findings** (previously PASS).
- S5 original hostsetup quoted filename and netplan `$RUN_DIR/$(printf SAFETY_INJECTED).pcap` payloads: both **REJECTED** by validators before script execution. No shell payload was executed.

### SAFETY Important R4-S3 — cumulative provisioning disk use remains unbounded by admission

`provision.py:145-157` admits with a fixed 8 GiB free; `_copy_release`/`_stage_payload` (`224-290`) impose no aggregate source-size budget. The release tree, image tar copy, payload ISO, overlay, serial and qemu.log coexist. `RLIMIT_FSIZE` is a maximum for **each file**, not their sum. For example a 2.5 GiB image copied into staging and then ISO consumes approximately 5 GiB, plus a 4 GiB guest disk, before serial/logs/metadata; every file is below 8 GiB, yet an admitted 8 GiB filesystem can fill. In addition, the 64 MiB serial check ends immediately when the guest prints the success marker (`321-325`), after which `process.wait(timeout=180)` (`524-529`) has no serial or free-space monitor; an untrusted guest can then write until the 8 GiB per-file limit. This is residual S3, not a separate newly invented threat. Require aggregate admission based on staged bytes plus ISO/overlay/log budgets and a storage quota or continuous free-space/serial guard through actual process exit.

### SAFETY Important R4-S2 — fixed-shape login tokens still carry recoverable secrets (residual S2)

The original single long base64-key probe is closed, but the underlying confidentiality claim is **not closed**. `login_url.py:30-44,78-86` accepts a guest-selected 16-hex-character token; `run_phase.py:1570-1576` writes and prints it. A fresh synthetic-only probe encoded `bytes(range(32))` as four successive 8-byte hex chunks, each a valid `/a/<16 hex>` URL, and invoked the real `login_phase_wait` four times with fake QGA/evidence. Concatenating the tokens recovered the entire 32-byte value from both stderr and file contents: **true / true**. Even one call releases 64 selected bits. No actual key was read.

This is a bounded covert channel intrinsic to forwarding an unauthenticated guest-selected login token, rather than a regex escape or new regression. Keep it as residual S2 Important when the requirement is that a malicious guest cannot disclose its profile/state through the helper. Either authenticate the URL against a trusted source, remove forwarding under that threat model, or explicitly accept this declassification and withdraw the no-secret-channel claim. Syntax validation alone cannot close it.

### SAFETY Important R4-N1 — guard kill can target a reused non-QEMU PID/group (NEW)

`CaptureGuard._breach` now calls `kill_qemu` from its watcher thread (`run_phase.py:1814-1834`) while main-thread `poweroff_vm` can concurrently `wait`/reap the same child (`2263-2272`, `3075-3077`). `kill_qemu` polls, checks `/proc/<pid>/exe` and `/proc/<pid>/cmdline`, then separately calls `os.getpgid(pid)` and `os.killpg(...)` (`2206-2224`). The retained **Popen object** does not pin the PID after another thread reaps the child. If QEMU exits and the main thread reaps it after the final proc read, PID reuse can make getpgid refer to an unrelated non-QEMU process, and root sends SIGKILL to that process's group. The helper also proceeds if the concurrently reaped Popen already has returncode set after verification.

Offline interleaving probe: real `_breach`, `kill_qemu` and identity decision code; mocked proc bytes/getpgid/killpg only. The final proc read returns the original valid QEMU cmdline after simulating main-thread reap; getpgid then models the recycled PID. Recorded sequence:

```text
read_original_qemu_cmdline
main_reaped_original_child_PID_now_reusable
getpgid_of_reused_PID_non_QEMU
SIGKILL_selected_group 987654321
```

No real PID reuse, signal or unrelated process harm was attempted. This establishes the unsafe code interleaving, not its probability on debdev. Use a retained pidfd and pidfd signal for the owned process, or serialize every reap and identity-check/signal across both threads while the original child remains unreaped; an extra unlocked poll/proc check is insufficient.

### Additional S3 limit-installation evidence

`apply_child_limits` (`run_phase.py:182-211`) runs **after** Popen (`2127-2143`) and silently ignores every OSError/ValueError for both resetting AS and setting FSIZE. A fake `resource.prlimit` raising PermissionError for both operations was accepted with no exception after two calls. Thus an inability to raise AS (availability) is conflated with an inability to install a new FSIZE cap (safety). A test QEMU otherwise inherits no newly set runner FSIZE bound. `_apply_qemu_limits` (`provision.py:160-175`) similarly returns on PermissionError during its first AS operation, skipping FSIZE; provisioning at least inherits the parent's soft FSIZE limit when launched through main. The mandatory per-file bound must be installed before exec/guest writes, and a failed mandatory cap must refuse/reap rather than continue silently. No real failed prlimit was induced on debdev. Folded into residual resource finding R4-S3 rather than counted twice.

## Focused path conclusions

- **Deferred signals:** no new orphan/unobserved interval established in the phase runner for handled SIGINT/SIGTERM/SIGHUP. The flag-only handler cannot interrupt Popen handle assignment; start_capture readiness has local exception cleanup; start_vm has a local setup reaper; caller retains both handles before explicit checkpoints; ordered cleanup keeps capture through shutdown and runs after its first interrupt. Bounded QGA/subprocess calls can delay observation. SIGKILL/host death cannot be handled. Provisioning retains its earlier raise-once handler; it is not the newly deferred phase implementation and no new claim is made for it.
- **Capture liveness / S1 CLOSED:** original fixture records early exit. With the same harness and shape-valid `wg_data()` substituted to remove S4 interference: `exit=2, result=INVALID, scan=PASS, errors=[capture_ended_early], dead_before_qemu_exit=true, real_stop_status=0`. Capture is checked after QEMU poweroff and drain before the intentional stop, so a clean early capture exit cannot hide a shutdown tail behind PASS in this probe.
- **Serial:** test argv is `-serial none`, closing the original test-console flood path. Provisioning serial/resource concerns are R4-S3 above.
- **Guard identity:** ordinary mismatched executable/pidfile attacks are refused, but the NEW concurrent-reap race is R4-N1 above.
- **WireGuard shape / S4 original repro CLOSED, inherent limitation remains:** obvious plaintext is LEAK. A fresh 32-byte payload `b"\x04\0\0\0" + b"\0"*12 + b"PLAINTEXT_SECRET"`, sent both directions at the allowed tuple with controls, is **PASS, zero findings**. This is inherent: the monitor cannot authenticate ciphertext, and any shape-valid plaintext can mimic transport data. It is explicitly documented, is not newly introduced, and is **not counted as a new finding**. An initial supplemental payload accidentally had a 17-byte body and correctly returned LEAK; the corrected 16-byte-body probe above establishes the inherent case.
- **Injection / S5 CLOSED:** both original payloads rejected; new path validators reject metacharacters, empty/dot/dot-dot components, whitespace and substitutions before rendering; assignments use shlex.quote and RUN_DIR is composed as a quoted variable plus validated quoted components. No new generator injection was established.
- **Scanner wrapper:** code uses isolated Python to set the 1 GiB AS limit before exec of the existing argv, with no preexec_fn/thread deadlock. Suite verifies the actual resulting limit; full scanner/hashes were also exercised in-process by S1. No new safety defect established in the wrapper. Existing scanner trust/environment boundaries are not reopened.

## Availability only

- `stop_capture` catches the first 0.5 s wait timeout outside its loop (`787-809`), so a normal slow flush is SIGKILLed after about 0.5 s despite a larger timeout; evidence is forced-stop/INVALID.
- Resetting inherited AS with post-spawn prlimit may be too late for QEMU's early mappings, and failure to raise a pre-existing hard limit can cause startup failure.
- Installed manifest/repository mismatch, unsupported login URL forms and scanner wrapper limit/exec failure fail closed; they can block a run.

## Final gate

**FAIL — 3 SAFETY Important findings: residual S2 (bounded/chunked secret channel), residual S3 (aggregate disk/limit coverage), and NEW N1 (concurrent reap/PID reuse in guard SIGKILL). No Critical or separately classified Minor findings.**

S1 and S5 are closed by fresh probes. S4's obvious-plaintext repro is closed, but its inherent shape/authentication limitation remains and is not counted as new. S2's exact long-token repro is closed while its underlying channel remains. S3's test UART path is closed while its aggregate host-disk risk remains.

442 tests passed across the two single suite runs. Live bring-up, actual debdev resource/privilege behavior, capture continuity, and runtime safety: **NOT_RUN**, as instructed. Offline review/component evidence does not authorize or establish live/runtime/release acceptance.

Completion checks: requested scratch directory deleted; HEAD remains `0097e78059ffc44cee8c925ab1f950acc43b48a5`; `git status --short` empty and `git diff --check` passed. The report is Git-ignored (`git check-ignore` confirmed), so status does not display it. Only this report was intentionally changed in the repository.
