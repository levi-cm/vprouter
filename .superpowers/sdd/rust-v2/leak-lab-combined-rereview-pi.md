# Leak-lab combined adversarial re-review (round 2, pi)

- **Reviewed commit:** `545fb95` (`fix(leak-lab): combined review — root-owned layout,
  vprlab-qemu user, fd-anchored evidence, readiness gating, bounded scanner`).
  Working tree was clean before and after; only this report was written.
- **Scope:** the whole leak lab at that commit — `tools/leak-lab/{pcapscan,policy,netplan,control,tsnames}.py`,
  `policy.schema.json`, `test_leak_lab.py`, `docs/rust-v2/leak-lab.md`, and
  `tools/leak-lab/vm/{qga,guest,hostcheck,provision,run_phase,login_url,runlock,hostsetup,rootfs}.py`,
  `test_vm.py`, `docs/rust-v2/leak-lab-vm.md`.
- **Previous reports re-audited:** `leak-lab-combined-review-{gpt,opus,pi}.md` (all FAIL, 0 Critical).
  Every Important item in those three reports was re-run (see §2).
- **Constraints honoured:** no sudo, QEMU, tcpdump, ip, nft, iptables, docker, useradd or
  network execution. The two generated shell scripts (M1 plan, hostsetup plan) were executed
  only with every privileged command stubbed and destinations inside
  `/var/tmp/leaklab-crr-pi`. I did not read `/etc/vprouter`, `/DATA/AppData/vprouter/conf`,
  `*.zip`, `/var/lib/vprouter` or any key file. I read `/opt/vprouter/current/**` read-only
  to check the readiness contract. Scratch `/var/tmp/leaklab-crr-pi` was deleted at the end.
- **Suites (warnings as errors, TMPDIR in scratch), run twice with identical results:**

```
$ python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py
Ran 246 tests in 7.625s
OK
$ python3 -B -W error -m unittest discover -s tools/leak-lab/vm -p 'test_*.py'
Ran 133 tests in 7.530s
OK
```

246/246 M1 and 133/133 M2 pass, no skips. The fix-round claim (246 + 133) is accurate.

## Verdict: **FAIL — 0 Critical, 2 Important, 11 Minor**

The fix round is substantial and honest: the M1/M2 table contract is repaired end to end, the
root-owned layout is real, evidence is descriptor-anchored (the prior rename forgery no longer
works), the outer loader environment is clean, QGA error text is gone, readiness now gates every
fault phase, the lifecycle keeps admission and isolates the tap when a guest survives, the
input-tar chmod is gone, the link-inventory failure branch is fail-closed, and the scanner
streams with bounded state. **No false PASS was found** (96,624 differential scanner evaluations,
0 verdict differences against `e1535b8`; 0 `OLD LEAK → NEW non-LEAK`).

Two Important items remain, both new/remaining rather than regressions:

1. the capture/disk bound is enforced only inside the duration wait, so a hostile guest can write
   unbounded bytes during setup/action/teardown and a phase can PASS with the pcap far above the
   cap (contradicting the doc and the CLI help);
2. the guest-controlled Tailscale `BackendState` string is written verbatim (up to 64 printable
   characters, enough for a whole WireGuard key) into `phase.json`, contradicting the doc's
   "It never contains profile bytes or key material", and `start-router` can PASS with it.

---

## 1. Method and fresh validation

- Re-ran every Important reproducer from the three combined reports with the real parsers,
  the real `run_phase()` decision path (via the suite's `RunPhaseTests` harness), the real
  `pcapscan` module, and a differential old-vs-new scanner fuzz.
- Executed the rendered `hostsetup.py` script in a temp tree with stubbed
  `id/getent/groupadd/useradd/usermod/userdel/install/chown/rm/rmdir/pgrep/flock/python3`,
  a real `cp/find/sha256sum/sha512sum/awk`, and fixture tool/image trees. Injected a
  copy-tamper, a held run lock, and a live-QEMU stub.
- Executed the rendered M1 teardown through the suite shim (the shim was already in the
  repository) and independently parsed the generated shell.
- Read the release (`orchestrate.py` `status`/`router_health`, `vprouter@.service`,
  `router_runtime.py`, `Dockerfile`, `docker-compose.yaml`) to answer whether the new
  readiness commands actually work inside the VM.

## 2. Prior-round Important closure (all three reports)

| Prior finding | Reproducer re-run at `545fb95` | Status |
|---|---|---|
| **GPT I1 / Opus I-1 / pi I-1** — M2 requires the old fixed nft table tag, so every phase refuses | `verify_host_network` with the plan's exact shapes and `comment = vprlab-owned:<token>` → `[]`; old `vprlab-leak-lab-m1` → `nft table inet vprlab does not carry the per-run ownership tag`; another token → same; no token → two problems. `OWNER_TAG` is gone (`hostcheck.py:27`, `:36`); the M1-generated state is fed into M2 by `test_leak_lab.OwnershipIntegrationTests` (15 single-field mutations all refused). | **fixed** |
| **GPT I2** — trusted `setpriv` still loaded libraries from an opsec directory | `start_vm` records outer exec `/usr/bin/setpriv`, env `{PATH, LANG, LC_ALL}` only (no `LD_LIBRARY_PATH`); `LD_LIBRARY_PATH`/`QEMU_MODULE_DIR` appear only after `setpriv -- /usr/bin/env -i ...` (`guest.py:243-266`, `:424-456`; `provision.py:125-131`, `:420`; `run_phase.py:1581`, `:1637`). Tools now live under root-owned `/opt/vprlab-tools`; no tool is ever executed as root (all go through `build_setpriv_argv`). | **fixed** |
| **GPT I3 / Opus I-2 / pi I-2** — evidence below an operator-owned ancestor, re-read by path | `rootfs.py` walks from `/` with `O_DIRECTORY|O_NOFOLLOW` and checks uid 0 + no g/o write per component; every evidence file is created `dir_fd`-relative `O_NOFOLLOW|O_CREAT|O_EXCL`; pcap/stats/argv/policy and the scan report are read/hashed through the retained fd. Probe: after renaming the evidence root and planting `FORGED-FORGERY`, the fd read still returns `ORIGINAL` and the fd hash matches; intermediate symlink, file-as-ancestor, symlink-file and exclusive overwrite are all refused; `expected_uid=0` on a user-owned path is refused. The only remaining path uses are `stat()` size checks (cap/login) and display strings. | **fixed** |
| **GPT I4 / pi I-3** — printable 44-char WireGuard key in QGA errors | The `desc` field is discarded; only an allowlisted class is named (`qga.py:35-63`, `:201-224`); the sentinel `PrivateKey = AAAA…=` in `desc` or in `class` is not rendered, and the chained exception carries only `guest-ping: guest agent error GenericError`. `login_url.py` prints only that bounded error and holds the run lock across connect (`login_url.py:83-98`; pi M-9 fixed). | **fixed** |
| **GPT I5 / Opus I-3** — PASS on a node that never logged in/reached READY | `kill-wireguard`/`stop-router` with `BackendState=NeedsLogin` → exit 2 INVALID `router_not_ready`; release status non-READY → INVALID; `exit_node:false` → INVALID; stale handshake (age > 180 s) → INVALID; `login` with `NeedsLogin` → INVALID `login_not_running`; `login` with Running → PASS; `idle` READY → PASS. `wait_router_ready(require_tailscale=True)` now consumes `orchestrate.py status` READY (`run_phase.py:1228-1255`) plus `tailscale status --json` (`:1195-1211`, `:1257-1271`). `restart-docker` now requires the router READY again after the new Docker PID. | **fixed** (see §4 for the release-workability check; `start-router` keeps the documented pre-login bootstrap exception, M-3) |
| **GPT I6** — lifecycle failure can leave an unobserved VM; provision has no handlers | `poweroff_vm` now falls back to a verified `kill_qemu`, then tap isolation; the finally catches `BaseException`, records `forced_poweroff`, and on survival sets `lifecycle.qemu_alive`, keeps the run lock fd open and isolates the tap. Harness reproducer (poweroff raises `OSError`/`PhaseInterrupted`): exit 2 INVALID, `qemu_survived=true`, `tap_isolated=true`, no `qemu_exit`, and the lock is **not** re-acquirable. Direct `poweroff_vm` with a timeout raises → `kill_qemu` is called. Provision installs SIGTERM/SIGHUP/SIGINT handlers that route to `_terminate` (SIGTERM, then SIGKILL) in its finally. | **fixed for the original reproducers** (a second signal during provision cleanup remains, M-8) |
| **GPT I7 / pi M-4** — payload staging chmods the operator's hard-linked image tar | `_stage_payload` now `shutil.copyfile`s the image (`provision.py:176-193`). Probe: source 0600 → stays 0600, same inode, content unchanged; staged copy 0644. | **fixed** |
| **GPT I8** — a failed link inventory is read as isolation and protection is removed | `link_state`/`neigh_state` distinguish 0 present / 1 proved absent / 2 inventory failed; `verify_ownership`, `isolate_tap`, `delete_link`, `remove_docker_*` treat only 1 as absence, and `iptables -C` exit 1 as "absent" (pi M-12 fixed too). Suite `test_gpt_i8_failed_link_inventory_is_never_absence` (bad JSON and exit 2) and `test_iptables_check_error_is_not_rule_absence` pass; my stubbed M1 teardown refuses with `cannot inventory` and mutates nothing. | **fixed** |
| **GPT I9** — unbounded host capture/scanner resources; per-packet retention | Scanner streams (`_read_pcap_stream`), keeps counters, ≤1000 outside-window indexes and ≤4096 fragment associations with completed-state eviction; overflow is a finding + INVALID; `RLIMIT_AS` 1 GiB and a 300 s timeout are applied by the runner. Differential fuzz old vs new (`pcapscan` at `e1535b8` vs `HEAD`, 96,624 sequences over before/after/WG out/WG in/DNS/ARP/foreign-IP/TCP/ICMP/fragments/duplicate-before × `any|up|down` × `allow_arp`): **0 verdict differences, 0 LEAK→non-LEAK**. Admission now checks `MemAvailable ≥ 1536 MiB` and free disk ≥ cap+1 GiB. | **fixed for the scanner/allocation half; the capture/disk half is still incomplete — I-1** |

Every Minor from the three reports was re-checked in the diff: pi M-1 (boot postcondition now
feeds `postcondition_failed`), pi M-2 (non-dict `scan.json` → `scan_report_invalid`), pi M-3
(`restart-docker` requires READY), pi M-7 (pre/post hashes bound to `capture_meta`), pi M-10
(`setup.active` set for `start-router`), pi M-11 (doc now says the qcow2 is secret-bearing),
pi M-12 (`iptables -C` status), Opus m-1 (`setup` mode, intended `tcpdump` argv no longer starts
a second capture), m-4 (dedicated `vprlab-qemu`), m-5 (container-stopped proof), m-6 (helper
prints bounded errors), m-7 (`check_admission`), m-8 (`validate_tap_owner`), m-9, and the
stale host-prerequisite section (removed) are all addressed or narrowed truthfully. Two doc
bits are still wrong (M-5, M-6 below).

## 3. Important findings

### I-1 — Important: the capture-size/disk bound is enforced only during the duration wait, so a hostile guest can fill the host disk and a phase can PASS above the cap

**Files:** `tools/leak-lab/vm/run_phase.py:1440-1456` (`wait_capture_room` — the only size
check), `:1283-1294` (`login_phase_wait`, the only other check), `:2264` and `:2272` (the only
call sites), `:1411-1430` (`check_admission`, one-shot before boot);
`docs/rust-v2/leak-lab.md:530-536` and `docs/rust-v2/leak-lab-vm.md:634-638` (the claim that
exceeding the cap "stops the phase and makes it INVALID"); `--capture-size-cap` help text
(`:2541-2544`).

The capture starts before QEMU and stays alive through guest cleanup, poweroff and QEMU exit.
Between `start_capture` and `wait_capture_room` the runner performs the QGA boot wait, initial
silence check (180 s), image verification (180 s), secret installation, boot-control staging or
the setup `systemctl start` (up to 360 s) and up to four readiness waits (180 + 120 + 180 +
120 s). None of these consult the capture size. The same is true of the after-wait
AFTER/cleanup/poweroff/quiet window (up to ~180 s). Admission only reserves `cap + 1 GiB` once,
so the pcap can grow far past the reserved headroom during those windows; nothing else (no
cgroup, no quota, no `RLIMIT_FSIZE`, no rotating capture) bounds it.

**Reproducer** (behavioural harness, no QEMU): `stop-router`, `capture_size_cap = 2 MiB`, a
guest-command hook that appends 1.5 MiB to the live pcap in each final-cleanup call (i.e. after
the last `wait_capture_room` check):

```
cap=2097152 pcap_size=3072068 over_cap=True exit=0 result=PASS errors=[] scan_verdict=PASS
```

A second probe with the same cap and growth during the pre-wait silence check shows the
opposite outcome (`result=INVALID capture_size_cap`) only because the later wait finally
notices the already-written bytes — the disk damage has already happened. With a real guest
(the tap is live from the first second) at 1 Gbit/s, the pre-wait window alone is tens of GB;
the one-shot `free_bytes >= cap + 1 GiB` check cannot prevent that, and a full `/var` affects
non-lab services on debdev.

Required: enforce the bound for the whole capture lifetime (a watchdog thread over the retained
fd, a size check in every QGA wait helper and in the teardown path, or `RLIMIT_FSIZE` on the
tcpdump child so it dies and the phase becomes INVALID), and make the doc/help text match.
Rotating/discarding capture data must stay forbidden (the whole file is scanned).

### I-2 — Important: guest-controlled `BackendState` is written verbatim into `phase.json`; a whole WireGuard key fits and `start-router` can PASS with it

**Files:** `tools/leak-lab/vm/run_phase.py:1195-1215` (`read_tailscale_status`,
`read_tailscale_backend_state` keeps any printable characters, truncates at 64,
`record_tailscale_state` writes it), `:2211-2219` (`start-router`'s post-action
`wait_router_ready(require_tailscale=False)` followed by `record_tailscale_state`),
`:692` (`record["tailscale"]`); claim `docs/rust-v2/leak-lab-vm.md:555-561` ("`phase.json` …
It never contains profile bytes or key material").

`read_tailscale_status` runs `docker exec NAME tailscale status --json` inside the untrusted
guest and treats its output as authoritative (as it must for readiness). The `BackendState`
value is not checked against Tailscale's known state enum; it is only stripped to printable
characters and truncated to 64. `start-router` deliberately requires only a fresh handshake
(pre-login), so a compromised guest can report an arbitrary 64-character `BackendState`, keep
the handshake alive and obtain `result=PASS` with that string in the evidence record. A
WireGuard private key is 44 printable base64 characters, so one phase is enough to move a whole
key into the artifact the operator hands to reviewers.

**Reproducer** (behavioural harness): `start-router`, override the `tailscale status --json`
reply with `{"BackendState": "PrivateKey=" + "A"*43 + "=", "Self": {"Online": true,
"ExitNodeOption": true}}`, clean scan:

```
exit: 0 result: PASS errors: []
backend_state in phase.json: 'PrivateKey=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='
sentinel leaked into phase.json: True
```

Required: map `BackendState` to a local allowlist (`Running`, `Stopped`, `NeedsLogin`,
`NeedsMachineAuth`, `Starting`) and store only that token (or `None`); never store the raw
string. The same applies to any other guest string that reaches the record (this is currently
the only one: `wan_device` is regex-bound, boot IDs are UUID-bound, wg0 facts are integers).

## 4. The new root-owned layout, fd anchoring, launch boundary, QGA, readiness, lifecycle

**hostsetup.py / Debian 13 host safety.** The plan creates `vprlab-qemu`
(`useradd --system --no-create-home --shell /usr/sbin/nologin --gid vprlab-qemu`,
`usermod -aG kvm`) and immediately re-validates uid≠0, nologin, no home, exactly primary+kvm
and no forbidden group (`hostsetup.py:139-175`, embedded `check_account`). Destinations are
validated root-owned all the way to `/` before `install -d` and again afterwards; the script
refuses symlinked ancestors; the tools and image trees are copied, hashed file-by-file and
`chown -R root:root`; the base image is additionally pinned with a 128-hex SHA-512 checked
before and after the copy; `/var/lib/vprlab/vm-NNN` is chowned to the QEMU user 0700,
`evidence` and `/run/vprlab` are root 0700, `images` root 0755 files 0644. My stubbed run
confirmed the exact sequence, the manifests and that a tampered copy aborts with
`hash mismatch after copying …` and no committed manifest. Teardown refuses while the phase
lock is held or a QEMU for the account exists, removes exactly the lab directories and the
account, and my stub run confirmed all three branches. The setup half is *not* gated by the
lock (M-2 below).

Why this closes GPT I2 rather than merely moving it: `/opt/vprlab-tools` is root-owned, and the
only executions of its content are behind `setpriv --reuid/--regid --init-groups
--no-new-privs --inh-caps=-all --bounding-set=-all -- /usr/bin/env -i …`; the trusted
`setpriv`/`env` see `PATH/LANG/LC_ALL` only. Nothing from the staged tree ever runs as root
(`_run_json`, `isolate_tap` and tcpdump use system paths/PATH). A malicious staged tool would
therefore run only as `vprlab-qemu` with an empty capability set, and `/dev/kvm` via the `kvm`
group is the intended access. Tool-tree *content* is still not pinned (the SHA256SUMS is
written from the same operator-owned source), which is acceptable under "tools run unprivileged"
but makes the doc's "verified" wording stronger than the property (M-7).

**rootfs.py.** `validate_ancestry`/`open_directory` open each component from an anchor with
`O_NOFOLLOW`, reject non-directories and, when the caller is root, reject non-root owners and
group/other-writable modes; `make_run_directory` creates and re-opens the final directory
relative to the root fd. All security-relevant evidence I/O is `dir_fd`-relative with
`O_NOFOLLOW|O_EXCL`; the scan is invoked with `pass_fds=(evidence.fd,)` and
`/proc/self/fd/<N>/…` paths, so the child resolves through the inherited descriptor, not a
name. `proc_path` therefore survives a rename and cannot be redirected by an ancestor owner.
There is no path re-resolution left on the read/write hash path; the residual path uses are
`stat()` size checks and human-readable record fields (M-6). `_check_directory` disables the
owner/mode checks for non-root callers, which is correct for tests and cannot happen in
production (`expected_uid` is 0 when euid is 0).

**readiness against the real release.** `orchestrate.py status --name NAME` is a real CLI
action (`choices=["validate","serve","cleanup","status"]`) that prints
`{"name": ..., "state": "READY", "heartbeat": ...}` only after `router_health()` has verified
quarantine state, both owned containers running, `br-vpr-uplink`, the guard snapshot, root
ownership of the site/release files, the router policy, `wg0` up with a default route, and a
fresh `runtime_health_state == READY`. Provisioning installs `python3`, `iproute2`, `nftables`,
`util-linux`, `docker.io` and `docker-compose`, and the provision script installs
`/opt/vprouter/current` with exactly the files `assert_host_ownership` requires, so those
commands work inside the VM. The runner's `wait_release_ready`
(`run_phase.py:1228-1255`) requires exit 0, `state == "READY"` and the right `name`, i.e. the
release's own contract, not a proxy. `docker exec NAME tailscale status --json` also works: the
pinned image ships `/usr/local/bin/tailscale`, Alpine's PATH includes it, `tailscaled` is
started with the default socket under the container's `/run` tmpfs, and the release itself uses
the same call and the same `Self.ExitNodeOption`/`AdvertiseRoutes`/`NetfilterMode` checks.
One caveat is inherent, not a code defect: all readiness is measured by commands the untrusted
guest executes, so a compromised guest can lie about readiness; the host pcap remains the only
independent evidence, which is exactly what `certifies: "server_side_no_client_traffic"`
states. `start-router` intentionally keeps the pre-login bootstrap exception (handshake only)
and is now documented that way (M-3).

**QGA secrecy.** `qga.py` discards `desc`, allowlists the class and keeps only the local method
name in chained errors; the CLI prints only `exit=`; `login_url.py` prints only a bounded
`QGAError` (and the intended URL). File contents written through QGA never appear in errors.
The only remaining guest-string channel is I-2.

**Lifecycle.** Control order is AFTER → guest cleanup → poweroff → QEMU wait/kill → AFTER in
pcap → 2 s → SIGINT → scan; every finally step is individually guarded; a surviving QEMU keeps
the lock and has its tap brought down; `kill_qemu` verifies pidfile + cmdline + state path
before signalling; `start_capture` and `start_vm` are inside
`block_termination_signals()` so a signal cannot orphan a process between fork and assignment
(the narrow fdopen-close case remains, M-4). Provision handles signals and reaps in its finally.

## 5. False-PASS hunt

- **Scanner differential (new vs `e1535b8`):** 96,624 evaluations, all sequences of length 1–4
  over `{BEFORE, AFTER, WG-out, WG-in, DNS leak, legit ARP, foreign-IP UDP, TCP, ICMP, first
  fragment, non-first fragment, duplicate BEFORE}` × `any/up/down` × `allow_arp`:
  **0 verdict differences, 0 LEAK→non-LEAK, 0 PASS→non-PASS**. The only differences were the
  `tunnel_not_observed` invalid reason when the AFTER control is missing (the new streaming
  window opens at BEFORE even if AFTER never arrives; still INVALID`missing_positive_controls`).
  Window semantics are equivalent because non-monotonic timestamps are an invalid reason.
- **Bounded state:** 50k-record stream scan peaks under 8 MiB (suite), fragment-table overflow
  is INVALID, outside-window indexes are capped with an exact total. A replayed control nonce
  is a `replayed_control` finding (LEAK).
- **Runner decision path:** every prior C1/C2 fault still forces INVALID; a scanner exit/report
  mismatch, nonce mismatch or missing AFTER is INVALID; the pcap/stats/argv/policy hashes are
  bound to the scanner's `capture_meta` before and after the scan; LEAK keeps precedence.
- **Evidence substitution:** the rename-and-forge primitive that produced PASS last round no
  longer reaches the scan (fd-anchored read/hash; root-owned ancestors refuse an operator-owned
  parent).
- **Residual false-PASS paths found:** none. The remaining Important items are a host-resource
  gap (I-1) and a secret channel into the evidence (I-2); neither turns a real leak into PASS.

## 6. Minor findings

1. **M-1 — `hostsetup.py --check` rejects the executable tools that `hostsetup.py` installs.**
   `hostsetup.py:217-221`: the file mask `0o133` includes owner-execute, so a normal
   `0755` `qemu-system-x86_64` is reported as "unsafe". Reproducer: take `HostsetupTests`'
   valid inventory and add `TOOLS_ROOT/usr/bin/qemu-system-x86_64` mode `0755` →
   `['/opt/vprlab-tools/usr/bin/qemu-system-x86_64 file mode 0755 is unsafe']`; mode `0644`
   → `[]`. The intended mask is group/other write/execute (plus setuid/setgid). The suite
   never lists an executable in the inventory, and the mode-`0755` `TOOLS_ROOT` is accepted,
   so the contradiction is hidden. Also `/` is required to be exactly `0755`
   (`hostsetup.py:185`), which a hardened host may not satisfy.
2. **M-2 — hostsetup's setup path takes no run lock/QEMU guard.** Teardown refuses while a
   phase or QEMU is live (`:376-384`), but a re-run of setup during a phase runs
   `cp -p` over the tool tree that a running QEMU has mapped (ETXTBSY, or content change /
   truncation under a mapped binary), `chown -R` the same tree, and `install -d`/`chown` on
   `vm-NNN`. Fail-closed for leaks, but it can abort or crash a phase. Reuse the teardown's
   guard at the top of the setup path.
3. **M-3 — teardown's QEMU check is skipped when `pgrep` is absent, and `userdel` failure is
   ignored.** `hostsetup.py:382` gates the check on `command -v pgrep`; without procps the
   teardown proceeds while a QEMU runs (the run-lock check still covers a live *phase*, but not
   a provision VM orphaned after a lock release — M-8). `userdel "$QEMU_USER" || true`
   (`:394`) still prints "teardown complete" with the account and its `kvm` membership left
   behind. Make the absence of `pgrep` a refusal and report a failed `userdel`.
4. **M-4 — `start_capture`/`start_vm` spawn inside a `with` whose close can raise.**
   `run_phase.py:510-519`, `:1634-1640`: if `error_log.__exit__`/`os.fdopen(...).close()`
   raises after `Popen` (e.g. ENOSPC on flush), the handle is never assigned to `capture`/
   `qemu_process`; the finally has nothing to stop, and `lifecycle.qemu_alive` is false, so the
   lock is released while the child runs. The signal mask covers the signal path but not this.
   Assign the handle before leaving the `with`, or wrap close failures.
5. **M-5 — stale capture path in the M1 doc.** `docs/rust-v2/leak-lab.md:417` and `:705-711`
   use `-w /var/lib/vprlab/manual-capture.pcap`, while the plan default is
   `$RUN_DIR/manual-capture.pcap` = `/run/vprlab/manual-capture.pcap` (`netplan.py:55-60`,
   `:799-805`); line 618 and 687 give the correct `$RUN_DIR`. The example would scan a file the
   plan never writes. (The JSON `-w` value only has to realpath to `--pcap`, so the example is
   not unsafe — it is misleading.)
6. **M-6 — `/proc/self/fd/<N>` paths in the evidence are not replayable.** `phase.json` and
   `capture-argv.json` record the tcpdump/scan argv with the run-directory fd number
   (`run_phase.py:503`, `:2394-2412`). The hashes bind the real bytes, but re-running the
   recorded command later resolves a different fd. Record the resolved evidence path too (as
   a non-authoritative field) or a copy of the argv with the display path.
7. **M-7 — the staged tool tree's authenticity is not pinned, and its symlinks are silently
   dropped.** `hostsetup.py:262-283` uses `find . -type f` (runtime symlinks are not copied)
   and writes `SHA256SUMS` from the same operator-owned source it just copied, so the
   verification is copy-fidelity, not provenance. Harmless while every tool runs unprivileged,
   but the doc's "verified against a written SHA256SUMS" (`leak-lab-vm.md:61-63`) should say
   exactly that, and a pinned digest list (like the base image) would be stronger.
8. **M-8 — a second signal during provision cleanup can orphan the provision VM.**
   `provision.py:45-50` raises on every signal; `_terminate` (`:252-264`) waits inside the
   finally, so a second SIGINT/SIGTERM during that wait raises out of the finally, skips the
   rest of `_terminate`, and `provision()` releases the run lock as the exception propagates.
   The child is in a new session with user-mode networking only, so there is no tap leak, but a
   detached 512 MiB VM survives until manual cleanup (the next runner's
   `refuse_if_qemu_running` then refuses, fail-closed). Mirror `run_phase`'s idempotent
   `_signal_seen` handler.
9. **M-9 — a scanner crash is recorded as LEAK.** `pcapscan.py:1691-1704` catches only
   `OSError`; any other uncaught exception exits 1, and `run_phase.py:2482-2490` maps
   `scan_exit == 1` to `LEAK` before looking at the report (`report = None` →
   `scan_report_invalid`). No false PASS (LEAK is the safe direction), but it contradicts
   `leak-lab-vm.md:570` ("a crash is never reported as LEAK") and makes a host bug look like a
   leak. Map a missing/invalid report to INVALID even when the exit status is 1, or have
   pcapscan catch `Exception` and exit 2.
10. **M-10 — `qemu_env()` is dead code that still returns `LD_LIBRARY_PATH`.** `guest.py:235-241`
    is unused now, but it is exactly the environment GPT I2 forbade on the outer executable; a
    future caller would reintroduce the finding. Delete it or rename it to a post-drop-only
    helper with an assertion.
11. **M-11 — `run_phase` resolves `ip`/`nft` through root's `PATH`.** `run_phase.py:1495-1520`
    (`ip -d -j link`, `ip -j addr`, `nft -j list table`, `ip -j neigh`) and `:1721-1734`
    (`isolate_tap`) use bare names, unlike the release's own absolute `/usr/bin/ip`,
    `/usr/sbin/nft`, `/usr/bin/nsenter`. Under `sudo`'s `secure_path` this is fine, but a root
    shell with an operator-influenced `PATH` would execute an operator binary as root. Use
    absolute paths (as `pcapscan` already does for its known tools) or pin `PATH`.

## 7. Integration trace and remaining limits (NOT_RUN)

- **Ownership/topology:** `owner.json` schema 1/32-hex, per-run `ifalias` on both links, the
  same tag on the table comment and both DOCKER-USER comments; fixed MACs
  `52:54:00:76:70:01/02`, static host neighbour and guest `[Neighbor]` agree; `allow_arp:false`
  makes every ARP a finding. `netplan.py --tap-user` default is `vprlab-qemu`, matching the
  account; `hostcheck` refuses a present, different tun owner.
- **Capture binding:** tcpdump argv is identical to `guest.tcpdump_argv` except the fd-anchored
  `-w`; the scanner requires `realpath(-w) == realpath(--pcap)`; the banner, stats parser,
  count binding, `--expect-tunnel` table and both nonces are checked; hashes are compared
  before and after the scan.
- **Not run / not certifiable by this review:** any real QEMU boot, tap attach, tcpdump
  run/drain, nft/iptables application, Docker firewall, QGA socket, boot timing vs
  `networkd`/docker, provisioning script completion (including the in-script
  `systemctl disable --now cloud-final.service` self-stop risk and the `ip tuntap add`
  persistence question), Mullvad endpoint reachability, tailscaled login/approval, `README`
  not relevant. The M2 doc's own statement that "nothing … has been run against QEMU" remains
  true; all conclusions here are offline/source-level.
- **Secret boundary:** the profile is read once, only the `[Peer] Endpoint` is decoded, bytes go
  only through QGA into 0600 root files, nothing secret is in argv/stdout/record; the qcow2 is
  documented as secret-bearing after the first phase. Remaining exposure is I-2.
- **Evidence:** `/var/lib/vprlab/evidence` is root 0700 with root-only ancestors; the runner
  creates each run directory through the retained fd and hashes/scans through it.

## 8. Final verification

- `git status --porcelain` was empty before the review and after all probes; the only
  repository file written is this report. `HEAD` remained
  `545fb95ad448ca86d5b7514e01f48fc4cbf0ae79`.
- No prohibited command was executed; every generated script ran with stubbed privileged
  commands inside `/var/tmp/leaklab-crr-pi`.
- Scratch `/var/tmp/leaklab-crr-pi` was removed after the probes.
- Passing suites do not certify runtime behaviour; the Important closure statements above are
  scoped to the re-run offline reproducers and the named code paths.
