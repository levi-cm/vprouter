# Leak-lab combined adversarial review (pi) — M1 monitor round 4 + M2 runner round 2

- **Reviewed commit:** `e1535b8` ("fix(leak-lab): M2 round 1 — failed phases never
  PASS, capture outlives QEMU, fixed tunnel table, root-only evidence, run lock").
  The working tree was clean before and after this review.
- **Scope:** the whole leak lab at that commit —
  `tools/leak-lab/{pcapscan,policy,netplan,control,tsnames}.py`,
  `tools/leak-lab/policy.schema.json`, `tools/leak-lab/test_leak_lab.py`,
  `docs/rust-v2/leak-lab.md` (M1 monitor round 4), **and**
  `tools/leak-lab/vm/{qga,guest,hostcheck,provision,run_phase,login_url,runlock}.py`,
  `tools/leak-lab/vm/test_vm.py`, `docs/rust-v2/leak-lab-vm.md` (M2 runner round 2).
- **Constraints honoured:** no sudo, no QEMU, no tcpdump/ip/nft/iptables/docker
  or network execution. The generated host script was executed only with every
  privileged command stubbed, inside `/var/tmp/leaklab-comb-pi`; it was also
  parsed with `sh -n`. I did not read `/etc/vprouter`,
  `/DATA/AppData/vprouter/conf`, any zip, `/var/lib/vprouter` or key files. I
  read `/opt/vprouter/current/**` read-only for release behaviour.
  Scratch `/var/tmp/leaklab-comb-pi` was deleted after the review.
- **Tests (run twice, identical):**

```
$ python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py
Ran 239 tests in 4.931s
OK
$ python3 -B -W error -m unittest discover -s tools/leak-lab/vm -p 'test_*.py'
Ran 96 tests in 1.302s
OK
```

239/239 M1 and 96/96 M2 pass with warnings-as-errors; no skips.

## Verdict

**FAIL — 0 Critical, 3 Important, 12 Minor.**

Every Critical/Important from the previous round is now closed **except** the
evidence-boundary family (prior `pi I9` / `gpt I3` / `opus I4`) and the
guest-controlled QGA error text (prior `gpt I10`); both remain reproducible.
The two parts also do not actually fit together: the M2 runner still compares
the `inet vprlab` table comment against the **old fixed tag**
`vprlab-leak-lab-m1`, while the current M1 plan writes the **per-run**
`vprlab-owned:<token>`. `run_phase.verify_host_lab()` therefore refuses every
phase before evidence is created. That is a total integration blocker (it fails
closed, so it is Important rather than Critical), and it is the first finding
below.

The scanner itself survived a fresh adversarial battery: 48,312 sequence/
expectation evaluations over an alphabet that includes DNS, foreign-IP, TCP,
ICMP, IPv6 and fragmented frames produced **zero** cases where a leak frame was
not `LEAK`; the one-line-stats, fragment-finalisation, banner, L2 and per-run
token fixes all hold. The runner's C1/C2 fixes hold under behavioural
fault injection (action/setup/postcondition/cleanup/capture/QEMU faults), and
the monitor interface (argv/`-w`/banner/stats/policy/nonces/expectation/order)
is correctly bound end to end.

---

## Prior-round closure audit

### M1 `leak-lab-m1-rereview3-{gpt,opus,pi}.md` (all previously FAIL)

All three reports had **0 Critical**. Their Critical/Important items and my
re-run results:

| Prior finding | Re-run at `e1535b8` | Status |
|---|---|---|
| **pi I-1** — one-line SIGUSR1 `captured`/`received` discarded; unread-tail PASS | `zero_stats(4)` + `tcpdump: 4 packets captured, 100 packets received by filter, 0 ...` → **INVALID `unread_capture_tail`**; 4 records + one-line `100/100` → **INVALID `stats_packet_count_mismatch`**; legitimate mid-run `2/2` then final multi-line `4/4/0` → **PASS** | **fixed** |
| **gpt I1** — incomplete fragment whose first fragment is outside the window excused | `[first, A, O, I, B]`, `[A, O, I, B, first]`, and `first` exactly at the BEFORE timestamp all → **LEAK `fragment_incomplete`** (inside the window still LEAK) | **fixed** |
| **gpt I2** — ownership checked after mutation; fixed tag authorises another run; Docker rules not bound | foreign-alias tap + fresh `owner.json`: setup aborts at `ip tuntap add`, teardown aborts before **any** `link set`/`neigh del`/`nft delete`/`iptables -D`; stale-token objects with this run's `owner.json` → teardown aborts with no mutation; duplicate owned `DOCKER-USER` rules (`-C` loop) all removed; per-run `vprlab-owned:<token>` on both links, table and both rules | **fixed** |
| **gpt I3** — failed isolation still removes protection; teardown exits 0 after cleanup failure | stubbed `ip link set ... down` failure → exit 1, `inet vprlab` table and **both** DOCKER-USER rules still present, both links still present, `owner.json` retained; normal run removes everything and `owner.json` last | **fixed** |
| **opus I-1** — link check reads `alias`; iproute2 emits `ifalias`, so links never deleted | embedded checker: real `{"ifname":...,"ifalias":"vprlab-owned:<32hex>", "linkinfo":{"info_kind":"tun","info_data":{"type":"tap"}}}` → 0; `alias`-only → 1; `NOT-OWNED-...` → 1; plain `tun` → 1 | **fixed** |

Also re-checked (previous-round Minor items, no regression): anchored banner
(wrong interface / not first / duplicate / substring → `capture_banner_mismatch`),
fragment finalisation at both boundaries, API `expect_tunnel` required, per-run
token, fixed bridge MAC + neighbour, `UnicodeError` → exit 2, `DOCKER-USER`
preflight jump order, and the Ctrl-C trap (SIGINT/SIGTERM/SIGHUP during a
stubbed capture → teardown ran, rc 130, all objects removed).

### M2 `leak-lab-m2-review-{pi,gpt,opus}.md` (all previously FAIL)

Previous round: 2 Critical (all three reviewers) and 27 Important items
(17 distinct issue groups after overlap). Re-run results:

| Prior finding | Re-run at `e1535b8` | Status |
|---|---|---|
| **pi/gpt/opus C1** — failed setup/action/postcondition never INVALID; stale scan verdict | action exit 7 → **INVALID `action_failed`**; setup exit 7 → **INVALID `setup_failed`**, action not run; setup never active → **INVALID `router_not_ready`**; postcondition says container running → **INVALID `postcondition_failed`**; `start-router` action exit 1 → **INVALID**; `idle` setup exit 1 → **INVALID**; LEAK + action failure → **LEAK**; scanner exit 0 with report `LEAK` → **INVALID `scan_report_mismatch`**; stdout/record show `result=INVALID`, `scan_verdict=PASS` | **fixed** |
| **pi/gpt/opus C2** — capture stopped before router/guest teardown | event order: AFTER control → `cleanup_guest_units` (`systemctl stop/disable`) → `guest-shutdown` → `qemu_exit` → AFTER-in-pcap → 2 s quiet → `capture_stop` → scan. Forced poweroff / QEMU exit 3 / capture-stop failure → INVALID; phase.json still written | **fixed** |
| **pi I1 / opus I1** — silence check unusable on Debian 13 (`ip neigh show "$if"`, `DHCP4_CLIENT=0`) | script now uses `ip -4 -o neigh show dev "$interface"`, `DHCP=no` in the networkd file, lease-file absence, `networkctl` as an extra signal; no `DHCP4_CLIENT`/`DHCP6_CLIENT`; cloud-init 25.x units added | **fixed** |
| **pi I2 / opus I2 / gpt I8** — `--expect-tunnel` not tied to the phase; `down`/`any` false PASS | fixed `PHASE_EXPECTATIONS` (all `up`); setup inside the window requires exit 0 + handshake; fault postconditions (unit inactive, `wg0` absent, container not running, new Docker PID); docs phase table. Residual: `start-router` still does not require Tailscale READY (docs narrowed to unit+handshake), `restart-docker` does not require router recovery (docs narrowed) — Minor | **fixed for the certification claim** |
| **pi I3** — no AFTER-in-pcap/2 s drain | `wait_for_control_in_pcap()` + `QUIET_SECONDS` before SIGINT; test asserts `qemu_exit < quiet < capture_stop` | **fixed** |
| **pi I4 / opus I5 / gpt I7** — `login_url.py` cannot coexist with the runner's single QGA stream | `login_url` takes the global lock non-blockingly and exits 2 while a phase runs; `login` phase polls the URL through the runner's own QGA connection and writes only `login-url.txt` 0600 | **fixed** |
| **pi I5** — root executes opsec-owned `qemu-img`/`genisoimage` | `verify_state` and `provision._run_generator` run them through `setpriv --reuid/--regid --no-new-privs --inh-caps=-all --bounding-set=-all` as the QEMU user; `qemu-img info -U`; tests assert the wrapper | **fixed** |
| **pi I6 / gpt I6** — no signal handling; cleanup OSError skips poweroff; finally failures bypass evidence | SIGTERM/SIGHUP/SIGINT handlers raise `PhaseInterrupted`; each finally step catches `BaseException`; capture/poweroff/cleanup failures are noted; phase.json is written even after a capture-stop failure; main returns 2 for unexpected exceptions | **fixed** |
| **pi I7** | tap must have `master == vprlab0`; missing master is refused | **fixed** |
| **pi I8** | `cloud-init-main.service`, `cloud-init-network.service`, `cloud-init-hotplugd.socket` (and the compatibility names) are in `SILENCE_MASK_UNITS`; the silence script also rejects any active `cloud-init*` unit via `systemctl list-units 'cloud-init*' --state=active` (this covers `cloud-init.target`) | **fixed** |
| **pi I9 / gpt I3 / opus I4** — root path writes/evidence substitution below an opsec-owned ancestor | evidence moved out of the state directory and the qemu log is opened by root in the evidence dir with `O_NOFOLLOW`; **but** `EVIDENCE_ROOT` is still below the opsec-owned `/DATA/vprouter-lab`, `ensure_root_directory()` follows intermediate symlinks, and the report is re-read by path — see **I-2** | **partially fixed** |
| **pi I10** | `start-router` does not require Tailscale `READY`; the docs now claim only unit-active + handshake and record `BackendState` | **fixed by narrowing the claim** (residual Minor) |
| **pi I11 / gpt I5** | `resolve_unprivileged_user()` and `build_setpriv_argv()` reject uid 0; `--qemu-user root` and `--qemu-user 0` refused | **fixed** |
| **pi I12** | no `-qmp` socket in either QEMU mode | **fixed** |
| **gpt I1** — reboot BEFORE spec in volatile `/run` | `BOOT_CONTROL_DIR = /var/lib/vprlab`; spec/script/unit installed there; script consumes and unlinks the spec; unit runs `Before=docker.service`; simulated `/run` reset does not affect it | **fixed** |
| **gpt I2** — tap validation rejects real iproute2 shape | `_is_tap()` accepts `info_kind: tun` + `info_data.type: tap` and rejects plain `tun`; test covers both | **fixed** |
| **gpt I4** — single-guest rule is a non-atomic snapshot | `runlock` (`flock` on `/run/vprlab/run.lock`) is held from before `refuse_if_qemu_running()` through guest exit by both provision and phase runners; second runner refused | **fixed** |
| **gpt I9** — policy may allow unrelated endpoints | runner builds the policy itself from the profile endpoint; `verify_policy()` requires exactly one UDP flow equal to the endpoint, `allow_arp:false`, the fixed MAC/IP and sink | **fixed** |
| **gpt I10** — guest-controlled QGA error text printed without redaction | still rendered (`qga.py:179-185`); the test only checks control characters/length; `login_url.py:97` prints the message — see **I-3** | **not fixed** |

---

## Important

### I-1 — The M2 runner compares the nft table comment against the old fixed tag; every phase refuses before evidence

**Files:**
`tools/leak-lab/vm/hostcheck.py:26` (`OWNER_TAG = "vprlab-leak-lab-m1"`),
`:170` (`owner_tag: str = OWNER_TAG`), `:272`
(`elif table.get("comment") != owner_tag:`);
`tools/leak-lab/vm/run_phase.py:1133` (passes `owner_token=token` but **not**
`owner_tag`);
`tools/leak-lab/netplan.py:173`/`:192` (`print("vprlab-owned:" + token)`),
`:587` (`nft create table inet vprlab "{ comment \"$OWNER\"; }"`);
`tools/leak-lab/vm/test_vm.py:802` (fixture hard-codes
`"comment": hostcheck.OWNER_TAG` while its links use
`"vprlab-owned:" + "e"*32`);
docs `docs/rust-v2/leak-lab.md:542-546` (the table comment is
`vprlab-owned:<token>`) and `docs/rust-v2/leak-lab-vm.md:63`
("the `inet vprlab` table exists with its ownership comment").

**Reproducer (real parsers, the plan's exact shapes, no privileges):**

```python
import sys, json
sys.path.insert(0, "tools/leak-lab"); sys.path.insert(0, "tools/leak-lab/vm")
import netplan as N, hostcheck as H
token = "e"*32; owner = N.OWNER_PREFIX + token
links = [
 {"ifname":"vprlab0","address":N.BRIDGE_MAC,"flags":["UP"],"ifalias":owner,
  "linkinfo":{"info_kind":"bridge"},
  "addr_info":[{"family":"inet","local":"10.250.0.1","prefixlen":24}]},
 {"ifname":"vprlab-tap0","flags":["UP"],"master":"vprlab0","ifalias":owner,
  "linkinfo":{"info_kind":"tun","info_data":{"type":"tap","persist":True}}},
]
table = {"nftables": [{"table": {"family":"inet","name":"vprlab","comment": owner}}]
         + [{"chain":{"family":"inet","name":n,"table":"vprlab"}}
            for n in H.REQUIRED_CHAINS]}
neigh = [{"dst":"10.250.0.2","dev":"vprlab0","lladdr":N.VM_WAN_MAC,
          "state":["PERMANENT"]}]
print(H.verify_host_network(links, table, neigh, owner_token=token))
# => ['nft table inet vprlab does not carry the ownership tag']
```

End to end, with `run_phase._run_json`/`subprocess.run` fed the same documents
and a real `/run/vprlab/owner.json` (schema 1, token `e`*32, 0600):

```
verify_host_lab REFUSED: nft table inet vprlab does not carry the ownership tag
```

The real plan never writes the fixed tag (`git show
e1535b8:tools/leak-lab/netplan.py | grep -c vprlab-leak-lab-m1` is 0; the M1
suite itself asserts `assertNotIn("vprlab-leak-lab-m1", plan)` at
`test_leak_lab.py:3353`). Therefore **every** `run_phase.py` invocation reaches
`verify_host_lab()` and exits 2 with the message above; no phase can produce
evidence. The current `test_vm.py` fixture is internally inconsistent (token
`ifalias` + fixed-tag table comment), so the suite passes while the shipped plan
cannot.

**Why Important, not Critical:** it fails closed; no leak is hidden and no
secret is exposed. But it is a total integration blocker and the same class as
the previous round's `opus I-1` (`alias` vs `ifalias`) and `gpt I2` (tap shape),
which were both Important. The fix is one argument:
`verify_host_lab()` should pass `owner_tag=hostcheck.OWNER_IFALIAS_PREFIX +
token` (or make the table check use `expected_ifalias`), and the fixture should
use the plan's actual comment. Add a `verify_host_lab` test that consumes
`netplan.render_plan()`'s documented shapes instead of a hand-written hybrid.

---

### I-2 — Evidence is still replaceable by the QEMU user: the root-owned evidence root sits below the opsec-owned `/DATA/vprouter-lab`, and `ensure_root_directory()` follows intermediate symlinks

**Files:**
`tools/leak-lab/vm/run_phase.py:113` (`EVIDENCE_ROOT =
/DATA/vprouter-lab/leaklab/evidence`), `:653-677`
(`ensure_root_directory`: `mkdir(parents=True)` then `os.open(... O_NOFOLLOW)`
on the **final** component only), `:1316-1321` (`_evidence_run_dir`),
`:1408-1418` (the only boundary check: refuse when the evidence path is the
state dir or below it), `:1718-1732` (quiet/stop capture; the scan block at `:1737-1795`
reads `pcap`, `stats`, `capture-argv.json`, `scan.json` by path), `:1803-1806`
(hashes the same paths).
Docs `docs/rust-v2/leak-lab-vm.md:88-92` claim the root-owned evidence means
"an opsec process (or an escaped guest) cannot substitute it between capture
and scan".

**Host fact:** `stat -c '%U %G %a %n' /DATA/vprouter-lab` →
`opsec opsec 700 /DATA/vprouter-lab`. The QEMU user owns the parent of
`leaklab/`, so it can rename the whole `leaklab` tree (rename needs write on
the parent, which it has) at any time, including after `_evidence_run_dir()`
created it.

**Reproducer (path-following, no privileges):**

```python
import pathlib, sys, tempfile
sys.path.insert(0, "tools/leak-lab/vm")
import run_phase as RP
anc = pathlib.Path(tempfile.mkdtemp())
(anc/"elsewhere").mkdir()
(anc/"link").symlink_to(anc/"elsewhere")
RP.ensure_root_directory(anc/"link"/"evidence")
print((anc/"elsewhere"/"evidence").is_dir())   # True: intermediate symlink followed
```

The substitution primitive then follows the code's own path-based reads:
opsec renames `/DATA/vprouter-lab/leaklab` and recreates
`leaklab/evidence/<run>` with a forged `capture.pcap` (the two controls plus
allowed WireGuard frames), a matching `capture.pcap.stderr`, and
`capture-argv.json`. The runner's `wait_for_control_in_pcap()` (finally step 3),
`pcapscan --pcap ... --tcpdump-stats ... --capture-argv-file ...` and
`sha256_file(pcap)` all resolve the original path into the forged tree, so the
scan is PASS and `phase.json` records the forged hashes. The run-directory name
is in the root tcpdump argv (`/proc/<pid>/cmdline`, world-readable); an escaped
guest (the documented adversary for the QEMU sandbox) can read the nonces from
its own `/proc` because the control command is a `python3 -c` string containing
the nonce. This is a plausible false-PASS chain under the same escaped-guest
threat model the docs use, not a live exploit I executed.

**Why Important:** it is the remaining half of the prior `pi I9` / `gpt I3` /
`opus I4` finding, which asked for a "trusted root-owned control/evidence
boundary" and "validate ancestor ownership". Moving evidence out of
`vm-<NNN>/` did not make the ancestor stable, and the docs' "cannot substitute
it" sentence is now false. A complete fix needs a root-owned ancestor (for
example `/var/lib/vprlab/evidence` or a root-owned `/run` tree), descriptor-
relative creation (`openat` from a root-owned fd, `O_NOFOLLOW|O_EXCL` for every
component), and scanning/hashing from file descriptors opened before the
capture, or a copy of the pcap/stats/argv into a root-only directory that opsec
cannot rename.

---

### I-3 — Guest-controlled QGA error descriptions still reach a host log line (prior `gpt I10` not fixed)

**Files:**
`tools/leak-lab/vm/qga.py:179-185` (the error message is
`f"guest agent error {klass}: {description}"` with `description =
_bounded_guest_text(error.get("desc", ""))`), `:205`
(`raise QGAError(f"{name}: {exc}")`);
`tools/leak-lab/vm/login_url.py:97` (`print(f"login_url: {exc}", file=sys.stderr)`);
`tools/leak-lab/vm/test_vm.py:274-287` (the test asserts only that control
characters are removed and the length is bounded; it does not assert the
sentinel is absent).
Docs `docs/rust-v2/leak-lab-vm.md:359-361` say the text is "stripped of control
characters and truncated to 200 printable characters before it can reach an
exception or log line" — it still reaches.

**Reproducer (pure parser):**

```python
from qga import QGAClient, QGAError
c = QGAClient("/not-connected")
c._buffer = b'{"error":{"class":"GenericError","desc":"PRIVATE-KEY-SENTINEL"}}\n'
try:
    c._read_response(0)
except QGAError as exc:
    print(exc)
# => guest agent error GenericError: PRIVATE-KEY-SENTINEL
```

**Why Important:** the prior `gpt I10` asked to map remote errors to bounded,
locally defined diagnostics and not to print guest-provided class/description.
The current code sanitizes but still renders the guest text. The runner itself
records only `phase_exception:QGAError` (no message) in `phase.json`, and its
`main` catch-all is not reached by QGA errors inside the phase try, so the
practical sink is `login_url.py` (which runs as root and prints the message) and
any future caller. A compromised guest can place profile or Tailscale-state
bytes in `desc`; `login_url.py` then writes them to the operator's terminal/log.
The helper refuses while a phase holds the lock, but an orphaned QEMU (a crash
before `poweroff_vm`) leaves the lock free and the guest reachable. Either
redact the description (map known classes to local strings) or stop printing
`str(QGAError)` in the helper; add a test that a sentinel is absent.

---

## Minor

1. **M-1 — Reboot postcondition is recorded but never consumed.**
   `run_phase.py:1533-1541` stores
   `postcondition.exitcode = 0 if boot_id_changed else 1`, but no `note()` or
   result transition reads it. `wait_for_reboot()` (`:1016-1050`) normally
   guarantees a changed boot ID, so this is unreachable in a healthy run; with
   the default `HarnessQGA` (one boot ID) the reboot phase returns
   `exit 0 / result PASS` with `boot_id_changed: false` and
   `postcondition.exitcode: 1`. Treat a nonzero boot postcondition as
   `note("postcondition_failed")` for defence in depth.

2. **M-2 — A non-dict `scan.json` with pcapscan exit 0 yields PASS with
   `scan.verdict: null`.** `run_phase.py:1775-1795` only runs the
   verdict/exit/nonce cross-checks when `isinstance(report, dict)`; a file
   containing `[]` (or any non-object) skips them, and `:1821` then returns
   PASS because `scan_exit == 0` and `errors` is empty. Reproduced with the real
   `run_phase` and a fake scanner returning `[]`/0:
   `exit 0 result PASS scan.verdict None errors []`. pcapscan itself always
   emits a dict on exit 0, so this is a hardening/evidence-substitution gap, not
   a normal-run bug; an unparseable report should be
   `note("scan_report_invalid")` → INVALID.

3. **M-3 — `restart-docker` PASS does not require the router to recover, and
   `start-router` PASS does not require Tailscale READY.** The docs' phase table
   narrows the claims to "new Docker PID + `docker info`" and "unit active +
   handshake", so the code matches the docs; but a `restart-docker` phase can
   PASS with the router container dead (the unit is `PartOf=docker.service` and
   may fail to restart), and a `start-router` phase can PASS on a `BLOCKED`
   node. Record/require `docker inspect State.Running` after the restart and
   the release's health (`/run/vprouter-health.json` or
   `router_runtime --status`) for the phases that claim a working exit node.

4. **M-4 — `_stage_payload()` chmods the operator's hard-linked image tar.**
   `provision.py:180-188` hard-links `--image-tar` into the staging tree and
   then `os.chmod(path, mode | 0o444)` on every staged file. Hard links share
   the inode, so a root-owned `0600 /root/vprouter-image.tar` becomes `0644`
   (verified in a temp tree: before `0600`, after `0644`, same inode). That is
   a root mode change outside the lab; it also means a `0600` tar only becomes
   readable by `genisoimage` because the source is modified. Copy when the
   source is not readable by the QEMU user, or stage a private copy and leave
   the operator file untouched.

5. **M-5 — The M2 doc's host-prerequisite section is stale and its evidence
   claim is false.** `docs/rust-v2/leak-lab-vm.md:45-46` says the M1 plan
   "does not set a stable bridge MAC or the VM neighbour"; the current plan sets
   the MAC at `netplan.py:576` and installs the neighbour at `:620` (the extra
   commands at `:50-57` are now redundant). The same doc does not mention that
   `run_phase.verify_host_lab()` requires `net.ipv4.ip_forward == 1`
   (`run_phase.py:1101-1105`), which the M1 doc does mention. The "cannot
   substitute it between capture and scan" sentence at `:88-92` is contradicted
   by I-2.

6. **M-6 — The M1 plan's default capture/stats files are relative to the CWD.**
   `netplan.py:55` (`DEFAULT_CAPTURE = "vprlab-capture.pcap"`) and
   `render_plan()`'s `stats_file = capture_file + ".stderr"` mean running the
   documented `./lab.sh` from the repository writes `vprlab-capture.pcap` and
   `.stderr` into the opsec-owned checkout as root. The e1535b8 commit fixed
   this only for the stubbed tests; the plan's documented example
   (`docs/rust-v2/leak-lab.md:595-598`) does not tell the operator to run in a
   scratch directory or pass an absolute `--capture-file`.

7. **M-7 — The scanner report is not hash-bound to the files the runner
   keeps.** `run_phase.py:1799-1806` hashes the pcap/stats/argv *after* the
   scan but never compares them with the report's
   `source_sha256`/`stats_sha256`/`capture_argv_sha256`/`policy_sha256`; a
   substitution between the scan and the hash is invisible. `run_phase.py:1724`
   also records `record["tcpdump_exit_status"]` without noting a stop-capture
   timeout/SIGKILL (the stats file usually catches an incomplete summary, and a
   complete summary after a SIGKILL is not itself invalid, but the timeout
   should be recorded). Bind the report to the files (hash before the scan and
   compare afterwards), and note a nonzero tcpdump stop status.

8. **M-8 — `profile_endpoint()` diverges from the release's `configparser`.**
   `run_phase.py:194-230` splits only on `=`, is case-insensitive for the
   section/key, and does not strip inline comments; `orchestrate._provider`
   uses `configparser` (also `:` separators, duplicate-key errors). Every
   divergence I found fails closed (refusal), but a valid profile using
   `Endpoint: 1.2.3.4:51820` would be refused. Use the same parser or document
   the narrower grammar.

9. **M-9 — `login_url.py` releases the run lock before connecting.**
   `login_url.py:82-98` calls `runlock.ensure_unlocked()` (acquire + release),
   then `wait_for_qga()`; a phase can acquire the lock and open the single QGA
   stream in between, so the helper can still contend. The window is narrow and
   the helper exits 2 on timeout; hold the lock across the connection or
   document the race.

10. **M-10 — The `record["setup"]["active"]` field is `None` for
    `start-router`.** The action's `wait_router_ready()` success is not written
    to `record["setup"]["active"]` (`run_phase.py:1597-1635`), although the
    docs' phase table calls "unit active and a handshake" the proof. The
    effective result is correct (a failure notes `router_not_ready`), but the
    record is less explicit than for the setup phases.

11. **M-11 — M2 doc says the profile is never "copied into the state
    directory".** `docs/rust-v2/leak-lab-vm.md:351-353`; the profile is written
    to the guest's `/etc/vprouter/<name>.conf`, which is the qcow2 in the
    opsec-owned state directory. The Limits section (`:93`) acknowledges the
    qcow2 becomes secret-bearing; the Secrets bullet should say the same.

12. **M-12 — `iptables -C` failure is treated as "rule absent".**
    `netplan.py:454-475` (`while iptables -C DOCKER-USER ...; do ... done`) and
    the generated teardown's `remove_docker_out/in`: if `iptables -C` fails for
    a reason other than "no such rule" (backend error, missing binary), the
    loop does not run, returns 0, and teardown proceeds to delete the table and
    links while the stale DOCKER-USER rules remain. They reference a deleted
    `vprlab0`, so they are inert, but "removed exactly" is not proven. Check
    the `-C` exit status distinguishes 1 (absent) from other errors, or use
    `iptables-save` to verify absence.

---

## Integration end to end (the requested checklist)

I checked the runner↔monitor contract with the real generators/parsers and a
real pcapscan subprocess, plus behavioural fakes for the runner.

| Contract | Result |
|---|---|
| `owner.json` schema/token; per-run `ifalias` on both links | **works**: plan writes `{"schema":1,"token":"<32hex>","created":...}` 0600; runner `load_owner_token()` requires schema 1/32 hex/0600/root; both links carry `vprlab-owned:<token>`; the runner's `expected_ifalias` matches. |
| nft table ownership comment | **broken**: plan writes `vprlab-owned:<token>`; runner requires `vprlab-leak-lab-m1` → **I-1**. |
| Fixed MACs / static neighbours | **works**: `guest.VM_MAC/GATEWAY_MAC/VM_IPV4/GATEWAY_IPV4` equal `netplan.BRIDGE_MAC/VM_WAN_MAC/VM_WAN_IPV4/BRIDGE_ADDRESS`; plan sets the bridge MAC before enslaving and installs `ip neigh replace 10.250.0.2 ... nud permanent`; runner requires the bridge MAC, tap master, `PERMANENT` neighbour with the VM MAC. |
| Policy built from the profile Endpoint | **works**: `build_lab_policy()` emits exactly one UDP flow = the endpoint, `allow_arp:false`, the fixed facts, `gateway_mac`, sink 39001; `verify_policy()` refuses an extra flow/wrong endpoint. `pcapscan.py --policy <that file>` with a control+WG pcap returns PASS/0; a renamed `-w` returns INVALID `capture_argv_mismatch`. |
| Capture argv / `-w` / banner / stats | **works**: `guest.tcpdump_argv()` equals `netplan.capture_argv()` except the absolute `-w`; `check_capture_argv()` ignores only `-w` and requires `realpath(-w) == --pcap`; the banner check is anchored to the first non-empty line and rejects extra `listening on` lines; the stats parser parses every multi-line and one-line summary, requires `captured == received`, zero drops, non-decreasing counters and the final `captured == records`. |
| `--expect-tunnel` table | **works**: `PHASE_EXPECTATIONS` is fixed (all `up`); the runner passes it to pcapscan; setup starts the router inside the window and requires exit 0 + a real `wg show wg0 latest-handshakes`; fault phases add in-guest postconditions. Residual M-3 (READY/recovery not required). |
| Control nonces: before via QGA or boot unit, after via QGA | **works**: `fresh_pair()` + `append_used_nonces()` (0600, `O_NOFOLLOW`); `emit_control()` uses `control.build_command()` (SO_BINDTODEVICE, bind `10.250.0.2`); the reboot phase stages the nonce in `/var/lib/vprlab` for the one-shot boot unit and verifies the boot token/sent file; AFTER is always QGA. `pcapscan` requires exactly one sighting of each. |
| Order: AFTER → router stop → poweroff → QEMU exit → AFTER-in-pcap → 2 s quiet → SIGINT → scan | **works**: the finally does exactly this; the test asserts the order; a forced poweroff/QEMU exit/capture-stop failure is INVALID and phase.json is still written. |
| Scan binding and precedence | **works**: `pcapscan.py` argv includes `--policy`, `--pcap`, `--tcpdump-stats`, `--capture-argv-file`, `--expect-tunnel`, both nonces; the runner cross-checks the report's verdict/exit and control nonces; LEAK keeps precedence; any other error is INVALID; stdout prints `result`/`verdict` = the effective result and `scan_verdict` = the raw scanner verdict. Residual M-2/M-7. |

---

## False-PASS hunt

- **Scanner sequence fuzz:** 16,104 sequences of length 1–4 over
  `{before, after, WG-out, WG-in, DNS leak, legit ARP, foreign-IP frame, TCP,
  ICMP, IPv6, first fragment}` × `{any, up, down}` = 48,312 evaluations. Every
  sequence containing a real leak frame returned `LEAK`; no PASS without an
  ordered before/after control pair. The ARP frame was the only non-leak in the
  alphabet with `allow_arp:true`; with `allow_arp:false` it is
  `arp_not_allowed`.
- **Monitor blind spots:** `up` is satisfied only by both directions on the same
  allowed label inside the window; VM-emitted inbound-shaped frames,
  VLAN-tagged frames and different relays are `LEAK` (`allowed_tuple_wrong_l2`
  / `udp_not_allowed`); controls cannot satisfy `up`; ARP cannot satisfy `up`;
  out-of-window leaks are `LEAK`; a replayed/unexpected control is `LEAK`; a
  missing control is `INVALID`. No leak-hidden PASS found.
- **Runner C1/C2:** the behavioural battery above (action/setup/postcondition/
  cleanup/capture/QEMU/signal) always produced INVALID unless the scan was
  LEAK; the only PASS was the clean baseline. The scan report's verdict/exit
  mismatch is INVALID.
- **Remaining false-PASS paths:** I-2 (evidence substitution under opsec),
  M-2 (non-dict scan report with exit 0), M-1 (unconsumed boot postcondition
  under a fake agent). I-1 is a false-INVALID/blocker, not a false PASS.
- **Phase-certified-without-behaviour:** the setup phases require a real
  handshake and an in-guest postcondition; `stop-router` requires the unit
  inactive, `kill-wireguard` requires `wg0` absent, `kill-container` requires
  the container not running, `restart-docker` requires a new daemon PID and
  `docker info`. The `restart-docker`/`start-router` residuals are M-3.
- **Leak not captured/not scanned:** the capture starts before QEMU, survives
  the router stop and QEMU exit, includes the teardown, and is scanned even on
  failure; a missing pcap/stats/argv/scan report is INVALID. The only way to
  lose the capture is the evidence-path substitution (I-2).

## Secrets

- The WireGuard profile is read once (`read_profile_fd`/`read_profile_path`,
  root-owned 0600, no symlink), held in `SecretMaterial` (redacted `repr`),
  only the `[Peer] Endpoint` is decoded, and only the bytes are written to the
  guest through QGA. It is never in argv, `phase.json`, stdout or the evidence
  directory; the `policy.json` contains only the endpoint. The qcow2 becomes
  secret-bearing (documented).
- The login URL is written to `login-url.txt` 0600 and printed to stderr; the
  runner's `login` phase uses its own QGA connection (the helper refuses while
  the lock is held). No Tailscale state is printed.
- The remaining exposure is I-3: guest-controlled QGA error text is rendered by
  `login_url.py`; a compromised guest can put profile/Tailscale bytes there.
  The runner itself records only the exception class.
- `provision`'s serial marker / guest text is stored in `provision.json`; the
  provision guest has no profile/Tailscale state.

## Host safety

- QEMU runs as the unprivileged user via `setpriv --reuid/--regid
  --clear-groups --no-new-privs --inh-caps=-all --bounding-set=-all`, with
  `-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny`,
  `-nodefaults`, `-no-user-config`, no QMP, one NIC (tap in test mode, user
  netdev in provision mode), `-m 512 -smp 1`. `--qemu-user root` is refused
  before any process starts. A single global `flock` serialises both runners
  (and makes `login_url` refuse while a phase holds it; see M-9 for the
  check/connect race).
- `qemu-img`/`genisoimage` and every qcow2 parse run as the QEMU user, never as
  root (`verify_state`, `provision._run_generator`).
- The host plan touches only `vprlab0`, `vprlab-tap0`, `inet vprlab`, Docker's
  `DOCKER-USER` chain (two exactly tagged inserts) and the lab neighbour; no
  `flush`, no global sysctl write (`ip_forward` is printed, never changed), and
  IPv6 sysctls are device-scoped. Teardown verifies ownership before any
  mutation, isolates the tap and reads back `down`+detached before deleting the
  table/rules, removes duplicates until absent, and keeps `owner.json` on
  failure. The stubbed shell runs confirmed all of this, including the Ctrl-C
  trap.
- Residual host-safety items: I-2 (root evidence below an opsec-owned
  ancestor), M-4 (hard-link chmod of the operator tar), M-6 (default capture in
  the CWD), and M-12 (`iptables -C` error treated as absent). No OOM risk was
  found: one 512 MiB guest, the lock covers admission, and no second QEMU can
  start through the lab.

## Docs vs code

1. `docs/rust-v2/leak-lab-vm.md:63` "the `inet vprlab` table exists with its
   ownership comment" vs the runner's fixed-tag check (I-1); the M1 doc
   `:542-546` correctly says `vprlab-owned:<token>`.
2. `docs/rust-v2/leak-lab-vm.md:88-92` "an opsec process ... cannot substitute
   it between capture and scan" vs I-2.
3. `docs/rust-v2/leak-lab-vm.md:45-46` "does not set a stable bridge MAC or the
   VM neighbour" vs `netplan.py:576`/`:620` (M-5); the doc also omits the
   `ip_forward == 1` prerequisite.
4. `docs/rust-v2/leak-lab-vm.md:351-353` "never ... copied into the state
   directory" vs the guest write to the qcow2 (M-11).
5. `docs/rust-v2/leak-lab-vm.md:359-361` "stripped ... before it can reach an
   exception or log line" — it still reaches (I-3).
6. `docs/rust-v2/leak-lab.md:595-598` capture example uses a relative `-w` from
   the CWD (M-6).
7. The M2 test count (96) and the M1 suite (239) match the actual runs; the M2
   doc's `--tap/--bridge` fixed, `--expect-tunnel` table, `poweroff_vm` 180 s,
   `install_guest_file` non-atomic move, staging-boot capture and
   `ControllerDecisionTests` notes are accurate.

## Verified-good (adversarial checks that produced no false PASS)

- **Stats:** multi-line and one-line `received`>captured and `<captured` →
  `unread_capture_tail`; `captured`≠records → `stats_packet_count_mismatch`;
  nonzero kernel/interface drop in any summary → `packet_drops`; missing
  counters → `stats_incomplete`; conflicting/decreasing counters →
  `stats_contradictory`; `pcap_loop`/`went down`/`permission denied` →
  `stats_error_line`; a counter-shaped malformed line → `stats_unparseable`;
  empty stats → INVALID; a legitimate mid-run one-line smaller than the final
  multi-line → PASS.
- **Banner/argv:** wrong interface, non-Ethernet link type, banner not first,
  duplicate banner, banner text in a later line, extra BPF filter, missing
  `-U`/`-nn`/`--immediate-mode`, `-s 96`, wrong interface, duplicate `-w`,
  empty/non-list argv, and a `-w` that does not realpath to `--pcap` → INVALID.
- **Controls/window:** missing before/after → INVALID; equal nonces → ValueError
  (CLI exit 2); reversed timestamp order → `non_monotonic_timestamps`; equal
  control timestamps → `control_order`; replayed/unexpected/malformed control →
  LEAK; out-of-window leaks → LEAK; out-of-window allowed flows → PASS with
  packet indexes; keepalives before A/after B → PASS.
- **Tunnel:** `up` with out+in in-window → PASS; out-only/in-only → INVALID;
  different relays → LEAK; VM-emitted/VLAN-tagged inbound → LEAK
  (`allowed_tuple_wrong_l2`); ARP/controls cannot satisfy `up`; `down` with an
  inbound anywhere → INVALID; `down` controls-only/outbound-only → PASS
  (documented).
- **ARP:** VM/foreign MAC claiming the gateway IP → LEAK; gateway MAC claiming
  the VM IP → LEAK; Ethernet/ARP sender mismatch → LEAK; unsupported
  htype/ptype/opcode → LEAK; legit request/reply → PASS; `allow_arp:false` →
  every ARP is a finding.
- **Fragments:** outside-window, equal-to-marker and in-window unfinished
  allowed datagrams → `fragment_incomplete`; replaced/stale/orphan/overlap/gap/
  out-of-range/zero-payload/duplicate-final → LEAK; structural truncation →
  INVALID (finalisation skipped).
- **Policy:** RFC1918/CGNAT/Tailscale/loopback/link-local/multicast/reserved/
  test-net destinations rejected; ports 53/853/123/5353/5355 rejected;
  `gateway_ipv4 != 10.250.0.1` rejected; `gateway_mac` required/unequal to the
  VM MAC; non-unicast/zero MAC rejected; sink must equal the gateway; duplicate
  labels/endpoints and control overlap rejected; `ipv6_allowed` must be literal
  false; duplicate JSON keys/non-finite numbers rejected; proto must be `udp`.
- **Runner C1/C2:** see the closure table; the `run_phase` battery always
  returned INVALID for setup/action/postcondition/cleanup/capture/QEMU faults,
  and LEAK when the scanner said LEAK.
- **Runner lifecycle:** `runlock` refusal, `refuse_if_qemu_running` under the
  lock, uid-0 refusal, no QMP, signal handler, per-step finally, phase.json on
  failure, stdout/record agreement, evidence-inside-state refusal, qemu-log
  symlink refusal, `qemu-img`/generators as the QEMU user, cloud-init 25.x
  silence checks, `ip -4 -o neigh show dev`, boot-control persistence, tap
  shape/master, `login_url` lock refusal and login-phase URL polling.

## Limits of this review

- No live QEMU, tcpdump, tap, nft, iptables, Docker or network command was
  executed. The runner/monitor reproducers use the real generators/parsers,
  real pcapscan subprocesses and behavioural fakes; the generated host script
  was executed only with every privileged command stubbed in
  `/var/tmp/leaklab-comb-pi`. The tcpdump "no verbose line with `-w`" premise is
  reasoned from the 4.99.5 strings/source knowledge, not observed.
- The I-2 substitution is a demonstrated path primitive plus a plausible
  escaped-guest chain, not a live exploit; the I-1 refusal is demonstrated end
  to end with the real `verify_host_lab` and the plan's exact shapes.
- The `inet vprlab` nft JSON table-comment field and the Docker FORWARD/DOCKER-
  USER accept finality remain reasoned from the man pages and prior reviews,
  not observed live.
- Scratch `/var/tmp/leaklab-comb-pi` was removed; the only repository file
  written by this review is this report.
