# Leak-lab M3 — independent adversarial review (Pi)

Commit reviewed: `b849e3c` (`git diff 888f0d4..b849e3c`, 16 files, +5502/-243).
Binding design: `docs/rust-v2/leak-lab-m3-clients.md` (read fully).
Implementation report: `.superpowers/sdd/rust-v2/leak-lab-m3-impl-report.md`.
Context: `docs/rust-v2/leak-lab.md`, `leak-lab-vm.md`,
`.superpowers/sdd/rust-v2/progress.md` (last lines).

Method: source read of every changed file, then targeted reproducers run under
`/var/tmp/leaklab-m3-pi` against the committed tree (extracted with
`git archive b849e3c`), using crafted pcaps, forged tcpdump stats/argv files,
crafted probe logs, the generated shell with the existing stub `ip`/`nft`/
`iptables` harness, and the existing fake-QGA `RunPhaseTests` harness.  No
privileged command, network execution, QEMU, tcpdump, `ip`, `nft`, `iptables`,
Docker or user management was run.  No file outside this report and the scratch
directory was changed; scratch was deleted at the end.

## Test runs (as required)

- `cd tools/leak-lab && python3 -B -W error -m unittest test_leak_lab`
  → **Ran 301 tests, OK**.
- `cd tools/leak-lab && python3 -B -W error -m unittest vm.test_vm`
  → **Ran 227 tests, OK**.

Both counts match the implementation report.  The suites are green; every
finding below is a case the suites do not assert.  `git diff --check` is clean;
`py_compile` of the touched Python files is clean.

## Findings

### C1 — Critical: a phase can PASS with no client traffic during the fault (or with a stale probe log)

Evidence:

- `run_phase.py:3865` starts the transient unit, `:3872` sets
  `traffic_started = True`, `:3932-3944` holds for `--duration` and then
  `stop_client_traffic`; `traffic_started` is written but never read.
- `client_traffic_unit_active()` exists at `run_phase.py:3096` and is **never
  called** (the only occurrence in the tree is its definition).
- `start_client_traffic()` (`run_phase.py:2996-3022`) only checks that
  `systemd-run` exited zero.  `systemd-run` returns after starting the unit; it
  does not prove the script exec'd, truncated the log, or is still looping.
  The code does not delete or truncate the probe log on the host side, and does
  not require the first probe line to be newer than the traffic start.
- `wait_client_first_mullvad()` (`run_phase.py:3105-3126`) scans whatever
  `client-probe.jsonl` currently contains.  A stale log from the previous client
  phase with one `ok:true,m:true` line therefore satisfies the pre-fault
  control even when the new unit never executed.
- `clientprobe.evaluate_probe_log()` (`clientprobe.py:190-198`) returns PASS
  when there is one pre-fault Mullvad success, even if the log contains **zero**
  post-fault probes.  Zero attempted probes is not a "failure after the fault".
- `client_runtime_seconds()` (`run_phase.py:3089-3093`) gives the unit
  `duration + 120` seconds from its start.  The unit is started before the
  up-to-90-second `wait_client_first_mullvad`; a slow pre-fault wait plus a slow
  fault action (up to `ACTION_TIMEOUT=360`) can consume the 120-second margin,
  so `RuntimeMaxSec` can terminate the unit **during** the hold.  Nothing
  notices: the missing post-fault samples are counted as nothing, not INVALID.
- The committed fake test encodes this gap: `test_vm.py:5880-5886` writes only
  one pre-fault exit/marker pair; `test_vm.py:6043-6052` asserts the phase
  result is PASS.  The orchestration test never asserts a post-fault probe.

Reproducer (ran, fake two-VM harness; the patched start models a unit that
exited after its first probe, which is exactly the unobserved state):

```sh
cd /var/tmp/leaklab-m3-pi/tools/leak-lab/vm
python3 -B - <<'EOF'
import sys, pathlib
from unittest import mock
sys.path.insert(0, str(pathlib.Path.cwd()))
import test_vm, run_phase

case = test_vm.ClientRunPhaseTests(
    'test_client_idle_passes_with_both_captures_and_the_probe_log')
case.setUp()
calls = []
def fake_start(client, *, marker, https_ip, http_ip, runtime_sec):
    calls.append('start')
    # systemd-run returned 0; the unit wrote its first probe and exited.
    client.log = (b'{"t":100,"k":"exit","ok":true,"m":true}\n'
                  b'{"t":100,"k":"marker","ok":true}\n')
    return None
with mock.patch.object(run_phase, 'start_client_traffic', side_effect=fake_start), \
     mock.patch.object(run_phase, 'client_traffic_unit_active',
                       side_effect=lambda c: calls.append('active') or False):
    try:
        code, record, client, events, out, err, ev = case._run('idle', 30.0)
        print('exit', code, 'result', record['result'],
              'probe', record['client']['probe']['verdict'],
              'client_combined', record['client']['combined'])
        print('start calls', calls.count('start'),
              'client_traffic_unit_active calls', calls.count('active'))
        print('probe log bytes', len((ev / 'client-probe.jsonl').read_bytes()))
    finally:
        case.doCleanups()
EOF
```

Observed:

```
exit 0 result PASS probe PASS client_combined PASS
start calls 1 client_traffic_unit_active calls 0
probe log bytes 73
```

The same verdict is produced directly by the probe evaluator:

```sh
python3 -B - <<'EOF'
import sys; sys.path.insert(0, 'tools/leak-lab'); import clientprobe
log = (b'{"t":100,"k":"exit","ok":true,"m":true}\n'
       b'{"t":100,"k":"marker","ok":true}\n')
print(clientprobe.evaluate_probe_log(log, fault_epoch=101)['verdict'])
EOF
# PASS
```

Impact: the phase's only certification ("client traffic through the test exit
node while the fault runs") can be issued without any traffic during the fault.
A crashed unit, a unit that exited after its first probe, or a stale log yields
PASS.  This is the false-PASS class the review treats as critical.

Suggested fix:

1. QGA `rm -f` the probe log before `systemd-run`, and require the first new
   line's `t` to be at/after the host-recorded traffic start (or require the
   script to write an explicit start marker).
2. Require the unit to be active immediately after start and at least once near
   the end of the hold (`client_traffic_unit_active` already exists); record
   the result and make false INVALID.
3. Require at least one probe line (exit or marker) with `t > fault_epoch`
   after the fault; a phase whose client never tried a post-fault probe is
   INVALID, not PASS.
4. Compute `RuntimeMaxSec` from `duration + CLIENT_ROUTED_TIMEOUT +
   ACTION_TIMEOUT + margin`, or stop the unit only after collection; do not let
   a self-timeout silently end the traffic window.
5. Add tests: zero post-fault lines -> INVALID; stale pre-fault log with a
   failed unit -> INVALID; `client_traffic_unit_active` false -> INVALID.

### I1 — Important: “right peer” exit-node check accepts any active exit node through the `Self.ExitNode` fallback

Evidence: `run_phase.py:2925-2954`.  If `ExitNodeStatus` is present but names a
different peer, the function falls through to `Self.ExitNode is True` and
returns True.  A different exit node (including a production Mullvad exit) can
therefore satisfy `wait_client_exit_node`; the pre-fault probe then reports
`mullvad_exit_ip: true` through that node, not through the test router, and the
phase can PASS.  `clear_client_exit_node()` (`run_phase.py:2971-2978`) also only
checks the command exit code; it never waits for `Self.ExitNode` to become
false, so a persisted exit node is not proved cleared.

Reproducer (ran):

```sh
python3 -B - <<'EOF'
import sys
sys.path.insert(0, 'tools/leak-lab/vm'); sys.path.insert(0, 'tools/leak-lab')
import run_phase
peer = {"ID": "test-router", "HostName": "zz-vprtest-01-do-not-use",
        "ExitNodeOption": True, "Online": True, "TailscaleIPs": ["100.64.0.9"]}
status = {"ExitNodeStatus": {"ID": "production-exit-node", "Online": True,
                             "TailscaleIPs": ["100.64.0.99"]},
          "Self": {"ExitNode": True, "ExitNodeOption": False}}
print(run_phase.client_peer_is_active(status, peer))
EOF
# True
```

Impact: a client routed through another Mullvad exit (or a stale/wrong exit
node) certifies the test router's exit path without using it.  This is a false
PASS on the peer binding, although a normal `tailscale set` usually makes the
status match.

Suggested fix: require `ExitNodeStatus.ID` (or one of the exact expected
Tailscale IPs) to match; if `ExitNodeStatus` names another peer, return False;
remove the bare `Self.ExitNode is True` fallback or only accept it when
`ExitNodeStatus` is absent **and** the status also reports the expected peer.
After clearing, wait for `Self.ExitNode` false / `ExitNodeStatus` absent before
sending the before-control and before the after-control.

### I2 — Important (host safety): a teardown rendered without `--client` deletes the shared nft table and owner record but leaves `vprlab1`, the client tap, neighbour and client DOCKER-USER accepts behind

Evidence: teardown coverage is entirely a function of the render-time
`clients` argument.  `render_plan()` adds the client helpers/verify/delete
blocks only when `client_indices` is non-empty (`netplan.py:955` onward;
`CLIENT_VERIFY` at `netplan.py:621`, `CLIENT_*_DEL` at `:1139-1154`).
`owner.json` contains only the token, not the client set (`_CREATE_OWNER_CODE`
contains `{"schema":1,"token":...,"created":...}`).  A no-client teardown
therefore:

- verifies only the router tap/bridge/table/neighbour (`netplan.py:583-622`);
- deletes the shared `inet vprlab` table (`:751-764`), which contains the
  `vprlab1` input/forward/output drops and the scoped masquerade;
- removes only the router DOCKER-USER rules (`:744-746`), leaving the two
  client `DOCKER-USER` accepts;
- removes `owner.json` (`:771-774`), so a later `--client` teardown cannot read
  the token and refuses.

Reproducer (ran with the existing stub harness; setup with a client plan, then
teardown with a no-client plan and the same owner/state):

```sh
cd /var/tmp/leaklab-m3-pi/tools/leak-lab
python3 -B - <<'EOF'
import pathlib, tempfile, sys
sys.path.insert(0, '.')
import test_leak_lab as T, netplan
case = T.ClientNetplanTests('test_router_plan_is_unchanged_without_clients')
run = T.NetplanTests._run_lab
with tempfile.TemporaryDirectory() as d:
    result, log, state, owner = run(case, pathlib.Path(d),
        netplan.render_plan('eth0', clients=(1,)), {}, args=('setup',))
    print('setup rc', result.returncode, 'links', sorted(state['links']))
    owner_bytes = owner.read_bytes()
with tempfile.TemporaryDirectory() as d2:
    root2 = pathlib.Path(d2); (root2 / 'run').mkdir()
    (root2 / 'run' / 'owner.json').write_bytes(owner_bytes)
    result, log, after, owner2 = run(case, root2,
        netplan.render_plan('eth0'), state, args=('teardown',))
    print('teardown rc', result.returncode)
    print('links', sorted(after['links']))
    print('rules', after['rules'])
    print('neigh', after['neigh'], 'owner exists', owner2.exists())
EOF
```

Observed:

```
setup rc 0 links ['vprlab-ctap1', 'vprlab-tap0', 'vprlab0', 'vprlab1']
teardown rc 0
links ['vprlab-ctap1', 'vprlab1']
rules ['DOCKER-USER -i vprlab1 -o eth0 -s 10.251.0.0/24 ... -j ACCEPT',
       'DOCKER-USER -i eth0 -o vprlab1 -d 10.251.0.0/24 ... -j ACCEPT']
neigh {'10.251.0.2': {'lladdr': '52:54:00:76:71:02', 'permanent': True}}
owner exists False
```

Impact: the client bridge/tap and its Docker accepts remain while the nft
input/forward/output protections for `vprlab1` are gone.  A client VM still
attached (or later booted on the stale tap) is no longer isolated from host/WAN
paths; production objects are not deliberately touched, but the host’s
protections for the lab are removed.  The missing owner record also blocks the
tool from cleaning the leftovers.

Suggested fix: record the created client indices/taps/bridge in `owner.json`
(or an owned-object inventory); on teardown, if any owned client object exists
that is not covered by the rendered plan, either remove it or refuse **before**
deleting the shared table and owner.  Do not remove `owner.json` while an owned
object remains.  Add a stub test for the mismatched-client-set teardown.

### I3 — Important: admission does not reserve both captures or both overlays

Evidence: `check_admission()` (`run_phase.py:1875-1915`) reserves
`capture_size_cap + 1 GiB` for the evidence filesystem and
`OVERLAY_VIRTUAL_SIZE + 1 GiB` for the state filesystem.  A client phase has
**two** captures of the same cap and **two** overlays (router 4 GiB + client
2 GiB); the client call at `run_phase.py:3384-3389` passes only
`client_memory_mib`.  The `CaptureGuard` checks each capture separately, and
does not measure the state filesystem at all.

Reproducer (ran):

```sh
python3 -B - <<'EOF'
import sys, pathlib
sys.path.insert(0, 'tools/leak-lab/vm'); sys.path.insert(0, 'tools/leak-lab')
import run_phase, guest
root = pathlib.Path('/var/tmp'); GiB = 1024**3
run_phase.check_admission(root, 2*GiB, state_root=root, mem_available=8*GiB,
    free_bytes=2*GiB+GiB, state_free_bytes=5*GiB,
    client_memory_mib=guest.CLIENT_MEMORY_MIB)
print('admitted 5 GiB state; two overlays need 4+2+1 = 7 GiB')
run_phase.check_admission(root, 2*GiB, mem_available=8*GiB,
    free_bytes=3*GiB, client_memory_mib=256)
print('admitted 3 GiB evidence; two captures need 4+1 = 5 GiB')
EOF
```

Observed: both admissions succeed.  Impact: a client phase can start with
insufficient state/evidence space for the two guests, risking host-filesystem
exhaustion before the per-capture guard sees the evidence-side low-water mark;
this is a host-safety/resource-admission gap for the two-guest design.

Suggested fix: add a client overlay size and a capture-count argument to
`check_admission`; reserve `OVERLAY_VIRTUAL_SIZE + CLIENT_OVERLAY_VIRTUAL_SIZE +
DISK_HEADROOM` on state and `2*capture_size_cap + DISK_HEADROOM` on evidence;
add tests at the exact boundary.

### M1 — Minor: the client forward accepts are interface-scoped, not source-scoped

`netplan.py:1049-1050` emits

```
nft add rule inet vprlab forward iifname "vprlab1" oifname "<wan>" accept
nft add rule inet vprlab forward iifname "<wan>" oifname "vprlab1" accept
```

without `ip saddr 10.251.0.0/24` / `ip daddr`.  The postrouting masquerade
(`:1052`) and the Docker rules (`:1055-1056`) are subnet-scoped, but the nft
accept is not.  On this host Docker’s FORWARD policy/DOCKER-USER scoping may
still block a spoofed source, but the binding design says “NAT/forward scope
limited to 10.251.0.0/24 and the WAN”.  A compromised client could emit a
spoofed source toward the WAN where the Docker path is absent/changed.
Suggested fix: add `ip saddr 10.251.0.0/24` to the outbound accept and
`ip daddr 10.251.0.0/24` to the return accept; add a plan test.

### M2 — Minor: the no-client plan is not byte-identical to the M2 plan, contrary to the code/doc claim

`netplan.py:1185-1189` claims the no-client plan is “the unchanged router
plan, down to its formatting”, and `docs/rust-v2/leak-lab.md` says “exactly the
unchanged M2 router plan”.  Rendering old and new no-client plans shows length
20607 vs 20613 and extra blank lines at every removed `@@CLIENT_*@@`
placeholder; the commands are identical only after dropping blank lines.
`test_router_plan_is_unchanged_without_clients` (`test_leak_lab.py:4834`) only
checks for the absence of `vprlab1`/`vprlab-ctap`/`10.251.0`, not equality.
This is cosmetic for execution but the claim/test name are inaccurate.
Suggested fix: render the no-client plan from the old template path or compare
against a stored fixture ignoring blank lines, and correct the claim.

### M3 — Minor: `clientprobe.py` documents the wrong probe-log path

`clientprobe.py:5` says `/var/lib/vprouter/client-probe.jsonl`; the actual
path is `/var/lib/vprlab/client-probe.jsonl` (`guest.py:84`,
`guest.client_traffic_script_text()`).  Contract documentation only; fix the
docstring.

### M4 — Minor: the design’s before-control order is not the code order

The design step 3 says clear the exit node, send the client before-control, and
then (step 4) wait for `BackendState == Running`.  The code does
`clear_client_exit_node()` at `run_phase.py:3758`, `wait_client_running()` at
`:3759`, and only then sends the before-control at `:3766-3772`.
Functionally the control is still before the router/fault and is sent with
`SO_BINDTODEVICE`, so it remains clear; but the implementation report/docs do
not flag this ordering deviation.  Either move the before-control before
`wait_client_running` (as designed) or document the change.

### M5 — Minor: client-scan controls are raw-substring matches, not the client UDP 5-tuple

`clientscan.py:74-85` and `:213-225` accept any frame on the client tap that
contains `VPRLEAKCTL1:<nonce>`, regardless of source/destination MAC/IP,
protocol or port.  The design says the control is a UDP datagram from the
client to `10.251.0.1:39001`; a frame with the nonce from another source, or
from the host, would satisfy the scanner.  The nonce is fresh and the client is
the only sender, so this is defense-in-depth; suggested fix: parse the Ethernet
frame and require the client MAC/IP, UDP, destination `10.251.0.1:39001`, and
payload exactly `VPRLEAKCTL1:<nonce>`.

### M6 — Minor: the client scanner does not bind the pcap snaplen to the `-s 0` argv

`pcapscan.iter_pcap_records` rejects records whose `incl_len < orig_len` and
`incl_len > snaplen`, but neither `clientscan` nor `pcapscan` compares the pcap
global-header snaplen with the `-s 0` capture argv.  A crafted pcap with a
small snaplen and consistent `orig_len == incl_len` would scan cleanly while
the argv/stats claim full frames.  The evidence is root-only and the argv file
is runner-generated, so this is a defense-in-depth gap; suggested fix: record
the pcap snaplen and require it to match the expected full-frame capture (or at
least reject a snaplen smaller than the Ethernet header plus expected payload).

### M7 — Minor: marker split across frames remains a known false-negative

The design explicitly puts a marker split across two frames out of scope, and
`test_leak_lab.py` asserts PASS for that case.  The marker is present twice in
the HTTP request, so a normal single-segment request is likely to leave one
occurrence intact, but a TCP retransmission/segmentation boundary can split one
and the scanner will not reassemble.  This is a design limitation, not a code
deviation; record it as an accepted false-negative (or add stream reassembly).

### M8 — Minor: the optional `h` field is a reversible hash of an IPv4 address

`guest.py` computes `sha256(reported_ip)[:12]`; 48 bits is not an anonymisation
of an IPv4 address (2^32 candidates are trivially enumerable).  The binding
design explicitly permits “at most the first 12 hex characters”, so this is
not a deviation, but the Evidence section’s claim that non-Mullvad IPs are
never recorded is weaker than it sounds.  Consider dropping `h` or using a
keyed hash.

### M9 — Minor: `client-login` prints the bearer login URL to stderr

`login_phase_wait()` (`run_phase.py:1757`) prints the URL to stderr in addition
to the 0600 `login-url.txt`.  The design says “shows the login URL the way the
router login phase does”, so this matches existing behaviour, but stderr can
land in a terminal scrollback or a world-readable service log.  If the login
URL is treated as a secret, print it only to the root-only evidence file.

### M10 — Minor: runtime host verification does not prove the client nft drops/forward rules exist

`hostcheck.verify_client_network()` (`hostcheck.py:327-446`) verifies the
client bridge, tap, address, neighbour, ownership and owner tag, but not the
`vprlab1` input/forward/output/postrouting rules or the `vprlab0 <-> vprlab1`
drops.  `verify_host_lab()` (`run_phase.py:2162`) adds this call but does not
inspect the table rules; only the generated-plan tests check the text.  An
older/modified plan with valid links and table could pass the runtime check
without the client isolation rules.  Add rule-level checks (or at least the
two explicit cross-bridge drops and the client input/output drops) to
`verify_client_network`.

### M11 — Minor test gap: the two-VM orchestration harness fakes the client scanner verdict

`test_vm.py` `fake_run` returns a synthetic `{"verdict":"PASS"}` for
`clientscan.py` (`test_vm.py:5944` onward) and never runs the real scanner on
the fake pcaps.  The orchestration tests therefore prove ordering/argv, not
that the real client scan can produce the recorded verdict.  Add an integration
case that runs the real `clientscan.py` over the evidence produced by the fake
harness (the existing `RealScannerIntegrationTests` pattern).

### M12 — Minor: `clientprobe.py` CLI without `--fault-epoch` can PASS a post-fault-only log

`evaluate_probe_log(..., fault_epoch=None)` puts every line in “before”; the
docstring says the caller must mark the phase INVALID independently, but the
CLI (`clientprobe.py:208-223`) does not.  The runner always passes the recorded
epoch (and an error path is INVALID), so this is a tooling/documentation issue,
not a phase false pass; make the CLI require the epoch or emit INVALID when it
is absent.

## Host-safety positives verified

- `netplan.py` client plan creates `vprlab1` with the fixed MAC, client tap
  `vprlab-ctap1` owned by `vprlab-qemu`, static neighbour, IPv6 disabled, and
  the explicit `vprlab0 <-> vprlab1` drops in both directions before the links
  are brought up; the no-client render contains no `vprlab1`/`vprlab-ctap`/
  `10.251.0`/`@@` text.
- The client bridge/tap/table/neighbour ownership checks and the
  verify-before-mutate teardown exist for a client-plan teardown; the stub
  setup/teardown test passes.  The no-client mismatch is I2.
- QEMU client test argv: `-nic none`, `-netdev tap,ifname=vprlab-ctap1,
  script=no,downscript=no`, `-serial none`, `-sandbox on,...`, `-m 256`,
  `-smp 1`, fixed client MAC, `setpriv --reuid/--regid --init-groups
  --no-new-privs --inh-caps=-all --bounding-set=-all`, then `env -i`.
- `provision.py` client verifies the base image SHA-512, the pinned tarball
  SHA-256 (wrong file and symlink both refused in the run below), 2 GiB
  overlay, 384 MiB provisioning boot, client state/name/address validation.
- Client state/evidence files are 0600 and the client probe log cap/parser are
  strict; no Tailscale state, auth key or raw reported IP was found in
  `phase.json`, the probe log or stdout/stderr paths inspected.

```sh
python3 -B - <<'EOF'
import pathlib, sys
sys.path.insert(0, 'tools/leak-lab/vm'); sys.path.insert(0, 'tools/leak-lab')
import provision
p = pathlib.Path('/var/tmp/leaklab-m3-pi/fake-tailscale.tgz')
p.write_bytes(b'not the pinned tarball')
for target in (p,):
    try: provision.verify_tailscale_tarball(target)
    except Exception as e: print(type(e).__name__, e)
EOF
# Refusal tailscale tarball sha256 does not match the pinned digest
# Refusal tailscale tarball must be a regular file (symlink case, run too)
```

## Doc claims vs code

- No-client plan equality: M2.
- Before-control order: M4.
- Probe log path: M3.
- The docs’ “client capture stats exact banner” permits an omitted snapshot
  length (`pcapscan.stats_banner_re` makes `, snapshot length N bytes`
  optional); minor wording, not a verdict gap.
- The docs’ “any non-Mullvad IP is never recorded” is qualified by the allowed
  `h` hash prefix (M8); align the wording or remove the field.
- The implementation report’s “the pre-existing router-only suites pass
  unchanged” is supported: `_run_phase_locked`, `scan_evidence`’s effective
  code and `base_phase_record` are unchanged; `start_vm` defaults are the same;
  `run_phase` only dispatches on `getattr(arguments, "client", None)`.  The
  no-client netplan plan differs only in blank lines (M2).

## Verdict

The client capture/scan/probe machinery is mostly strict and the host-network
and QEMU additions are well scoped, but the phase verdict can be PASS without
client traffic during the fault (C1), the “right peer” check has a real
fallback hole (I1), and a no-client teardown can remove the lab nft isolation
while leaving the client objects and owner lost (I2).  These are
Critical/Important findings for a false-PASS-critical milestone.

Verdict:
FAIL
