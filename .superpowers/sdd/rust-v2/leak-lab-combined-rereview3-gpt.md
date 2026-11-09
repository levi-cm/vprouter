# Focused SAFETY review at 79a5bd5

Target HEAD: `79a5bd5286db538625d846de51859f7d77c9de7b`; initial worktree clean.

**Verdict: FAIL — five SAFETY Important findings (one is the documented tuple-only limitation); no Critical finding.**

Static/offline review of the three requested questions. No privileged commands, network execution, production configuration/state/archive/key reads. Only this report changes in the repository. Scratch `/var/tmp/leaklab-safety-gpt` was deleted after the probes.

## Tests

Each requested suite ran exactly once, from the repository root with `TMPDIR=/var/tmp/leaklab-safety-gpt/tmp`:

- `python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py`: **249 tests, OK**, 7.683 s.
- `python3 -B -W error -m unittest discover -s tools/leak-lab/vm -p 'test_*.py'`: **161 tests, OK**, 7.852 s.
- Total: **410**, zero failures/errors/skips reported. Offline component evidence only.

## Answers to the requested questions

### 1. False PASS

**(a) Yes for non-WireGuard payloads matching the declared outer UDP flow (S4); no blanket certification of WireGuard is possible.** The scanner checks Ethernet/IP/UDP shape, length, tuple and control placement, not WireGuard encryption or even message type. The runner separately consumes guest-reported fresh-handshake/readiness proof, which does not establish that every allowed datagram was WireGuard. A normal off-tuple frame is a finding anywhere in the pcap, including outside controls (`pcapscan.py:446-489`, `1138-1175`, `1542-1547`). Expected controls are explicit exceptions.

**(b) Yes (S1), including a real uncaptured shutdown tail.** Startup orders capture before QEMU (`run_phase.py:2516-2555`), but no ongoing capture-process liveness/exit-time contract ties capture to the whole boot-to-QEMU-exit interval. File size/free-space monitoring is not process monitoring. A clean SIGINT after AFTER can leave valid counters, controls and hashes while the VM continues running.

**(c) Ordinary reported failures fail closed; independent truth of guest assertions is not proved.** Setup/action nonzero status, missing active unit, stale/missing handshake, missing READY/exit-node state, failed postcondition or reboot ID check feed errors (`run_phase.py:1222-1300`, `1416-1457`, `2587-2630`, `2640-2759`), and errors force INVALID (`2933-2942`). Fresh suite tests cover these paths (`vm/test_vm.py:2129`, `2158`, `2221`, `2396`, `2501`, `2580`, `2619`, `2626`). Idle intentionally has action `true`; login requires final BackendState Running (`run_phase.py:2678-2680`, `2773-2774`). These are QGA/guest assertions: a malicious guest can fake command exit status, clock, handshake output, boot ID, READY and Tailscale JSON, so this is not action attestation against a dishonest guest. No additional ordinary failure-to-PASS path was established within this focused review.

**(d) No unprivileged evidence-substitution bypass found for the default installed layout; hashes do not authenticate a compromised host.** Evidence is root-only, outside QEMU-owned state, created exclusively and accessed through a retained directory fd (`run_phase.py:907-945`, `2450-2460`; `rootfs.py:128-173`, `185-210`, `285-319`). Before/after scanner hashes bind pcap, stats, exact argv-file bytes and policy; report/exit mismatch adds errors (`run_phase.py:2199-2319`). CLI argv hashing uses original bytes (`pcapscan.py:1692-1719`), fixing the pretty-JSON/canonical-JSON mismatch. Stats' text hash matches normal ASCII tcpdump output; altered/non-UTF8 bytes cannot silently match the runner's raw-byte hash.

Scanner resolution defaults to `/opt/vprlab-tools/leaklab/pcapscan.py`: manifest/ancestry and every listed file hash are verified, and the installed scanner must match the repository scanner bytes (`run_phase.py:183-291`, `2433-2437`). There is no silent repo fallback; `--allow-repo-scanner` explicitly permits it. The installed module tree is copied and root-normalized by `hostsetup.py:571-579`. The manifest is a local integrity contract, not a signature; operator changes to repo code, explicit overrides, privileged replacement before the initial hash, or root compromise remain outside this evidence guarantee (`docs/rust-v2/leak-lab.md:804-806`). The pcap hashes cannot fix S1's missing lifetime.

### 2. Secret exposure

**Yes: S2 exposes a guest-selected secret encoding to stderr and the login URL file; the standalone helper also prints it to stdout (`vm/login_url.py:114-116`).** Only a synthetic 32-byte value was used. Raw captured packets/guest console are additional opaque guest output: a malicious guest already holding the profile/state can emit them into `capture.pcap` or `serial.log` (`guest.py:329-330`; `run_phase.py:651-699`); those files must be treated as potentially secret-bearing.

The intended normal profile path avoids argv and structured-record disclosure: redacted repr, 64 KiB read cap, root-private file check, endpoint-only extraction (`run_phase.py:295-386`), QGA file transfer rather than shell content interpolation (`476-549`), guest 0700 staging/0600 file checks. Tailscale raw status and container logs are read in host memory but only normalized BackendState is added to phase.json (`1356-1405`); QGA errors discard guest descriptions (`qga.py:39-70`). scan.json contains classifications/hashes/addresses rather than raw payload bytes (`pcapscan.py:1549-1586`). Normal evidence files are 0600 under root-only directories; VM overlay/state is private (0700 directory, 0600 overlay; `run_phase.py:1840-1874`). No ordinary key/state write to the repo or publicly accessible world-readable path was found. Guest overlay persistence of both secrets is intentional and documented (`docs/rust-v2/leak-lab-vm.md:662-668`). These protections do not sanitize the deliberate URL channel.

### 3. Host harm

**Yes: S3 permits shared host resource exhaustion; S5 permits arbitrary privileged shell execution from crafted accepted generator filenames.** The default code does drop QEMU privilege: uid 0 is refused and setpriv supplies target uid/gid, initialized account groups, no-new-privs and empty capability sets (`guest.py:349-396`, `416-447`). Both provision/test launches use it (`provision.py:418-435`; `run_phase.py:1933-1954`); -m 512 and seccomp sandbox are present (`guest.py:289-292`, `341-342`). No ordinary default path launching QEMU as root was found.

With default arguments and absent crafted inputs, network mutations are lab bridge/tap/neighbour, `inet vprlab`, interface-local IPv6 sysctls, and two narrowly scoped, owned DOCKER-USER rules (`netplan.py:695-736`, `809-817`). Teardown checks ownership before mutating, isolates tap before removing protection, and deletes exact rule specifications (`netplan.py:483-529`, `558-679`). Other nft tables are not flushed. Docker restart and router/container actions are QGA guest commands (`run_phase.py:973-1008`, `2704-2707`), not host service commands. Hostsetup intentionally changes account/group databases for the lab account (`hostsetup.py:528-536`, `486-489`); those are expected writes outside the three storage roots. It accepts configurable root paths and user names, and teardown deletes those supplied tool/image/state paths (`397-409`, `477-489`), so it is not a hard sandbox restricting even a mistaken operator to the defaults.

Source copy uses confined relative links, excludes special files, opens regular source files O_NOFOLLOW with identity checks and verifies copies (`vm/hostcopy.py:252-268`, `299-323`, `376-438`). This does not correct S5's shell interpolation or provide S3's disk quota.

Availability-only observations, one line each:

- Missing or stale installed scanner/manifest fails closed unless the explicit repo-scanner override is supplied (`run_phase.py:268-291`).
- Forced shutdown, failed cleanup, incomplete controls, capture errors, or hash/report mismatch produce INVALID rather than PASS (`run_phase.py:2811-2919`, `2933-2942`).

## Confirmed source findings (incremental)

- **SAFETY Important S1 — no proof capture survives to QEMU exit.** `run_phase.py:1634-1743` watches file size/free space only; `stop_capture` (`714-750`) accepts an already-exited status-0 process. AFTER is emitted before cleanup/poweroff (`2784-2789`, `2808-2841`), so clean early capture termination after AFTER can leave the shutdown tail unobserved while final result is PASS (`2930-2942`). Fresh nonce/stats/hash checks cannot detect packets occurring after capture exit. Offline reproducer confirmed below.
- **SAFETY Important S2 — guest-controlled login URL is a secret output channel.** `vm/login_url.py:34-67` accepts arbitrary alphanumeric/slash/underscore/hyphen path text from guest status or logs. `run_phase.py:1485-1489` writes that text and prints it to stderr. An untrusted guest can place a reversible encoding of its private key/state in that path. BackendState/QGA-error allowlists do not cover this channel. Synthetic-only reproducer confirmed below.

Fresh requested single runs: `python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py`: **249, OK**, 7.683 s. VM discover (`-s tools/leak-lab/vm -p 'test_*.py'`): **161, OK**, 7.852 s. `TMPDIR` was confined to the requested scratch. No live network or privileged binaries executed.

### Reproducer results

S1: real `run_phase.run_phase`, `scan_evidence` and in-process `pcapscan.main` were driven with the existing suite's fake QGA/QEMU/capture layers. The fake capture cleanly exited immediately after writing AFTER, before the fake QEMU shutdown. The real `stop_capture` accepted that already-dead capture. All scanner input hashes were checked by the real runner, with real scanner output:

```text
early_capture_exit: {"exit": 0, "result": "PASS", "scan": "PASS", "errors": [], "dead_before_qemu_exit": true, "real_stop_status": 0}
login_secret_channel: {"key_recoverable_from_stderr": true, "key_recoverable_from_file": true}
```

No real process termination, VM or packet capture was performed. The first experimental harness invocation used mismatched fixture nonces and correctly returned LEAK; correcting those synthetic nonces produced the result above. Neither requested suite was rerun.

- **SAFETY Important S3 — host disk/resource exhaustion remains possible.** QEMU sends guest-controlled console bytes straight to an unbounded host file (`vm/guest.py:329-330`), and its overlay can grow to 4 GiB (`480-491`). Neither launch path applies `RLIMIT_FSIZE`/storage quotas (`vm/run_phase.py:1914-1955`, `vm/provision.py:420-438`). CaptureGuard measures the pcap/evidence filesystem (`run_phase.py:1674-1685`) and reacts only by isolating the tap (`1687-1696`): that does not stop console writes or overlay growth during QGA/action/poweroff waits, and cannot protect a separate state filesystem. Provisioning has neither that guard nor phase admission; it stages copies of an uncapped input image/release (`provision.py:187-220`) and permits a 1800-second boot (`37`, `441-443`). A guest console flood can fill shared host storage and harm unrelated services; no exhaustion experiment was run. Provisioning also has no host-memory admission or address-space bound, although its guest is fixed at 512 MiB (`guest.py:291-292`); the phase runner's 2 GiB AS limit and scanner's 1 GiB limit do not apply to standalone provisioning. Do not interpret fixed guest RAM as a host-memory guarantee.

- **SAFETY Important S4 — arbitrary UDP payload at the allowed tuple certifies PASS.** `pcapscan.py:1138-1170` validates tuple and UDP length, then marks the packet allowed without testing WireGuard payload shape. With controls and both directions, plaintext payloads `CLEAR_TEXT_NOT_WIREGUARD` / `CLEAR_REPLY` returned `PASS`, zero findings. This is an explicitly documented limitation (`docs/rust-v2/leak-lab.md:793-795`, `leak-lab-vm.md:641-642`), not a newly introduced regression, but it fails question 1(a)'s literal non-WireGuard criterion. Expected positive-control frames are also intentional non-WireGuard exceptions.

- **SAFETY Important S5 — filename arguments become shell code in generated privileged scripts.** `hostsetup.py:393-394` accepts a basename containing single quotes/semicolons, then interpolates it into a single-quoted assignment at `450`. `netplan.py:800-807` removes `shlex.quote` protection for paths beginning `$RUN_DIR/`, inserting the entire remainder in double quotes (so command substitutions execute). These require crafted generator arguments and subsequent operator execution of the printed script; they are not remotely reachable from a normal guest and defaults do not contain the payload. Nevertheless accepted filename data can execute arbitrary commands with the script's root privileges, outside all lab roots. Harmless assignment/argument-expansion-only probes confirmed both:

```python
# Imports from tools/leak-lab/vm and tools/leak-lab; no full script execution.
s = hostsetup.render_setup_script(
    base_image_name="x'; printf SAFETY_INJECTED; : '")
line = next(x for x in s.splitlines() if x.startswith('BASE_IMAGE_NAME='))
# line == "BASE_IMAGE_NAME='x'; printf SAFETY_INJECTED; : ''"
# /bin/sh -c line prints SAFETY_INJECTED.
p = netplan.render_plan('eth0',
    capture_file='$RUN_DIR/$(printf SAFETY_INJECTED).pcap')
# Generated -w argument: "$RUN_DIR/$(printf SAFETY_INJECTED).pcap"
# Expanding only that argument with RUN_DIR=/synthetic gives
# /synthetic/SAFETY_INJECTED.pcap, demonstrating command execution.
```

No Critical finding. No finding here requires running a privileged command to reproduce.

## Executable offline reproducer for S1/S2/S4

This uses existing fixture helpers and real runner/scanner decision functions. Processes and guest replies are synthetic; scanner main executes in-process. Save into the requested scratch directory, set TMPDIR there, and invoke with `python3 -B -W error`. It does not rerun either suite.

```python
import sys, pathlib, importlib.util, json, io, contextlib, subprocess, base64
from unittest import mock
repo = pathlib.Path('/DATA/AppData/vprouter-rust-v2')
sys.path[:0] = [str(repo/'tools/leak-lab/vm'), str(repo/'tools/leak-lab')]
def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, repo/rel)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod
m = load('safety_monitor', 'tools/leak-lab/test_leak_lab.py')
v = load('safety_vm', 'tools/leak-lab/vm/test_vm.py')
r = v.run_phase
# Arbitrary plaintext on the declared tuple, with both directions and controls.
frames = m.phase_frames(
    m.ipv4_frame(m.udp_segment(40000,m.WG_PORT,b'CLEAR_TEXT_NOT_WIREGUARD')),
    m.ipv4_frame(m.udp_segment(m.WG_PORT,40000,b'CLEAR_REPLY'), src_ip=m.WG_IP,
                 dst_ip=m.VM_IP,src_mac=m.GW_MAC,dst_mac=m.VM_MAC))
report = m.scan(frames, pol=m.make_policy(allow_arp=False), expect_tunnel='up')
print('tuple_plaintext:', report['verdict'], 'findings=',report['findings_total'])
# Keep all real runner decisions, but synthesize all processes/QGA; run the real
# scanner main in-process, so no QEMU/tcpdump/network or subprocess is executed.
orig_capture = r.Capture
orig_execute = v.HarnessQGA.execute
orig_scan = r.scan_evidence
orig_stop = r.stop_capture
slot = {}
def capture_factory(**kw):
    cap = orig_capture(**kw)
    slot['capture'] = cap
    slot['dead'] = False
    cap.process.poll = lambda: 0 if slot['dead'] else None
    return cap
def execute(self, program, args=(), **kw):
    command = args[-1] if args else ''
    if 'VPRLEAKCTL1:' in command:
        if self.after_nonce in command:
            cap = slot['capture']
            cap.pcap.write_bytes(m.pcap([m.control_frame(v.NONCE_A), *frames[1:-1], m.control_frame(v.NONCE_B)]))
            cap.stats.write_text(m.zero_stats(len(frames)))
            slot['dead'] = True  # tcpdump receives SIGINT and exits cleanly now
        return v.ExecResult(exitcode=0, stdout=b'', stderr=b'')
    return orig_execute(self,program,args,**kw)
def scan(evidence, **kw):
    slot['real_stop_status'] = orig_stop(slot['capture'], evidence_fd=evidence.fd)
    def inprocess(argv, **kwargs):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            rc = m.pcapscan.main(argv[3:])
        return subprocess.CompletedProcess(argv,rc,out.getvalue().encode(),err.getvalue().encode())
    with mock.patch.object(r.subprocess,'run',side_effect=inprocess):
        return orig_scan(evidence,**kw)
def poweroff(client, process, **kw):
    slot['dead_before_qemu_exit'] = slot['dead']
    process.wait()
    return 0,False,False
case = v.RunPhaseTests()
case.setUp()
try:
    with mock.patch.object(r,'Capture',side_effect=capture_factory), mock.patch.object(v.HarnessQGA,'execute',execute), mock.patch.object(r,'scan_evidence',side_effect=scan):
        code, rec, *_ = case._run('idle',poweroff_override=poweroff)
    print('early_capture_exit:',json.dumps(dict(exit=code,result=rec['result'],scan=rec['scan']['verdict'],errors=rec['errors'],dead_before_qemu_exit=slot['dead_before_qemu_exit'],real_stop_status=slot['real_stop_status'])))
finally:
    case.doCleanups()
# Recoverable synthetic 32-byte key encoded in an allowed URL path.
synthetic = base64.b64encode(bytes(range(32))).decode()
url = 'https://login.tailscale.com/a/' + synthetic.rstrip('=')
class Agent:
    def execute(self,*a,**kw):
        return v.ExecResult(0,json.dumps({'AuthURL':url}).encode(),b'')
class Evidence:
    path = pathlib.Path('/synthetic-evidence')
    def write_text(self,name,text): self.text = text
out=io.StringIO(); ev=Evidence()
with contextlib.redirect_stderr(out):
    r.login_phase_wait(Agent(),name=v.guest.DEFAULT_NAME,duration=0,evidence=ev,record={})
print('login_secret_channel:',json.dumps(dict(key_recoverable_from_stderr=synthetic.rstrip('=') in out.getvalue(),key_recoverable_from_file=synthetic.rstrip('=') in ev.text)))
```

## Completion and limits

Final verdict: **FAIL** (S1-S5 SAFETY Important; no Critical finding). Live runtime, real capture continuity, privilege-drop effectiveness on the target host and resource-exhaustion behavior: **NOT_RUN**, as instructed. This review supplies source/component evidence, not runtime/release acceptance. Scratch removed after completion; HEAD remains `79a5bd5286db538625d846de51859f7d77c9de7b`; tracked/untracked Git status remains clean. This report is Git-ignored (`git check-ignore` confirmed), so it does not appear in status. Only this report was intentionally changed in the repository.
