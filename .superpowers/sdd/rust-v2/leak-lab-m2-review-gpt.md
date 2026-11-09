# M2 independent adversarial review — FAIL

Reviewed commit: `e1a66013eb5769926f643fbc44b048dfbf30f702`.
Scope: `tools/leak-lab/vm/{qga,guest,hostcheck,provision,run_phase,login_url,test_vm}.py` and `docs/rust-v2/leak-lab-vm.md`. Monitor sources and `docs/rust-v2/leak-lab.md` were read for their interfaces only. Deployed release source was read, never executed.

**Verdict: FAIL.** Two Critical findings and ten Important findings remain. Passing unit tests do not establish VM, leak, release, or host qualification.

## Verification and limits

Executed exactly the requested test command, with `TMPDIR` directed into the authorized scratch directory:

```text
python3 -B -W error -m unittest discover -s tools/leak-lab/vm -p 'test_*.py'
.............................................
Ran 45 tests in 0.308s
OK
```

45 run, 45 passed, 0 failures, 0 errors. Additional offline Python probes exercised the real runner with all process/network operations mocked, the generated boot sender with an absent scratch spec, pure parsers/generators, a synthetic QGA response, a scratch-only symlink, and the existing fake Unix-socket agent. No sudo, QEMU, qemu-img, tcpdump, ip, nft, iptables, Docker, or IP-network command was executed. No prohibited config, archive, state, or key file was read. All secret examples were synthetic sentinels. Scratch: `/var/tmp/leaklab-m2-gpt`, removed after review.

Actual VM boot/provisioning, tap traffic, QGA interoperability, Debian networkd runtime fields, guest service inventory, actual memory headroom, and release runtime readiness: **NOT_RUN**. Conclusions about QEMU's single-client socket and iproute2's tun/tap JSON are interface/source reasoning, with fake/representative fixtures explicitly identified below.

## Critical findings

### C1. Failed setup and actions still produce exit 0 / PASS

Locations: `tools/leak-lab/vm/run_phase.py:1118`, `:1122`, `:1133`, `:1223`; inadequate regression at `tools/leak-lab/vm/test_vm.py:898`.

The invalidation guard only tests `error is not None`. A nonzero or signalled `guest-exec` returns an `ExecResult`; it does not raise. Setup failure merely sets `setup.active=False`. An inactive setup's `Refusal` is explicitly swallowed. The action exit code is only recorded. None of these paths sets `error`, and execution proceeds through AFTER and the scanner.

Reproduced by calling real `run_phase()` with fake process/client operations and a scanner response of exit 0 / `{"verdict":"PASS"}`:

| Injection | Result |
|---|---|
| `kill-container` action returns exit 7 | exit 0, `result=PASS`, `action.exitcode=7` |
| Action terminates by signal, returns `exitcode=None` | exit 0, PASS |
| `stop-router` setup start returns exit 7; stop returns 0 | exit 0, PASS, `setup.active=false` |
| Setup returns 0; `wait_router_active()` raises `Refusal` | exit 0, PASS, `setup.active=false` |

The scanner was mocked to isolate the controller decision; this is not a measured pcap PASS. A clean pcap with successful setup traffic and an unsuccessful fault injection can legitimately pass `--expect-tunnel up`, so this is not limited to `any`. A failed initial start followed by a successful no-op stop can also pass a quiet `down` capture.

The existing test only searches source text for the exception guard. It never executes a failed action. This directly contradicts `docs/rust-v2/leak-lab-vm.md:400` and the just-applied controller decision.

Required correction: require every setup/action exit to be exactly integer zero, abort injection on unsuccessful setup, and make inactive setup a phase error. Add behavioral runner tests for each case, including signalled execution. Preserve LEAK precedence when the capture contains a leak.

### C2. Capture ends while the VM is still alive; shutdown and teardown are unobserved

Locations: `tools/leak-lab/vm/run_phase.py:1148`, `:1152`, `:1156`, `:1162`; shutdown wait/forced kill at `:861`–`:876`.

The finally block SIGINTs and waits for tcpdump **before** disabling reboot units, stopping the router, or powering down the VM. `poweroff_vm()` can subsequently wait 60 seconds and force-kill QEMU. Traffic during service shutdown, Docker teardown, route/firewall withdrawal, guest poweroff, or that timeout has no capture at all. This is a false acceptance of the VM lifetime, even with perfect positive controls and a perfect scanner.

The offline runner probe recorded this exact order:

```text
capture_start -> capture_stop -> poweroff
```

A fake poweroff returning `-9` still yielded exit 0 / PASS. This does not demonstrate real shutdown traffic; it demonstrates the missing observation interval and acceptance of a forced end.

There is also no check that AFTER reached the pcap and no quiet/drain interval before SIGINT. That violates the monitor's controller interface in `docs/rust-v2/leak-lab.md:223`–`:240`. Strict scanner counters may turn this second problem into INVALID, but cannot detect packets emitted after capture has stopped.

Required correction: keep capture alive until QEMU has verifiably exited, including error cleanup and forced termination; then drain and stop capture. Define how AFTER brackets shutdown (for example a final guest shutdown control) and separately account for lifetime coverage. Never infer lifetime coverage solely from two controls inside a shorter capture.

## Important findings

### I1. Reboot BEFORE specification is stored in volatile `/run`

Locations: `tools/leak-lab/vm/guest.py:91`, `:543`; `tools/leak-lab/vm/run_phase.py:591`, `:1081`, `:1087`; documentation `docs/rust-v2/leak-lab-vm.md:261`.

`stage_boot_control()` installs the only copy of the nonce specification at `/run/vprlab-boot-control.json`, then performs a real reboot. Debian/systemd recreates `/run` on boot. The enabled unit survives under `/etc`, but its script immediately opens a file that no longer exists. No BEFORE or sent marker is produced; `wait_boot_control_sent()` times out. Ordering the unit before Docker does not preserve the specification, and an ordering dependency does not make Docker require successful control emission.

Offline reproducer: load `guest.boot_control_script_text()` into a Python namespace, replace `SPEC` with an absent scratch path, and invoke `main()`. Result: `FileNotFoundError` before any socket is created. This models the documented runtime-directory reset; no reboot was performed.

Required correction: stage the one-shot spec in a private persistent location, consume it at the intended boot, bind it to the phase/boot, and securely remove it. Test disappearance of all previous-boot `/run` state. Verify that control failure prevents certification and that the intended boot actually ran the action.

### I2. Tap validation rejects the normal iproute2 JSON representation

Location: `tools/leak-lab/vm/hostcheck.py:160`; unrealistic fixture at `tools/leak-lab/vm/test_vm.py:605`.

`verify_host_lab()` requests `ip -d -j link show`. A Linux persistent tap is represented by link kind `tun` with `linkinfo.info_data.type = "tap"`; the validator requires the kind itself to equal `tap`. Its unit fixture repeats that mistaken representation. The normal lab tap therefore fails preflight before a VM can run.

Pure parser probe supplied all otherwise-valid existing fixtures, changing just the tap to:

```json
{"ifname":"vprlab-tap0","flags":["UP"],"master":"vprlab0",
 "linkinfo":{"info_kind":"tun","info_data":{"type":"tap","persist":true}}}
```

Result: `["vprlab-tap0 is not a tap"]`. This was a representative interface fixture, not live output collected with `ip`.

Required correction: validate the tun link's subtype, require attachment to the expected bridge (the current check also accepts a missing `master`), and cover both a real tap shape and a tun rejection.

### I3. Root opens files inside a user-owned state directory through symlinks

Locations: `tools/leak-lab/vm/run_phase.py:764`, `:819`, `:826`, `:976`; ownership established at `tools/leak-lab/vm/provision.py:212`.

The state directory is intentionally owned by the unprivileged QEMU user. The root runner later opens `state/qemu.log` with `open("ab")`, following symlinks without validating that entry. The state owner can replace it with a link to a file outside the lab. Preflight validates only the state directory and overlay, so it does not prevent this. Root-owned evidence beneath a replaceable user-owned ancestor also lacks a stable path boundary; a one-time `is_symlink()` check is racy.

Reproduced entirely inside scratch: make `state/qemu.log` a symlink to a separate `victim.log`, mock Popen to write `INJECTED QEMU LOG` through the supplied stdout descriptor, and call real `start_vm()`. The external target changed from `b'initial\n'` to `b'initial\nINJECTED QEMU LOG\n'`. No QEMU or privileged operation was executed. In the prescribed root invocation, the same open carries root authority.

Required correction: retain a trusted root-owned control/evidence boundary; give QEMU a separate writable subtree. Anchor operations to securely opened directory descriptors, reject symlinks and unexpected hardlinks/types with descriptor-based checks, and create/open logs without following links. Validate ancestor ownership and replacement races as well as the leaf.

### I4. The single-guest rule is a non-atomic process snapshot

Locations: `tools/leak-lab/vm/provision.py:197`, `:212`, `:299`; `tools/leak-lab/vm/run_phase.py:936`, `:1028`; `tools/leak-lab/vm/hostcheck.py:70`.

There is no shared admission lock spanning preflight through guest exit. Two provisioners using distinct indexes, or a provisioner and phase runner, can both observe no QEMU process and later launch guests. Exclusive creation of one state directory only prevents collision on that one path. Two test runners also race on one tap and fixed MAC/IP. On debdev this defeats both the one-guest invariant and the intended memory bound; a second guest can invalidate evidence or increase OOM risk.

Reproducer design (offline, no guests required): barrier both mocked process checks before either mocked Popen, give the provisioners distinct scratch state directories, then release both. Nothing in either path reserves global admission. Existing tests cover an already-visible QEMU, not concurrent starts.

Required correction: one root-controlled, non-symlink global lock held by both runners for the complete guest lifecycle, with deterministic refusal of the second entrant. Apply it before allocating expensive payload/overlay resources. Verify current memory headroom separately; a 512 MiB guest setting is not a host memory-admission check.

### I5. `--qemu-user root` is accepted and produces a root QEMU launch

Locations: `tools/leak-lab/vm/guest.py:304`–`:329`; `tools/leak-lab/vm/provision.py:199`; `tools/leak-lab/vm/run_phase.py:957`–`:964`.

Neither identity lookup nor launch generation rejects UID 0. The configurable QEMU user can be `root` (or another UID-0 account), contradicting the promised unprivileged execution. Clearing supplementary groups and applying the QEMU sandbox does not remove UID-0 authority.

Pure reproducer, no process execution:

```python
guest.build_launch_argv(["QEMU-NOT-EXECUTED"], "root", uid=0, gid=0)
# ['/usr/bin/setpriv', '--reuid=0', '--regid=0', '--clear-groups', '--', ...]
```

Required correction: reject UID 0 before state mutation or command execution in both runners and defensively in the generator. Add explicit rejection tests.

### I6. Cleanup and finally failures bypass complete phase invalidation/evidence

Locations: `tools/leak-lab/vm/run_phase.py:689`–`:696`, `:1049`, `:1148`–`:1164`, `:1223`, `:1248`.

`cleanup_reboot_units()` discards its ExecResult, and its shell intentionally suppresses disable/stop errors. The initial cleanup before BEFORE can therefore fail without setting `error`. In finally, reboot cleanup exceptions are discarded, and a negative QEMU exit/forced kill is recorded but never invalidates PASS. Exceptions from `stop_capture()` or `poweroff_vm()` escape before scanning and before writing phase.json; the outer main usually returns 2, but leaves no final phase record and suppresses scan-based LEAK reporting. If capture stopping raises, that process is also not retried after poweroff.

Offline probes:

- initial cleanup returns exit 7: runner exits 0 / PASS;
- poweroff returns -9: runner exits 0 / PASS;
- `stop_capture()` raises OSError: VM poweroff is attempted, but there is no scan or phase.json;
- AFTER is sent but its QGA acknowledgement fails, followed by scanner PASS: runner returns 2 and writes `result=INVALID`, **while stdout still says `"verdict":"PASS"`** and the nested scan verdict remains PASS.

For errors before BEFORE, the ordinary caught-exception path normally relies on missing controls to make the scanner return INVALID; that is not comprehensive error handling. Errors before evidence creation only reach main and leave no structured phase record. No capture means `result=ERROR`, rather than the documented uniform INVALID. Interrupted execution and finally failures are outside the guarded error-to-result transition.

Required correction: independently collect setup, action, capture, cleanup, and VM-exit failures; ensure final evidence writing is attempted even when teardown fails; preserve LEAK precedence when scanning is possible. Publish an unambiguous effective phase verdict in stdout as well as phase.json, while labeling the scanner's verdict as a capture verdict. Add pre-BEFORE, post-send, and finally fault-injection tests.

### I7. Interactive login helper competes with the runner for one QGA stream

Locations: `tools/leak-lab/vm/run_phase.py:1045`, `:1136`, `:1162`; `tools/leak-lab/vm/login_url.py:86`; socket backend `tools/leak-lab/vm/guest.py:290`; workflow `docs/rust-v2/leak-lab-vm.md:332`–`:350`.

The phase runner opens QGA and keeps that connection during the long login phase. `login_url.py` independently connects to the same QEMU socket chardev. A socket chardev is a single client stream, not an RPC server that multiplexes multiple QGA connections. The second client cannot complete its handshake while the first owns the connection. Thus the documented mechanism for fetching the first login URL while the phase is live cannot work as written.

A probe against the existing single-client FakeQGAServer reproduced the contention: connect and ping client A; keep A open; client B's handshake times out (`QGATimeout`). That is a fake-agent concurrency demonstration, not a QEMU interoperability measurement. A guest agent's one virtio-serial channel also requires serialized request/reply ownership.

Required correction: have the runner extract and expose only the login URL through a private controller interface, or introduce an explicit serialized QGA broker/handoff. Do not let independent clients interleave protocol transactions. Add a concurrent login-workflow test.

### I8. Service-active and whole-window tuple traffic cannot prove the fault phase's pre/postconditions

Locations: `tools/leak-lab/vm/run_phase.py:630`, `:1098`, `:1108`–`:1138`, `:1182`; documentation `docs/rust-v2/leak-lab-vm.md:354` and `:398`.

The just-applied `--expect-tunnel` requirement is present and forwarded correctly. However, failure phases include router startup and fault injection in one scanner window. From the monitor interface, `up` requires bidirectional allowed traffic anywhere inside that window; setup alone can satisfy it. `down` requires no inbound allowed traffic anywhere in the entire capture, so successful initial tunnel traffic makes a later successful stop/delete INVALID. Neither describes a transition or establishes post-action behavior.

Separately, `wait_router_active()` only checks systemd. The actual release's `host/orchestrate.py:424` sends `READY=1` after namespace/tunnel configuration, before its monitor starts. Its monitor explicitly accepts fresh STARTING/BLOCKED/RECOVERING health (`:539`–`:546`). Therefore systemd active does not establish approved/online Tailscale exit-node readiness, which lives in `router_runtime.py:116`–`:125` and is exposed by the release's status path. There is no readiness check, workload, or behavioral postcondition at injection time. `idle` also never starts a router; it can only be interpreted as a baseline silent-guest phase here.

Reproducer/test design: provide clean allowed setup packets both ways, then no post-fault packets. Whole-window `up` is satisfied. Conversely, the same setup followed by a successful stop fails whole-capture `down`. Mock systemd active with fresh runtime BLOCKED and observe that the runner still injects the fault. These are interface consequences; no real capture was executed.

Required correction: define each phase's exact prerequisites and postconditions, separate setup from the fault measurement when necessary, and check the release's runtime status before claiming an approved working exit-node test. Distinguish the clean-capture result from behavioral qualification, including explicitly report-only `any` runs. A root service being active and UDP tuples appearing are insufficient proof of the behavior named by the phase.

### I9. Policy binding permits unrelated allowed endpoints

Locations: `tools/leak-lab/vm/run_phase.py:883`–`:906`, `:951`–`:955`; claim at `docs/rust-v2/leak-lab-vm.md:289`.

The profile's endpoint need only be a member of `policy.outbound_allowed()`. The runner never requires the allowed set to equal this single-peer profile's endpoint. A reused policy can therefore authorize additional destination/port tuples unrelated to the actual tunnel, and the monitor correctly treats them as allowed according to that supplied policy. M2 would no longer be testing the promised “only this declared endpoint plus controls” invariant.

Pure parser/validator probe accepted an allowed set containing both the profile endpoint `185.65.134.10:51820` and unrelated `1.1.1.1:4444`. `verify_policy()` succeeded and the endpoint membership condition succeeded. This demonstrates the controller-policy binding gap, not a defect in the separately reviewed monitor.

Required correction: for this single-peer release, require the policy endpoint set to be exactly the parsed profile endpoint. Reject extras before guest launch; if multiple endpoints become an explicit feature, bind every one to the actual release configuration and phase contract.

### I10. Guest-controlled QGA error descriptions are printed without redaction

Locations: `tools/leak-lab/vm/qga.py:179`–`:185`, `:205`, `:332`; output sinks `tools/leak-lab/vm/run_phase.py:1244`, `:1297` and `tools/leak-lab/vm/login_url.py:97`.

The QGA client's “never file contents” error contract is not enforced. It incorporates the guest's arbitrary `error.class` and `error.desc` verbatim into exceptions, and callers print those exceptions. An untrusted guest/agent can put profile bytes or Tailscale state in that error channel and cause host log exposure. `SecretMaterial.__repr__` does not protect this separate path. The existing error test injects only a harmless description, so it tests no actual redaction boundary.

Pure response-parser reproducer:

```python
client = QGAClient('/not-connected')
client._buffer = b'{"error":{"class":"GenericError","desc":"PRIVATE-KEY-SENTINEL"}}\n'
client._read_response(0)
# QGAError: guest agent error GenericError: PRIVATE-KEY-SENTINEL
```

No real key or actual QGA error was observed. This is a reproduced secret-channel violation under the documented untrusted-guest model, not a claim that stock QEMU normally echoes valid write payloads.

Required correction: map remote errors to bounded locally defined diagnostics; do not print guest-provided descriptions/classes or chain them into rendered errors. Test sentinel-bearing descriptions on write, read/status, handshake, and cleanup error paths.

## Minor findings and documentation corrections

- **M1 — Silence assurance is narrower than the claim.** `tools/leak-lab/vm/guest.py:98`, `:744`, `:955`, `:997`: the fixed mask list and checks omit chrony/chronyd, ntp/ntpsec, other installed timers, and getty units. Mask checks inspect enablement, not whether a masked unit remains active. DHCP process checks cover only three names; IPv6 checks inspect root-namespace all/default and WAN addressing, not every interface or container namespace. QGA's enabled transport is correct (virtio-serial), but no active-service/timer/listener inventory proves absence of other network emitters. `dns: []` in daemon.json is not a general DNS-emission prohibition. No chrony presence, unwanted network emission, or wrong Debian runtime field was measured in the pinned image; these remain explicit qualification gates. Mask/remove unwanted installed services and timers, assert inactivity, and verify actual selected networkd settings and namespaces after boot. Do not turn an unverified inventory into a SILENCE completeness claim.
- **M2 — Examples omit newly required argument.** `docs/rust-v2/leak-lab-vm.md:335` and `:466`, plus the runner module example `tools/leak-lab/vm/run_phase.py:6`, omit `--expect-tunnel`; they now exit at argparse. Choose a justified expectation and update every runnable example.
- **M3 — Documentation drift.** `docs/rust-v2/leak-lab-vm.md:137` says test boots use `ipv6.disable=1`, although the CLI defaults to netns-safe; `:475` says 42 tests, while discovery runs 45; `:80` says the state directory contains no profile bytes, although its qcow2 intentionally contains them after injection (acknowledged later at `:451`); `:245` says “fresh copy of the overlay” although phases reopen the same overlay; `:434` discusses Docker fallback DNS although this deployed compose explicitly supplies `dns: [9.9.9.9]`; `:502` omits the four setup phases that also start the service. Correct these operationally significant distinctions.

## Release interface checks that did match

Read-only comparison against `/opt/vprouter/current` confirms:

- `docker-compose.yaml:1` and `:33` define router plus transport; router uses `network_mode: none`, transport uses the dedicated IPv4 bridge; both use the pinned image variable.
- `host/orchestrate.py:91`–`:109`, `:191`–`:207` accept the generated site document and enforce ownership, permission, parent-directory, name, and image constraints. Guest-installed config/profile modes and paths are compatible with these checks in the ordinary non-racy path.
- `host/orchestrate.py:171`–`:180`, compose `:23`, and `router_runtime.py:168`–`:174` implement the claimed TS_HOSTNAME mechanism.
- `host/orchestrate.py:341`–`:356` creates/configures wg0 in the transport namespace and moves it into the router namespace. The generated `nsenter -t <router-pid> -n ip link del wg0` targets the correct namespace. The defect is missing execution/postcondition validation, not this namespace choice.
- Compose `:19` writes the IPv6 forwarding sysctl. The provision CLI really defaults to netns-safe and forwards that choice to user-data generation. This avoids removing the sysctl tree. It does not independently qualify IPv6 silence in all namespaces; generator helper defaults still select kernel-disable if called without the CLI's explicit value.
- Runtime exit-node readiness includes provider validation, approved/online Self.ExitNodeOption, exactly the two advertised default routes, and NetfilterMode 0. The runner does not consume that readiness contract (I8).

The ordinary secret-installation path does use QGA file writes and a private guest staging directory instead of putting the profile in argv or phase.json. The overlay is intentionally a secret-bearing artifact. No real key exposure was measured; I3 and I10 identify concrete unsafe host/error boundaries.

## Required regression evidence before accepting M2

Replace source-string assertions with behavioral runner tests covering nonzero/signalled actions, unsuccessful/inactive setup, failures before BEFORE, post-send QGA errors, teardown failures, and conflicting effective/capture verdicts. Verify capture remains alive through VM exit. Add reboot tests that clear `/run`, representative tun/tap JSON, a globally serialized two-controller admission test, UID-0 refusal, state-path substitution tests, concurrent login access, exact policy/profile binding, secret-bearing QGA errors, and phase-specific readiness/transition tests.

Only after those offline gates pass should the controller separately qualify real provisioning, pinned-image silence, memory headroom, login/exit-node readiness, actual fault behavior, and capture lifetime/drain behavior in the authorized lab. None of those runtime gates was executed or certified by this review.
