# Combined leak-lab adversarial review

Review target: `e1535b809c20814018b62cce4fbcad690e56b50f` (2026-11-09). Monitor round 4 and VM runner round 2. Review completed; findings were recorded incrementally.

**Verdict: FAIL — 0 Critical, 9 Important, 1 Minor.** The ordinary capture/shutdown ordering and many prior reproducers are repaired, but the default M1/M2 table-ownership contract cannot run, and host privilege/evidence/secrecy and behavioural-certification gaps remain. Passing suites do not establish runtime qualification. Other findings are independent/latent where the table mismatch currently prevents a default phase from starting.

Constraints: offline/source/component review only. No sudo, QEMU, tcpdump, ip, nft, iptables, Docker or network execution. No prohibited configuration, archive, state or key reads. Generated shell execution, if needed, uses harmless substitutes for every privileged command in scratch. Scratch: `/var/tmp/leaklab-comb-gpt2`, removed at completion. No runtime qualification implied.

Initial Git status: clean; HEAD matches the requested commit. Only this report is authorized for repository writes.

## Fresh validation

Both requested suites completed with warnings treated as errors and TMPDIR inside the authorized scratch directory:

- `python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py`: **239 passed**, 0 failures/errors, 5.403 s.
- `python3 -B -W error -m unittest discover -s tools/leak-lab/vm -p 'test_*.py'`: **96 passed**, 0 failures/errors, 2.540 s.

Additionally, 28 independent behavioural controller cases covered exit 7/signalled actions in all five command-action phases and nonzero/signalled/inactive setup in all six setup phases: all INVALID; failed setup aborted injection. These are additional probes, not included in the suite counts.

Independent packet probes reran M1 GPT I1 (unfinished fragments before, after, and equal to BEFORE): all now LEAK `fragment_incomplete`. M1 pi I-1 (contradictory one-line 4/100 and 100/100 summaries after final 4/4): now INVALID `unread_capture_tail` / `stats_packet_count_mismatch`.

## Findings recorded during review

### I1 — Important: M1's per-run nft comment is incompatible with M2's host preflight

Locations: `tools/leak-lab/netplan.py:587`; `tools/leak-lab/vm/hostcheck.py:26`, `:170`, `:272`; fixture `tools/leak-lab/vm/test_vm.py:801`.

M1 creates `inet vprlab` with comment `vprlab-owned:<owner.json token>`, also used for both link ifaliases and Docker rules. M2 loads the token and checks link ifaliases, but still compares the table comment to the old constant `vprlab-leak-lab-m1`. The default generated topology is therefore always refused before capture/boot. Changing the table back to the constant would break M1 teardown ownership.

Reproducer (pure parser, rerun): use `test_vm.HostcheckTests()._valid_documents()`, with `owner_token='e'*32`. Its obsolete constant table comment returns `[]`; replacing only `table['nftables'][0]['table']['comment']` with `'vprlab-owned:'+'e'*32` returns `['nft table inet vprlab does not carry the ownership tag']`. The suite passes because its fixture repeats the obsolete contract.

Required: compare the table comment to the same token-derived alias, and feed actual M1-generated ownership data into an integration test. This is a demonstrated availability/integration blocker, not an observed WAN leak.

### I2 — Important: the privilege wrapper itself loads libraries from an opsec-owned directory while still root

Locations: `tools/leak-lab/vm/guest.py:225-229`, `:334-357`; `tools/leak-lab/vm/provision.py:109-112`, `:398-404`; `tools/leak-lab/vm/run_phase.py:1172-1178`, `:1226-1233`.

Moving qemu-img/genisoimage/QEMU behind setpriv fixes the old direct executable invocation, but every root `subprocess` launch still passes `guest.qemu_env({})` to **/usr/bin/setpriv itself**. That environment contains `LD_LIBRARY_PATH=/DATA/vprouter-lab/lab-tools/root/usr/lib/x86_64-linux-gnu`. The dynamic loader resolves setpriv's dependencies before setpriv can change UID or apply `--no-new-privs`/capability restrictions. An opsec-installed `libcap-ng.so.0` or `libc.so.6` in that directory executes at root authority.

Offline evidence: the actual launch generator starts with `/usr/bin/setpriv --reuid=1000 --regid=1000 ...`; the recorded environment contains that library path. `readelf -d /usr/bin/setpriv` reports DT_NEEDED `libcap-ng.so.0` and `libc.so.6`; `stat` reports the library directory UID/GID 1000:1000, mode 0755, and `/DATA/vprouter-lab` UID/GID 1000:1000, mode 0700. No malicious library or privileged wrapper was executed. These are current local metadata facts, not a root-exploit runtime test.

Required: launch the trusted setpriv with a clean loader environment, then set the staged library/module variables only **after** dropping privilege (for example trusted `/usr/bin/env` after `--`), or use verified libraries under an entirely root-controlled ancestry. Test the environment at the outer executable boundary, not just the presence of setpriv in argv. Previous M2 pi I5 remains open through this alternate root-execution route.

### I3 — Important: root-owned evidence still has an opsec-controlled ancestor

Locations: `tools/leak-lab/vm/run_phase.py:108`, `:653-675`, `:1412-1427`, `:1777-1807`; `tools/leak-lab/vm/provision.py:289-300`.

Moving evidence out of `vm-001` protects against the old leaf symlink but does not establish trusted ancestry. `ensure_root_directory()` validates only the final directory; it neither validates ancestors nor anchors later operations to a retained directory fd. The default is beneath `/DATA/vprouter-lab`, which is currently opsec-owned 0700. The root-created `leaklab` child can be renamed/replaced by that parent's owner, regardless of the child's owner/mode. Root later opens stats, policy, pcap, argv, scan and phase paths through this replaceable ancestor. This permits evidence substitution/false PASS and redirection of root writes. Provision's root staging also trusts that parent while copying/chmodding paths.

Reproducer (scratch only, rerun): create `user-parent/lab/evidence` through real `ensure_root_directory()`, rename `lab` to `old`, create a replacement `lab/evidence` with a sentinel, call `ensure_root_directory()` again: accepted, sentinel `substituted`, original evidence still under `old`. This models the demonstrated writable ancestor; no real evidence or external file was modified. Root-only leaf checks do not block the parent's rename authority.

Required: an evidence/control tree whose ancestry is root-owned and not user-writable all the way to `/`, plus descriptor-anchored no-follow/exclusive opens; separately retain opsec's QEMU state subtree. Previous M2 GPT I3 / Opus I4 / pi I9 are only partially fixed.

### I4 — Important: QGA printable truncation still exposes an entire WireGuard private key

Locations: `tools/leak-lab/vm/qga.py:35-44`, `:201-210`, `:234-235`; output sink `tools/leak-lab/vm/login_url.py:108-109`; claim `docs/rust-v2/leak-lab-vm.md` Secrets.

The prior secret-channel reproducer still succeeds. Removing control characters and limiting descriptions to 200 characters does not redact secrets: a WireGuard key is only 44 printable base64 characters. Both remote `class` and `desc` are rendered in exceptions; the class field alone can carry a key (64-character limit). The runner now normally records only the exception class, but the standalone login helper prints the full QGA exception, and the QGA module's promised content boundary remains false.

Pure reproducer rerun: set `QGAClient('/not-connected')._buffer` to JSON `{'error':{'class':'GenericError','desc':'PrivateKey = '+'A'*43+'='}}` plus newline, then call `_read_response(0)`. Exception: `guest agent error GenericError: PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`. No socket or real secret was used.

Required: locally defined bounded error codes/messages without guest-provided class/description, including chained exceptions and helper sinks. Previous M2 GPT I10 remains open; printable/length tests are not secrecy tests.

### I5 — Important: phase PASS still does not require a working approved exit node, and faults can run before that behaviour exists

Locations: `tools/leak-lab/vm/run_phase.py:905`, `:911-913`, `:977-980`, `:1588-1595`, `:1629-1634`; release `/opt/vprouter/current/host/orchestrate.py:424`, `:495-518`, `/opt/vprouter/current/router_runtime.py:116-125`, `:230-263`.

The new prerequisites prove a systemd unit and a positive WireGuard handshake timestamp. They do not consume the deployed release's READY/freshness/provider/exit-node contract. `BackendState` is recorded but never gates a result. A newly unauthenticated node can handshake with Mullvad while `tailscaled` needs login and the release remains BLOCKED. Every phase, including `idle`, reboot and the four fault phases, can certify PASS in that condition. A handshake integer of `1` is also accepted; there is no freshness check. There is no client/workload stimulus proving the advertised exit behaviour was exercised across the fault.

Independent integration reproducer rerun: drove real `run_phase()` with fake process/QGA operations, but used the **real pcapscan CLI subprocess**, real built policy, actual `capture-argv.json`, its `-w` path, matching tap banner and 4/4/0 stats. Generated pcap records `[BEFORE, allowed-WG-out, allowed-WG-in, AFTER]`; QGA returned systemd active, handshake `peerkey\t1700000000`, `BackendState=NeedsLogin`, successful action/postcondition (and changed boot ID/token for reboot). All eight phases returned exit 0, effective PASS, scanner PASS, no findings/invalid reasons, and `tailscale.backend_state=NeedsLogin`. This is a component/controller acceptance proof with synthetic traffic, not a real tunnel measurement. The source explains why the same readiness gap is reachable with the deployed release.

`login` necessarily needs a bootstrap exception, but its PASS cannot certify successful login/approval. For the other phases, require the release's fresh READY/status (and a successful in-tunnel/client probe when claiming exit traffic) before the fault; define and observe recovery/silence as appropriate afterwards. Distinguish clean-capture/bootstrap evidence from behaviour certification. Previous M2 GPT I8 / pi I10 remain partly open despite the fixed expectation table and fault postconditions.

### I6 — Important: lifecycle failure paths can still leave a live unobserved VM, and provision has no termination handlers

Locations: `tools/leak-lab/vm/provision.py:398-404`, `:447-455`, `:461-493`; `tools/leak-lab/vm/run_phase.py:1262-1290`, `:1695-1706`, `:1722-1730`.

`run_phase.main()` now handles termination signals, and independent cleanup steps fix the old ordinary QGA/OSError skip. However, a raised `poweroff_vm()` is merely marked `forced_poweroff`; there is no fallback kill/wait or tap isolation before tcpdump is stopped and the admission lock released. A QGA shutdown exception outside its narrow catch, or a failure while waiting/killing, can leave QEMU alive without observation. INVALID prevents a false success claim but does not restore host safety.

Offline runner reproducer rerun: use the behavioural runner harness, make `poweroff_vm` raise `OSError`, leave fake QEMU live. Result exit 2 / INVALID with `errors=['forced_poweroff']`, **no `qemu_exit` event**, followed by `capture_stop` and `scan`. No real VM was started.

Separately, `provision.py` imports signal only to terminate its child; it never installs handlers. Its QEMU child has a new session. SIGTERM/SIGHUP terminates Python without running the `finally: _terminate(process)`. Reran the real provisioning pipeline with fake generators/QEMU, injected self-SIGTERM or self-SIGHUP in `_wait_for_marker`, and instrumented `_terminate`: subprocess exit `-15` / `-1`, reached the real provisioning wait, **no cleanup callback**. This exercised actual Python signal termination and real provision control flow, without a real child VM. A real detached QEMU would survive that parent death.

Required: terminate/reap or verifiably isolate a VM before stopping observation/releasing admission, including exceptions from the first shutdown attempt. Install orderly termination handlers in provision too; preserve failed evidence. Prior M2 Opus I3 / pi I6 / GPT I6 are fixed for the original runner cases but not for the whole lifecycle.

### I7 — Important: payload staging changes the permissions of an input file outside the lab

Locations: `tools/leak-lab/vm/provision.py:176-193`.

The image tar is hardlinked into staging when possible. Although the immediate chmod is skipped for a successful hardlink, the later recursive loop adds mode 0444 to **every** staged file. That changes the input tar's inode too. Root thus makes a private 0600 operator file 0644 outside the lab. This violates the host-safety scope and can disclose private image layers to users who can traverse the source's parent; it does not demonstrate a WireGuard key in this particular image.

Reproducer rerun entirely in scratch: make a fixture release containing the required filenames and an `original-image.tar` mode 0600, call real `_stage_payload(state, release, source)`, then stat the original source. Result: **0644**. No Docker/image parsing or real source artifact was accessed.

Required: copy the image into a separate inode before normalizing staging modes, or exclude hardlinked files from chmod and reject unreadable inputs without mutating them. Regression must assert the source inode's mode and content are unchanged.

### I8 — Important: a failed link inventory is interpreted as isolation and protection is removed while the tap stays attached

Locations: `tools/leak-lab/netplan.py:405-415`, `:432-437`, `:474-478`, `:511-535`.

The fixed teardown now gates on down/detach command failures and readback, but `isolate_tap()` still interprets **any** nonzero `ip link show dev vprlab-tap0` as “tap absent; guest already isolated”. `verify_ownership()` and `delete_link()` make the same assumption. An inventory failure (for example netlink ENOBUFS during host memory pressure) therefore skips both ownership and isolation of the live tap, then deletes neighbours, Docker accepts and the input/output DROP table. No successful inventory proves absence.

Reproducer rerun: run the generated teardown using the existing complete harmless stubs for `ip`, `nft`, `iptables`, `sysctl`, `tcpdump`. Start with fully owned UP bridge/tap, tap mastered to bridge. Change only the stub's **plain tap `link show`** to return status 2 and `RTNETLINK answers: No buffer space available`; also inject `del_bridge` failure to retain the final unsafe state. Observed: `tap absent; guest already isolated`, table deleted, both Docker rules deleted, tap still **UP/master=vprlab0**, bridge retained, exit 1 and owner retained. Without the extra deletion failure there is still an unprotected interval before bridge deletion. All commands were stubs and all state was scratch JSON.

Required: acquire a successful complete link inventory and prove the tap is absent, or successfully bring it down/detach and read back isolation. An unreadable inventory must retain protection. Original M1 GPT I3 command-failure reproducers now pass, but this distinct observation-failure branch remains unsafe.

### I9 — Important: the untrusted guest can exhaust host capture/scanner resources; 512 MiB guest RAM is not a host bound

Locations: `tools/leak-lab/pcapscan.py:338`, `:345-347`, `:837-875`, `:1572`; `tools/leak-lab/vm/run_phase.py:481-493`, `:1334-1335`, `:1758-1759`; `tools/leak-lab/vm/guest.py:263-264`.

The runner accepts phases up to 86400 seconds, starts unlimited tcpdump output without a private quota/cgroup, then reads the **entire** pcap in a root scanner. The scanner additionally retains a tuple for every packet and fragment state for every distinct fragment key; completed states are not globally evicted. There is no capture-size/disk/memory admission or isolation. A guest with bounded RAM can stream unlimited packets over time. A timeout limits elapsed time, not allocation, and a per-report MAX_FINDINGS does not limit these data structures. Exhaustion can affect the shared host and its non-lab services.

Bounded reproducer rerun (no OOM induced): use `_Scanner(T.make_policy(), A, B)` and repeatedly call `parse_frame(T.wg_outbound(), timestamp, index)` under tracemalloc. A 51-byte allowed frame repeated 10,000 times retained 10,000 records and **1,522,646 bytes**; 20,000 retained 20,000 records and **3,047,912 bytes**, excluding the full input pcap that the CLI also holds. This demonstrates linear unbounded host allocation, not a measured failure at production throughput. At 1 Gbit/s, one minute is approximately 7.5 GB of capture bytes before Python's per-record overhead (estimate, not measured). The admission lock fixes concurrent lab runners but supplies no resource budget/headroom gate.

Required: contain capture, QEMU and scan in host resource budgets that cannot harm other services; enforce disk/capture bounds and mark the run INVALID when reached; stream packet classification and bound/expire fragment associations. Never rotate/discard evidence and then scan only a tail as PASS. Live host headroom and Docker/guest OOM behaviour remain NOT_RUN.

## Previous-round Critical/Important closure audit

All three `m1-rereview3-*` and all three `m2-review-*` reports were read. Duplicates are grouped below, with every prior Critical/Important identifier listed. “Fixed” means the original offline reproducer/behaviour is closed; it is not runtime qualification. Regressions below were freshly rerun in the requested suites; independent probes described above add cross-component cases.

| Previous report / finding | Fresh evidence and disposition |
|---|---|
| M1 GPT I1 | Independent pre-/post-/equal-boundary incomplete-fragment probes all LEAK; `test_gpt_i1_opus_m3_incomplete_fragment_outside_window_is_a_finding` passes. **Fixed**. |
| M1 GPT I2 | Stubbed foreign ownership aborts before mutation, existing owner refuses setup, run-token rules/duplicate removal pass. Old fixed-tag/alias-only reproducers no longer authorize teardown. **Fixed for original cases**; M2 table contract is I1 and ancestry is I3. |
| M1 GPT I3 | Stubbed `tap_down` and `nomaster` failures return nonzero and keep table/rules; deletion failure keeps owner. **Fixed for original command failures**; inventory failure remains I8. |
| M1 Opus I-1 | Embedded predicates accept real `ifalias` and `info_kind=tun/info_data.type=tap`; alias-only/foreign fixtures refused; stubbed normal teardown deletes both links. **Fixed**. |
| M1 pi I-1 | Independent mixed one-line counter probes now INVALID; standalone final one-line, non-decrease and legitimate mid-run tests pass. **Fixed**. |
| M2 GPT/Opus/pi C1 | Real controller behavioural tests: action exit 7, signalled action, setup exit 7, inactive setup → INVALID; failed setup aborts injection; LEAK precedence retained. **Fixed for original cases**. |
| M2 GPT/Opus/pi C2 | Behavioural order test and independent real-scanner shutdown-DNS case prove normal capture extends through QEMU exit and scans after AFTER. Forced QEMU exit now INVALID. **Fixed normal path**, exceptional termination still I6. |
| M2 GPT I1 | Generated boot sender test consumes persistent spec and writes matching token with no old `/run`; reboot requires changed boot ID and readiness; no-ready reboot INVALID. **Fixed for original lost-spec case**; actual boot timing NOT_RUN. |
| M2 GPT I2; pi I7 | Realistic tun/tap JSON accepted, plain tun and missing bridge master rejected. **Fixed**. Default topology still refused by independent I1. |
| M2 GPT I3; Opus I4; pi I9 | Old `state/qemu.log` symlink no longer followed, state-local evidence rejected, provision uses held fds before handing state over. **Partly fixed**: ancestor substitution persists (I3), source chmod I7. |
| M2 GPT I4 | Shared real flock tests refuse second runner and provision while lock held; both complete pipelines hold/release admission. **Fixed for cooperating default-lock callers**. Resource/OOM bound remains I9. |
| M2 GPT I5; pi I11 | UID-0 rejected by provision and launch generator; wrapper has no-new-privs and capability removal. **Fixed UID-0 override**; outer loader environment remains I2. |
| M2 GPT I6; Opus I3; pi I6 | Initial/teardown cleanup failure, OSError capture stop, pre-BEFORE exception, AFTER acknowledgement error, forced poweroff, unexpected main exception all fail closed and write effective result in behavioural tests; handler raises on first signal. **Original runner verdict bugs fixed**, whole-lifecycle orphan paths I6 remain. |
| M2 GPT I7; Opus I5; pi I4 | Login runner polls through its own QGA, writes URL-only private file; helper refuses while run lock held. **Documented concurrent-helper workflow replaced/fixed**. |
| M2 GPT I8; pi I10 | Pre-fault handshake and fault postconditions now required; no-handshake/postcondition-failure cases INVALID. **Partly fixed**: real release READY/client behaviour not required (I5). |
| M2 GPT I9 | Built policy has exactly the profile Endpoint, extra flow/public-address regressions refuse. **Fixed**. |
| M2 GPT I10 | Independent printable 44-character private-key sentinel still rendered verbatim. **Open, I4**. |
| M2 Opus I1; pi I1 | Generated shell fixture uses `neigh show dev`, static file/no lease/no DHCP process checks, no invented systemd link-state keys. `test_script_executes_against_debian_13_shims` passes. **Fixed original parser/field reproducers**; real pinned-image silence NOT_RUN. |
| M2 Opus I2; pi I2 | Operator `any/down` removed from runner; fixed all-up table, setup handshake and explicit fault postconditions enforced. `idle` intentionally changed to running-router idle and documented. **Fixed old expectation choice**, readiness I5 remains. |
| M2 pi I3 | AFTER-in-pcap check, QEMU exit, 2 s sleep, SIGINT order behavioural tests pass. **Fixed original missing drain**, with lifecycle caveat I6. |
| M2 pi I5 | Generator and qcow2 parser now run behind setpriv; behavioural tests record non-root target. **Partly fixed**, root setpriv dynamic loading remains I2. |
| M2 pi I8 | Debian 25.x main/network/hotplugd socket names included; active-unit wildcard checked, old false “all masked” condition removed in docs. **Original omission addressed in source/fixture**, real cloud-init target/unit activation NOT_RUN. |
| M2 pi I12 | QMP option/socket removed; test/provision argv retain only QGA control. **Fixed unused-QMP bypass**. |

The binding closure checklist is the immediately previous round requested above; older findings were assessed through their round-3 closure entries.

## Integration trace and remaining limits

- **Ownership:** M1's `owner.json` schema 1/32-hex token matches M2's loader and link `ifalias` prefix. **Table binding fails** (I1). Teardown works on ordinary real-shape stub inventories, but lookup errors do not prove absence (I8).
- **L2/neighbours:** M1 bridge MAC `52:54:00:76:70:01`, VM NIC MAC `52:54:00:76:70:02`, static host neighbour `10.250.0.2` and generated systemd `[Neighbor]` gateway entry agree. Runner policy has `allow_arp=false`; ARP becomes a finding. Both actual MAC directions are enforced on allowed tuple first/non-first fragments. Ordinary L2/fragment regressions pass. Live bridge/networkd/NUD behaviour NOT_RUN.
- **Policy/profile:** one public IPv4 UDP tuple is built from the actual profile Endpoint and written to a separate policy document. The deployed `_provider` accepts that tuple and uses PersistentKeepalive=25; compose's DNS is 9.9.9.9. The Endpoint extractor still differs from ConfigParser's colon/defaults/duplicate syntax, but tested/inspected divergences fail through service refusal rather than broadening the monitor policy. Real keys were never read.
- **Capture binding:** runner uses M1's exact `tcpdump -i vprlab-tap0 -nn -U --immediate-mode -s 0 -w PATH` argv, records it, scans that same `-w` path, and supplies stats with the tap/EN10MB banner. Independent integration used the real scanner subprocess and accepted exact 4/4/0 records; monitor negative argv/path/banner/drop/tail tests passed. The trusted-host process/environment boundary is still exposed by I2/I3; hashes of paths cannot repair it.
- **Expectations:** all eight runner phases are fixed to `up`, including failure setups. Setup must be active with a handshake; fault command and postcondition must exit zero; restart-docker must change dockerd PID and pass `docker info`. This closes no-op/nonzero-action certification. Whole-window tuple evidence still does not prove READY, traffic use or post-restart router recovery (I5). The deployed unit has `Requires=docker.service`, `PartOf=docker.service`; daemon restart alone is insufficient evidence of a functioning router afterwards.
- **Controls:** normal BEFORE and all AFTER markers use QGA and the exact SO_BINDTODEVICE command. Reboot BEFORE is in the persistent one-shot boot spec, consumed by the boot sender, with token and changed boot ID checked. Boot sender was executed with fake socket/subprocess; no network was opened. Actual boot-unit ordering versus networkd/Docker and first-frame timing NOT_RUN.
- **Lifetime/order:** normal behavioural traces show AFTER → router/unit cleanup → guest shutdown → QEMU wait/exit → AFTER found in pcap → 2 s sleep → capture stop → scan. An independent synthetic DNS leak appended by guest shutdown **after AFTER** produced exit 1 / LEAK `udp_not_allowed` through the real scanner. This closes the old normal teardown blind interval. Exception path I6 still can stop observation before a verified exit. The marker wait is a raw payload search and the quiet interval is a fixed sleep; exact marker validity/counters are finally verified by the scanner. No real tcpdump ring/drain measurement was made.
- **Release:** read-only comparison with `/opt/vprouter/current` confirms two containers, router `network_mode:none`, WireGuard born in transport netns/moved into router netns, state volume/TS_HOSTNAME, root/private config requirements, service READY notification preceding runtime READY, restart propagation, quarantine/cleanup, runtime freshness and approval gates. QEMU test argv has one tap NIC, no user netdev/seed/payload or QMP; provision has only user netdev and readonly seed/payload. The release was not executed.
- **Secrets:** ordinary profile writes stay out of argv/stdout/phase.json and use private guest staging; qcow2 intentionally holds the profile and Tailscale state as an opsec-owned secret-bearing artifact. That is documented, not a claim of storage secrecy from opsec. Remaining demonstrated host/error channels are I2/I3/I4 and input permission mutation I7. No real key/state exposure was attempted or observed.
- **Host safety/resources:** no real lab object was changed. Standard Docker iptables-nft forwarding/preflight fixtures pass; no live Docker 26–29 firewall, bridge, provision, authentication, workload, restart, QEMU privilege, memory/headroom/OOM, physical WAN or soak result is certified. Those checks are **NOT_RUN**, not PASS. The global lock covers cooperating VM controllers; it does not itself contain host memory/disk usage (I9).


## Minor finding

### M1 — Minor: VM instructions still claim M1 does not set the fixed MAC/static neighbour

Location: `docs/rust-v2/leak-lab-vm.md:44-58`; implementation `tools/leak-lab/netplan.py:576`, `:620`.

The “Host prerequisites M1's plan does not create” section says M1 does not set a stable bridge MAC or VM neighbour and instructs the operator to take the bridge down and change it after setup. The current M1 plan already sets both before links come up. Reproducer: compare `netplan.render_plan('eth0')` with the section; both `ip link set vprlab0 address 52:54:00:76:70:01` and `ip neigh replace 10.250.0.2 ... nud permanent` are generated. Remove the obsolete mutation instructions; keep preflight verification.

## Unresolved runtime gate, not counted as a finding

Provisioning calls `systemctl disable --now cloud-final.service` from a cloud-init runcmd script (`guest.py:825-832`, `:966`). I examined the self-termination risk with a stub that models cgroup-wide stop; under that model the shell exits -15 before completion. The installed pinned image's cloud-final `KillMode`/parent-child/pipe behaviour was **not verified**, so that model is insufficient to assert that Debian 13 actually terminates the provision shell. This is deliberately **not** an Important finding or a claim every provision fails. Qualify completion and shutdown on the actual image before accepting provisioning.


## Final verification

HEAD remained `e1535b809c20814018b62cce4fbcad690e56b50f`. No Git writes, source changes or forbidden command executions were performed. The only repository file written is this report (the `.superpowers` path is ignored by Git). Scratch `/var/tmp/leaklab-comb-gpt2` was removed after the probes. All conclusions labelled “Fixed” are scoped to the specified offline reproducer; live qualification remains NOT_RUN.
