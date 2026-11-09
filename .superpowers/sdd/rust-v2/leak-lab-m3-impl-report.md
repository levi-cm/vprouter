# Leak-lab M3 implementation report

Milestone: M3 real client traffic through the test exit node
Repository: /DATA/AppData/vprouter-rust-v2 (branch rust/v2)
Base commit at start: 888f0d4
Date: 2026-11-09

## Status

Implementation and offline tests complete.  All work is in the working tree;
nothing was staged, committed or pushed.  No privileged command (sudo, QEMU,
tcpdump, ip, nft, iptables, docker, useradd, systemctl or network execution)
was run.  Generated shell was exercised only through the existing stub harness
in a temporary directory.

## Files changed

- `tools/leak-lab/tsnames.py` — client names
  `zz-vprclient-NN-do-not-use`: `generate_client`, `is_client_node`,
  `client_index`, CLI `--client-index` / `--check-client`.  Router names
  unchanged.
- `tools/leak-lab/netplan.py` — M3 client network: `vprlab1` bridge,
  `vprlab-ctapN`, client MAC/IP helpers, client subnet, explicit
  `vprlab0 <-> vprlab1` drops in both directions, mirrored NAT/Docker/input/
  output/IPv6 rules, static neighbour, setup order, ownership checks, teardown
  (verify-before-mutate, isolate, neighbours, Docker rules, links), collision
  checks, `--client N` CLI and client capture argv/interface binding.
  With no `--client` the generated plan contains no `vprlab1`/client text.
- `tools/leak-lab/clientscan.py` (new) — M3 client capture scanner: strict
  pcap walk over client and router captures, client tcpdump stats/banner/argv
  binding, exactly-one in-order client controls, plaintext marker search over
  every record in both pcaps, LEAK > INVALID > PASS.
- `tools/leak-lab/clientprobe.py` (new) — strict JSONL parser and verdict for
  the client probe log, with pre/post-fault counts and the LEAK/INVALID/PASS
  rules.
- `tools/leak-lab/pcapscan.py` — extracted `iter_pcap_records` for reuse;
  parameterised the stats banner/parser by capture interface (default remains
  `vprlab-tap0`); capture-argv check takes the interface.
- `tools/leak-lab/vm/guest.py` — client constants, state/tap/MAC/IP/name
  helpers, client QEMU memory/MAC parameters, 2 GiB overlay size parameter,
  client networkd text, client traffic script, client provisioning script and
  user-data, client silence check; router defaults unchanged.
- `tools/leak-lab/vm/provision.py` — `--client` provisioning, pinned
  Tailscale tarball hash verification before staging, client-NNN state,
  384 MiB provisioning boot, 2 GiB overlay, client record; router path
  unchanged.
- `tools/leak-lab/vm/hostcheck.py` — `verify_client_network` for the client
  bridge/taps/neighbours with the same exact ownership rules.
- `tools/leak-lab/vm/login_url.py` — shared candidate extraction plus native
  client (`tailscale status` + `journalctl -u tailscaled`) login URL flow.
- `tools/leak-lab/vm/hostsetup.py` — installs `clientprobe.py` and
  `clientscan.py`; teardown removes `client-NNN`; layout check covers client
  state directories.
- `tools/leak-lab/vm/run_phase.py` — `--client N`, `client-login`, the full
  two-VM phase flow, client capture/guard, exit-node selection/wait, traffic
  unit, probe log, client scan, combined verdicts and client phase record.
  Router-only paths are unchanged.
- `tools/leak-lab/test_leak_lab.py` — client tsnames/netplan/hostcheck,
  client scan and client probe tests (new classes).
- `tools/leak-lab/vm/test_vm.py` — client guest/provision/combined-verdict
  tests, plus a fake two-VM orchestration harness.
- `docs/rust-v2/leak-lab.md` — M3 client network plan (`--client N`).
- `docs/rust-v2/leak-lab-vm.md` — M3 topology, provisioning, client-login,
  phase-with-client, evidence/verdict docs and operator commands.
- `.superpowers/sdd/rust-v2/leak-lab-m3-impl-report.md` — this report.

## Design deviations and interpretations

1. **Pre-fault traffic start.** The design numbers the pre-fault positive
   control (step 7) before "Start the traffic unit" (step 8).  A probe cannot
   succeed before the probe stream exists, so the traffic unit is started for
   step 7 and remains the same unit through the fault/hold; step 8's "start"
   is satisfied by that already-running unit.  The pre-fault success is a
   real line in `client-probe.jsonl`, not a separate probe.
2. **`start-router --client`.**  A pre-fault Mullvad success requires a ready
   exit node, so every client phase brings the router to READY before its
   action.  `start-router --client` therefore performs an idempotent
   `systemctl start` as its action.  Router-only `start-router` is unchanged.
3. **Probe log clock boundary.** Counts split before/after the fault using the
   client's own `date +%s` immediately before the action, because the guest
   has no NTP and host/client clocks may differ.  The leak rule and pre-fault
   requirement apply to the whole log.
4. **`client-login` captures.** The phase boots only the client and writes
   `login-url.txt`; it starts no capture (it is not a leak phase).  Router
   `login` is unchanged.
5. **Client marker split across frames.** Out of scope per the design; a
   marker split across two records is not a finding.
6. **`reboot-with-router-enabled --client`.** The router's before-control is
   the M2 boot-control unit datagram (transport `boot-control-unit`), staged
   after the client is routed and just before the reboot, so the router scan
   window still brackets the fault.

## Operator commands

Client provisioning (online, root, after `hostsetup.py`):

```sh
python3 -B tools/leak-lab/vm/provision.py --client --index 1 \
  --tailscale-tar /root/vprlab/tailscale_1.104.5_amd64.tgz
```

Client login (root; no profile):

```sh
python3 -B tools/leak-lab/vm/run_phase.py \
  --phase client-login --client 1 --duration 900 \
  --used-nonces /root/leaklab-used-nonces.txt
```

Phase with the client:

```sh
python3 -B tools/leak-lab/vm/run_phase.py \
  --phase idle --client 1 --duration 120 --index 1 \
  --profile-file /root/vprouter-lab.conf \
  --used-nonces /root/leaklab-used-nonces.txt
```

Host plan with the client bridge (add `--client 1` to the collision preflight
too):

```sh
python3 -B tools/leak-lab/netplan.py \
  --wan-interface <wan> --client 1 > /root/vprlab-lab.sh
```

## Test counts

- The pre-existing router-only suites pass unchanged (same tests, same
  expected argv/evidence/verdict behaviour); the no-client `netplan.py` plan
  contains no `vprlab1`/`vprlab-ctap`/`10.251.0` text or `@@` tokens.
- `python3 -B -W error -m unittest vm.test_vm` — 227 tests, OK.
- `python3 -B -W error -m unittest test_leak_lab` — 301 tests, OK.
- `python3 -B -W error -m unittest discover -s tools/leak-lab/vm -p 'test_*.py'` — 227, OK.
- `python3 -B -m py_compile` on every touched Python file — OK.
- `sh -n` on the generated no-client and `--client 1,2` plans — OK.
- `git diff --check` — OK (no whitespace errors).
- Generated shell was only run through the existing stub harness in a
  temporary directory.  Scratch space `/var/tmp/leaklab-m3-impl` was deleted.

## Open questions

- None blocking.  The M2 skipped-minors list (live tcpdump AppArmor/priv-drop
  order, QEMU/KVM/tap, Docker/Tailscale readiness) remains a live gate; this
  milestone is offline code plus fake-agent tests.
- The client `start-router`/pre-fault interpretation (deviation 1/2) should be
  confirmed by the controller before a certification run.
