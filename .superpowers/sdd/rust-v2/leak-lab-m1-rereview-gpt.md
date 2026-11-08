# External leak monitor M1 — second independent adversarial review

**Verdict: FAIL — 0 Critical, 6 Important, 4 Minor findings.** The 150-test suite passes, but the claim that every round-1 Critical/Important issue is closed is too strong. The captured-count bug is fixed; the excess-received-count reproducer from pi F-01 still passes. New fragment-state replacement and ARP exceptions also produce PASS for traffic/evidence that the documented contract rejects. Host teardown still has ownership and isolation defects.

Reviewed HEAD: `2fc1779b1d6d3d10defc9679386ac4cc2e897cc5`. Review completed 2026-11-09, Europe/Berlin. Scope: `tools/leak-lab/{control,netplan,pcapscan,policy,test_leak_lab,tsnames}.py`, `policy.schema.json`, `docs/rust-v2/leak-lab.md`, and all three round-1 reports. The checkout was initially clean. Only this report was added. Scratch was confined to `/var/tmp/leaklab-rr-gpt` and removed after review.

This is source and synthetic component evidence. **No sudo, VM, network, nft or ip command was run.** Host rule behavior below is a static assessment of generated commands, not live qualification. I used the stated silent-guest/QEMU-guest-agent context; ordinary guest DNS/NTP/apt traffic is not assumed. No undeclared-destination WAN leak was demonstrated at runtime. The confirmed PASS reproducers establish contract/completeness gaps, with their limits stated below.

## Validation

The requested command was run with `TMPDIR=/var/tmp/leaklab-rr-gpt` so the suite's temporary files stayed in the authorized scratch directory:

```text
python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py
......................................................................................................................................................
----------------------------------------------------------------------
Ran 150 tests in 0.252s

OK
```

**150 passed, 0 failures, 0 errors, 0 skipped; warnings treated as errors.** Additional independent work comprised 41 named packet/API/plan probes, a 139-assertion boundary sweep, and separate ICMP-classification/teardown-order checks. These also completed successfully: they assert the observed failures as well as the working protections. They are not additional shipped unit tests.

The boundary sweep covered both positive and negative padding cases for IPv4 and ARP; realistic tcpdump banners, three-line summaries, later drops, contradictory counters and errors; control omissions/replays/order; fragment gaps/overlaps/ranges/missing tails; and LEAK precedence over stats and structural defects.

## Round-1 Critical/Important closure audit

Reproducers were rerun against the new API, changing only the now-mandatory control/stats arguments and supplying correct record counts unless the count mismatch was the subject of the probe. Generated privileged commands were inspected, never executed.

| Original finding | Result now | Closure |
|---|---|---|
| GPT C1: first drop counter hides later drops | Later kernel `6` and interface `7` counters each produce INVALID `packet_drops`; realistic banner accepted | Fixed (`pcapscan.py:175-206`) |
| GPT I1: incomplete/contradictory stats, captured count mismatch | Interface-only summary → `stats_incomplete`; captured `300` vs 3 records → `stats_packet_count_mismatch`; conflicting counters → `stats_contradictory` | Fixed (`pcapscan.py:195-206`, `:1083-1088`) |
| GPT I2: ignored snaplen truncation / arbitrary trailers | Known missing wire bytes → INVALID `snaplen_truncated_record`; captured `SECRET` trailer → LEAK `ethernet_trailer` | Fixed (`pcapscan.py:285-321`, `:1001-1004`) |
| GPT I3: invalid UDP lengths / extra IP bytes after control | Lengths 0, 1, 7, 65535 → LEAK `malformed_frame`; extended control also LEAK, before control remains missing | Original reproducers fixed (`pcapscan.py:775-793`, `:844-859`); fragmented degenerate lengths remain M2 below |
| GPT I4: orphan/overlap after completed fragment association | Original far-offset orphan and conflicting final fragment each → LEAK `fragment_after_complete` | Original reproducers fixed; reassembly closure incomplete, see I2 |
| GPT I5: source-routing IPv4 options | Original LSRR packet → LEAK `ipv4_options` | Fixed (`pcapscan.py:532-546`) |
| GPT I6: duplicated expected nonces | Equal before/after → `ValueError`; CLI rejects with exit 2; replay in pcap → LEAK `replayed_control` | Fixed (`pcapscan.py:1055-1056`, `:1214-1219`, `:910-921`) |
| GPT I7: source NAT affects non-lab ingress | Rule now requires lab source subnet **and** `iifname "vprlab0"` and selected WAN | Fixed statically (`netplan.py:150`) |
| GPT I8: incomplete/malformed preflight; nonexclusive table creation; unsafe teardown | Missing inventories rejected; original malformed link/table entries rejected; `nft create` and tags added | Partly fixed; teardown still accepts false ownership matches, I4 |
| Opus I1: PASS without stats/controls | API omissions raise; CLI requires both controls and stats; unreadable stats → INVALID | Fixed (`pcapscan.py:1029-1059`, `:1177-1194`) |
| Opus I2: one nonce satisfies both controls / missing per-control evidence | Equal nonces rejected; duplicate sighting → LEAK; per-control timestamps, counts and packet indices present | Fixed for nonce reuse; timestamp-only ordering limitation is M1 |
| Opus I3: malformed frame abort hides later leaks; INVALID outranks known leak | Complete short IPv4 followed by two DNS packets → LEAK, all 3 findings retained; bad IHL followed by DNS → both findings; DNS + drop → LEAK with `packet_drops` alongside | Fixed (`pcapscan.py:466-520`, `:1116-1121`); real structural damage still stops, always non-PASS |
| Opus I4: closed UDP sink replies with ICMP; kill-switch requirement absent | Input silent DROP and output IPv4 DROP now printed; kill-switch exception documented; synthetic ICMP remains LEAK rather than whitelisted | Fixed in steady-state plan, statically (`netplan.py:136-148`); runtime NOT_RUN; cold-neighbour integration issue is I6 |
| pi F-01: captured/received counts ignored | Captured `4` vs 3-record prefix, captured `0` vs nonempty pcap → INVALID; **received `100`, captured `3`, drops `0` still PASS** | Partly fixed; see I1. Fix intentionally omitted the received discrepancy check |
| pi F-02: first-match stats parser | Both later positive-drop reproducers → INVALID | Fixed, same evidence as GPT C1 |
| pi F-03: stats optional | Missing API stats rejected; CLI omission rejected; unreadable file → INVALID | Fixed |
| pi F-04: expected controls optional | Missing API controls rejected; CLI omission rejected; absent sighting → INVALID | Fixed |
| pi F-05: duplicate nonces silently deduplicated | Equal values rejected, replay → LEAK, per-control evidence recorded | Fixed |
| pi F-06: host services exposed / control ICMP | Static input/output DROP rules now present; no control-port ACCEPT that would reach a closed socket | Fixed in steady-state plan; teardown protection gap is I5; runtime NOT_RUN |
| pi F-07: `allow_arp:false` unusable without static neighbours | Original ARP pair with false still → two `arp_not_allowed` findings; true accepts the normal pair; docs now require true or static neighbours | Original documentation issue fixed (`leak-lab.md:116-120`, `:312-313`); true plus cold before-control still INVALID, I6 |

## Reproducer setup

All following Python snippets run from the repository root with `python3 -B -W error`, after this shared setup. They only construct bytes and inspect generated text; they open no socket.

```python
import sys, struct, json, shlex
sys.path.insert(0, "tools/leak-lab")
import test_leak_lab as T
import pcapscan as S
import netplan

A = T.control_frame(T.NONCE_A)
B = T.control_frame(T.NONCE_B)
BANNER = ("tcpdump: listening on vprlab-tap0, link-type EN10MB (Ethernet), "
          "snapshot length 262144 bytes\n")

def stats(n, received=None):
    return (BANNER + f"{n} packets captured\n"
            f"{n if received is None else received} packets received by filter\n"
            "0 packets dropped by kernel\n")

def run(frames, times=None, received=None):
    return S.scan_capture(
        T.pcap(frames, timestamps=times), T.make_policy(),
        T.NONCE_A, T.NONCE_B,
        tcpdump_stats_text=stats(len(frames), received),
    )

def inside(frames):
    return run([A, *frames, B])

def first(ident=77, length=24):
    return T.ipv4_frame(
        T.udp_segment(40000, T.WG_PORT, b"a" * 8, length=length),
        ident=ident, more_fragments=True)

def last(ident=77):
    return T.ipv4_frame(b"b" * 8, ident=ident, frag_units=2)

# Realistic tcpdump 4.99 stderr: banner plus exactly the three normal lines.
assert inside([T.wg_outbound()])["verdict"] == "PASS"
```

The exact baseline stderr was:

```text
tcpdump: listening on vprlab-tap0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
3 packets captured
3 packets received by filter
0 packets dropped by kernel
```

It parses as captured=3, received=3, kernel drops=0, optional interface drops=None, no problem. The banner is correctly ignored, not mistaken for an error. No artificial fourth summary line is necessary.

## Important findings

### I1 — Unexplained excess receive count still permits completeness PASS (partly unresolved pi F-01)

**Location:** `tools/leak-lab/pcapscan.py:195-206`, `:1083-1088`; regression explicitly permitting it at `test_leak_lab.py:521-526`; docs `docs/rust-v2/leak-lab.md:267-269`.

```python
r = run([A, T.wg_outbound(), B], received=100)
assert r["verdict"] == "PASS"
assert r["capture_meta"]["stats"]["captured"] == 3
assert r["capture_meta"]["stats"]["received"] == 100
assert r["capture_meta"]["invalid_reasons"] == []
```

The fix reconciles packets processed by tcpdump with records written, but does not reconcile packets reported received with packets processed. The exact excess-received part of the original Critical reproducer remains accepted. The documentation explicitly permits the discrepancy, including while packets remain queued. Queued but unread packets are precisely a potential blind spot: kernel-drop counters measure buffer loss, not necessarily packets left unread at termination. `--immediate-mode` reduces buffering; it does not prove the capture was drained before SIGINT.

The installed tcpdump manual (`/usr/share/man/man8/tcpdump.8.gz`, read as text only) distinguishes processed `captured` packets from `received by filter` packets that may not yet have been read. Round-1 GPT I1 explicitly warned against a universal receive/captured equality, while pi F-01 requested receive-count validation. Counter meanings are platform-dependent, so imposing a universal equality on every libpcap backend would also be wrong. That is a reason to qualify the fixed Debian/Linux/tap backend or refuse unexplained evidence, not a proof that this 97-packet discrepancy is safe.

**Required:** for the intended backend, establish and enforce a conservative receive/processed/drop accounting rule, or drain and record sufficient additional evidence; otherwise return INVALID. Also reject impossible counter relationships for the qualified backend. Do not label this whole round-1 finding fixed merely because `captured == records` now holds.

**Limit:** the executable reproducer proves the unsupported completeness PASS. It does not prove that those hypothetical unread packets contained a leak within the control window; no live queue/drop experiment was authorized. Severity Important reflects this unresolved evidence gap, not a claim of a demonstrated runtime leak.

### I2 — Expiring/replacing an incomplete fragment state erases the obligation to report it

**Location:** `tools/leak-lab/pcapscan.py:623-650`, `:735-745`.

```python
r = run([A, first(), first(), last(), B],
        times=[100, 101, 132, 133, 134])
assert r["verdict"] == "PASS"
assert r["findings_total"] == 0
assert r["allowed_counts"]["mullvad-wg"] == 3
```

The datagram started at 101 never receives its last 8 bytes. At 132, the same key starts a new datagram. Because the previous first fragment is more than 30 seconds old, the duplicate-first check is skipped and the old state is overwritten. The new datagram completes at 133. Finalization sees only that complete state, so the earlier incomplete datagram disappears from the evidence. Every record is inside a valid control window; there are no drops or count mismatches.

**Required:** report/finalize an unfinished allowed datagram before evicting or replacing its state, or retain a separate pending-failure ledger. Test expiry plus ID reuse, not just an old first followed by a stale non-first fragment. Conservative rejection of all fragments is another safe M1 option.

**Documentation conflict:** `leak-lab.md:329-332` promises a finding when a fragmented datagram never completes after a structurally complete read. This example violates it. It does not establish a different-destination or port-overwrite exploit; the failure is erased reassembly/completeness evidence.

### I3 — The gateway ARP branch accepts the VM MAC claiming the gateway IP

**Location:** `tools/leak-lab/pcapscan.py:437-448`; docs `docs/rust-v2/leak-lab.md:308-311`.

```python
for op in (1, 2):
    spoof = T.arp_frame(op, T.VM_MAC, T.GW_IP, T.VM_MAC, T.VM_IP,
                        dst_mac=T.VM_MAC)
    r = inside([spoof])
    assert r["verdict"] == "PASS"
    assert r["allowed_counts"]["arp"] == 1

foreign = T.arp_frame(2, "02:00:00:00:00:01", T.GW_IP,
                      T.VM_MAC, T.VM_IP, dst_mac=T.VM_MAC)
assert inside([foreign])["verdict"] == "PASS"
```

The VM-to-gateway branch is strict, but `gateway_to_vm` checks only IPs and, for replies, the target MAC. It does not exclude `sender_mac == vm_wan_mac` or pin the gateway MAC. Thus a frame the declared VM MAC emits while claiming the gateway is accepted through the other branch. The current tests reject a VM claiming the gateway with a different target shape, leaving this alternative open.

**Required:** at minimum reject the declared VM MAC with any non-VM sender IP before either allowance. For the documented exact exchange, bind the independently obtained gateway MAC, enforce the permitted request/reply Ethernet and ARP identities, and add these reverse-branch tests. Do not claim cryptographic ARP authentication: a VM can forge an entire allowed frame; this finding is the simpler contradictory identity that is directly observable and currently allowed.

**Impact:** a false PASS for explicitly forbidden ARP misbehavior on the monitored tap, not a demonstrated Internet real-IP exposure. It matters under the stated strict traffic contract and contradicts the explicit documentation that VM/foreign gateway claims are findings.

### I4 — Teardown's substring searches are not table-comment / exact-alias ownership checks

**Location:** `tools/leak-lab/netplan.py:164-180`; docs `docs/rust-v2/leak-lab.md:358-359`, `:402-403`.

This reproduces the **exact fixed-string grep predicates** in memory, without running nft/ip or creating objects:

```python
p = netplan.render_plan("eno1")
tg = next(x for x in p.splitlines() if "nft list table" in x and "grep -Fq" in x)
lg = next(x for x in p.splitlines()
          if "ip -d link show dev vprlab0" in x and "grep -Fq" in x)
tneedle = shlex.split(tg.split("|", 1)[1])[2].rstrip(";")
lneedle = shlex.split(lg.split("|", 1)[1])[2].rstrip(";")
foreign_table = ('table inet vprlab {\n chain unrelated { '
                 'counter comment "vprlab-leak-lab-m1"; }\n}\n')
foreign_link = ('12: vprlab0: <BROADCAST,MULTICAST> mtu 1500\n'
                '    alias NOT-OWNED-vprlab-leak-lab-m1-backup\n')
assert tneedle in foreign_table  # no table ownership comment exists
assert lneedle in foreign_link  # alias is not equal to OWNER_TAG
```

Both guards accept and would select whole-object deletion. A rule comment anywhere in a table satisfies the purported table ownership check; any occurrence of the tag inside detailed link output satisfies the alias check. A fixed tag also cannot distinguish an object from an earlier setup from one created by this invocation. Exclusive creation correctly prevents mutating a pre-existing table during setup, but there is no setup-success/created-object record binding the later teardown to this run. Running teardown after a refused/partial setup can still target pre-existing resources.

**Required:** parse structured object metadata and require exact equality of the correct ownership field, bind ownership to a setup/run record, and delete only objects that this setup actually created. Preserve same-name resources after failed exclusive creation. Test teardown decisions against misleading rule comments and aliases; checking only that a `grep` precedes each deletion does not establish ownership (`test_leak_lab.py:1467-1481`).

**Limit:** no real table/link was deleted. The confirmed result is that the generated deletion branch's predicate accepts these non-owned object descriptions. This leaves part of round-1 GPT I8 open.

### I5 — Teardown removes the firewall before isolating the still-live tap

**Location:** `tools/leak-lab/netplan.py:160-180`; steady-state input/output protections at `:136-148`.

```python
p = netplan.render_plan("eno1")
assert p.index("nft delete table inet vprlab") < p.index("ip link del vprlab-tap0")
assert not any("link set" in x and "down" in x for x in p.splitlines())
```

Section 4 first deletes `inet vprlab`, including both host-protecting DROP chains, while the tap, bridge and host `10.250.0.1` address still exist. It contains no step requiring the VM to be stopped/disconnected or bringing the tap down first. With an attached running guest, packets during that interval can reach host services previously protected by the input chain. A failure before tap deletion can extend the interval indefinitely. Stopping tcpdump is not stopping the VM.

**Required:** verify ownership, isolate the guest on the host and verify that isolation before removing protection; retain the DROP rules on failure. Then remove only this run's resources. Alternatively make a verified stopped/disconnected guest an enforced teardown precondition. The current docs do not supply that precondition.

**Limit:** this is a static ordering finding with the explicit precondition of an attached running VM; no host service exposure was exercised. It concerns protection during lifecycle operations, not the correctness of the steady-state input DROP.

### I6 — Cold-neighbour ARP makes the documented before-control sequence INVALID

**Location:** `tools/leak-lab/pcapscan.py:1100-1106`; operational sequence `docs/rust-v2/leak-lab.md:182-188`; ARP guidance `:116-120`.

```python
req = T.arp_frame(1, T.VM_MAC, T.VM_IP, "00:00:00:00:00:00", T.GW_IP)
rep = T.arp_frame(2, T.GW_MAC, T.GW_IP, T.VM_MAC, T.VM_IP,
                  dst_mac=T.VM_MAC)
r = run([req, rep, A, T.wg_outbound(), B])
assert r["verdict"] == "INVALID"
assert r["findings_total"] == 0
assert r["allowed_counts"]["arp"] == 2
assert r["capture_meta"]["invalid_reasons"] == ["outside_control_window"]
```

A freshly started VM has to resolve the gateway before its first UDP control can leave. With the documented order (start capture, send before-control), that normal request/reply is recorded before marker A. Even with `allow_arp:true`, the new all-record window rule invalidates the capture. Silencing NTP/DNS/apt and using virtio-serial control does not remove this neighbour-resolution dependency. The suite exercises ARP only inside the window, or intentionally outside-window non-ARP records.

**Required:** document and implement a deliberate neighbour-preparation step before capture, or configure verified static neighbours for both necessary directions; alternatively define a narrowly justified boundary-ARP rule. Keep forbidden traffic and findings visible. Do not fix this by broadly ignoring out-of-window records or weakening controls. This is a false INVALID/integration defect, not a missed leak, but the advertised normal phase cannot qualify on a cold neighbour cache.

## Minor findings

### M1 — Control ordering is timestamp-only; reversed record order can PASS

**Location:** `tools/leak-lab/pcapscan.py:1092-1106`; stronger ordering claim at `docs/rust-v2/leak-lab.md:185-188`.

```python
r = run([B, T.wg_outbound(), A], times=[103, 102, 101])
assert r["verdict"] == "PASS"
assert r["positive_controls_seen"] == [T.NONCE_B, T.NONCE_A]
assert run([A, B, T.wg_outbound()], times=[101, 103, 102])["verdict"] == "PASS"
```

Packet indices are recorded but never used to establish order/window membership, and timestamp regressions are not rejected. The specific timestamp rule in the docs matches the implementation; the general statement that the scanner enforces the operational sequence is stronger. Require index ordering as well, and define handling of clock regressions. This does not demonstrate a missed non-declared packet; host timestamps are outside VM control, so I do not promote this synthetic ordering gap to a proven critical leak path.

### M2 — Zero-payload fragments can complete or extend an allowed association

**Location:** `tools/leak-lab/pcapscan.py:680-701`, `:844-850`.

```python
f = first(ident=78, length=16)  # MF is set although all 16 UDP bytes are present
empty_last = T.ipv4_frame(b"", ident=78, frag_units=2)
assert inside([f, empty_last])["verdict"] == "PASS"
empty_middle = T.ipv4_frame(b"", ident=77, frag_units=2, more_fragments=True)
assert inside([first(), empty_middle, last()])["verdict"] == "PASS"
```

The first-fragment length check permits equality with declared UDP length despite MF, and the non-first path accepts zero bytes as contiguous progress/completion. Reject empty fragment payloads and require an allowed MF first to leave a genuine remainder. These are malformed fragment false allowances to the already-declared relay tuple; no new destination escape was demonstrated.

### M3 — Preflight overstates route coverage and malformed-entry rejection

**Location:** generated inventory command `tools/leak-lab/netplan.py:96`; parser `:269-271`; docs `docs/rust-v2/leak-lab.md:385`, `:398-400`.

```python
p = netplan.render_plan("eno1")
assert "#   ip -j route > routes.json" in p
assert "ip -j route show table all" not in p
assert netplan.check_name_collisions(
    T.CLEAN_LINKS, T.CLEAN_ADDRS, "[{}]", T.CLEAN_TABLES, "eth0") == []
assert netplan.check_name_collisions(
    T.CLEAN_LINKS, T.CLEAN_ADDRS,
    '[{"dst":"10.250.0.0/24","table":200}]', T.CLEAN_TABLES, "eth0")
```

The parser detects a non-main-table overlap **if supplied**, but the printed collection command collects the default main table, not all policy-routing tables. Thus it cannot establish the documented absence of any explicit overlapping route. A malformed empty route object is also silently skipped. Collect all relevant tables, validate entries, and scope the stated guarantee to the inventory actually inspected. No current host overlap was asserted or inspected.

### M4 — Accepted gateway policy need not match netplan's fixed gateway

**Location:** `tools/leak-lab/policy.py:282-285`, `:338-342`; `netplan.py:29`, `:125`; docs `docs/rust-v2/leak-lab.md:98`, `:341`.

```python
p = T.make_policy(gateway_ipv4="10.250.0.9", positive_control={
    "sink_ipv4": "10.250.0.9", "sink_udp_port": T.SINK_PORT})
assert p.gateway_ipv4 == "10.250.0.9"
assert netplan.BRIDGE_ADDRESS == "10.250.0.1/24"
```

The loader enforces lab membership and sink equality, but does not enforce the advertised host bridge address. A policy valid under the loader can therefore disagree with the generated host network. Tie the policy and plan to one gateway value or explicitly validate their agreement. This normally fails control delivery rather than hiding a leak.

## Host command and ICMP assessment

- **Steady-state control sink:** on the intended plain bridge/tap topology, locally delivered IPv4 from the bridge reaches the inet input hook with the bridge as the input interface. `iifname "vprlab0" drop` is a terminal silent discard before UDP local-socket delivery. It does not invoke `reject` and does not cause the closed-port ICMP response. The separate output IPv4 DROP toward the bridge also suppresses host IPv4 transmissions. No listener is needed for this design. A synthetic port-unreachable still produces LEAK `icmp_not_allowed`, confirming that the fix did not add a broad ICMP exception. **Live input-interface/readback/packet behavior: NOT_RUN.**
- **ARP:** inet input/output DROP rules do not match ARP; the gateway can answer it. Boundary timing and scanner identity gaps remain I6 and I3.
- **Other nft tables:** active generated commands only create/mutate/delete `inet vprlab`; no ruleset flush or Docker/other-table edit is printed. Accept verdicts in this table do not override a DROP in a different base chain. Existing Docker/host forward policy may still prevent lab WAN connectivity; this plan is not evidence that connectivity works.
- **Non-lab traffic:** active packet rules require lab ingress or lab egress, and NAT now requires both lab ingress and lab source subnet. Under a genuinely nonoverlapping subnet, they do not intentionally match unrelated host/Docker traffic. A new connected route and any subnet collision still affect host routing; preflight limitations are M3. The WAN argument must name the intended WAN.
- **Host services/lifecycle:** the steady-state input DROP protects host services; deletion ordering reopens access if the VM remains attached (I5). Ownership checks can select pre-existing resources (I4). These block an unqualified claim that the plan cannot harm host services/resources.
- **Sysctls:** executable writes affect only the two newly created lab interfaces' IPv6 settings. The plan prints global `ip_forward` enable/restore commands only as comments; it does not execute them. Following that optional manual guidance changes a host-global setting and can affect routing/Docker assumptions; it is not an isolated lab-local write. In particular, Linux treats changing `ip_forward` specially and resets IPv4 configuration defaults. Restoring just the boolean is not proof of restoring all prior host networking state. Prefer requiring an already-qualified forwarding host or explicitly preserving/verifying affected host state. No sysctl was read or written during review.

## Documentation and remaining proof boundary

Most round-1 doc mismatches were corrected: mandatory stats/distinct controls, UDP length checks, source-route options, trailer accounting, exact control observations, malformed-frame continuation, stats hashes and LEAK-first precedence match the corresponding code and passing probes. The schema correctly calls itself a shape mirror with the Python loader as binding validator; it must not replace that loader.

The remaining material mismatches are the unconditional fragment-completion promise (I2), claimed rejection of gateway-IP ARP spoofing (I3), and ownership guarantee (I4). The operational sequence also lacks required cold-neighbour preparation and safe teardown ordering (I6/I5). The narrower timestamp-only and received-counter rules are accurately documented, but do not justify the broader ordering/completeness language (M1/I1).

With the VM OS silent and control over virtio-serial, a valid phase should still reject every observed unexpected frame; fixes should preserve that strictness. A passing offline classifier suite is not proof of a functioning tunnel, a drained and correctly bound capture, live host isolation, or phase execution. Allowed outer UDP tuples do not authenticate WireGuard payloads; this remains an endpoint-policy monitor. Runtime, host/Docker compatibility and release acceptance remain **NOT_RUN**.

**Final verdict: FAIL.** Close the Important findings and rerun independent reproducers before treating PASS as trustworthy phase evidence.
