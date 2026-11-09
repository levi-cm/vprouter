# External leak monitor M1 — third independent adversarial review

**Verdict: FAIL — 0 Critical, 3 Important, 2 Minor findings.**

Reviewed commit: `b0c06f8e943b453e304ae41b8edc744966580175`, 2026-11-09. Scope: `tools/leak-lab/{pcapscan,policy,netplan,control,tsnames}.py`, `policy.schema.json`, `test_leak_lab.py`, and `docs/rust-v2/leak-lab.md`. The three round-2 reports were checked individually. The VM milestone directory and its documentation were excluded. The silent guest, static neighbours on both sides, and QEMU guest-agent control are accepted premises.

The receive-count, fragment-replacement, gateway-MAC, timestamp and directional-count fixes work for the original reproducers. The claim that all round-2 Important findings are fixed is nevertheless incorrect: exact field comparison closes the old substring trick but does not establish run ownership, and teardown still removes protection after isolation fails. A new false-PASS path results from changing the outside-window rule without updating fragment finalization.

This is an offline source/component review. No sudo, VM, network, nft, ip or iptables executable was run. Host-script experiments replaced **every** networking/sysctl/capture command with a harmless Python logging stub before shell evaluation; original command names were data arguments only. The unmodified generated script was only parsed with `sh -n`. No live host or Docker qualification is claimed.

## Validation

With `TMPDIR=/var/tmp/leaklab-rr3-gpt`:

```text
$ python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py
.................................................................................................................................................................................................................
----------------------------------------------------------------------
Ran 209 tests in 0.407s

OK
```

**209 passed, 0 failures, 0 errors, 0 skipped; warnings treated as errors.**

Additional independent checks:

- 87 named scan/argv/policy cases, including all round-2 Critical/Important reproducers; the host predicates/order checks and CLI reproducer were additional checks, not included in that 87.
- 27,990 sequence/expectation evaluations: every sequence of length 1–5 over `{before, after, allowed-out, allowed-in, ARP, DNS-leak}`, for each of `any`, `up`, `down`. Every sequence containing the DNS-leak frame returned LEAK. PASS required one ordered pair of controls; `up` additionally required both directional relay records strictly inside the window, and `down` rejected every inbound relay record anywhere.
- 343 stats combinations: 337 INVALID, 6 PASS; no combination containing the tested nonzero drops or excess receive count passed.
- Three generated-shell scenarios with all host commands substituted: foreign link ownership, failed isolation/deletion, and objects left by an older run. All three returned shell status 0; the unsafe actions are detailed below.
- The generated script passes `sh -n`. That is syntax evidence only.

Scratch was confined to `/var/tmp/leaklab-rr3-gpt` and deleted after the review. The only repository file written by this review is this report. Existing untracked VM milestone paths were preserved. During final verification, another actor advanced HEAD to `e1a66013eb5769926f643fbc44b048dfbf30f702`, adding the excluded VM milestone. All eight files in this review were rechecked byte-for-byte against `b0c06f8` and remained identical. This review performed no Git writes.

## Round-2 Critical/Important closure audit

Reproducers use the new mandatory capture argv, realistic tap banner, distinct controls and matching record counts except where a mismatch is the test subject. Privileged-command reproducers were rerun as text/predicate checks and substituted-shell experiments, never against the host.

| Round-2 report / ID | Fresh result at b0c06f8 | Disposition |
|---|---|---|
| GPT I1: excess receive count | `captured=3, received=100, drops=0` → INVALID `unread_capture_tail`; received 0, 2 and 4 also rejected; received 3 passes | Fixed for original reproducer |
| pi C1: same unread-tail issue, API and CLI | Original 3-record/100-received API case → INVALID; CLI exits 2 and emits INVALID | Fixed |
| GPT I2: expired incomplete state overwritten by reused ID | `[A, first(77), first(77), last(77), B]` at `[100,101,132,133,134]` → LEAK `incomplete_fragment` | Original reproducer fixed; new boundary regression is I1 below |
| GPT I3: VM/foreign MAC claims gateway IP through gateway branch | Both original VM-MAC opcodes and foreign-MAC gateway reply → LEAK `arp_not_allowed` | Fixed; gateway sender is now pinned |
| GPT I4: teardown substring ownership / missing run ownership | Rule-only ownership comment and `NOT-OWNED-<tag>-backup` alias now rejected by the actual embedded Python predicates. Older-run objects with the exact fixed tag still accepted; unowned links mutated before predicates run | Partly fixed; remains Important, I2 below |
| GPT I5: protection deleted before guest isolation | Normal text order is now down → detach → neighbour/rules → table → links. Both isolation commands may fail and protection is still deleted; no readback gate | Partly fixed; remains Important, I3 below |
| GPT I6: cold-neighbour ARP invalidates before-control sequence | Original `[ARP request, reply, A, WG-out, B]` → PASS, outside allowed indexes `[0,1]`; both-side static-neighbour instructions now explicit | Fixed for original reproducer; under the supplied static-neighbour premise these ARPs are not expected |
| Opus I-1: allowed keepalive/return/NUD at window edges invalidates phase | WG before A, WG return after B, and ARP probe after B each → PASS with the correct outside-window index; forbidden traffic in those positions remains LEAK | Fixed for original reproducers; fragment finalization was missed, I1 |
| Opus I-2: Docker DROP blackholes WAN; counts hide direction | Two scoped DOCKER-USER accepts now generated. Outbound-only and inbound-only captures have different directional counts and each is INVALID with `expect_tunnel='up'`; both directions pass | Source fix for standard Docker chain path; live forwarding NOT_RUN; preflight limits are M2 |

Also reran the round-2 GPT timestamp and zero-payload-fragment cases: reversed record/timestamp order → INVALID `non_monotonic_timestamps`; empty middle/final fragments → LEAK. The all-table route inventory and empty-route-object regressions also now fail closed.

## Shared packet-reproducer setup

The following is sufficient to rerun the packet findings from the repository root with `python3 -B -W error`. It constructs bytes only and opens no socket:

```python
import sys
sys.path.insert(0, "tools/leak-lab")
import test_leak_lab as T
import pcapscan as S
import netplan as N

A = T.control_frame(T.NONCE_A)
B = T.control_frame(T.NONCE_B)
O = T.wg_outbound()
I = T.wg_inbound()

def run(frames, times=None, stats=None, expect="any"):
    return S.scan_capture(
        T.pcap(frames, timestamps=times), T.make_policy(),
        T.NONCE_A, T.NONCE_B,
        tcpdump_stats_text=T.zero_stats(len(frames)) if stats is None else stats,
        capture_argv=T.CAPTURE_ARGV, expect_tunnel=expect,
    )

def first(ident=77):
    return T.ipv4_frame(
        T.udp_segment(40000, T.WG_PORT, b"a" * 8, length=24),
        ident=ident, more_fragments=True,
    )
```

## Important findings

### I1 — Incomplete fragment evidence is excused when its first fragment is outside the control window

**Locations:** `tools/leak-lab/pcapscan.py:829-849`, `:1193-1194`, `:1251-1258`; documentation `docs/rust-v2/leak-lab.md:204-210`, `:462-466`.

```python
f = first()  # 16 UDP bytes present, 24 declared; final 8 bytes never captured
r = run([f, A, O, I, B], expect="up")
assert r["verdict"] == "PASS"
assert r["findings_total"] == 0
assert r["capture_meta"]["outside_window_allowed_packets"] == [0]
assert r["capture_meta"]["tunnel_expectation"]["satisfied"] is True

assert run([A, O, I, B, f], expect="up")["verdict"] == "PASS"
assert run([A, f, O, I, B], times=[100,100,101,102,103],
           expect="up")["verdict"] == "PASS"

# Move the identical unfinished association strictly inside the window:
r = run([A, f, O, I, B], expect="up")
assert r["verdict"] == "LEAK"
assert T.reasons(r) == ["fragment_incomplete"]
```

`finalize_fragments()` retains the previous rule that only associations whose **first timestamp is strictly inside** the control window are judged. Its comment still assumes an outside-window association already makes the capture INVALID. That premise became false in this commit: the first fragment is labelled allowed immediately, outside-window allowance now permits PASS, and the missing-tail obligation is skipped. The equality case also skips finalization despite the fragment being recorded after A.

This is an actual synthetic false PASS for evidence that the fragment contract rejects. It survives matching captured/received/record counts, zero drops, correct argv/banner, monotonic timestamps, both controls, and `expect_tunnel='up'`. The repaired expiry/replacement path does not cover it.

**Required:** reconcile fragment finalization with the new boundary policy. Do not silently treat an unfinished association as a fully allowed outside-window flow. Report a finding under the documented strict contract, or explicitly mark a boundary-cut incomplete association INVALID; either must prevent PASS. Test unfinished associations before, after and equal to both marker timestamps, together with valid bidirectional in-window packets.

**Impact boundary:** this proves an erased fragment-completeness finding to an already-allowed endpoint, not a demonstrated different-destination WAN leak. That is why it is Important rather than a claimed Critical Internet escape.

### I2 — Ownership checks occur after mutation, and fixed tags still authorize another run's resources

**Locations:** `tools/leak-lab/netplan.py:128-139`, `:152-162`, `:170-185`, `:237-247`, `:261-275`; documentation `docs/rust-v2/leak-lab.md:507-519`, `:579-580`.

There are three related ownership failures:

1. Teardown brings any existing `vprlab-tap0` down and detaches it **before** checking its alias. It deletes the neighbour on any existing `vprlab0` without checking link ownership or whether this invocation installed that neighbour. The later refusal to delete a foreign link does not undo those changes.
2. The default owner tag is constant across invocations. No created-object/run record exists. Exact aliases/comments establish membership in this tool family, not creation by this setup. `./lab.sh teardown` after a failed setup can delete older/concurrent lab objects bearing the same tag.
3. Both Docker rules use the constant comment `vprlab-owned`, even when different `owner_tag` overrides are supplied. Teardown unconditionally attempts `-D` for those specifications. It can remove an identical rule installed earlier, including after this run inserted no rule. `-D` selects an existing matching rule, not a specific creation by this invocation.

Offline reproducer for ordering and rule identity:

```python
p = N.render_plan("eno1")
guard = p.index("ip -j -d link show dev vprlab-tap0 2>/dev/null |")
assert p.index("ip link set dev vprlab-tap0 down") < guard
assert p.index("ip link set dev vprlab-tap0 nomaster") < guard
assert p.index("ip neigh del 10.250.0.2 dev vprlab0") < guard

def docker_deletes(tag):
    return [line for line in N.render_plan("eno1", owner_tag=tag).splitlines()
            if line.startswith("iptables -D DOCKER-USER")]
assert docker_deletes(N.OWNER_TAG + "-one") == docker_deletes(N.OWNER_TAG + "-two")
```

The actual embedded table and link predicates were also rerun with older-run metadata:

```python
# Feed these JSON documents to the exact Python predicates embedded in p:
table = {"nftables": [{"table": {
    "family": "inet", "name": "vprlab", "comment": N.OWNER_TAG}}]}
link = [{"ifname": N.TAP, "alias": N.OWNER_TAG}]
# Both exit 0. Neither predicate receives any evidence of this run creating it.
```

In the substituted-shell foreign-link scenario, both link inventories had `alias="foreign-owner"`. Observed call order was `down`, `nomaster`, neighbour deletion, both Docker-rule deletions, and only later the link-ownership refusals. Teardown exited 0. In the older-run scenario, exact old tags authorized table and both link deletions, also with exit 0.

A realistic partial-setup sequence is: preflight passes; another actor creates a tagged same-name object; this invocation fails exclusive creation; the documented recovery command runs teardown. The teardown has no record distinguishing the two actors. Even without that race, directly running the advertised teardown-only command against a pre-existing foreign tap proves the first defect.

**Required:** verify ownership before **any** mutation; use a fresh run identity plus a persisted record of successfully created objects/rules/neighbours; carry that identity into Docker comments; remove only recorded resources. On failed exclusive creation, do not acquire ownership of the existing object. A global lab lock can complement creation records. Retain the new exact structured comparisons.

**Impact:** destructive interference with another run or foreign same-name resources. No real host resource was changed in this review.

### I3 — Failed isolation does not gate protection removal, and teardown reports success after cleanup failure

**Locations:** `tools/leak-lab/netplan.py:237-253`, `:265-285`; documentation `docs/rust-v2/leak-lab.md:507-512`.

Changing the normal command order is insufficient: both isolation operations use `|| echo`, so failure becomes a successful shell list. There is no readback that the tap is down/detached. Table deletion proceeds. Failed link deletion is also converted to success; the teardown-only entry point explicitly exits 0.

Static reproducer, without running any host command:

```python
p = N.render_plan("eno1")
lines = p.splitlines()
for prefix in ("ip link set dev vprlab-tap0 down",
               "ip link set dev vprlab-tap0 nomaster"):
    assert next(x.strip() for x in lines if x.strip().startswith(prefix)).split("||",1)[1].lstrip().startswith("echo ")
assert p.index("ip link set dev vprlab-tap0 nomaster") < p.index("nft delete table inet vprlab")
assert 'if [ "${1:-}" = "teardown" ]; then\n  do_teardown\n  exit 0' in p
```

The generated shell was additionally evaluated with every networking command replaced by a Python stub. Stub conditions: links exist, exact ownership checks pass, tap `down` and `nomaster` both return 1, both link deletions return 1, table deletion succeeds. Observed trace:

```text
tap down -> failure, logged
nomaster -> failure, logged
neighbour and both DOCKER-USER rules -> deletion attempted
inet vprlab -> deleted
both links -> deletion attempted, fail, logged
shell exit -> 0
```

The live guest can remain attached and the bridge address can remain present after the input/output DROP table is gone. Removing Docker forward accepts does not protect host-local services on that bridge. Even when subsequent link deletions succeed, the interval after table deletion is unprotected if isolation failed.

**Required:** establish and verify guest isolation before removing protection. If isolation cannot be proved, retain the DROP table and return nonzero. Continue only cleanup actions that are safe under that failure state. Aggregate cleanup failures rather than unconditionally reporting success. Add behavior tests for failing commands; the current suite deliberately checks for `||` on every risky line (`test_leak_lab.py:2146-2157`), which enshrines the unsafe dependency handling.

**Impact boundary:** a confirmed shell-control-flow defect under injected failures, not a live host-service exposure experiment. This remains the unresolved failure branch of round-2 GPT I5.

## Minor findings

### M1 — Banner validation is a substring count, not a check of the capture's banner

**Location:** `tools/leak-lab/pcapscan.py:1199-1205`; docs `docs/rust-v2/leak-lab.md:350-353`, `:383-398`.

```python
stats = T.zero_stats(4)
wrong = "tcpdump: listening on eth0, link-type EN10MB (Ethernet), snapshot length 262144 bytes\n"
assert run([A,O,I,B], stats=wrong + stats, expect="up")["verdict"] == "PASS"
assert run([A,O,I,B], stats=stats.replace("EN10MB (Ethernet)",
           "EN10MB_BOGUS (fake)"), expect="up")["verdict"] == "PASS"
assert run([A,O,I,B], stats=stats.replace(T.CAPTURE_BANNER,
           "unrelated: " + S.REQUIRED_STATS_BANNER + " garbage\n"),
           expect="up")["verdict"] == "PASS"
```

A wrong-interface banner plus one correct banner passes; an unsupported link-type name sharing the prefix passes; an unrelated line containing the magic substring passes. The check neither parses the full banner nor rejects additional listening banners. This weakens the provenance check and its documentation, although it does not itself demonstrate a hidden prohibited packet on a trusted capture host.

**Required:** parse anchored complete listening-banner lines, require exactly one, and validate interface and link type as complete fields. Reject extra/mismatched banners even if the required substring occurs elsewhere.

### M2 — Docker preflight does not establish that its accepts can be installed and reached

**Locations:** `tools/leak-lab/netplan.py:511-516`, `:525-527`, `:575-582`, generated unconditional inserts at `:307-308`.

```python
# Chain exists, but FORWARD never calls it:
s = T.DOCKER_DROP_IPTABLES.replace("-A FORWARD -j DOCKER-USER\n", "")
assert N.check_name_collisions(T.CLEAN_LINKS, T.CLEAN_ADDRS,
    T.CLEAN_ROUTES, T.CLEAN_TABLES, "eth0", s) == []

# ACCEPT-policy host has no DOCKER-USER chain; inserts still unconditional:
s = T.CLEAN_IPTABLES.replace(":DOCKER-USER - [0:0]\n", "").replace(
    "-A FORWARD -j DOCKER-USER\n", "")
assert N.check_name_collisions(T.CLEAN_LINKS, T.CLEAN_ADDRS,
    T.CLEAN_ROUTES, T.CLEAN_TABLES, "eth0", s) == []
```

The first inventory passes although the inserted rules cannot overcome the FORWARD DROP. The second passes although setup's unconditional inserts fail after creating/activating the lab links. Ordinary Docker defaults include the jump, so this is a preflight coverage gap rather than a claim about the present host. An outbound-only phase with `up` fails closed, reducing severity.

**Required:** require the chain whenever inserting into it, and validate the effective FORWARD path to it for the supported Docker layout. Otherwise report the forwarding prerequisite as unproven. Qualifying the actual iptables-nft backend remains a runtime/environment requirement.

## Requested attack surfaces and limits

- **Received/captured rule:** original excess/unread-tail PASS is closed in API and CLI. Both unequal directions reject. Later kernel/interface drops, contradictory summaries and the tested one-line SIGUSR1 drop cannot produce PASS. This does not experimentally establish Linux/libpcap backend semantics or that the manual two-second quiet protocol was actually followed.
- **Window ordering and leaks:** ordinary forbidden records before A, after B, inside, and in reversed-control captures remain LEAK. Findings outrank INVALID. There is no filtering of findings at report construction. The confirmed exception is the finding that is never created by fragment finalization (I1), not suppression of an existing finding.
- **Timestamp regressions:** the original reversed-control and reordered-action captures are INVALID `non_monotonic_timestamps`. Equal control timestamps fail `control_order`; records equal to marker timestamps are outside the strict evidence window. Ordinary out-of-window allowed records do not satisfy `up`.
- **ARP and controls as tunnel evidence:** controls-only, ARP-only, outbound-only, inbound-only, and relay records only outside the window all fail `up`. Reserved labels `arp` and `positive-control` are rejected, preventing a policy label from aliasing the ARP pseudo-label into the tunnel counts. An inbound relay record after B also fails `down`.
- **Can `up` PASS without real WireGuard or host-observed bidirectional traffic? Yes, under its documented endpoint-only model.** Direction is inferred from IP addresses, not trusted tap ingress/egress metadata. The following observed PASS uses zero-byte UDP payloads and a VM-emittable forged return frame:

```python
empty_out = T.ipv4_frame(T.udp_segment(40000, T.WG_PORT))
forged_in = T.ipv4_frame(T.udp_segment(T.WG_PORT, 40000),
    src_ip=T.WG_IP, dst_ip=T.VM_IP, src_mac=T.VM_MAC, dst_mac=T.VM_MAC)
r = run([A, empty_out, forged_in, B], expect="up")
assert r["verdict"] == "PASS"
assert r["capture_meta"]["tunnel_expectation"]["inbound_in_window"] == 1
```

  This is not promoted to an additional implementation finding because `docs/rust-v2/leak-lab.md:658-675` explicitly permits IP/MAC spoofing and disclaims authentication or proof of a working tunnel. The result must nevertheless be interpreted literally: `up` is a count gate, not proof of real bidirectional traffic or successful phase execution. If the acceptance requirement is real ingress or a working WireGuard tunnel, it needs trusted direction evidence and independent handshake/data-plane evidence. Do not claim that this gate alone meets that stronger requirement. Fragment tails whose first fragments precede A can also satisfy both in-window directional counts; those are fragment-record counts, not a requirement for whole datagrams contained within the window.
- **Capture argv:** extra BPF filters, packet limits, wrong interface and empty argv are rejected; exact argv is hashed. This binds the submitted declaration, not the actual executed process or its output path to the pcap. The generated script does not collect process argv evidence; the docs tell the operator to supply the JSON. That trust/collection boundary remains external to M1. Banner weakness is M1 above.
- **Public-unicast/ports:** original LAN/MagicDNS/DNS allowlist cases are rejected. Tested RFC1918, CGNAT, documentation, benchmark and multicast destinations fail. The exact five prohibited ports are rejected even at public addresses. Ports 67/68 at a public address remain accepted; that matches the documented five-port list, rather than a general validator for genuine Mullvad peers or all plaintext protocols. Policies must still come from the reviewed active endpoint configuration. The schema describes itself as a shape mirror; the Python loader remains binding.
- **Gateway ARP binding:** original VM/foreign gateway-IP claims now produce findings; missing/equal/non-unicast gateway MAC is rejected when required. The gateway sender is pinned. ARP target MAC/Ethernet destination are not fully constrained for every shape; matching whole-frame forgery remains possible and is explicitly documented. Under the given strict static-neighbour premise, use `allow_arp:false`: any ARP then remains a finding.

## Generated host script and docs assessment

Under standard Debian 13 iptables-nft Docker semantics, the two generated rules are syntactically appropriate: `-I DOCKER-USER` inserts before RETURN; outbound matches lab bridge, selected WAN and lab source /24; inbound matches selected WAN, lab bridge, lab destination /24 and `ESTABLISHED,RELATED`. At filter/FORWARD, return NAT has already restored the lab destination, so the inbound destination match is appropriate. ACCEPT terminates that iptables chain traversal and avoids Docker's policy DROP; an independent nft base-chain DROP still wins.

The corresponding `-D` specifications match the inserts exactly. This is correct rule matching, but not run ownership (I2). The rules intentionally modify only Docker's DOCKER-USER chain in the existing filter table; the other executable nft operations name only `inet vprlab`. No ruleset flush, global policy rewrite, unrelated chain/service restart, or global ip_forward write is executed by the generated script. IPv6 writes name only the lab interfaces. Global ip_forward change/restore examples remain comments requiring separate operator action. NAT is correctly scoped by lab ingress, source subnet and selected WAN. None of these source observations constitutes live firewall/readback qualification.

The steady-state input DROP precedes UDP socket delivery and suppresses the closed control port's ICMP reply; output IPv4 DROP provides a second barrier. ARP is outside the inet family. The host rules do not acquire an exemption for unexpected VM traffic; the external scanner still classifies it. Inbound RELATED ICMP may be forwarded and is deliberately a scanner finding, as documented. These conclusions concern steady-state rules; lifecycle defects I2/I3 prevent an unqualified host-safety claim.

Material documentation problems:

- The unconditional missing-tail promise and “out-of-window findings are still LEAK” do not describe I1's skipped finalization. The stale implementation comment explicitly relies on the former outside-window INVALID rule.
- “Teardown can never claim a resource that setup did not create” (`leak-lab.md:518-519`) is false with fixed tags, unrecorded Docker rules/neighbours and pre-guard link mutations.
- “First isolates the guest ... while the DROP rules are still installed” describes command order, not successful verified isolation. Failure handling in I3 removes that guarantee.
- The banner check implements substring occurrence, while the surrounding provenance language suggests a validated capture banner (M1).

The revised receive equality, normal outside-window accounting, directional counts, explicit tunnel expectations, gateway-MAC requirement, static neighbours on both sides, fixed gateway address, all-table route collection, control nonce-file initialization, exit codes, and endpoint-only limits otherwise match the examined code and fresh probes.

**Final verdict: FAIL.** The shipped tests pass, but incomplete fragment evidence can still receive PASS and the generated teardown does not preserve exact ownership or protection on failure. Live host/Docker forwarding, guest operation, actual WireGuard traffic and release acceptance remain **NOT_RUN**.
