# leak-lab M1 adversarial review (pi)

**Verdict: FAIL** — one Critical false-pass path and six Important issues.

Reviewed (uncommitted): `tools/leak-lab/policy.py`, `policy.schema.json`,
`pcapscan.py`, `control.py`, `tsnames.py`, `netplan.py`,
`test_leak_lab.py`, `docs/rust-v2/leak-lab.md`.

Method: source read, adversarial packet/pcap construction, direct function
calls, CLI checks, and the existing suite. No network, no nft/ip commands, no
sudo. Scratch scripts were written under `/var/tmp/leaklab-review-pi` and
deleted; no repository file was modified except this report.

Existing suite:

```
$ python3 -B -m unittest tools/leak-lab/test_leak_lab.py -v
Ran 56 tests in 0.096s
OK
```

The suite passes, but it does not exercise the false-pass cases below. Two of
its own fixtures are internally inconsistent and encode the main bug (see
F-01).

---

## Summary

| ID | Severity | Area | Finding |
|----|----------|------|---------|
| F-01 | **Critical** | pcapscan | tcpdump `packets captured` / `received` are parsed but never compared with the pcap; a structurally valid prefix reports PASS |
| F-02 | **Important** | pcapscan | stats parser takes the **first** matching summary; a later nonzero drop line is missed |
| F-03 | **Important** | pcapscan/CLI | `require_stats` defaults to false; a run with no stats file can PASS even if tcpdump dropped packets |
| F-04 | **Important** | pcapscan/CLI | expected controls default to empty; a capture with zero controls can PASS (monitor not proven) |
| F-05 | **Important** | pcapscan/CLI | duplicate expected nonces are silently deduped; one replayed marker satisfies both before/after slots |
| F-06 | **Important** | netplan | no input chain and no control sink/silent drop; untrusted VM reaches host services, and the documented control elicits an ICMP unreachable that the scanner reports as LEAK |
| F-07 | **Important** | policy/control | `allow_arp: false` is offered as supported, but the VM must ARP for its gateway and the on-link control sink; every real phase then LEAKs on its own ARP |
| F-08 | Minor | netplan | source-NAT rule is not scoped to `iifname "vprlab0"`; collision check does not inspect addresses/routes/subnets |
| F-09 | Minor | netplan | no `ip_forward` enable/verify; a local control can PASS while the VM has no WAN path |
| F-10 | Minor | netplan | no `--immediate-mode`; the after-control can be lost on SIGINT (fails safe as INVALID, but the procedure is unreliable) |
| F-11 | Minor | pcapscan | `allow_arp` permits spoofed/gratuitous ARP from foreign MACs; foreign MAC + VM IP is IP-classified (documented) |
| F-12 | Minor | policy | control sink can be any IPv4 (public/multicast/VM IP); non-unicast/reserved addresses are not rejected |
| F-13 | Minor | pcapscan | report has no per-control timestamps and no stats-file hash; before/after ordering cannot be verified from the report |
| F-14 | Minor | netplan/docs | teardown `set -e` can leave state, or delete pre-existing fixed-name objects if the collision check was skipped; `-s 0` "mandatory" is not enforced |

---

## Critical

### F-01 — Stats counts are recorded but never checked; a valid pcap prefix reports PASS

**Files:** `tools/leak-lab/pcapscan.py:686-708` (stats are parsed into
`stats`, then only `stats_problem` affects the verdict; `scanner.packets` is
never compared with `stats["captured"]` or `stats["received"]`);
`tools/leak-lab/pcapscan.py:153` in the docstring;
`tools/leak-lab/test_leak_lab.py:414-421` and `:492-505` (fixture mismatch).

**Reproducer** (run from the repository root):

```python
import sys; sys.path.insert(0, "tools/leak-lab")
import test_leak_lab as T, pcapscan

pol = T.make_policy()
frames = [
    T.control_frame(T.NONCE_A),
    T.wg_outbound(),
    T.control_frame(T.NONCE_B),
    T.ipv4_frame(T.udp_segment(40000, 53, b""), dst_ip="1.1.1.1"),  # DNS leak
]
stats = "4 packets captured\n4 packets received by filter\n0 packets dropped by kernel\n"

# Valid prefix of the capture, cut at a record boundary after the after-control.
r = pcapscan.scan_capture(T.pcap(frames[:3]), pol, (T.NONCE_A, T.NONCE_B),
                          tcpdump_stats_text=stats)
print(r["verdict"], r["packets"], r["capture_meta"]["stats"])
# => PASS 3 {'captured': 4, 'received': 4, 'dropped_kernel': 0, ...}
```

The pcap is structurally valid, contains both controls and an allowed WG flow,
and omits the DNS leak after the cut. The stats file says four packets were
captured; the pcap has three records. The scanner reports **PASS**. A copy,
archive, `head`/`truncate`-style transfer, or a write failure that preserves
whole records produces exactly this artifact. This is the stated catastrophic
failure mode: a leak is missed and the verdict is PASS.

Further examples that also pass today:

```python
# stats says nothing was captured, pcap has two records
r = pcapscan.scan_capture(T.pcap(frames[:2]), pol, (T.NONCE_A,),
    tcpdump_stats_text="0 packets captured\n0 packets received by filter\n0 packets dropped by kernel\n")
# => PASS, packets=2, stats.captured=0

# received by filter is 100, captured is 2, drops are 0
r = pcapscan.scan_capture(T.pcap(frames[:2]), pol, (T.NONCE_A,),
    tcpdump_stats_text="2 packets captured\n100 packets received by filter\n0 packets dropped by kernel\n")
# => PASS; 98 packets are unaccounted for
```

The second case matters even for a one-summary stats file: libpcap's
`ps_recv` can exceed `packets_captured + ps_drop` when packets are still queued
in the ring at SIGINT (the reason the repository's own
`tools/wg-birth-kernel-oracle.py:25` uses `--immediate-mode`). Those packets
are in the stats but not in the pcap; the scanner ignores the signal.

The suite itself demonstrates the hole:

- `test_leak_lab.py:416` says `4 packets captured`; the test at `:419` scans
  three frames and asserts PASS.
- `test_leak_lab.py:499` says `5 packets captured`; `:505` writes a two-record
  pass pcap and asserts PASS.

**Expected:** `INVALID` when `stats["captured"]` is missing or differs from
`scanner.packets`; also reject/flag `stats["received"] != stats["captured"] +
stats["dropped_kernel"]` when both drop counters are zero. Add an
`invalid_reason` such as `stats_packet_count_mismatch`. Include the stats file
SHA-256 and path in `capture_meta` so the count evidence is bound to the report.
Update the two fixtures to use the real record counts.

**Severity rationale:** This is a false PASS on a structurally valid evidence
file with an honest-looking stats file. It violates the doc's central promise
(`docs/rust-v2/leak-lab.md:8-11`: "a capture that cannot prove completeness is
`INVALID`, never `PASS`") and `:285-287`.

---

## Important

### F-02 — Stats parser keeps the first summary; a later nonzero drop line is invisible

**File:** `tools/leak-lab/pcapscan.py:101-113` (`pattern.search(text)` for each
counter; only the first match is used), `_STATS_PATTERNS` at `:60-75`.

**Reproducer:**

```python
import sys; sys.path.insert(0, "tools/leak-lab")
import pcapscan

text = ("3 packets captured\n3 packets received by filter\n0 packets dropped by kernel\n"
        "3 packets captured\n3 packets received by filter\n500 packets dropped by kernel\n")
print(pcapscan.parse_tcpdump_stats(text))
# => ({'captured': 3, ..., 'dropped_kernel': 0}, None)
```

A valid three-record pcap plus this text reports PASS. This can happen when an
operator appends a second tcpdump run to the same stderr file, or when an old
zero-drop summary precedes the real one. The later 500 drops mean the monitor
was blind, but the parser returns "no problem".

**Fix:** use `finditer`/`findall` and take the maximum for each counter, or
reject a stats file containing more than one distinct summary as ambiguous.
Combined with F-01's count check, a second summary will also fail the
`captured == packets` test.

---

### F-03 — Missing stats is allowed by default

**Files:** `tools/leak-lab/pcapscan.py:659-660` (`require_stats: bool = False`),
`:686-691` (`stats_required` only when the caller opts in);
`tools/leak-lab/pcapscan.py:763-764` (`--require-stats` is opt-in);
`docs/rust-v2/leak-lab.md:240-250` tells operators to use it in production.

**Reproducer:**

```python
r = pcapscan.scan_capture(T.pcap([T.control_frame(T.NONCE_A), T.wg_outbound()]),
                          T.make_policy(), (T.NONCE_A,))
print(r["verdict"], r["capture_meta"]["stats"])
# => PASS None
```

If tcpdump dropped the packet containing the leak, and no stats file was
supplied, the scanner has no way to know and returns PASS because both controls
were seen. The documented production command includes `--require-stats`, but
the default API and CLI option do not; one omitted flag is a false PASS.

**Fix:** make stats required by default (`require_stats=True`), require
`--tcpdump-stats` in the CLI, and add an explicit `--no-stats` /
`allow_missing_stats` escape hatch for unit tests only. Update the tests that
currently pass with no stats (e.g. `test_allowed_wg_both_directions_passes_with_controls`)
to supply a consistent synthetic stats file.

---

### F-04 — Zero expected controls is allowed and can PASS

**Files:** `tools/leak-lab/pcapscan.py:657` (`expected_nonces: Iterable[str] = ()`),
`:698-708` (empty `missing` list; `PASS`); CLI `:756-762`
(`--expect-control` optional); `docs/rust-v2/leak-lab.md:291-292` admits this
and delegates to the future M2 runner.

**Reproducer:**

```python
r = pcapscan.scan_capture(T.pcap([T.wg_outbound()]), T.make_policy(), ())
print(r["verdict"], r["positive_controls_seen"])
# => PASS []
```

A monitor bound to the wrong interface, or a capture filter that hides every
leak shape, produces the same one-record pcap of allowed WG traffic and
returns PASS. There is no marker proving the monitor sees anything it was
required to see. The doc calls this "not proof"; the engine still says `PASS`.

**Fix:** require at least one (preferably two distinct) expected control by
default; add `--allow-no-controls` for tests. The M2 runner must pass the
before/after nonces, but the engine should fail closed when it does not.

---

### F-05 — Duplicate expected nonces silently collapse; one packet satisfies both slots

**Files:** `tools/leak-lab/pcapscan.py:668-673` (`if nonce not in expected:
expected.append(nonce)`), `:698` (missing checked against the deduped set);
CLI `:756-762`; `tools/leak-lab/control.py:80` (`--nonce` explicitly allows
reusing an existing nonce); doc `:128`, `:144-145`.

**Reproducer:**

```python
r = pcapscan.scan_capture(T.pcap([T.control_frame(T.NONCE_A), T.wg_outbound()]),
                          T.make_policy(), (T.NONCE_A, T.NONCE_A))
print(r["verdict"], r["capture_meta"]["expected_controls"],
      r["positive_controls_seen"])
# => PASS ['0123456789abcdef0123456789abcdef'] ['0123456789abcdef0123456789abcdef']
```

The caller asked for two controls; one packet satisfied both. The report does
not preserve the duplicate or record per-nonce timestamps, so a downstream
verifier cannot see that the "after" marker was a replay of the "before"
packet. If the M2 runner reuses a nonce, or an attacker replays a captured
marker, a single packet on the tap proves two control windows. The doc says
"fresh" controls and puts before/after enforcement on the caller, but the tool
has no guard and no per-control timing evidence.

**Fix:** reject duplicate `--expect-control` values (exit 2) rather than
deduping; require the before and after nonces to differ; add a
`controls: [{nonce, first_ts, last_ts, packets}]` field to the report, or at
least per-nonce timestamps. Keep `--nonce` for debugging but document that it
defeats freshness.

---

### F-06 — No host input chain and no control sink; the documented control produces an ICMP LEAK and the VM can reach host services

**Files:** `tools/leak-lab/netplan.py:94-104` (only `forward` and `postrouting`
chains; no `input` chain), `docs/rust-v2/leak-lab.md:16-21` ("isolated" bridge,
capture host trusted), `:99-109` (control protocol: UDP to
`positive_control.sink_ipv4:sink_udp_port`), `:138-142` (control sequence),
`:204-214` (host network plan), `tools/leak-lab/control.py` (only prints a
sender; no listener anywhere in the repository).

**Reproducer A (plan inspection):**

```python
import sys; sys.path.insert(0, "tools/leak-lab")
import netplan
plan = netplan.render_plan("eth0")
print("hook input" in plan)                    # False
print("start a sink" in plan.lower())           # False
```

The plan creates a bridge with the host's `10.250.0.1/24` and only filters
**forwarded** traffic. The untrusted router VM is on the same L2 and can reach
any host service bound to `10.250.0.1` or `0.0.0.0` (SSH, Docker API, etc.)
unless the host's own, unmentioned firewall blocks it. That undermines the
trusted-capture-host assumption the doc relies on.

**Reproducer B (the control's normal host response):**

The sample policy's sink is `10.250.0.1:39001` (`docs:59-63`). Nothing in the
plan or tools binds that port. On a normal Linux host, the kernel answers a UDP
packet to a closed port with an ICMP destination-unreachable (port unreachable)
to the VM. The scanner treats every ICMP as a finding:

```python
import struct
icmp = T.ipv4_frame(struct.pack("!BBH", 3, 3, 0) + b"\x00" * 4,
                    src_ip=T.GW_IP, dst_ip=T.VM_IP, protocol=1,
                    src_mac=T.GW_MAC, dst_mac=T.VM_MAC)
r = pcapscan.scan_capture(T.pcap([T.control_frame(T.NONCE_A), icmp]),
                          T.make_policy(), (T.NONCE_A,))
print(r["verdict"], [f["reason"] for f in r["findings"]])
# => LEAK ['icmp_not_allowed']
```

So a real before/after control phase with the documented sink and no listener
ends in LEAK, not PASS. The operator's likely reactions are to enable
`allow_arp`/ignore findings or to omit controls (F-04), both of which weaken
the evidence. M1 is offline and M2 may add a sink, but the plan and protocol
currently do not mention the requirement.

**Fix:** add an input chain to `inet vprlab` that accepts only the control UDP
port and drops the rest from `vprlab0`, or start a UDP sink in the runner;
document the required control port and the "closed port must not send ICMP"
requirement. The input chain also closes the host-service exposure. The plan
needs the control port (from the policy) as an argument or a documented
placeholder.

---

### F-07 — `allow_arp: false` is not usable with a real router VM; the control's own ARP is a LEAK

**Files:** `tools/leak-lab/pcapscan.py:350-377` (any ARP involving the VM MAC/IP
is a finding when `allow_arp` is false), `tools/leak-lab/policy.py:238-240`
(`allow_arp` is a free boolean), doc `:31` ("ARP (optional)"), `:59` (sample
`allow_arp: true`), `:85`.

**Reproducer:**

```python
arp_req = T.ethernet(T.arp_packet(1, T.VM_MAC, T.VM_IP,
                                  "00:00:00:00:00:00", T.GW_IP), 0x0806,
                     src=T.VM_MAC, dst="ff:ff:ff:ff:ff:ff")
arp_rep = T.ethernet(T.arp_packet(2, T.GW_MAC, T.GW_IP,
                                  T.VM_MAC, T.VM_IP), 0x0806,
                     src=T.GW_MAC, dst=T.VM_MAC)
r = pcapscan.scan_capture(T.pcap([T.control_frame(T.NONCE_A), arp_req, arp_rep]),
                          T.make_policy(allow_arp=False), (T.NONCE_A,))
print(r["verdict"], [f["reason"] for f in r["findings"]])
# => LEAK ['arp_not_allowed', 'arp_not_allowed']
```

The VM's gateway and the sample sink `10.250.0.1` are on-link, so the VM must
ARP for them. With `allow_arp: false`, the phase LEAKs on the ARP that makes
the control possible. The doc calls ARP "optional", but for any real router
phase it is mandatory unless a static neighbor entry is installed (the plan
does not install one). A user who chooses the stricter-looking option cannot
pass, and the natural workaround is to enable broad ARP (F-11).

**Fix:** state that `allow_arp` must be true for a real phase, or add a static
neighbor for the gateway/sink and document it; make the sample and the
collision/control setup explicit. If a strict ARP mode is desired, allow only
the VM's own request/reply to the gateway rather than all ARP involving the VM.

---

## Minor

### F-08 — Masquerade not scoped to the lab bridge; no subnet/route collision check

`tools/leak-lab/netplan.py:104`:

```
nft add rule inet vprlab postrouting ip saddr 10.250.0.0/24 oifname "eth0" masquerade
```

There is no `iifname "vprlab0"`. If the host already uses `10.250.0.0/24`
(Docker, another lab, a VPN), this rule NATs that traffic too, and
`ip addr add 10.250.0.1/24` at `:89` may conflict. The advertised collision
check (`netplan.py:153-170`, doc `:220-230`) only inspects link names and table
names; it does not inspect `ip -j addr` or `ip -j route`. `render_plan("eth0")`
contains no `iifname` on the masquerade, and `check_name_collisions` returns
`[]` for any address/route state.

**Fix:** add `iifname "vprlab0"` to the masquerade; extend
`--check-name-collisions` to accept `ip -j addr`/`ip -j route` and reject an
existing `10.250.0.0/24`, or make the subnet configurable and checked.
Severity Minor because the plan is manual/reviewed, but this is host state
outside the lab.

### F-09 — No IPv4 forwarding enable/verify; a local control can PASS a phase with no WAN

`tools/leak-lab/netplan.py:83-104` creates the bridge, tap and NAT but never
ensures `net.ipv4.ip_forward=1` or verifies the host's WAN route. The tap still
captures the VM's egress (so a real leak is not missed if the VM sends one),
but a phase whose test action never reaches the WAN can PASS on the local
control plus an allowed WG packet. The doc `:267-273` scopes the proof to the
captured window, not to WAN connectivity; the M2 runner should check.
**Fix (Minor):** add an explicit verify/readback (not silently changing a host
global without review), and consider a remote end-to-end marker or a
required-WG-packet rule.

### F-10 — No `--immediate-mode`; the after-control can be lost on SIGINT

`tools/leak-lab/netplan.py:110` captures with `-U` but not
`--immediate-mode`. The repository's own prior evidence
(`tools/wg-birth-kernel-oracle.py:25`,
`docs/rust-v2/wg-birth-kernel-evidence.json:13`) added immediate mode "so
queued packets reach capture before SIGINT". Without it, the after-control may
be missing and the phase is INVALID (fails safe), but the procedure is flaky
and the `received` count can show unprocessed packets (see F-01).
**Fix (Minor):** add `--immediate-mode`; check `received == captured + dropped`.

### F-11 — ARP spoofing from foreign MACs is allowed; foreign MAC + VM IP is IP-classified

`pcapscan.py:350-377` treats any ARP whose sender/target MAC or IP matches the
VM as allowed when `allow_arp` is true. A foreign MAC can send a gratuitous
reply claiming the VM IP or the gateway IP and the scanner returns PASS:

```python
spoof = T.ethernet(T.arp_packet(2, "02:00:00:00:00:01", T.VM_IP,
                                T.VM_MAC, T.VM_IP), 0x0806,
                   src="02:00:00:00:00:01", dst=T.VM_MAC)
r = pcapscan.scan_capture(T.pcap([T.control_frame(T.NONCE_A), spoof]),
                          T.make_policy(allow_arp=True), (T.NONCE_A,))
# => PASS, no findings
```

`pcapscan.py:421-436` classifies IPv4 by IP only; a foreign MAC with the VM IP
and an allowed WG flow is PASS (the doc at `:193-198` says this is intentional).
Neither directly hides a real-IP leak from the VM tap, but they are L2
integrity/spoofing gaps. **Fix (Minor):** if ARP integrity matters, require
`sender_mac == vm_wan_mac` when `sender_ip == vm_wan_ipv4`, and require
`target_mac == vm_wan_mac` for replies to the VM; add a `strict_l2` policy
option if frames with a foreign MAC but the VM IP should be findings. Document
the current IP-only behavior clearly (it is currently only implied).

### F-12 — Control sink can be any IPv4; non-unicast/reserved addresses are not rejected

`policy.py:272-282` rejects only an exact `(sink_ipv4, sink_udp_port)` overlap
with an allowed flow. `sink_ipv4` may be a public real IP, multicast,
broadcast, `0.0.0.0`, `127.0.0.1`, or the VM's own IP. A valid control packet
to that endpoint is excluded from findings (`pcapscan.py:512-544`), so an
over-broad policy can declare a real-IP sink and exclude traffic to it. The doc
warns that an over-broad policy is an evidence defect (`:89-91`), but the
loader does not enforce a local/unicast sink. `allowed[].dst_ipv4` and
`vm_wan_ipv4` likewise accept non-unicast/reserved addresses.
**Fix (Minor):** require the control sink to be on the lab subnet (or add an
explicit `sink_is_local`), and reject multicast/broadcast/`0.0.0.0`/`127/8` and
the VM IP for control/allowed endpoints unless explicitly overridden.

### F-13 — No per-control timestamps or stats hash in the report

`pcapscan.py:710-720` reports `positive_controls_seen` as unique nonces and
`first_ts`/`last_ts` for the whole pcap, but no timestamp/count per control.
The canonical JSON therefore cannot prove the before/after ordering or that a
nonce was not replayed; a verifier must re-parse the pcap. The stats file's
SHA-256 is also absent (`source_sha256` covers only the pcap). **Fix (Minor):**
record per-nonce first/last timestamps and counts, and `stats_sha256`.

### F-14 — Netplan teardown fragility; `-s 0` is a doc requirement, not a scanner check

`netplan.py:114-116` deletes fixed names `inet vprlab`, `vprlab-tap0`,
`vprlab0`. If setup failed because one of those pre-existed (the collision
check is separate and can be skipped), running section 4 deletes the
pre-existing object. If `nft delete table` fails (table already gone), `set -e`
at `:84` stops before deleting the tap/bridge. The docs say check first
(`:220-230`), but the plan does not enforce it. **Fix (Minor):** make teardown
idempotent per object without deleting pre-existing objects (verify ownership
or a setup marker), and report partial cleanup.

The doc says `tcpdump -s 0` is mandatory (`:292-294`); the scanner does not
require a large snaplen, but any snaplen-truncated IP packet is INVALID via
`total_length > len(l3)`, so this is not a false pass. A small snaplen with
only small packets is accepted; that is acceptable because the full IP datagram
is present.

---

## Verified-good areas (adversarial checks that did not produce a false pass)

I constructed and ran the following; the classifier was conservative unless
noted:

- **pcap framing:** little/big endian microsecond/nanosecond magic, version
  2.4, linktype 1, snaplen 0, snaplen-truncated headers, truncated global/record
  data, `incl_len > orig_len`, `incl_len > snaplen`, trailing <16-byte garbage,
  pcapng magic, zero packets. All INVALID where expected.
- **IPv4:** IHL/options (20-60), `total_length < ihl`, `total_length >
  captured`, Ethernet padding, TCP/ICMP/other protocols, broadcast/multicast,
  VM MAC with other IP, foreign source with allowed destination. All findings
  except the documented IP-classification case.
- **Fragments:** first/non-first, non-first before first (resolved after the
  file), non-first without first, first allowed + later fragments allowed,
  first disallowed + later findings, fragment ID reuse. The key is
  `(src, dst, protocol, identification)`, so a later fragment can only be
  allowed when its destination IP is the allowed endpoint; this is not a
  real-IP leak. No false pass found.
- **VLAN/QinQ/non-IP:** 802.1Q allowed WG passes; 802.1Q leak detected with
  `vlan`; inner 802.1Q/QinQ, outer 0x88a8, LLDP 0x88cc, PPPoE 0x8863, unknown
  ethertypes all findings.
- **IPv6:** any frame with a complete 40-byte header is a finding; truncated
  header is INVALID; extension headers/fragments are irrelevant because the
  frame is already a finding.
- **ARP:** normal request/reply allowed only with `allow_arp`; unsupported
  htype/ptype/hlen/plen findings; truncated bodies INVALID; foreign ARP
  findings. The spoof/gratuitous behavior is F-11.
- **Controls:** exact prefix `VPRLEAKCTL1:`, 32 lowercase hex, exact 44-byte
  UDP payload, ASCII decode, unexpected nonce LEAK, uppercase/extra/short
  malformed, fragmented control malformed, UDP length bounds. Correct.
- **Verdict precedence:** structural/stats/zero/findings/missing controls/PASS
  matches the doc; findings beat missing controls (LEAK, fail-safe).
- **Findings cap:** 200 entries, `findings_total` complete, `_seq` removed;
  correct.
- **Policy:** bool-as-int, leading-zero IPv4, 3-octet IPv4, hostnames, ports
  0/65536, bool ports, bad MAC formats, duplicate JSON keys, duplicate
  endpoints, duplicate/reserved labels, control overlap, `ipv6_allowed`
  literal false, schema closure. Correct. The only gaps are address-class
  restrictions (F-12).
- **tsnames:** no `is_test_node` bypass found. The regex accepts only
  `zz-vprtest-01..99-do-not-use[-suffix]`, length <= 63, lowercase; generation
  refuses overlong rather than truncating; bool/out-of-range indices and bad
  suffixes rejected; trailing newline/space rejected.
- **netplan:** no `flush`, no edit of another table, per-interface IPv6
  sysctl keys, exact teardown names, JSON collision parsing, WAN interface
  syntax; plan-only. The gaps are F-06/F-08/F-09/F-10/F-14.
- **control.py:** nonce/IP/port/device validation, no shell injection, exact
  payload, `SO_BINDTODEVICE` with NUL, single-line output, no socket opened.
  Correct.

---

## Final verdict

**FAIL.**

F-01 is a Critical false PASS: a structurally valid pcap that is a prefix of
the real capture, with an honest tcpdump stats file whose `captured` count is
larger than the record count, returns PASS while a leak after the cut is never
examined. The engine has the count and simply does not use it. F-02 makes the
same class of failure possible through the drop counters. F-03/F-04 leave the
completeness evidence optional by default, and F-05 lets one replayed marker
satisfy both control slots. F-06/F-07 mean the documented host/control setup
either exposes the capture host or produces a false LEAK on the control's own
ICMP/ARP, which invites operators to disable the very evidence the monitor
needs.

The packet parser itself is conservative and well-tested for the shapes in the
brief; the failures are evidence completeness, fail-open defaults, control
freshness/ordering, and host/control integration, not the IPv4/IPv6/ARP
classifier. The existing 56 tests pass but do not cover any of F-01–F-07; two
of them encode F-01.

Recommended minimum before merge: F-01 and F-02 fixed; F-03/F-04 fail closed by
default; F-05 duplicate nonces rejected; F-06 input chain/sink and F-07 ARP
requirements documented and tested; add regression tests for each reproducer.
