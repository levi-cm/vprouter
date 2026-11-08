# Independent adversarial review: external leak monitor M1

**Final verdict: FAIL.** One Critical finding and eight Important findings remain. The most direct false PASS is a tcpdump stderr file containing an initial zero-drop summary and a later nonzero-drop summary: even `--require-stats` accepts it. Other confirmed PASS cases include known capture truncation, malformed UDP, extra bytes outside the marker's declared UDP length, and unvalidated fragment associations.

Review date: 2026-11-08. Scope: the seven requested files under `tools/leak-lab/` and `docs/rust-v2/leak-lab.md`, all initially uncommitted. This is an offline source/component review, not VM, host-network, or release qualification. No sudo, VM, network, nft or ip command was run. Only Python stdlib was used for executable probes. No implementation file was changed. Scratch artifacts were confined to `/var/tmp/leaklab-review-gpt` and removed after review.

## Validation

Requested command:

```text
python3 -B -m unittest tools/leak-lab/test_leak_lab.py -v
Ran 56 tests in 0.118s
OK
```

**56 passed, 0 failed, 0 errors.** This suite passing does not cover the failures below. Additional synthetic packet/stats probes reproduced the reported scanner failures. A separate 16-case assertion run verified structural rejection, IPv6 extensions, direction/port behavior and verdict precedence. Generated network-plan effects were assessed statically; privileged execution was NOT_RUN, as requested.

The following setup makes the reproduction snippets executable from the repository root with `python3 -B`. It uses the existing suite's pure in-memory packet builders; no socket is opened:

```python
import sys, struct, socket
sys.path.insert(0, "tools/leak-lab")
import test_leak_lab as t
import pcapscan as s
import policy, netplan

def zero_stats(n):
    return (f"{n} packets captured\n"
            f"{n} packets received by filter\n"
            "0 packets dropped by kernel\n")

def raw_scan(data, n, *, stats=None, expected=None):
    return s.scan_capture(
        data, t.make_policy(),
        [t.NONCE_A, t.NONCE_B] if expected is None else expected,
        tcpdump_stats_text=zero_stats(n) if stats is None else stats,
        require_stats=True,
    )

def review(middle, *, stats=None):
    frames = [t.control_frame(t.NONCE_A), *middle,
              t.control_frame(t.NONCE_B)]
    return raw_scan(t.pcap(frames), len(frames), stats=stats)
```

Except where the finding specifically tests missing/reused controls, scanner reproductions include both distinct expected controls and required stats. The fixture builders leave IPv4 checksums zero, as does the shipped suite; the reader does not inspect them. These are parser/classifier reproductions, not claims of successful delivery through a real network.

## C1 — Critical: the first drop counter hides later nonzero counters

**Location:** `tools/leak-lab/pcapscan.py:102-113` (especially `pattern.search` at line 103).

The parser takes only the first occurrence of each counter. An ordinary intermediate tcpdump status summary followed by its final summary can therefore report zero drops in the JSON even when the final stderr explicitly reports drops. An unobserved leak in the dropped packets can be followed by PASS. This directly violates the required rule that any positive drop counter makes the evidence INVALID.

```python
stats = zero_stats(3) + (
    "3 packets captured\n"
    "9 packets received by filter\n"
    "6 packets dropped by kernel\n"
)
r = review([t.wg_outbound()], stats=stats)
assert r["verdict"] == "PASS"                       # reproduced BUG
assert r["capture_meta"]["stats"]["dropped_kernel"] == 0

stats = zero_stats(3) + (
    "0 packets dropped by interface\n"
    "7 packets dropped by interface\n"
)
assert review([t.wg_outbound()], stats=stats)["verdict"] == "PASS"
```

**Required result:** INVALID for either input. Parse every relevant counter occurrence and reject any positive value; do not discard intermediate or final reports. Anchor and validate complete counter lines and reject ambiguous summaries.

**Documentation conflict:** `docs/rust-v2/leak-lab.md:168-169` promises INVALID for *any* nonzero kernel/interface drops.

## I1 — Important: partial or contradictory stats still certify completeness

**Location:** `tools/leak-lab/pcapscan.py:95-113`, `:686-696`.

The presence of either one drop counter is enough. No captured/received summary is required, and the scanner never reconciles the reported captured count with the records read. `--require-stats` thus means only that some recognizable zero-drop text exists, not that a complete capture summary was supplied. A missing kernel-drop line can be hidden by an interface-zero line. An incomplete pcap or mismatched stats file is also accepted even when its captured count demonstrably contradicts the pcap.

```python
r = review([t.wg_outbound()], stats="0 packets dropped by interface\n")
assert r["verdict"] == "PASS"                       # BUG: no kernel/capture summary
assert r["capture_meta"]["stats"]["dropped_kernel"] is None
assert r["capture_meta"]["stats"]["captured"] is None

r = review([t.wg_outbound()], stats=zero_stats(300))
assert r["packets"] == 3
assert r["verdict"] == "PASS"                       # BUG: stats say 300 captured
```

**Required result:** INVALID for incomplete required summaries or a captured-record count mismatch. Require the counters guaranteed by the supported tcpdump platform; interface-drop reporting may remain platform-dependent, but its presence must not replace a required kernel counter. Do not require `received == captured`: libpcap receive-counter semantics can differ.

**Documentation conflict:** `docs/rust-v2/leak-lab.md:10-11`, `:168-169`, `:240-242` overstate the completeness guarantee of the current stats parser.

## I2 — Important: known snaplen truncation and arbitrary frame trailers are ignored

**Location:** `tools/leak-lab/pcapscan.py:246`, `:279-284`, `:398-410`, `:650`.

The reader computes `orig_len > incl_len` and passes it as `truncated`, but `parse_frame` never uses that argument. If enough bytes remain for the stated IPv4 packet, the frame is allowed regardless of missing bytes on the wire. The code also silently slices away every Ethernet byte after IPv4 `total_length`, including trailers far beyond minimum Ethernet padding. It cannot establish what those captured or missing bytes contain.

This is a real pcap length/snaplen example: both controls are exactly 86 bytes and fully captured; the middle frame is only partially captured at the same snaplen.

```python
a, b = t.control_frame(t.NONCE_A), t.control_frame(t.NONCE_B)
full = t.wg_outbound() + b"SECRET" * 50
cap = full[:86]
records = [(a, len(a), len(a)),
           (cap, len(cap), len(full)),
           (b, len(b), len(b))]
r = raw_scan(t.pcap_from_records(records, snaplen=86), 3)
assert len(full) == 351 and len(cap) == 86
assert r["verdict"] == "PASS"                       # BUG: known missing wire bytes

assert review([full])["verdict"] == "PASS"          # arbitrary captured tail ignored
```

**Required result:** a capture with known missing frame bytes cannot produce a completeness PASS. Reject it as INVALID before allowing the frame. Define a narrow, explicit Ethernet-padding/FCS policy and account for all remaining bytes; do not equate arbitrarily large trailers with harmless minimum padding. The reproducer demonstrates ignored/missing data, not delivery of a separate IP datagram hidden in padding.

**Documentation conflict:** the general completeness promise at `docs/rust-v2/leak-lab.md:10-11` is stronger than the implementation. The later wording at `:291-295` narrows rejection to headers and declared IPv4 length, leaving this gap.

## I3 — Important: the relay allowance ignores UDP lengths; marker exemptions ignore extra IP bytes

**Location:** `tools/leak-lab/pcapscan.py:507-510`, `:519-526`, `:546-553`.

`udp_length` is parsed but never validated for allowed relay traffic. An unfragmented packet declaring a UDP length of 0, 1, 7 or 65535 is counted as allowed merely because its port bytes match. Such packets have not been established to contain a valid UDP datagram, let alone the allowed flow.

For controls, the code rejects `udp_length > len(payload)` but allows `udp_length < len(payload)`. It slices at that length and exempts the expected nonce while ignoring additional IPv4 payload bytes. Unlike minimum Ethernet padding, these extra bytes are inside the IP packet. This defeats the intended exact control exception at the complete-packet boundary.

```python
for length in (0, 1, 7, 65535):
    frame = t.ipv4_frame(t.udp_segment(
        40000, t.WG_PORT, b"PLAIN_SECRET", length=length))
    assert review([frame])["verdict"] == "PASS"      # BUG

# No genuine, exact A control is supplied: only this extended packet supplies A.
a_extra = t.ipv4_frame(t.udp_segment(
    40000, t.SINK_PORT,
    policy.control_payload(t.NONCE_A) + b"PLAIN_SECRET",
    length=8 + policy.CONTROL_PAYLOAD_LEN), dst_ip=t.SINK_IP)
r = raw_scan(t.pcap([a_extra, t.control_frame(t.NONCE_B)]), 2)
assert r["verdict"] == "PASS"                       # BUG
assert r["positive_controls_seen"] == [t.NONCE_A, t.NONCE_B]
```

**Required result:** reject invalid UDP lengths before allowlisting. For an unfragmented IPv4 UDP datagram, enforce the intended relationship between IP payload size and UDP length; a strict monitor should reject unaccounted bytes. Validate controls over the complete accepted datagram and reject extra IP payload bytes. Fragmented traffic needs full validation or a conservative finding, not the unfragmented equality check applied blindly.

**Documentation conflict:** `docs/rust-v2/leak-lab.md:106-107`, `:133-136`, `:166-167` claim exact controls and malformed-length rejection. Normal suffixes *included in* UDP length are correctly rejected; the reproducer places the suffix outside that length but inside IPv4 total length.

## I4 — Important: a first-fragment label allows unrelated, overlapping and impossible later fragments

**Location:** `tools/leak-lab/pcapscan.py:197-243`, `:438-449`, `:487-488`.

The fragment cache stores only a label keyed by source, destination, protocol and 16-bit ID. It never checks fragment byte ranges, conflicting overlap, UDP length, datagram completion, age or reuse. A completed allowed datagram leaves a permanent authorization for every later fragment with that key. Deferred fragments can also borrow a first fragment from arbitrarily later in the file.

```python
first = t.ipv4_frame(
    t.udp_segment(40000, t.WG_PORT, b"a" * 8, length=24),
    ident=77, more_fragments=True)
last = t.ipv4_frame(b"b" * 8, ident=77, frag_units=2)
# The first datagram is complete. This is unrelated orphan data at byte offset 64000,
# far beyond its declared 24-byte UDP datagram, reusing the same identification.
orphan = t.ipv4_frame(b"PLAIN_SECRET" * 8, ident=77, frag_units=8000)
r = review([first, last, orphan])
assert r["verdict"] == "PASS"                       # BUG
assert r["allowed_counts"]["mullvad-wg"] == 3

conflict = t.ipv4_frame(b"c" * 8, ident=77, frag_units=2)
assert review([first, last, conflict])["verdict"] == "PASS"  # conflicting final overlap
```

**Required result:** reject these associations. The simplest safe M1 behavior is a finding for every fragmented IP packet. If fragments must be accepted, reassemble within bounded lifetimes, validate ranges and headers, reject ambiguous overlaps/reuse/incomplete datagrams, check UDP length, and retire completed state. Do not claim a demonstrated port-change exploit from a nonzero fragment offset: this reproducer demonstrates unvalidated fragment data and association, not overwriting UDP ports at offset zero.

**Documentation conflict:** `docs/rust-v2/leak-lab.md:198-202`, `:295-297` call the strategy conservative, but matching only this cache key is insufficient to prove that an observed fragment belongs to the allowed datagram. The shipped fragment tests assert these simple label associations and miss reassembly ambiguity.

## I5 — Important: IPv4 source-routing options are skipped before allowlisting

**Location:** `tools/leak-lab/pcapscan.py:390-410`, `:548-553`.

IHL is bounds-checked, but options are never parsed or restricted. A packet addressed to an allowed relay with a Loose Source and Record Route option naming a forbidden final destination gets PASS. Whether that packet is actually forwarded depends on external source-routing behavior; no such runtime behavior was tested. Nevertheless the monitor certifies a packet with routing semantics it does not inspect.

```python
l4 = t.udp_segment(40000, t.WG_PORT, b"a" * 16)
h = bytearray(t.ipv4_packet(t.VM_IP, t.WG_IP, 17, l4))
h[0] = 0x47                                      # 28-byte IPv4 header
h[2:4] = struct.pack("!H", len(h) + 8)
options = bytes([0x83, 7, 4]) + socket.inet_aton("1.1.1.1") + bytes([0])
frame = t.ethernet(bytes(h[:20]) + options + bytes(h[20:]), 0x0800)
assert review([frame])["verdict"] == "PASS"         # BUG
```

**Required result:** reject LSRR/SSRR and malformed/unknown options under the strict policy, or conservatively reject `IHL != 5` if there is no operational requirement for options. Do not assume the IP destination field is the full routing contract.

**Documentation gap:** `docs/rust-v2/leak-lab.md:8-11` promises only declared relay flows but does not disclose that source-routing options are unexamined.

## I6 — Important: duplicate expected nonces let one observation satisfy two requested controls

**Location:** `tools/leak-lab/pcapscan.py:668-673`, `:698-708`; CLI input at `:756-761`.

Expected nonces are silently deduplicated. If a caller accidentally reuses the before nonce as the after nonce, a capture containing just one occurrence passes even with two `--expect-control` values. Replaying the same marker provides no second independent liveness observation.

```python
frames = [t.control_frame(t.NONCE_A), t.wg_outbound()]
r = raw_scan(t.pcap(frames), 2, expected=[t.NONCE_A, t.NONCE_A])
assert r["verdict"] == "PASS"                       # BUG for before/after qualification
assert r["positive_controls_seen"] == [t.NONCE_A]
assert r["capture_meta"]["expected_controls"] == [t.NONCE_A]
```

**Required result:** reject duplicate expected nonces instead of silently rewriting the evidence requirement. A production qualification interface should require distinct before/after nonces, preserve each observation's packet index/time, and let the phase runner bind them to the action window. Merely seeing two different nonces cannot independently establish phase ordering without that runner.

**Documented boundary, not an undisclosed ordering feature:** `docs/rust-v2/leak-lab.md:128-145` explicitly assigns fresh before/after generation and sequencing to future M2. That does not make silently accepting duplicated expectations safe. Likewise the current defaults allow PASS with no expected controls and no stats:

```python
assert s.scan_capture(t.pcap([t.wg_outbound()]), t.make_policy())["verdict"] == "PASS"
```

That default is explicitly cautioned against at `:240-242` and `:291-292`; it is a documented unsafe qualification mode, not an additional claim that the code implements before/after enforcement. M2 must not use a generic PASS without checking those preconditions.

## I7 — Important: generated source NAT can affect traffic outside the lab

**Location:** `tools/leak-lab/netplan.py:103-104`.

The masquerade rule is scoped only by source subnet and output WAN. It has no input-interface condition. Existing traffic from another host interface with a `10.250.0.0/24` source, or locally generated traffic using that source subnet, matches it too. An isolated nftables table name does not isolate the hook's effect on packets. The collision checker checks names, not subnet/route ownership.

```python
plan = netplan.render_plan("eno1")
rule = next(line for line in plan.splitlines() if "masquerade" in line)
assert rule == ('nft add rule inet vprlab postrouting '
                'ip saddr 10.250.0.0/24 oifname "eno1" masquerade')
assert "iifname" not in rule
```

**Required result:** scope source NAT to lab ingress as well as its source subnet and WAN, and require a nonoverlapping subnet preflight before setup. This is a static rule-match finding; no claim is made that the current host actually has overlapping traffic.

**Documentation gap:** `docs/rust-v2/leak-lab.md:204-220` describes an isolated host plan but does not disclose the subnet-wide effect on non-lab ingress.

## I8 — Important: the host plan does not guarantee ownership of the table it mutates/deletes

**Location:** `tools/leak-lab/netplan.py:95-104`, `:112-116`, `:120-150`, `:153-169`, `:192-214`.

The optional collision check is separate from setup, can inspect only one resource class, and silently ignores malformed inventory entries. Setup uses `nft add table`, which is not an exclusive-create ownership guard for an existing table. It can consequently add to an already existing `inet vprlab`, while teardown unconditionally deletes the entire named table. This contradicts the claim that only objects created by the plan are deleted. Existing bridge/tap creation failures do not establish nft table ownership.

Pure stdlib reproductions of fail-open inventory validation:

```python
assert netplan.check_name_collisions('[null, {}, 7]', None) == []
assert netplan.check_name_collisions(
    None, '{"nftables":[{"table":{"family":"inet"}}]}') == []
assert netplan.check_name_collisions('[]', None) == []  # nft inventory not checked
plan = netplan.render_plan("eno1")
assert "nft add table inet vprlab" in plan
assert "nft delete table inet vprlab" in plan
```

No nft command was executed; table-existence behavior is a static command-semantics concern. A preexisting same-name table is the concrete precondition for the destructive case, not an assertion about current host state.

**Required result:** require both validated inventories for a full preflight, reject malformed entries that should describe resources, fail on preexisting names, use exclusive creation, and record ownership before allowing teardown. Preserve any preexisting table and links. Freshness/races also need a runtime guard; an old JSON snapshot alone is not ownership proof.

**Documentation conflict:** `tools/leak-lab/netplan.py:9-10`, `:112-113` and `docs/rust-v2/leak-lab.md:214`, `:220-230` overstate ownership and malformed-input rejection.

## Other requested attack surfaces and limits

- **Policy loader:** tested rejection of booleans as schema versions/ports, ports 0 and 65536, `010.1.1.1`, `1.1.1`, malformed MAC separators/trailing newlines, nonboolean `allow_arp`, and integer `ipv6_allowed=0`. The suite also passes duplicate-key, closed-object and duplicate endpoint/label checks. No additional loader bypass was demonstrated. The schema names the Python loader as the binding validator; schema-only validation must not replace it.
- **Ethernet and IP:** LLDP `0x88cc`, PPPoE `0x8864`, outer QinQ `0x88a8`, stacked 802.1Q, multicast/broadcast forbidden IP destinations, ICMP errors quoting a forbidden packet, and IPv6 extension chains produced LEAK. Single 802.1Q frames are intentionally inspected and can be allowed. Invalid IHL/version, missing options, too-short/too-long IPv4 total length produced INVALID.
- **Direction and spoofing:** an outbound packet with the VM MAC but another source IP to the allowed endpoint produced LEAK. A non-VM source to the allowed endpoint also produced LEAK. Wrong inbound endpoint source port produced LEAK. A VM source IP with another MAC and a different outbound UDP source port both produced PASS. These last two are explicitly permitted by the IP-based/endpoint-only policy at `pcapscan.py:415-436`, `:548-551` and `docs/rust-v2/leak-lab.md:193-197`; they are not claimed here as hidden port/MAC enforcement. There is no declared VM UDP local-port restriction.
- **ARP:** with `allow_arp=True`, ordinary/gratuitous ARP, opcode 65535, and a sender-MAC mismatch between Ethernet and ARP payload all produced PASS when an inner ARP address involved the VM. `pcapscan.py:340-377` never validates operation or consistency between Ethernet and ARP sender. This is a broad ARP exception, not ARP-spoofing detection or authentication. The supplied policy does not declare a gateway MAC/IP allowlist, so valid peer ARP cannot be authenticated from it. Before using the exception as an ownership guard, define allowed ARP operations, sender consistency and peer identities. `allow_arp=False` correctly makes ARP a finding; unsupported hardware/protocol/address lengths are findings or INVALID when truncated.
- **Controls:** uppercase nonce, normal prefix/suffix additions inside the declared UDP payload, unexpected nonces and fragmented controls are not silently excused. Exact matching works within the slice inspected; I3 is the extra-IP-bytes exception, I6 the duplicated-expectation exception. `control.py` generates a correctly NUL-terminated `SO_BINDTODEVICE` argument; its emitted Python was parsed with `ast` and the device argument bytes verified as `[101,116,104,48,0]` for `eth0`. No generated control command was executed.
- **Pcap:** both endian orders and micro/nanosecond formats pass the existing suite. pcapng, unsupported linktype, trailing non-record garbage, invalid timestamp fraction, zero snaplen, included length exceeding original length or snaplen, and truncated structures produce INVALID. I2 concerns complete record storage with known missing wire bytes, not a partial record header/body.
- **Verdict precedence:** a single positive drop summary plus a leak produced INVALID while retaining the finding. A finding plus a missing expected control produced LEAK. Both match the documented precedence. C1 is a stats-extraction failure before precedence, not reversal of the precedence itself.
- **`tsnames.is_test_node`:** tested newline/NUL suffixes, uppercase/Unicode, `.evil`, wrong-width/out-of-range indexes, doubled/trailing hyphens and overlong suffixes; no syntactic bypass was demonstrated. This is a strict name recognizer, not proof that a Tailscale node is expendable. No node identity/action is qualified here.
- **Host state boundaries:** generated commands contain no flush, global forwarding sysctl, other-table deletion, or sysctl on a variable WAN name. The two IPv6 sysctls target the fixed lab interface names. The plan only prints commands. I7 and I8 are the concrete non-lab/ownership concerns; no commands were executed to test them. The forward rules are broad accepts between lab and named WAN, including unsolicited inbound traffic; they are not stateful return-only rules. The docs describe that broad forwarding rather than promising a stateful firewall.
- **WireGuard identity:** matching an allowed outer UDP tuple does not authenticate WireGuard or prove encryption. Arbitrary UDP payload is accepted, and the suite's `b"wireguard"` payload is not a real WireGuard packet. Even syntactic WireGuard checks cannot authenticate encrypted traffic without the necessary trust/keys. Treat this monitor as an outer endpoint allowlist; do not turn its current PASS into proof of authenticated WireGuard operation or actual phase execution.

One minor documentation inconsistency also remains: `docs/rust-v2/leak-lab.md:186-187` says `fragment_without_first` means no first fragment was seen earlier, whereas the implementation and `:198-202` resolve against first fragments anywhere in the capture. Correct the reason description after choosing the safe fragment policy.

## Reviewed content hashes

SHA-256 at review completion:

```text
d129b63379ce6283d4e1711159a7d6413553fb7855633e516966e85781e3ae3c  tools/leak-lab/policy.py
44ddc853ec2f98da71b4be30374f9effa7f020ac38732371d9baedb37d37c0ed  tools/leak-lab/policy.schema.json
6130b680ac66c260899cb473da53f526fce091ff16004900085543d85cadaa67  tools/leak-lab/pcapscan.py
560d6e610956aa69f7be3e7a46ca93ccc12a21edb5f8094534a6e33b72c0a1b7  tools/leak-lab/control.py
348ae8b43b76a402d6af35fc6beb47cf61038e1d27b6b831387f3d2ef3ac17aa  tools/leak-lab/tsnames.py
57066d0af28a41706e706a167febdad725441d962584726bfb641db5feac7b99  tools/leak-lab/netplan.py
527c7fa63c884ed0b5f5153ba2b22ec188c7c084f3bdd02340a3006d1b0bc451  tools/leak-lab/test_leak_lab.py
2b30a5a5a5a7d53ed9b158a78d3fa53239e106dff7e77e77511c5ef56d396492  docs/rust-v2/leak-lab.md
```

**Final verdict: FAIL.** The passing offline suite is insufficient for this monitor's false-PASS risk. Fix the confirmed completeness/classification gaps and host-plan ownership/scope before using PASS as phase evidence; operational qualification remains NOT_RUN.
