# Leak-lab M1 review (adversarial, Opus) — 2026-11-08

Scope: uncommitted `tools/leak-lab/{policy.py,policy.schema.json,pcapscan.py,control.py,tsnames.py,netplan.py,test_leak_lab.py}` and `docs/rust-v2/leak-lab.md`.
Method: read every file. Then ran 16 scratch reproducer tests (72 cases counting the imported suite) under `/var/tmp/leaklab-review-opus`, built on the suite's own packet builders. The scratch directory was deleted afterwards. No sudo, VM, network, nft or ip commands were used.

Existing suite: `python3 -B -m unittest tools/leak-lab/test_leak_lab.py -v` gave **Ran 56 tests, OK** (0 failures, 0 errors, 0 skipped).

## Verdict: **FAIL** (0 Critical, 4 Important, 9 Minor)

The packet classifier is solid. I found no packet that leaves the lab toward a non-declared destination and gets counted as allowed. The FAIL comes from the verdict and protocol layer. PASS is reachable with no proof that the monitor saw anything. A replayed nonce satisfies both the before and the after control. Content the VM controls can turn a leak run into an INVALID report with zero findings. And on a stock host the documented control protocol produces a LEAK every run.

### Packet shapes I checked that are handled correctly (no finding)

- LLDP 0x88cc, PPPoE 0x8864, 802.3/LLC (length < 0x600), outer 0x88a8, and an inner QinQ tag all produce a finding.
- VLAN VID 0 plus DNS is a LEAK, consistent with Linux treating priority-tagged frames as untagged.
- A frame with the VM MAC and a different source IP is `foreign_frame`.
- Inbound traffic from the relay IP with the wrong source port is `udp_not_allowed`.
- Any frame with a full IPv6 header is a LEAK, even if the payload is truncated.
- Snaplen-truncated IPv4 is INVALID.
- pcapng magic, version 2.3, snaplen 0, FCS bits in the linktype field and trailing garbage are all INVALID.
- Control nonce variants are all `malformed_control` (LEAK): uppercase hex, one extra byte, one byte short, lowercase prefix.
- Fragments are sound:
  - Every offset-0 fragment is classified on its own merits.
  - Later fragments are keyed by `(src,dst,proto,id)`, so they cannot reach a different destination or port. The minimum non-zero offset is 8 bytes, so a fragment cannot overwrite the UDP ports.
  - A forged second "first fragment" with the same id is flagged on its own.
  - A first fragment too small to hold a full UDP header is `udp_header_incomplete`.
- Policy loader:
  - Rejects `010.1.1.1`, `1.1.1`, values with surrounding whitespace or a trailing newline, and Arabic-Indic digits.
  - Rejects ports 0, 65536, `true`, `51820.0` and `"51820"`.
  - Rejects MACs written with dashes, with no separators, or with a single-digit octet.
  - Rejects bools where ints are expected, duplicate keys and NaN.
- `tsnames.is_test_node` rejects an uppercase name, a trailing newline, a missing leading zero (`-1-`), a trailing hyphen, a double hyphen, `-do-not-usex`, a leading `x`, and the FQDN form.
- `netplan` never contains `flush`, never deletes or edits another table, and runs sysctl only on its own two interfaces.

---

## Important

### I1. PASS is reachable with no positive control and no tcpdump stats (fail-open defaults)
`pcapscan.py:654-708`, CLI `pcapscan.py:756-764`.

`expected_nonces` defaults to `()`, and `require_stats` defaults to `False`. So `pcapscan.py --policy p --pcap f` returns `PASS` and exit 0 when the capture holds a single WireGuard packet. It has no proof the monitor saw anything and no proof nothing was dropped.

The purpose of the tool is to make a false PASS impossible. The doc (lines 241, 291) says the operator or the M2 runner "must" supply both, but the tool does not enforce it. One forgotten flag in a script turns the monitor into a PASS stamp.

```python
r = pcapscan.scan_capture(pcap([wg_outbound()]), make_policy(), ())
assert r["verdict"] == "PASS"          # reproduced
```

Fix: an empty expected-control set is INVALID (`no_positive_controls`). Stats are required by default. Opting out takes an explicit, loud flag such as `--allow-no-stats`, which forces INVALID or at least `PASS_UNPROVEN`. Require at least 2 distinct controls.

### I2. The same nonce passed as both "before" and "after" collapses to one sighting
`pcapscan.py:668-673` (silent dedup) together with `control.py:80,115` (the `--nonce` option "reuse an existing nonce").

`--expect-control N --expect-control N` is deduplicated to `[N]`, and one sighting of N satisfies it. If an operator or runner reuses the nonce for the after-control, a capture that stopped early still passes. For example, tcpdump dies after the before-control and before the test traffic: the only control in the capture is the before-control, and the result is PASS.

The scanner also never checks control order or timing against the phase. `positive_controls_seen` carries no timestamps.

```python
r = pcapscan.scan_capture(pcap([control_frame(NONCE_A), wg_outbound()]),
                          make_policy(), (NONCE_A, NONCE_A))
assert r["verdict"] == "PASS"          # reproduced; expected_controls == [NONCE_A]
```

Fix:
- Reject duplicate expected nonces with exit 2.
- Better: take `--control-before N1 --control-after N2` and require N1 ≠ N2. Also require that N1's first sighting comes before N2's, and report each control's timestamp and packet index.
- Drop or restrict `control.py --nonce` reuse.

### I3. Content the VM controls aborts the scan, so a real leak becomes "INVALID, 0 findings"
`pcapscan.py:678-682` stops at the first `CaptureInvalid`. These raise on frame content rather than capture damage: `:247-248`, `:388-402`, `:578-581`. The `truncated` argument at `:246` is never used.

Structural capture damage (`incl_len < orig_len`, a truncated record) is treated the same as a complete frame the VM chose to emit malformed. That includes a runt shorter than 14 bytes, an IPv4 header under 20 bytes, IHL < 5, `total_length` larger than the frame, and an IPv6 ethertype with version ≠ 6. Every packet after it is never parsed.

The doc's threat model (lines 36-37: "a compromised or buggy router cannot hide frames") is false. One crafted frame, then the leak, yields INVALID with `findings_total == 0`. Since INVALID means "capture not evidence, re-run", the leak is dismissed. Separately, precedence at `:693-708` also makes drops outrank observed findings: a capture with a DNS leak and one kernel drop reports INVALID. That is inconsistent with missing controls, where LEAK wins.

```python
bad = ethernet(b"\x45" + b"\x00"*9, 0x0800)      # complete 24-byte frame, 10-byte "IPv4"
r = scan([control_frame(NONCE_A), bad, DNS(), DNS()])
# -> INVALID truncated_ipv4_header, findings_total=0, packets=2 (DNS never read)
# IHL=4 variant -> INVALID invalid_ipv4_ihl, findings_total=0
# DNS + "1 packet dropped by kernel" -> INVALID packet_drops (finding present but verdict not LEAK)
```

Fix:
- Raise INVALID for structure only when the record is actually truncated (`orig_len > incl_len`) or the pcap framing is broken.
- A complete frame with malformed L2/L3 is a finding (`malformed_frame`, LEAK), and scanning continues.
- Make LEAK outrank INVALID whenever `findings_total > 0`, because observed leaks are positive evidence that drops cannot create. Alternatively, emit both `verdict: LEAK` and `invalid_reason`.

### I4. The documented positive-control protocol produces a LEAK on a stock host, which pushes operators toward ignoring or whitelisting findings
`netplan.py:320-354`, `docs/rust-v2/leak-lab.md:99-145`.

The sink is the host's own bridge address, `10.250.0.1:39001`. Neither the plan nor the doc starts a listener or drops that port in an input hook. With no socket bound, the Linux host answers each control with an ICMP port-unreachable to `10.250.0.2`. The first one gets through the rate limiter. That reply crosses the tap and becomes `icmp_not_allowed`, so the verdict is LEAK every run.

The same applies to:
- ICMP "frag-needed" for oversized WireGuard packets;
- host-originated multicast on `vprlab0` (avahi/mDNS, LLMNR, IGMP), which shows up as `foreign_frame`.

None of this is a false PASS. But the protocol cannot produce a clean PASS, and the obvious local fix ("allow ICMP from the sink", "ignore foreign_frame") opens a real hole.

Also, SO_BINDTODEVICE bypasses routing but not the router VM's own kill-switch nftables. The doc should state that the system under test must explicitly permit `vm:* → sink:39001/udp`, and that this exception is part of the reviewed policy.

```python
ctrl = control_frame(NONCE_A)
icmp = ipv4_frame(struct.pack("!BBHI",3,3,0,0)+ctrl[14:42], src_ip=SINK_IP, dst_ip=VM_IP,
                  protocol=1, src_mac=GW_MAC, dst_mac=VM_MAC)
r = scan([ctrl, wg_outbound(), icmp])   # -> LEAK ['icmp_not_allowed']
```

Fix: in the `inet vprlab` table, add an `input` base chain (`policy accept`) with `iifname "vprlab0" udp dport <sink> drop`. Silent drop means no ICMP. Optionally also drop all other input from `vprlab0`, which protects the host from the untrusted VM. Document disabling mDNS/LLMNR on `vprlab0`, or explain the expected host-originated noise. Do not relax the scanner.

---

## Minor

**M1. tcpdump stats are not bound to the pcap, and parsing is first-match only.** (`pcapscan.py:88-113`)
- `captured` is never compared with the number of pcap records. `9999 packets captured` with a 2-record pcap gives PASS.
- `re.search` takes the first match. If the stats file holds two summaries (for example after an accidental `2>>`), a later `4 packets dropped by kernel` is ignored.
- Error lines are ignored, for example `tcpdump: pcap_loop: The interface disappeared`, which is still followed by a summary.
- The tcpdump exit status is not recorded.

Fix: require exactly one occurrence of each counter. Require `captured == packets`. Treat any `tcpdump: ... error`, `pcap_loop`, `disappeared` or `went down` line as INVALID. The controls give a backstop here, which is why this is Minor.

**M2. IPv4 options are accepted on allowed flows.** (`pcapscan.py:391-410`)
A packet with LSRR to `8.8.8.8` addressed to `relay:51820` counts as `mullvad-wg`. Debian's default `accept_source_route=0` drops it on the host, and WireGuard never sends options. Fix: from the VM, IHL ≠ 5 (or any option at all) should be a finding.

**M3. The policy accepts semantically wrong addresses.** (`policy.py:231-282`)
These are all accepted:
- `vm_wan_ipv4` set to `0.0.0.0`;
- `vm_wan_ipv4 == sink_ipv4`;
- an allowed relay of `255.255.255.255:67`;
- the bridge or host IP `10.250.0.1:53` as a relay;
- the VM's own IP as a relay;
- a broadcast or multicast `vm_wan_mac` (`ff:…`, `01:00:5e:…`).

The doc admits an over-broad policy hides leaks, so the loader should reject at least: unspecified, broadcast, multicast, loopback and link-local addresses; private or lab-subnet relays; and overlaps between the relay, VM and sink addresses. A non-unicast VM MAC should also be rejected.

**M4. ARP spoofing from the VM is counted as allowed.** (`pcapscan.py:350-377`)
- A gratuitous ARP from the VM MAC claiming `10.250.0.1` is allowed.
- An ARP carrying the VM IP from a foreign MAC is allowed.
- The Ethernet source MAC is never compared with the ARP sender MAC.

This is not a WAN leak, because ARP stays local. But it is evidence the router is misbehaving. Suggest: when the sender MAC is the VM MAC, require the sender IP to be the VM IP (or 0.0.0.0 for a probe), and require the Ethernet source to match the ARP sender.

**M5. Bytes the scanner never inspects.**
- Bytes after the UDP length but inside the IP `total_length` of a control packet: a control with 10 hidden trailing bytes still PASSes.
- Ethernet trailer after the IP `total_length`.

Neither is routable beyond the host, but strict mode should require `udp_length == ip_payload_len` for controls, and should flag non-zero padding from the VM.

**M6. The source port of outbound flows is not pinned.** UDP from any source port to `relay:51820` is allowed. This is acceptable for real-IP exposure, since only Mullvad sees it. Note it in the doc, or optionally pin the WireGuard `ListenPort`.

**M7. netplan gaps.** (`netplan.py:320-354`)
- Nothing checks that `10.250.0.0/24` or `10.250.0.1` are not already used on the host. A clash adds a duplicate connected route, and the masquerade rule then also applies to the other network.
- `check_name_collisions` ignores `ip -j link` `altnames`.
- The plan never mentions `net.ipv4.ip_forward`. An operator who enables it globally changes host state, and Docker's iptables `FORWARD` policy DROP may silently block the lab.
- `--wan-interface` accepts `lo`, `.` and `-x`.
- `vprlab0` is brought up before IPv6 is disabled on it. This is harmless while it has no carrier, but disabling IPv6 first is cleaner.

**M8. Dead parameter.** `parse_frame(..., truncated, ...)` at `pcapscan.py:246` is unused. Fixing I3 should make use of it.

**M9. `tsnames.is_test_node` accepts any suffix,** for example `zz-vprtest-01-do-not-use-prod`. It rejects the MagicDNS FQDN, so callers must strip `.tailnet.ts.net` and must not treat the suffix as meaningful. This is not a bypass of the prefix, which is anchored. Document the FQDN behaviour.

---

## Doc vs code

- Lines 36-37, "a compromised or buggy router cannot hide frames": false, see I3.
- Lines 164-174, precedence: matches the code. But the "deliberate" choice of INVALID over LEAK for drops and malformed frames is the I3 defect, and missing controls deliberately go the other way.
- Lines 128-136 and 144-145, controls before and after: the scanner does not and cannot enforce this. Duplicate nonces are silently merged (I2).
- Lines 241-242 and 291: "always use --require-stats" and "must always provide nonces" are only advisory (I1).
- Lines 104-109 say the control bypasses "the tunnel and its routing". True for routing, but the VM's kill switch must allow it, and the host's ICMP reply makes it a LEAK (I4).
- The other claims match the code: closed policy shape; schema mirror; fragment resolution earlier or later in the file; IPv6 always a finding; snaplen truncation INVALID; netplan teardown deleting only its own objects; no `flush ruleset`; exit codes 0/1/2; the 200-finding cap with `findings_total`.

## Reproducer index (all run, all reproduced as stated)

| ID | Expected for a correct monitor | Observed |
|---|---|---|
| I1 | INVALID | PASS (no controls, no stats) |
| I2 | INVALID or usage error | PASS (`expected_controls=[A]`) |
| I3 | LEAK, scanning continues | INVALID `truncated_ipv4_header`/`invalid_ipv4_ihl`, 0 findings; drops + DNS → INVALID |
| I4 | PASS on a clean run | LEAK `icmp_not_allowed` from the host's port-unreachable |
| M1 | INVALID | PASS with captured=9999 vs 2 records; second summary with 4 drops ignored |
| M2 | LEAK | PASS, LSRR counted `mullvad-wg` |
| M4 | finding | PASS, `arp` +1 |
