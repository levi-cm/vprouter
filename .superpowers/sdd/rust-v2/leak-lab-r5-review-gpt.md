# Leak lab adversarial review, round 5 (GPT)

Scope: `0097e78..649a5e2`, limited to `tools/leak-lab`, `docs/rust-v2/leak-lab.md`, and `docs/rust-v2/leak-lab-vm.md`; surrounding code read as needed. Independent offline review. No subagents, privileged commands, network execution, or live lab activity.

Report opened before adversarial checks; findings and verification results will be appended incrementally.

## Critical R5-C1 — ICMP allowance silently accepts arbitrary bytes beyond the quoted datagram

Location: `tools/leak-lab/pcapscan.py:1154` (`_allowed_icmp_quote`, especially lines 1170–1184); accepted at lines 846–862.

**Actually reproduced:** an outbound ICMP 3/3 with correct outer VM/endpoint IPs and lab MACs contains a complete, correctly sized IPv4/UDP WireGuard initiation from the endpoint to the VM, followed by `REAL_IP=198.51.100.77;SECRET=synthetic-canary` **outside the quoted IP total_length**. The outer IP total_length includes these secret bytes. IPv4 and ICMP checksums were recomputed in the executed scratch probe. With genuine shape-valid UDP fixtures in both directions and both controls, the real scanner returns `PASS`, `findings_total=0`, `allowed_icmp_quotes={"mullvad-wg": 1}`. The same secret-bearing frame **before the before-control or after the after-control also returns PASS**, recorded only as one outside-window allowed packet. This is a newly introduced false PASS for actual non-WireGuard cleartext, distinct from the previously accepted inability to authenticate ciphertext-shaped UDP. No live capture was read or modified.

Minimal equivalent reproducer (run from `tools/leak-lab`; test helper packets use zero checksums, which this scanner accepts; the executed scratch variant additionally corrected checksums):

```python
import test_leak_lab as t
quote = t.ipv4_packet(t.WG_IP, t.VM_IP, 17,
    t.udp_segment(t.WG_PORT, 40410, t.wg_initiation()))
icmp = bytes([3, 3]) + bytes(6) + quote + b"REAL_IP=198.51.100.77;SECRET=synthetic-canary"
frame = t.ipv4_frame(icmp, protocol=1)
r = t.scan_middle([frame, t.wg_outbound(), t.wg_inbound()], expect_tunnel="up")
assert r["verdict"] == "PASS" and r["findings_total"] == 0
assert r["allowed_icmp_quotes"] == {"mullvad-wg": 1}
```

The parser never reads quoted IPv4 total_length, UDP length, fragment flags/offset, or the WireGuard length implied by UDP length. Additional executed variants all returned PASS/zero findings: quoted total_length 0, 20, or 65535; quoted UDP length 8 or 65535; a complete quote declaring only a four-byte type-1 or type-4 payload; quoted MF flag; quoted nonfirst fragment offset 1. These are the same missing structural-validation defect, not separate findings. The four-byte-only type-1 case is not a truncated quote of a valid handshake: its quoted IP/UDP lengths themselves declare only four payload bytes.

**Suggested fix:** parse and validate the quoted IPv4/UDP datagram, refuse all quoted fragmentation/options and inconsistent lengths, apply `wireguard_length_problem` to the declared UDP payload length, and reject every byte beyond the declared quoted IP packet. Permit truncated ICMP quotes only under explicit, validated bounds (enough prefix, internally consistent original IP/UDP/WireGuard lengths). Preserve the correct outer L2, source/destination and endpoint-port checks. Add adversarial full-scanner regressions for these cases inside and outside the control interval. Re-scan retained live evidence with the corrected scanner before relying on its PASS; this review proves scanner unsoundness, not that those live captures actually contain a leak.

## Required suites (each invoked once)

Both ran from `tools/leak-lab` with `TMPDIR=/var/tmp/leaklab-r5-gpt`:

- `python3 -B -W error -m unittest test_leak_lab`: **261 tests, OK**, 8.599 s.
- `python3 -B -W error -m unittest vm.test_vm`: **202 tests, OK**, 10.447 s.
- Total **463 tests**, zero failures/errors/skips reported.

