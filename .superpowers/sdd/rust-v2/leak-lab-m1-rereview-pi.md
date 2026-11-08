# leak-lab M1 second-round adversarial review (pi)

**Verdict: FAIL** — the fixes closed every round-1 Critical/Important
reproducer I re-ran except one: the `received by filter` half of pi F-01 is
still ignored, and the tool still returns `PASS` on a stats file that itself
says packets were received by the filter but never written (C1, Critical). No
new Critical was introduced by the fixes; six Minor issues remain.

Scope: the six Python tools, `policy.schema.json`, `test_leak_lab.py` and
`docs/rust-v2/leak-lab.md` at commit `2fc1779` (working tree otherwise clean
except an untracked `tools/leak-lab/vm/qga.py` created at 00:12:23 by a
concurrent process — not by this review; see the end). Offline only: source
read, in-memory packet/pcap/stats construction, direct calls, CLI runs, and
static command-semantics checks. No sudo, VM, network, `nft` or `ip` command was
executed. Scratch lived in `/var/tmp/leaklab-rr-pi` and was deleted.

Requested suite:

```
$ python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py
Ran 150 tests in 0.225s

OK
```

150 tests, 0 failures, 0 errors, 0 skipped. The suite passes; the false-PASS
below is asserted by one of its own tests (`test_leak_lab.py:521-526`).

Reviewed SHA-256 at review time (unchanged during the review):

```
7caef839c7c3b8fb9035ca41599d9791153e0bda5fb6c4060fa741a619abfbef  tools/leak-lab/pcapscan.py
ad4d90749bbd64a8ad1ad2df844af92cca11c1a20825ed6fa42d0f38b7f7596e  tools/leak-lab/policy.py
96d66f7c04b13aaea3e6ff9f60a5677390f1ccba3a36ca4bee8c04aec958c3ca  tools/leak-lab/netplan.py
33eda7f9fe1c47ff5aaf520a0ad019d9ed548d0e98a22102a411f5de3aa9dcce  tools/leak-lab/control.py
6715c7cfcbbcb7ea4d4613e44f06a506a7d70f2861c5d172e249279e1c28a3d1  tools/leak-lab/tsnames.py
edba9329d246aa20d595c8a705d65df3baf8d3a65de7d9e78358de301c9ba097  tools/leak-lab/test_leak_lab.py
434c48d13e9c3b29cfa1b6e8ec9dd678205bab1cd870050b236011c51564b9e8  tools/leak-lab/policy.schema.json
86d39fcb37e90a68c30b586424965e646ed16c11bd3a608f9839fa3568382c09  docs/rust-v2/leak-lab.md
```

## Round-1 disposition (all reproducers re-run)

The new API requires `control_before`/`control_after` and stats text, so I
adapted the snippets minimally (distinct nonces, matching stats counts) and used
the suite's own builders.

| Round-1 ID | Sev | Result now | Evidence |
|---|---|---|---|
| pi F-01 (captured prefix) | C | **FIXED** | 4-record stats + 3-record pcap -> `INVALID`, `stats_packet_count_mismatch`; `0 captured` with records -> `INVALID` |
| pi F-01 (received unread) | C | **NOT FIXED** | `received=100, captured=3` -> `PASS`, exit 0 (see C1) |
| pi F-02 / gpt C1 (later drop summary) | I/C | fixed | second summary `500 dropped by kernel` -> `INVALID`, `packet_drops`; later interface drop -> `packet_drops` |
| pi F-03 (stats optional) | I | fixed | `tcpdump_stats_text=None` -> `ValueError`; CLI requires `--tcpdump-stats` |
| pi F-04 (zero controls) | I | fixed | API requires two distinct nonces; nonces not in the pcap -> `INVALID`, `missing_positive_controls` |
| pi F-05 / gpt I6 / opus I2 (duplicate nonces) | I | fixed | `before == after` -> `ValueError`; CLI -> exit 2; a repeated nonce in the pcap -> `replayed_control` LEAK |
| pi F-06 / opus I4 (no input chain, control ICMP) | I | fixed in the plan | `netplan.py` input chain drops `iifname "vprlab0"`; output chain drops host IPv4 to the lab (see the kernel-path analysis below) |
| pi F-07 (`allow_arp: false` unusable) | I | documented boundary | docs now say a real phase needs `allow_arp: true` or a static neighbour; sample uses `true` |
| gpt I1 (partial/contradictory stats) | I | fixed except the received relation | only an interface line -> `stats_incomplete`; `captured=300` vs 3 records -> `stats_packet_count_mismatch`; two distinct summaries -> `stats_contradictory` |
| gpt I2 (snaplen truncation, arbitrary trailer) | I | fixed | `incl_len < orig_len` -> `INVALID`, `snaplen_truncated_record`; 150-byte trailer -> `ethernet_trailer` LEAK; zero pad to 60 bytes -> PASS |
| gpt I3 (UDP length, control extra bytes) | I | fixed | udp_len 0/1/7/65535 on an allowed flow -> `malformed_frame`; control + hidden IP payload -> `malformed_frame`, nonce not seen |
| gpt I4 (fragment association) | I | fixed | orphan after complete -> `fragment_after_complete`; conflicting final overlap -> finding; gap/overlap/out-of-range/stale/duplicate-first -> findings; only exact contiguous completion is counted (matrix below) |
| gpt I5 (IPv4 options) | I | fixed | LSRR to 1.1.1.1 -> `ipv4_options` LEAK |
| gpt I7 (NAT scope) | I | fixed | rule is `ip saddr 10.250.0.0/24 iifname "vprlab0" oifname "<wan>" masquerade` |
| gpt I8 (ownership) | I | fixed | `nft create table ... { comment ... }` (exclusive per nft(8)); four-inventory preflight; tagged teardown |
| opus I1 (fail-open defaults) | I | fixed | as F-03/F-04 |
| opus I3 (malformed frame aborts scan; drop outranks finding) | I | fixed | malformed frame is a finding and the scan continues; DNS leak + 1 kernel drop -> `LEAK` with `invalid_reasons=["packet_drops"]` |

No round-1 Critical/Important other than the pi F-01 remainder is still
reproducible.

---

## Findings

### C1 — Critical: `received by filter` is never reconciled; a capture with unread ring packets reports PASS

**Files:**
`tools/leak-lab/pcapscan.py:1083-1088` (only `stats["captured"]` is compared
with the record count), `tools/leak-lab/pcapscan.py:158-160` (docstring:
received "is not required to equal captured + drops"),
`docs/rust-v2/leak-lab.md:11-13` ("all three must agree with the pcap"),
`docs/rust-v2/leak-lab.md:267-269` (explicitly not required),
`tools/leak-lab/test_leak_lab.py:521-526` (asserts PASS with `received=100`).

**Reproducer (API):**

```python
import sys; sys.path.insert(0, "tools/leak-lab")
import test_leak_lab as T, pcapscan
r = T.scan_middle([T.wg_outbound()], stats=T.zero_stats(3, received=100))
print(r["verdict"], r["packets"], r["capture_meta"]["stats"])
# => PASS 3 {'captured': 3, 'received': 100, 'dropped_kernel': 0, ...}
```

**Reproducer (CLI):** the same text (`3 packets captured` / `100 packets
received by filter` / `0 packets dropped by kernel`) with a valid 3-record
pcap and both controls, `pcapscan.py ...` returns **exit 0 / PASS**
(observed). The report records `received: 100` in
`capture_meta.stats`; nothing else changes.

**Why this is a real false PASS, not a cosmetic overflow counter.** On Linux
(the only platform the host plan supports: `ip`/`nft`/Debian 13, tcpdump
4.99.5 + libpcap 1.10.5 TPACKET_V3), `ps_recv` is accumulated from
`tp_packets`, i.e. packets that **passed the filter** and were handed to the
ring; `ps_drop` is the ring-full counter. Packets counted in `received` that
were neither written (`captured`) nor dropped are, by construction, ring
entries tcpdump did not process before SIGINT. They are not in the pcap, so
they are never classified. That is exactly the round-1 pi F-01 prefix case,
one counter later: the evidence file says "100 received, 3 written, 0 dropped"
and the tool says PASS. A hostile VM can exploit it deliberately: it knows
the after-control (it sends it), can emit a burst immediately afterwards with
the leak packet last, and rely on `pcap_breakloop` stopping mid-block; the
unread tail is invisible, and the very counter that would expose it is
ignored. `--immediate-mode` narrows but does not remove the window (the
repo's own `tools/wg-birth-kernel-oracle.py` uses it for the same reason).

**Note on the round-1 conflict.** gpt I1 said "do not require
`received == captured`" because libpcap receive-counter semantics can differ
while packets are queued. That is right on BSD/macOS, where `ps_recv` is
pre-filter; it is not right on the documented Linux platform. A conservative,
platform-correct check is a **necessary** condition under both semantics:
`received <= captured + dropped_kernel + dropped_interface` (drops may or may
not be included in `received`; either way an excess is unread). Today the
suite enshrines the opposite behaviour, so this is the round-1 pi F-01
reproducer that was not fixed.

**Suggested fix:** add an invalid reason (e.g. `stats_unread_packets`) when
`stats["received"] > stats["captured"] + (dropped_kernel or 0) +
(dropped_interface or 0)`; document it next to `captured`. If portability is
wanted, gate it on the Linux capture path this plan mandates, or make it an
explicit `--allow-queued` opt-out that is not used by the plan. Update
`test_not_requiring_received_to_equal_captured_plus_drops` to expect INVALID
and add a "received == captured + drops" PASS fixture.

---

### Minor 1 — ARP: the docs promise rejection of gateway-IP claims that the code accepts

**Files:** `tools/leak-lab/pcapscan.py:437-448` (`gateway_to_vm` checks only
`sender_ip`, `target_ip`, and the reply `target_mac`; there is no sender-MAC
check and `vm_to_gateway` is not required for a frame that already satisfies
`gateway_to_vm`), `docs/rust-v2/leak-lab.md:300-312` ("a VM claiming another
IP (including the gateway), gratuitous ARP for another IP, a foreign MAC
claiming the VM or gateway IP ... is `arp_not_allowed`"),
`tools/leak-lab/test_leak_lab.py:1009-1013` (only tests the `target_ip ==
gateway` shape, which the code does reject).

**Reproducers (all PASS, `allowed_counts.arp == 1`, no findings):**

```python
run("foreign MAC claims gateway IP, reply to VM",
    [T.arp_frame(2, "02:00:00:00:00:01", T.GW_IP, T.VM_MAC, T.VM_IP, dst_mac=T.VM_MAC)])
run("VM MAC claims gateway IP, request to VM IP",
    [T.arp_frame(1, T.VM_MAC, T.GW_IP, "00:00:00:00:00:00", T.VM_IP)])
run("VM MAC claims gateway IP, gratuitous reply",
    [T.arp_frame(2, T.VM_MAC, T.GW_IP, T.VM_MAC, T.VM_IP, dst_mac=T.VM_MAC)])
```

The policy has no gateway MAC, so the code cannot authenticate the peer; the
real host bridge MAC is random and not declared. This cannot hide a WAN leak
(ARP is local), so it is Minor, but the doc must not claim the VM/foreign-MAC
gateway claim is rejected, and the `arp` count must not be presented as proof
of a legitimate exchange. Either add a `gateway_mac` policy field (read with
`ip link show vprlab0`) and require it, or document the IP-only behaviour and
add a test for the three shapes above.

### Minor 2 — the plan's forward `accept` cannot override an existing FORWARD `DROP` policy (Docker)

**Files:** `tools/leak-lab/netplan.py:138-144` (its own `inet vprlab` base
chain with `policy accept` and two `accept` rules),
`docs/rust-v2/leak-lab.md:354-355` ("forward chain that accepts only
`vprlab0 <-> WAN`"), preflight `tools/leak-lab/netplan.py:308-348` (checks
names, addresses, routes and table names only).

An `accept` in one nftables base chain ends that chain only; other base chains
at the same hook/priority still run (`nf_hook_slow` continues on
`NF_ACCEPT`). Docker sets `iptables -P FORWARD DROP`; on such a host the lab's
forwarded packets reach the end of Docker's FORWARD chain and are dropped,
despite the vprlab accept. `net.ipv4.ip_forward=1` and the vprlab rules are
therefore not sufficient for the lab to have a WAN path, and the preflight
does not read the FORWARD policy. This is not a false PASS of a leak (the tap
captures before forwarding), but it invalidates the connectivity the doc
implies and invites the operator to disable Docker's firewall. Static
command-semantics only; no `nft`/`ip` command was run. Suggest a preflight
check of the `ip filter` FORWARD policy (or an explicit review note in the
plan's section 2) and a doc sentence.

### Minor 3 — `gateway_ipv4` is not tied to the plan's fixed bridge address

**Files:** `tools/leak-lab/policy.py:283-285` and `policy.py:208-215` (any
usable host in `10.250.0.0/24`), `tools/leak-lab/netplan.py:30`
(`BRIDGE_ADDRESS = "10.250.0.1/24"`).

```sh
# accepted by the loader (exit 0):
{"gateway_ipv4": "10.250.0.9", "positive_control": {"sink_ipv4": "10.250.0.9", ...}}
```

The plan always puts the host at `10.250.0.1`; a policy with a different
gateway makes the VM's ARP for the gateway a `arp_not_allowed` LEAK or leaves
the controls unresolved (INVALID). It fails closed, so Minor, but the loader
and the plan should agree: require `gateway_ipv4 == "10.250.0.1"` (and
`sink_ipv4 == gateway_ipv4`, already enforced) or derive the bridge address
from the policy.

### Minor 4 — the documented `control.py --pair` command fails on a fresh tree

**Files:** `tools/leak-lab/control.py:46-53` (`load_used_nonces` raises on a
missing file), `docs/rust-v2/leak-lab.md:151-154` (the documented command).

```sh
$ rm -f used.txt
$ python3 -B tools/leak-lab/control.py --policy policy.json --device eth0 \
    --pair --used-nonces used.txt
control: cannot read used-nonces file: [Errno 2] No such file or directory: 'used.txt'
$ echo rc=$?   # 2
```

The first documented invocation needs `: > used.txt` first. Fails closed;
add "create an empty `used.txt` once" or treat ENOENT as empty in
`load_used_nonces` (still rejecting malformed lines).

### Minor 5 — control window rejects normal WG keepalives outside the markers (flake, not a false pass)

**Files:** `tools/leak-lab/pcapscan.py:1099-1106`,
`docs/rust-v2/leak-lab.md:169-172` and `:180-184`.

The doc's per-phase sequence is "start the tap capture, confirm tcpdump is
running, send the before control"; any WireGuard keepalive (commonly every
25 s) that lands in that gap, or between the after-control and SIGINT, makes
the capture `INVALID` (`outside_control_window`). This is the intended strict
rule and it fails safe, but with a live tunnel it is a regular flake that
pushes operators to re-run or to relax the window. A one-line operational note
(start tcpdump immediately before the before-control and SIGINT immediately
after the after-control, or pause keepalives for setup) and/or an M2 runner
that starts/stops the capture in the same step would remove the ambiguity.

### Minor 6 — a PASS may contain no allowed-flow packet at all

**Files:** verdict computation `tools/leak-lab/pcapscan.py:1116-1121` (no
`allowed_counts` gate), `docs/rust-v2/leak-lab.md:465-472` (documented limit).

A pcap with only the two controls and matching stats returns `PASS`
(observed). That is a valid "the monitor saw the markers and nothing else"
result, and the doc says a silent VM is indistinguishable from a clean one,
but it means a phase whose test action silently failed also PASSes. The
report already exposes `allowed_counts`; the M2 runner must require at least
one entry for a declared flow (and ideally the expected relay label) before
treating PASS as phase evidence. This is the residual of round-1 pi F-09.

---

## Netplan / control-sink analysis (requested)

Generated plan inspected statically for `--wan-interface eno1`:

- **No global or cross-table operations.** Executable lines contain no
  `flush`, no `iptables`/`ip6tables`, no `nft add table` (only `create`),
  no `nft delete table` other than the guarded `inet vprlab`, and no
  `sysctl -w net.ipv4.ip_forward`. `set -eu` only guards the pasted section.
- **Host services:** the only broad rule is
  `nft add rule inet vprlab input iifname "vprlab0" drop`; every other rule is
  scoped by `iifname`/`oifname` `vprlab0` or the WAN. Docker's
  `docker0`/veth traffic matches no vprlab rule and falls through the vprlab
  chain's `policy accept`. The one cross-table interaction worth knowing is
  Minor 2 (another table's FORWARD `DROP` policy still wins).
- **The input drop really does suppress the control's ICMP unreachable.**
  The control is addressed to the host bridge address, so it is delivered
  locally; `NF_INET_LOCAL_IN` runs in `ip_local_deliver()` before
  `udp_rcv()`/`__udp4_lib_rcv()`, and the port-unreachable is generated only
  inside that UDP receive path. Dropping at the input hook frees the skb
  before any socket lookup, so no ICMP is emitted. The output chain
  (`oifname "vprlab0" meta nfproto ipv4 drop`) would also discard any
  host-generated IPv4 ICMP (redirect, frag-needed, port-unreachable) toward
  the lab. ARP is not visible to the `inet` family (nft(8): hybrid IPv4/IPv6
  table), so neighbour discovery is unaffected.
- **Rule matching is sound.** For frames delivered to the host from the tap,
  the L3 input device is the bridge (`vprlab0`), the same pattern as
  `iptables -i docker0`. At postrouting, nft `iifname` uses the hook state's
  input device, which for forwarded packets is `vprlab0` (`ip_output` passes
  the original `indev` to `NF_INET_POST_ROUTING`), so the scoped masquerade
  matches.
- **Ownership/teardown.** nft(8) confirms `create table` is exclusive and that
  `create table ... { comment "..." }` is valid. The installed libnftables
  prints table/chain comments as `comment "%s"`, so the teardown grep should
  find the tag; if a future nft changes that format, teardown refuses to
  delete (fails closed). `ip -d link show` prints the alias used by the link
  checks.
- **Preflight** requires all four inventories, rejects malformed entries,
  duplicate names/altnames, an existing `inet vprlab`, and any address or
  explicit main-table route overlapping `10.250.0.0/24`. Two residual gaps:
  routes in non-main tables are invisible to `ip -j route` (Minor), and the
  forwarding policy itself is not inspected (Minor 2).

## Docs vs code (requested)

Verified to match: verdict precedence (`LEAK` > `INVALID` > `PASS`), the
invalid-reason list, the stats rules (every summary parsed; any drop;
contradictory; incomplete; error lines; `captured == records`), control
semantics (exact 44-byte payload, distinct nonces, one sighting, order,
window, replay finding, controls not counted), frame classification (IPv6,
options, UDP length, trailer/padding, VLAN, unknown ethertypes), ARP request/
reply shapes and the Ethernet/ARP sender equality, fragment rules (30 s
window, contiguous ranges, UDP-length bound, duplicate first, incomplete at
EOF), `allow_counts`, `capture_meta` fields, exit codes 0/1/2, policy loader
rules and schema mirror, test-node naming, and the host plan (bridge/tap/
input/forward/output/postrouting/teardown). The doc's ARP rejection claim
(Minor 1) and the `received` rule (C1, docs:267-269 vs docs:11-13) are the two
mismatches I found. The doc's "the scanner requires exactly one sighting" is
accurate in effect (a second sighting is a LEAK, not a second sighting).

## Verified-good (adversarial checks that produced no false PASS)

- **Control window brute force:** every sequence of length 1..5 over
  {before-control, after-control, allowed WG, DNS leak} (1364 pcaps):
  `PASS` only for `before, WG*, after` (4 sequences), everything else
  `LEAK` (1289) or `INVALID` (71). No leak record can be `is_control`: that
  flag is set only for an exact expected-nonce control to the declared sink
  with the exact payload and `udp_length == ip payload`.
- **Stats fuzz:** all 343 concatenations of three summary lines from a set
  containing later nonzero kernel/interface drops, extra `received`, and
  missing counters: every input with a positive drop is rejected; no
  combination was reported clean with a nonzero drop.
- **Real tcpdump 4.99 stderr** (this host is tcpdump 4.99.5/libpcap 1.10.5):
  `tcpdump: listening on vprlab-tap0, link-type EN10MB (Ethernet), snapshot
  length 262144 bytes` + `4 packets captured` + `4 packets received by
  filter` + `0 packets dropped by kernel` -> PASS; version/libpcap/OpenSSL
  banner lines and a no-IPv4-address warning are not errors; CRLF, leading/
  trailing spaces, optional interface line, and a singular "1 packet" all
  parse; banner-only -> `stats_unparseable`; `tcpdump: pcap_loop: ...` ->
  `stats_error_line`; a bare unprefixed `pcap_loop:` line is ignored but real
  tcpdump always prefixes it with `tcpdump: `.
- **Fragments (matrix re-run):** only contiguous, non-overlapping,
  UDP-length-bounded, same-key fragments complete to allowed; zero-length
  final fragment short of the declared length, middle fragment ending at the
  UDP length, overrun, gap, overlap, disallowed first, duplicate first,
  control-as-fragment, and never-completed first all produce findings. A
  disallowed first fragment poisons the key (`fragment_of_disallowed_flow`).
- **Trailer/padding:** zero pad to the 60-byte Ethernet minimum (including
  the 18-byte pad of a real ARP request) is accepted; one nonzero pad byte,
  one byte over the minimum, and long zero trailers are `ethernet_trailer`.
  A real WireGuard keepalive is 74 bytes on the wire, so no padding is
  expected for the declared flows.
- **ARP normal rules:** VM request/reply for the gateway and gateway request/
  reply to the VM are allowed with Ethernet source == ARP sender; a foreign
  MAC claiming the VM IP, an unsupported htype/ptype, a truncated body, and a
  non-1/2 opcode are findings.
- **Policy:** bool-as-int, leading-zero/short/hostname addresses, ports 0 and
  65536, bool ports, multicast/broadcast/loopback/link-local/unspecified,
  lab-subnet and VM/gateway endpoints, duplicate keys/labels/endpoints,
  non-boolean `allow_arp`, literal-`false` IPv6, and sink != gateway are all
  rejected; the doc's sample policy parses; the schema is closed and mirrors
  the loader shape.
- **CLI:** PASS r=0, LEAK r=1, INVALID r=2, missing stats file r=2, missing
  required flags r=2, equal nonces r=2, canonical JSON round-trips.
- **Netplan:** no flush/other-table mutation; unique preflight messages;
  `10.250.0.0/24` address/route overlap detected (including a `/8`
  supernet); altname collision detected; missing WAN detected; existing table
  detected; `render_plan` rejects `lo`, `.`, `..`, `-x`, and lab names.

## Limits of this review

- No VM, tap, nftables, `ip`, or network command was executed (per the brief),
  so the input-drop/ICMP and postrouting-`iifname` conclusions are
  kernel-path and nft(8) reasoning, not runtime observation; the
  Docker FORWARD conclusion is command semantics, not a host test.
- Only classic pcap/linktype 1 is supported and reviewed.
- The pcap and stats file are assumed to come from a trusted capture host;
  this review covers a compromised/buggy router VM and operator error, not a
  root attacker on `debdev`.
- A phase with no allowed-flow packet is a documented "silent VM" result;
  proving the tunnel carried traffic is out of M1 scope (Minor 6).

## Working-tree note

`git status` at the end shows one untracked path, `tools/leak-lab/vm/qga.py`
(created 2026-11-09 00:12:23, during this review). It is an M2 QEMU
guest-agent client, is outside the reviewed commit/files, and was not created
or modified by this review. The only file this review wrote is this report.
