# External leak-test lab (M1: offline monitor)

Status: M1 tooling only. Everything in `tools/leak-lab/` is offline; it reads
files and prints reports. `netplan.py` prints privileged host commands but never
executes them. No lab VM, capture, network, nftables or Docker setup is performed
by this milestone.

The purpose is to prove, from outside the router VM, that the VM's WAN interface
carries only declared Mullvad WireGuard UDP flows (plus an exact gateway ARP
exchange when enabled) and no IPv6. A real-IP leak is treated as a catastrophic
event: the tool has no fail-open defaults. A capture must supply a tcpdump stats
file, exactly one before-control nonce and exactly one after-control nonce, and
all three must agree with the pcap. Otherwise the result is `INVALID`, never
`PASS`. Any observed leak finding is `LEAK` even when the capture is also
invalid; the invalid reasons are reported alongside.

## Topology and capture point

```
 debdev host (the capture host must itself be trusted)
 ┌───────────────────────────────────────────────────────────────────┐
 │  default WAN interface, e.g. eno1                                 │
 │        ▲   nft table inet vprlab:                                  │
 │        │     postrouting: masquerade 10.250.0.0/24 on vprlab0      │
 │        │     forward: accept only vprlab0 <-> WAN interface        │
 │        │     input: drop all vprlab0 IPv4/IPv6 (silent)            │
 │        │     output: drop host IPv4 toward vprlab0                 │
 │   vprlab0 bridge, 10.250.0.1/24, no physical ports                 │
 │        │                                                          │
 │   vprlab-tap0  <---- tcpdump -i vprlab-tap0 -nn -U                 │
 │                       --immediate-mode -s 0 -w FILE 2> STATS      │
 └────────┼──────────────────────────────────────────────────────────┘
          │ tap lives on the host, outside the VM
 ┌────────┴──────────────────────────┐
 │ router VM (untrusted)             │
 │ WAN eth0: 10.250.0.2              │
 │ gateway:  10.250.0.1              │
 │ legitimate WAN traffic:           │
 │   UDP to declared Mullvad relays  │
 │   ARP for/from the gateway only   │
 │ IPv6: must be absent              │
 └───────────────────────────────────┘
```

The capture point is the host tap. The monitor sees every Ethernet frame that
the host bridge receives from the VM, before host NAT. It does not see the
router's internal state, traffic on other interfaces, traffic the VM drops
before transmitting, or traffic that tcpdump itself drops.

Because the VM is untrusted, the host plan silently drops all input from
`vprlab0` with no reject/ICMP. That both protects host services and makes the
positive-control datagram to `10.250.0.1:<sink_udp_port>` disappear without a
port-unreachable reply. The host also drops host-originated IPv4 toward the lab,
so no ICMP unreachable is generated for the sink.

## Policy

`tools/leak-lab/policy.py` is the binding validator. `policy.schema.json` mirrors
the same closed shape for editors and CI, but cannot express duplicate-key,
duplicate-label, duplicate-endpoint, address-class or gateway-equality
rejection.

```json
{
  "schema_version": 1,
  "vm_wan_mac": "52:54:00:12:34:56",
  "vm_wan_ipv4": "10.250.0.2",
  "gateway_ipv4": "10.250.0.1",
  "allowed": [
    {
      "proto": "udp",
      "dst_ipv4": "185.65.134.10",
      "dst_port": 51820,
      "label": "mullvad-se-sto-wg"
    }
  ],
  "allow_arp": true,
  "positive_control": {
    "sink_ipv4": "10.250.0.1",
    "sink_udp_port": 39001
  },
  "ipv6_allowed": false
}
```

Loader rules (all enforced):

- closed object at the top level and in every nested object; unknown keys are
  rejected; duplicate JSON keys are rejected;
- `schema_version` must be the integer `1`;
- `vm_wan_mac` is six colon-separated hex octets, must be a unicast non-zero
  MAC, and is normalized to lowercase;
- `vm_wan_ipv4` and `gateway_ipv4` are required, must be usable host addresses
  inside the fixed lab subnet `10.250.0.0/24`, and must differ;
- `gateway_ipv4` is the host bridge address;
- `positive_control.sink_ipv4` must equal `gateway_ipv4`; the host drops that
  datagram silently (see the input chain above);
- `allowed[].dst_ipv4` must be a unicast address that is not in `10.250.0.0/24`
  and not equal to the VM or gateway address;
- unspecified (`0.0.0.0/8`), loopback (`127/8`), multicast (`224/4`), reserved
  (`240/4`) and link-local (`169.254/16`) addresses are rejected for the VM,
  gateway and every allowed endpoint; `255.255.255.255` is rejected by the
  reserved range;
- dotted-quad literals only for every address; hostnames, whitespace, leading
  zeros and non-ASCII digits are rejected;
- `allowed[].proto` is exactly `"udp"`; TCP is never allowed on the WAN;
- ports are integers in 1..65535;
- labels are 1..64 characters of `[a-z0-9-]`, start/end with `[a-z0-9]`, are
  unique, and may not use the report-reserved names `arp` or
  `positive-control`;
- allowed endpoints must be unique, and the positive-control endpoint must not
  duplicate an allowed flow;
- `allow_arp` is a JSON boolean. `allow_arp: false` makes the capture
  capture-only: it is valid only when no ARP can appear (for example a
  loopback/fixture capture). A real router phase must ARP for its gateway, so
  either use `allow_arp: true` with the exact ARP rules below, or install a
  static neighbour for the gateway and keep `allow_arp: false`;
- `ipv6_allowed` must be the literal JSON value `false`; any other value
  (including `0` or `true`) is rejected.

Generate the policy from the actual active WireGuard configuration. A stale or
over-broad policy is an evidence defect: a missing relay endpoint causes a
`LEAK`, while an unnecessarily broad flow could hide a real leak.

Validate a file with:

```sh
python3 -B tools/leak-lab/policy.py --check policy.json
```

## Positive-control protocol

A capture proves the monitor is working only if it is bracketed by two distinct
markers that the monitor was required to see. Each marker is:

- UDP from the VM WAN IPv4 to `positive_control.sink_ipv4`
  (`gateway_ipv4`): `positive_control.sink_udp_port`;
- payload exactly `VPRLEAKCTL1:` followed by 32 lowercase hexadecimal
  characters (16 random bytes from `secrets.token_hex(16)`);
- sent through the raw WAN device with `SO_BINDTODEVICE`, bypassing the tunnel
  and its routing, and bound to the VM WAN source address.

The VM's own firewall/kill-switch must explicitly permit
`vm:* -> gateway:<sink_udp_port>/udp`; `SO_BINDTODEVICE` bypasses routing but not
the system under test's nftables rules. That exception is part of the reviewed
policy and must not be widened.

A nonce is single-use. Generate a fresh before/after pair for every phase; the
tool never reuses one:

```sh
python3 -B tools/leak-lab/control.py \
  --policy policy.json --device eth0 --pair --used-nonces used.txt
```

It prints two copy-pasteable commands labelled `before-control` and
`after-control`, each followed by its nonce. `--json` prints the same data as
canonical JSON. `--nonce HEX` exists only for deterministic reproduction and
must be accompanied by `--used-nonces`; a nonce that already appears in that
file is refused. Append every nonce to `used.txt` after a phase so a replay is
detected before it is used.

Operational rule:

- send the before-control, run the test action, then send the after-control;
- pass the two nonces with `--control-before NONCE --control-after NONCE`;
- the scanner requires exactly one sighting of each nonce, and it requires
  `ts(before) < ts(after)`;
- every non-control record in the pcap must lie strictly between the two
  control timestamps. A record before the before-control, after the
  after-control, or at the same timestamp as either marker makes the capture
  `INVALID` (`outside_control_window`);
- a repeated expected nonce is a `replayed_control` finding (`LEAK`), never a
  second independent sighting;
- a control packet with an unexpected nonce or any wrong format is a `LEAK`
  finding; it is never excused;
- control packets are excluded from leak findings **only** on an exact
  expected-nonce match, and an unfragmented control must declare a UDP length
  exactly equal to its IPv4 payload. Controls are not counted in
  `allowed_counts`.

Per phase, the sequence is: start the tap capture, confirm tcpdump is running,
send the "before" control, run the test action, send the "after" control, stop
tcpdump with SIGINT, then pass the pcap, the stderr stats file and both nonces to
`pcapscan.py`. The scanner enforces the window, ordering, uniqueness and stats
agreement itself. The M2 runner still starts/stops the capture and invokes the
scanner; it must generate fresh nonces and send them at the right moments, but
it does not have to re-check the window.

## Verdict semantics

`tools/leak-lab/pcapscan.py` writes a canonical one-line JSON report with sorted
keys and these fields:

- `verdict`: `PASS`, `LEAK` or `INVALID`;
- `packets`: complete pcap records read;
- `allowed_counts`: per-label counts, plus the pseudo-label `arp` when ARP is
  allowed;
- `findings`: first 200 findings, each with `ts`, `src`, `dst`, `proto`,
  `src_port`, `dst_port`, `reason` and optional context (`detail`, `vlan`, ARP
  MACs, fragment key, ...);
- `findings_total` and `findings_truncated`;
- `positive_controls_seen`: expected nonces in first-seen order;
- `capture_meta`: pcap format/endianness/timestamp resolution/snaplen/linktype,
  pcap and policy SHA-256, the expected before/after nonces, a `controls` object
  with each control's `nonce`, `seen`, `packets`, `first_packet`, `last_packet`,
  `first_ts` and `last_ts`, `missing_controls`, tcpdump stats, `stats_source`,
  `stats_sha256`, and `invalid_reasons` (plus `invalid_reason`, the first one,
  for older consumers).

Verdict precedence:

1. any leak finding -> `LEAK`, even when the capture is also invalid; every
   capture defect is listed in `capture_meta.invalid_reasons`;
2. otherwise any invalid reason -> `INVALID`;
3. otherwise `PASS`.

Invalid reasons are drawn from:

- pcap-structure damage: `truncated_global_header`, `unsupported_pcap_magic`,
  `unsupported_pcap_version`, `invalid_snaplen`, `unsupported_linktype_N`,
  `truncated_record_header`, `truncated_record_data`,
  `record_length_inconsistent`, `record_exceeds_snaplen`,
  `invalid_timestamp_fraction`, `snaplen_truncated_record`;
- tcpdump stats: `stats_unreadable`, `stats_unparseable`, `stats_incomplete`,
  `stats_contradictory`, `stats_error_line`, `packet_drops`,
  `stats_packet_count_mismatch`;
- control qualification: `control_order`, `outside_control_window`,
  `missing_positive_controls`;
- `zero_packets`.

A complete record whose frame content is malformed is **not** an invalid
capture. It is a `malformed_frame` finding and scanning continues. This covers a
short Ethernet header, a bad IPv4 version/IHL, a short IPv4 header, a bad IPv4
total length, bad UDP length, a short IPv6 header, and truncated ARP bodies.
Only pcap-structure damage stops the scan.

### tcpdump stats

`--tcpdump-stats` is mandatory. The parser reads **every** summary line written
by Debian 13 tcpdump 4.99:

```
N packets captured
N packets received by filter
N packets dropped by kernel
N packets dropped by interface        # optional platform-dependent counter
```

Rules:

- every occurrence of every counter is parsed; a later nonzero drop summary is
  never hidden by an earlier zero one;
- any `dropped by kernel` or `dropped by interface` value greater than zero is
  `packet_drops` (a positive drop is reported as `packet_drops` even when the
  summaries also disagree);
- `captured` must equal the number of complete pcap records exactly, otherwise
  `stats_packet_count_mismatch`;
- `captured`, `received by filter` and `dropped by kernel` must all be present,
  otherwise `stats_incomplete`;
- the same counter reported with different values is `stats_contradictory`
  (concatenated or stale summaries are not evidence);
- a tcpdump error line such as `pcap_loop`, `interface disappeared`,
  `went down` or `permission denied` is `stats_error_line`;
- a counter-shaped line that does not match the supported format is
  `stats_unparseable`;
- `received by filter` is recorded but is not required to equal
  `captured + drops`: libpcap receive-counter semantics can differ while
  packets are still queued.

The stats file's SHA-256 is bound into the report. The tcpdump process's own
exit status is not present in the stderr file; record it separately if the
qualification procedure needs it.

### Frame classification

Direction is classified by the declared VM IP (`src == vm` outbound,
`dst == vm` inbound). `vm_wan_mac` is used for ARP rules and for frames that
involve neither the VM MAC nor the VM IP. A frame with the VM IP and a foreign
Ethernet MAC is still classified by IP: the tap sees whatever the VM emits, and
a foreign source IP is already a `foreign_frame` finding.

- Any IPv6 frame with a complete 40-byte header is `ipv6_not_allowed`.
- IPv4 packets with options (`IHL > 5`) are `ipv4_options`; source-routing
  options are never treated as an allowed relay flow.
- An unfragmented UDP datagram on an allowed flow must declare a UDP length
  exactly equal to its IPv4 payload; otherwise `malformed_frame`. The same
  applies to controls. An incomplete UDP header is `udp_header_incomplete`.
- Non-UDP protocols on the WAN are findings (`tcp_not_allowed`,
  `icmp_not_allowed`, `ip_protocol_not_allowed`).
- Every Ethernet byte after the declared IPv4/ARP payload must be accounted for.
  Only zero padding up to the 60-byte Ethernet minimum is accepted. Any longer
  trailer, or any nonzero padding byte, is `ethernet_trailer`. FCS bytes are not
  accepted; run tcpdump without FCS capture.
- Single 802.1Q frames are inspected. Stacked 802.1Q, QinQ, LLDP, PPPoE and
  unknown ethertypes are findings.

### ARP

`allow_arp: true` permits only two shapes, and the Ethernet source MAC must
equal the ARP sender MAC:

- the VM asking for or answering the gateway: sender `(vm_wan_mac,
  vm_wan_ipv4)` and target IP `gateway_ipv4`;
- the gateway requesting or replying to the VM: sender IP `gateway_ipv4`,
  target IP `vm_wan_ipv4`, and for a reply target MAC `vm_wan_mac`.

ARP operation must be request (1) or reply (2). Everything else is
`arp_not_allowed`: a VM claiming another IP (including the gateway), gratuitous
ARP for another IP, a foreign MAC claiming the VM or gateway IP, an
Ethernet/ARP sender mismatch, unsupported hardware/protocol types, and third
parties. `allow_arp: false` makes every ARP a finding; it is intended for
capture-only fixtures, not a real router phase without a static neighbour.

### Fragments

Fragments are conservative and in-order:

- a non-first fragment is associated only with a first fragment for the same
  `(src, dst, protocol, identification)` seen at most 30 seconds earlier, with
  no completed datagram and no reuse in between;
- a non-first fragment seen before its first fragment, more than 30 seconds
  after it, without any first fragment, or after the datagram completed is a
  finding (`fragment_without_first`, `fragment_stale_association`,
  `fragment_after_complete`);
- fragment ranges must be contiguous: an overlap is `fragment_overlap`, a gap is
  `fragment_gap`, and a fragment beyond the first fragment's declared UDP length
  is `fragment_out_of_range`;
- the final fragment must end exactly at the declared UDP length, otherwise
  `fragment_incomplete`; when the pcap was read to the end without structural
  damage, a fragmented datagram that never completes is also
  `fragment_incomplete`;
- a duplicate first fragment for an incomplete in-window key is
  `fragment_duplicate_first`; a middle fragment whose payload is not a multiple
  of 8 bytes is `malformed_frame`.

## Host network plan

`tools/leak-lab/netplan.py` prints (never executes) commands for:

- bridge `vprlab0`, address `10.250.0.1/24`, no physical ports;
- tap `vprlab-tap0` attached to the bridge, with IPv6 disabled **before** either
  link is brought up;
- dedicated `inet vprlab` nftables table created with `nft create` (exclusive:
  it fails if the table already exists) and carrying the ownership comment
  `vprlab-leak-lab-m1`;
- input chain (`hook input`) that silently drops all IPv4/IPv6 traffic from
  `vprlab0`, so the positive-control datagram to the gateway sink gets no
  port-unreachable and the VM cannot reach host services. The `inet` family does
  not see ARP, so the gateway's neighbour discovery is unaffected;
- output chain that drops host-originated IPv4 toward `vprlab0` (ARP is not
  IPv4 and is unaffected). This also suppresses mDNS/LLMNR/IGMP noise the host
  would otherwise send onto the lab bridge;
- forward chain that accepts only `vprlab0 <-> WAN`, drops other forwarding and
  drops IPv6;
- postrouting source NAT scoped to
  `ip saddr 10.250.0.0/24 iifname "vprlab0" oifname <WAN>`;
- teardown that deletes a table or link only after verifying its ownership
  comment/alias, and refuses anything else.

```sh
python3 -B tools/leak-lab/netplan.py --wan-interface eno1
```

The plan never contains `flush ruleset`, never edits another table, and never
changes `net.ipv4.ip_forward`. It prints the check and the exact restore
commands:

```sh
sysctl -n net.ipv4.ip_forward
# must print 1. If it prints 0, the plan requires 1 for the phase:
#   sysctl -w net.ipv4.ip_forward=1
# restore exactly after teardown:
#   sysctl -w net.ipv4.ip_forward=0
```

### Preflight

Before running the plan, generate all four inventories and run the collision
check. It reads the files only; it does not invoke `ip` or `nft`:

```sh
ip -j link > links.json
ip -j addr > addresses.json
ip -j route > routes.json
nft -j list tables > tables.json
python3 -B tools/leak-lab/netplan.py --check-name-collisions \
  --wan-interface eno1 \
  --links-json links.json --addresses-json addresses.json \
  --routes-json routes.json --tables-json tables.json
# exit 0 = clear, 1 = collision, 2 = unreadable/malformed input
```

The preflight requires all four inventories and rejects:

- an existing `vprlab0` or `vprlab-tap0` link name **or altname**;
- an existing `inet vprlab` table;
- any existing address or explicit route overlapping `10.250.0.0/24`;
- a WAN interface that does not exist, is `lo`, or is a lab interface;
- malformed inventory entries instead of silently skipping them.

A JSON snapshot is a preflight, not ownership proof; the exclusive `nft create`
and the ownership tags are the runtime guards.

Capture command printed by the plan (note `--immediate-mode` and `-s 0`, full
frames):

```sh
tcpdump -i vprlab-tap0 -nn -U --immediate-mode -s 0 -w vprlab-capture.pcap \
  2> vprlab-capture.pcap.stderr
```

`--immediate-mode` makes the after-control reach the file before SIGINT. `-s 0`
records full frames; a snaplen-truncated record is `INVALID` because hidden
bytes could be a control or a leak. tcpdump prints its packet/drop summary to
stderr when it exits (stop it with SIGINT / Ctrl-C). Pass both files and both
nonces to the scanner:

```sh
python3 -B tools/leak-lab/pcapscan.py \
  --policy policy.json \
  --pcap vprlab-capture.pcap \
  --tcpdump-stats vprlab-capture.pcap.stderr \
  --control-before <before-nonce> --control-after <after-nonce>
```

Exit codes: `0` = PASS, `1` = LEAK, `2` = INVALID or usage/policy error.

## Test-node names

`tools/leak-lab/tsnames.py` generates names such as:

```
zz-vprtest-03-do-not-use
zz-vprtest-03-do-not-use-mullvad-hot-dingo
```

`NN` is `01`..`99`. `is_test_node()` accepts exactly
`^zz-vprtest-(0[1-9]|[1-9][0-9])-do-not-use(-[a-z0-9]+(-[a-z0-9]+)*)?$` with a
total length of at most 63 characters. It matches the bare DNS label: a
MagicDNS FQDN such as `zz-vprtest-01-do-not-use.tailnet.ts.net` is rejected and
callers must strip the domain first. The optional suffix is opaque data, not a
safety claim; only the `zz-vprtest-NN-do-not-use` prefix is meaningful. The
generator refuses a result longer than 63 characters instead of truncating it.
These names are for throw-away test exit nodes only.

## Explicit limits

This milestone proves absence of leaks only:

- for the captured windows, on `vprlab-tap0`, on the debdev host;
- for traffic that actually reaches the host bridge from the VM WAN;
- for the policy that was supplied and reviewed.

What a compromised router VM can and cannot do:

- It **can** emit malformed frames. Those are now `malformed_frame` findings,
  not an early `INVALID` that aborts the scan; later records are still examined.
- It **can** spoof its own source IP/MAC within the captured Ethernet domain.
  IPv4 is classified by the declared VM IP, so a foreign MAC using the VM IP is
  not distinguished; ARP has the stricter sender rules above.
- It **cannot** make the monitor ignore a frame that reaches the tap: every
  captured frame is classified, and any nonzero tcpdump drop counter or a
  captured-count mismatch invalidates the capture.
- It **can** suppress traffic before it reaches the tap (by not sending it, or
  by causing tcpdump/kernel drops). Suppression is detected only when the drop
  counters or the record count expose it; a completely silent VM is
  indistinguishable from a clean VM by this monitor.
- It **cannot** make the monitor authenticate WireGuard or prove that the
  tunnel carried real traffic. Matching an allowed outer UDP tuple proves only
  the endpoint, not encryption or a working tunnel.

This milestone does **not** cover:

- the client-side WAN; that needs a separate capture and policy;
- traffic inside the WireGuard tunnel (the monitor sees only the outer UDP
  endpoint, sizes and timing, not decrypted destinations);
- traffic the VM drops before it reaches the WAN, or traffic on any other
  interface;
- a compromised capture host. Root on debdev could tamper with tcpdump, the
  pcap or the stats file. Keep the capture host trusted, store evidence
  off-box, and cross-check hashes/controls if the result matters;
- periods without captures, or captures whose tcpdump stats show drops or a
  count mismatch. Any structurally truncated record or snaplen-truncated record
  is `INVALID`, not a partial pass;
- IPv6 by any means: `ipv6_allowed` is always false and any IPv6 frame is a
  finding;
- the outbound UDP source port. Any source port to an allowed relay endpoint is
  accepted; only the destination tuple is declared. Note this when interpreting
  a `PASS`.

There is no `--allow-no-stats` or no-control escape hatch. Missing stats or a
missing control is `INVALID` (or `LEAK` when a finding is also present). Reusing
the same nonce for before and after is a usage error (exit 2), and a nonce
replayed in the capture is a `LEAK` finding; neither is ever a `PASS`.

## Tests

```sh
python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py -v
```

The suite synthesizes all pcaps with `struct`; it covers both pcap byte orders
and timestamp resolutions, Ethernet/802.1Q/ARP/IPv4/IPv6/UDP/TCP/ICMP,
fragments and fragment windows, both traffic directions, positive-control
windows and replays, malformed frames versus structural truncation, every
tcpdump stats rule, policy rejection cases, test-node naming, netplan
closure/ownership/preflight, and control nonce freshness.
