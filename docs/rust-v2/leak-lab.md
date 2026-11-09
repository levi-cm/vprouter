# External leak-test lab (M1: offline monitor)

Status: M1 tooling only. Everything in `tools/leak-lab/` is offline; it reads
files and prints reports. `netplan.py` prints privileged host commands but never
executes them. No lab VM, capture, network, nftables or Docker setup is performed
by this milestone.

The purpose is to prove, from outside the router VM, that the VM's WAN interface
carries only declared Mullvad WireGuard UDP flows (plus an exact gateway ARP
exchange when enabled) and no IPv6. A real-IP leak is treated as a catastrophic
event: the tool has no fail-open defaults. A capture must supply:

- a tcpdump stats file whose first non-empty line is exactly one
  `tcpdump: listening on vprlab-tap0, link-type EN10MB (Ethernet), ...` banner
  and whose every summary reports `captured == received by filter`, zero drops,
  non-decreasing counters, and a final `captured` equal to the pcap record
  count;
- the exact tcpdump argv printed by `netplan.py`, as a JSON list, so a hidden
  BPF filter or a short snaplen cannot silently narrow the evidence. Its `-w`
  path must resolve (`realpath`) to the submitted `--pcap` file;
- exactly one before-control nonce and exactly one after-control nonce;
- an explicit `--expect-tunnel up|down|any` phase expectation.

Otherwise the result is `INVALID`, never `PASS`. Any observed leak finding is
`LEAK` even when the capture is also invalid; the invalid reasons are reported
alongside.

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
 │        │   iptables DOCKER-USER (iptables-nft):                    │
 │        │     accept vprlab0 -> WAN and WAN -> vprlab0 (conntrack)  │
 │   vprlab0 bridge, 10.250.0.1/24, MAC 52:54:00:76:70:01, no ports      │
│        │   run owner record /run/vprlab/owner.json (token 0600)       │
 │        │                                                          │
 │   vprlab-tap0  <---- tcpdump -i vprlab-tap0 -nn -U                 │
 │                       --immediate-mode -B 8192 -s 0 -w FILE        │
 │                       2> STATS                                     │
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

**Docker caveat.** `debdev` runs Docker, whose iptables-nft `FORWARD` policy is
`DROP`. Netfilter requires every base chain at a hook to accept, so the `accept`
rules in `inet vprlab` alone cannot make the lab's WAN path work. The plan
therefore inserts two scoped `DOCKER-USER` accepts (bridge to WAN, and
WAN to bridge for `ESTABLISHED,RELATED`), each carrying this run's exact
`-m comment --comment vprlab-owned:<token>`, and removes them with the identical
`-D` specification in a loop until no duplicate of that exact owned rule
remains. The preflight reads an `iptables-save` dump and rejects any host where
the `DOCKER-USER` chain is absent, or where `FORWARD` does not jump to
`DOCKER-USER` before Docker's own rules (`DOCKER-FORWARD`,
`DOCKER-ISOLATION-STAGE-1`, ...): the inserts would fail or would not be
reached, and the tunnel would never come up (an outbound-only capture would
otherwise look like a PASS).

## Policy

`tools/leak-lab/policy.py` is the binding validator. `policy.schema.json` mirrors
the same closed shape for editors and CI, but cannot express duplicate JSON
keys, duplicate-label/endpoint rejection, the public-unicast address-class
rules, `gateway_mac != vm_wan_mac`, or the fixed lab MAC values as precisely as
the Python loader.

```json
{
  "schema_version": 1,
  "vm_wan_mac": "52:54:00:76:70:02",
  "vm_wan_ipv4": "10.250.0.2",
  "gateway_ipv4": "10.250.0.1",
  "gateway_mac": "52:54:00:76:70:01",
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
  MAC, and is normalized to lowercase. The host plan's lab uses the fixed VM
  WAN MAC `52:54:00:76:70:02`; a policy with any other value will not recognize
  the real lab frames as allowed;
- `vm_wan_ipv4` must be a usable host address inside the fixed lab subnet
  `10.250.0.0/24`;
- `gateway_ipv4` must be exactly `10.250.0.1`, the host bridge address the plan
  configures. Any other gateway is rejected: the plan would never answer the
  VM's ARP or deliver the controls;
- `gateway_mac` is **required always**, including when `allow_arp` is `false`.
  It must be a unicast non-zero MAC, and must differ from `vm_wan_mac`.
  Gateway-to-VM ARP is allowed only from this MAC, and outbound/inbound allowed
  tunnel frames must use this MAC as the Ethernet peer of `vm_wan_mac` in the
  correct direction. The host plan sets the bridge MAC to the fixed value
  `52:54:00:76:70:01` before the links come up, so this value does not change
  between runs;
- `positive_control.sink_ipv4` must equal `gateway_ipv4`; the host drops that
  datagram silently (see the input chain above);
- `allowed[].dst_ipv4` must be a **public unicast** address. RFC1918
  (`10/8`, `172.16/12`, `192.168/16`), CGNAT/Tailscale (`100.64.0.0/10`),
  `192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`,
  `203.0.113.0/24`, loopback (`127/8`), link-local (`169.254/16`), multicast
  (`224/4`), reserved (`240/4`), unspecified (`0/8`) and any address that
  `ipaddress` does not consider globally routable are rejected; the relay must
  not be the VM or gateway address either;
- `allowed[].dst_port` must not be 53, 853, 123, 5353 or 5355. A policy that
  allows DNS, DoT, NTP, mDNS or LLMNR as a "relay flow" could silently whitelist
  a plaintext service leak, so the loader refuses it;
- dotted-quad literals only for every address; hostnames, whitespace, leading
  zeros and non-ASCII digits are rejected;
- `allowed[].proto` is exactly `"udp"`; TCP is never allowed on the WAN;
- ports are integers in 1..65535;
- labels are 1..64 characters of `[a-z0-9-]`, start/end with `[a-z0-9]`, are
  unique, and may not use the report-reserved names `arp` or
  `positive-control`;
- allowed endpoints must be unique, and the positive-control endpoint must not
  duplicate an allowed flow;
- `allow_arp` is a JSON boolean. `allow_arp: false` makes ARP a finding; it is
  usable only with verified static neighbours on **both** sides (see below).
  A real router phase normally uses `allow_arp: true` with the exact rules
  below;
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

`--used-nonces` creates the file with mode `0600` when it does not exist, so the
first invocation works on a fresh tree; it still refuses any nonce that already
appears in it. The file is not a lock: append every nonce after a phase so a
replay is detected before it is used.

It prints two copy-pasteable commands labelled `before-control` and
`after-control`, each followed by its nonce. `--json` prints the same data as
canonical JSON. `--nonce HEX` exists only for deterministic reproduction and
must be accompanied by `--used-nonces`.

Operational rule:

- send the before-control, run the test action, then send the after-control;
- pass the two nonces with `--control-before NONCE --control-after NONCE`;
- the scanner requires exactly one sighting of each nonce, and it requires
  `ts(before) < ts(after)`. Both controls must be distinct;
- every record is classified. A record outside `[before, after]` that is an
  allowed flow (for example a WireGuard keepalive or handshake before the
  before-control, or a return packet after the after-control) is counted in
  `capture_meta.outside_window_allowed` and does **not** invalidate the
  capture. Packet indexes are listed in
  `capture_meta.outside_window_allowed_packets`. An out-of-window finding is
  still a `LEAK`;
- record timestamps must never decrease relative to the previous record.
  A regression is `INVALID` (`non_monotonic_timestamps`): timestamp ordering is
  the basis of the control window, so it cannot be assumed away;
- a repeated expected nonce is a `replayed_control` finding (`LEAK`), never a
  second independent sighting;
- a control packet with an unexpected nonce or any wrong format is a `LEAK`
  finding; it is never excused;
- control packets are excluded from leak findings **only** on an exact
  expected-nonce match, and an unfragmented control must declare a UDP length
  exactly equal to its IPv4 payload. Controls are not counted in
  `allowed_counts`.

Per phase, the sequence is:

1. prepare the neighbours deliberately (see ARP below) and start the tap
   capture;
2. send the "before" control;
3. run the test action;
4. send the "after" control;
5. wait until the after-control has appeared in the pcap file
   (`--immediate-mode` writes each packet as it is read);
6. wait 2 seconds of quiet so the ring drains;
7. stop tcpdump with SIGINT;
8. pass the pcap, the stderr stats file, both nonces, the exact capture argv
   JSON and `--expect-tunnel up|down|any` to `pcapscan.py`.

The scanner enforces the window, ordering, uniqueness, timestamp monotonicity
and stats agreement itself. Waiting for the after-control in the file and then
2 s of quiet is what makes `received by filter == captured` a meaningful
drain check; sending SIGINT immediately can leave unread ring packets.

### Static neighbours (`allow_arp: false`)

Both directions must be permanent; configuring only the VM side is not enough,
because the host also ARPs for `10.250.0.2` when it forwards inbound WireGuard.
The host plan already installs the fixed host entry before the links come up
and removes it in teardown. The VM side remains part of the reviewed guest
configuration.

Host (the plan uses these exact fixed values; do not run these by hand):

```sh
ip neigh replace 10.250.0.2 lladdr <vm-mac> dev vprlab0 nud permanent
# with the fixed lab MAC:
ip neigh replace 10.250.0.2 lladdr 52:54:00:76:70:02 dev vprlab0 nud permanent
```

VM (replace `<gateway-mac>` with `gateway_mac`; the fixed value is
`52:54:00:76:70:01`):

```sh
ip neigh replace 10.250.0.1 lladdr <gateway-mac> dev eth0 nud permanent
```

With `allow_arp: true`, the scanner accepts the exact ARP exchange described
below instead, and the cold-neighbour ARP is counted as
`outside_window_allowed` when it happens before the before-control.

## Verdict semantics

`tools/leak-lab/pcapscan.py` writes a canonical one-line JSON report with sorted
keys and these fields:

- `verdict`: `PASS`, `LEAK` or `INVALID`;
- `packets`: complete pcap records read;
- `allowed_counts`: per-label counts **split by direction**, for example
  `{"mullvad-wg": {"outbound": 4, "inbound": 3}}`, plus the pseudo-label
  `arp` with the same shape when ARP is allowed. `outbound` means
  `src == vm_wan_ipv4`; `inbound` means `dst == vm_wan_ipv4`;
- `findings`: first 200 findings, each with `ts`, `src`, `dst`, `proto`,
  `src_port`, `dst_port`, `reason` and optional context (`detail`, `vlan`, ARP
  MACs, fragment key, ...);
- `findings_total` and `findings_truncated`;
- `positive_controls_seen`: expected nonces in first-seen order;
- `capture_meta`: pcap format/endianness/timestamp resolution/snaplen/linktype,
  pcap and policy SHA-256, the expected before/after nonces, a `controls` object
  with each control's `nonce`, `seen`, `packets`, `first_packet`, `last_packet`,
  `first_ts` and `last_ts`, `missing_controls`, `outside_window_allowed` and
  `outside_window_allowed_packets`, `non_monotonic_timestamps`, the
  `tunnel_expectation` object, tcpdump stats, `stats_banner_ok`,
  `stats_source`, `stats_sha256`, `capture_argv`, `capture_argv_sha256`, and
  `invalid_reasons` (plus `invalid_reason`, the first one, for older
  consumers).

`tunnel_expectation` is
`{"value": "up|down|any", "outbound_in_window": N, "inbound_in_window": M,
"labels_both_directions": [...], "inbound_total": T, "satisfied": true|false}`.
For `up`, only allowed relay flows inside the control window count; ARP and
out-of-window traffic are not tunnel evidence. `up` requires at least one
outbound and one inbound allowed-flow packet inside the window **on the same
allowed flow label**: outbound to relay A plus inbound from relay B is not one
tunnel. `down` requires zero inbound allowed flows anywhere in the capture (a
keepalive after the after-control is still tunnel evidence). `any` reports
without a requirement. A failed `up`/`down` requirement is `INVALID`
(`tunnel_not_observed`), which prevents "the tunnel never came up" from being
reported as a clean phase.

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
  `stats_packet_count_mismatch`, `unread_capture_tail`,
  `capture_banner_mismatch`;
- capture provenance: `capture_argv_invalid`, `capture_argv_mismatch`;
- control qualification: `control_order`, `outside_control_window`,
  `missing_positive_controls`, `non_monotonic_timestamps`;
- tunnel evidence: `tunnel_not_observed`;
- `zero_packets`.

`outside_control_window` is now only reachable for a non-control record that is
neither an allowed flow nor a finding, which the classifier does not produce;
it remains as a defensive reason.

A complete record whose frame content is malformed is **not** an invalid
capture. It is a `malformed_frame` finding and scanning continues. This covers a
short Ethernet header, a bad IPv4 version/IHL, a short IPv4 header, a bad IPv4
total length, bad UDP length, a short IPv6 header, and truncated ARP bodies.
Only pcap-structure damage stops the scan.

### tcpdump stats

`--tcpdump-stats` is mandatory. The parser reads **every** summary line written
by Debian 13 tcpdump 4.99:

```
tcpdump: listening on vprlab-tap0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
N packets captured
N packets received by filter
N packets dropped by kernel
N packets dropped by interface        # optional platform-dependent counter
```

Rules:

- the first non-empty line must be one complete banner line of the form
  `tcpdump: listening on vprlab-tap0, link-type EN10MB (Ethernet)[, snapshot
  length N bytes]`, and there must be exactly one `listening on` line anywhere
  in the file, otherwise `capture_banner_mismatch`. A capture named `eth0`, a
  non-Ethernet link type, a concatenated/duplicated banner, a banner that is
  not first, or a foreign line merely containing the banner text is not this
  plan's capture;
- every summary is parsed in full, including every multi-line summary and every
  one-line SIGUSR1 summary
  (`tcpdump: N packets captured, M packets received by filter, K packets dropped
  by kernel`). The one-line form's `captured` and `received` values are
  binding exactly like the multi-line form's;
- every summary must contain `captured`, `received by filter` and `dropped by
  kernel`; otherwise `stats_incomplete`. `dropped by interface` is optional;
- within every summary, `captured` must equal `received by filter`, otherwise
  `unread_capture_tail`. On the supported Linux tap path, a packet that passed
  the filter but was never written is an unread ring entry, so the capture is
  incomplete even when no drop counter moved. The stop procedure (wait for the
  after-control in the file, 2 s of quiet, then SIGINT) is what normally makes
  the counters agree;
- any `dropped by kernel` or `dropped by interface` value greater than zero in
  any summary is `packet_drops` (a positive drop is reported as `packet_drops`
  even when the summaries also disagree);
- counters must be non-decreasing from one summary to the next; a decreasing
  counter in a later summary is `stats_contradictory` (concatenated or stale
  summaries are not evidence);
- the **final** summary is the binding count: its `captured` must equal the
  number of complete pcap records exactly, otherwise
  `stats_packet_count_mismatch`. A legitimate mid-run SIGUSR1 summary with
  smaller or equal counters is accepted; if the one-line summary is the last
  summary, its count is binding;
- a tcpdump error line such as `pcap_loop`, `interface disappeared`,
  `went down` or `permission denied` is `stats_error_line`;
- a counter-shaped line that does not match the supported format is
  `stats_unparseable`.

The stats file's SHA-256 is bound into the report; `capture_meta.stats` holds
the final summary's counters (the binding ones). The tcpdump process's own
exit status is not present in the stderr file; record it separately if the
qualification procedure needs it.

### Capture provenance

`--capture-argv-file` is mandatory. It must contain a JSON list equal to the
argv `netplan.py` prints:

```json
["tcpdump", "-i", "vprlab-tap0", "-nn", "-U", "--immediate-mode",
 "-B", "8192", "-s", "0", "-w", "/run/vprlab/manual-capture.pcap"]
```

Only the value after `-w` may differ from the printed command, and that value
must resolve (`os.path.realpath`) to the same file as `--pcap`. Any extra or
missing element, a BPF filter expression, a different interface, a short
snaplen, a missing `--immediate-mode`/`-U`, or a `-w` path such as `/dev/null`
or `-` that does not resolve to the submitted capture is
`capture_argv_mismatch` (or `capture_argv_invalid` when the value is not a
non-empty list of non-empty strings). The submitted argv is recorded in
`capture_meta` together with `capture_argv_sha256`, the SHA-256 of the exact
argv-file bytes, and `capture_argv_canonical_sha256`, the SHA-256 of the
compact canonical re-encoding.  Only the first is an evidence hash: the VM
runner compares it with its own exact-byte hash of `capture-argv.json`.

### Frame classification

Direction is classified by the declared VM IP (`src == vm` outbound,
`dst == vm` inbound). `vm_wan_mac` is used for ARP rules and for frames that
involve neither the VM MAC nor the VM IP. A frame with the VM IP and a foreign
Ethernet MAC is still classified by IP, but an allowed relay tuple additionally
requires the exact tunnel L2 shape:

- an allowed **outbound** frame must have Ethernet source `vm_wan_mac` and
  Ethernet destination `gateway_mac`;
- an allowed **inbound** frame must have Ethernet source `gateway_mac` and
  Ethernet destination `vm_wan_mac`;
- an allowed frame must not carry an 802.1Q tag (the host never tags lab
  traffic).

Any allowed tuple with another L2 shape is `allowed_tuple_wrong_l2`; it is a
finding and is not counted in `allowed_counts`, so a VM-emitted inbound-shaped
frame, a foreign MAC, or a tagged frame cannot satisfy `--expect-tunnel up`.

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

`allow_arp: true` requires `gateway_mac`. Exactly two shapes are allowed, and
the Ethernet source MAC must equal the ARP sender MAC:

- the VM asking for or answering the gateway: sender `(vm_wan_mac,
  vm_wan_ipv4)` and target IP `gateway_ipv4`;
- the gateway requesting or replying to the VM: sender MAC **and** Ethernet
  source `gateway_mac`, sender IP `gateway_ipv4`, target IP `vm_wan_ipv4`, and
  for a reply target MAC `vm_wan_mac`.

ARP operation must be request (1) or reply (2). Everything else is
`arp_not_allowed`: a VM claiming another IP (including the gateway), a
foreign MAC claiming the gateway IP, the VM MAC claiming the gateway IP, a
foreign MAC claiming the VM IP, gratuitous ARP for another IP, an
Ethernet/ARP sender mismatch, unsupported hardware/protocol types, and third
parties. The count `allowed_counts["arp"]` is directional: VM-to-gateway is
`outbound`, gateway-to-VM is `inbound`.

The monitor still cannot authenticate a frame cryptographically: a VM can forge
an entire ARP request or reply with the gateway's MAC. This branch rejects
contradictory identities that are directly observable on the tap; it is not a
proof of a legitimate exchange. That is why a phase that needs strict ARP
silence should use `allow_arp: false` with the verified static neighbours shown
above.

### Fragments

Fragments are conservative and in-order:

- a non-first fragment is associated only with a first fragment for the same
  `(src, dst, protocol, identification)` seen at most 30 seconds earlier, with
  no completed datagram and no reuse in between;
- a non-first fragment seen before its first fragment, more than 30 seconds
  after it, without any first fragment, or after the datagram completed is a
  finding (`fragment_without_first`, `fragment_stale_association`,
  `fragment_after_complete`);
- an incomplete allowed association that is replaced or expired by a new first
  fragment for the same key is itself a finding (`incomplete_fragment`). A new
  datagram must not erase the earlier datagram's missing-tail evidence. An
  allowed association that never completes by the end of a structurally
  complete capture is also `fragment_incomplete` **wherever its first fragment
  lies relative to the control window** (before, after, at either marker, or
  inside): a boundary-cut fragment is a finding, never an excused out-of-window
  flow;
- fragment ranges must be contiguous: an overlap is `fragment_overlap`, a gap is
  `fragment_gap`, and a fragment beyond the first fragment's declared UDP length
  is `fragment_out_of_range`;
- the final fragment must end exactly at the declared UDP length, otherwise
  `fragment_incomplete`;
- a zero-payload fragment (first, middle or final) is
  `zero_payload_fragment`. An empty fragment cannot complete, extend or pad an
  association;
- a first fragment with MF set must declare a UDP length strictly greater than
  the bytes it carries; equality leaves no genuine remainder and is
  `malformed_frame`;
- a duplicate first fragment for an incomplete key is
  `fragment_duplicate_first`; a middle fragment whose payload is not a multiple
  of 8 bytes is `malformed_frame`.

### Host resource bounds

The scanner is fed from a stream and never loads the pcap. It retains only
counters, at most 1000 outside-window packet indexes (the total is still
reported, and `outside_window_allowed_truncated` is true), and at most 4096
unfinished fragment associations. A full live fragment table is a
`fragment_table_overflow` finding and the verdict is INVALID (fragment
completeness is no longer judged); findings from actual frames still have LEAK
precedence. The M2 runner caps a phase at 3600 s, admits a boot only with
>= 1536 MiB `MemAvailable` and the capture cap plus 1 GiB free disk, stops the
phase with `capture_size_cap` above the cap (default 2 GiB) while still scanning
what exists, and runs the scanner with `RLIMIT_AS` 1 GiB and a timeout.

## Host network plan

`tools/leak-lab/netplan.py` prints (never executes) a standalone `#!/bin/sh`
script (`set -eu`) for deliberate execution as root; it is not a set of commands
to paste into an interactive shell. It contains:

- bridge `vprlab0`, address `10.250.0.1/24`, no physical ports, MAC fixed to
  exactly `52:54:00:76:70:01` with `ip link set vprlab0 address ...` before
  either link is brought up. The VM WAN MAC is the fixed
  `52:54:00:76:70:02`; the policy must use these values;
- tap `vprlab-tap0` created with
  `ip tuntap add dev vprlab-tap0 mode tap user vprlab-qemu` (the default is the
  dedicated QEMU account created by `vm/hostsetup.py`; `--tap-user` can name
  another non-root account, and `root`/uid `0` are refused), attached to
  the bridge, with IPv6 disabled **before** either link is brought up;
- a per-run owner record: setup first creates `/run/vprlab/` (mode `0700`,
  root-owned when run as root) and `/run/vprlab/owner.json` exclusively
  (`O_EXCL`, mode `0600`) containing
  `{"schema":1,"token":"<32 hex from /dev/urandom>","created":"<UTC>"}`. Setup
  refuses to start if that file already exists. Every owned object carries the
  exact string `vprlab-owned:<token>`: the `ifalias` of both links, the
  `inet vprlab` table comment, and both `DOCKER-USER` rule comments. The VM
  runner reads `/run/vprlab/owner.json`, reconstructs `vprlab-owned:<token>`,
  checks that exact `ifalias` on `vprlab0` and `vprlab-tap0` (using the
  `ip -j -d link show` key `ifalias`), and checks that `vprlab-tap0` has
  `vprlab0` as its master (is enslaved to the bridge) before it treats the lab
  as its own;
- two scoped `DOCKER-USER` accepts carrying the run token in
  `-m comment --comment vprlab-owned:<token>`, so Docker's FORWARD `DROP`
  policy does not blackhole the lab;
- dedicated `inet vprlab` nftables table created with `nft create` (exclusive:
  it fails if the table already exists) and carrying the run's exact ownership
  comment;
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
- the permanent host neighbour
  `ip neigh replace 10.250.0.2 lladdr 52:54:00:76:70:02 dev vprlab0 nud permanent`,
  installed after the firewall and before the links come up; teardown removes
  it;
- setup order is: owner record -> links created DOWN with their `ifalias` ->
  nft table (input drop, output drop, forward restrictions, scoped masquerade)
  -> `DOCKER-USER` accepts -> host neighbour -> links UP. The script installs
  `trap` handlers for `INT TERM HUP EXIT` that run teardown of what this run
  created (dash-compatible), so Ctrl-C or a setup failure cannot leave the lab
  unprotected;
- teardown reads the token from `owner.json` and **verifies every existing
  object's ownership before any mutation**: both links by `ifname`, exact
  `ifalias` and link kind (`tun`/tap, `bridge`), the table by exact structured
  `comment`, and the neighbour by destination/`lladdr`/permanent state. Any
  mismatch aborts with no changes and a nonzero exit. It then isolates the
  guest first (`ip link set vprlab-tap0 down` then `nomaster`, followed by a
  readback that the tap is down and detached). If isolation cannot be proved,
  teardown **stops** with the DROP table and `DOCKER-USER` accepts still
  installed and exits nonzero. Otherwise it removes the neighbour, the exact
  owned `DOCKER-USER` rules (looping until no duplicate of the exact owned
  specification remains), the nft table, and the two links, then removes
  `owner.json` last and only if every step succeeded. Any failure keeps
  `owner.json` for a retry and makes the final exit code nonzero; teardown
  never reports success after a failure. Ownership is exact structured
  equality, never a `grep` substring test, so a rule comment elsewhere in a
  table or an alias such as `NOT-OWNED-<tag>-backup` can never authorize
  deletion.  An `ip -j link show` inventory that fails or does not parse is
  **not** proof that a link is absent: teardown retains the protections and
  exits nonzero unless a complete successful inventory lacks the object or a
  down/detach operation is read back.  Teardown also refuses (nonzero, no
  changes) while `/run/vprlab/run.lock` is held by a phase, and it acquires
  and **holds** that lock for the whole teardown rather than probing and
  releasing it.

```sh
python3 -B tools/leak-lab/netplan.py --wan-interface eno1 > lab.sh
# review lab.sh, then as root:
#   ./lab.sh setup      # leaves the reviewed network running for M2 phases
#   ./lab.sh teardown   # refuses while /run/vprlab/run.lock is held
# `sh -n lab.sh` only parses it.  The default capture path is
# "$RUN_DIR/manual-capture.pcap" (root-owned run directory), never the CWD.
```

The teardown function is defined before setup exactly so the same reviewed
file can be run as `./lab.sh teardown` after a partial setup without hand-
extracting commands.

The plan never contains `flush ruleset`, never edits a table other than
Docker's `DOCKER-USER` chain (only its own exactly tagged rules), and never
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

Before running the plan, generate all five inventories and run the collision
check. It reads the files only; it does not invoke `ip`, `nft` or `iptables`:

```sh
ip -j link > links.json
ip -j addr > addresses.json
ip -j route show table all > routes.json
nft -j list tables > tables.json
iptables-save > iptables.txt
python3 -B tools/leak-lab/netplan.py --check-name-collisions \
  --wan-interface eno1 \
  --links-json links.json --addresses-json addresses.json \
  --routes-json routes.json --tables-json tables.json \
  --iptables-save iptables.txt
# exit 0 = clear, 1 = collision, 2 = unreadable/malformed input
```

The preflight requires all five inventories and rejects:

- an existing `vprlab0` or `vprlab-tap0` link name **or altname**;
- an existing `inet vprlab` table;
- any existing address or explicit route overlapping `10.250.0.0/24` in **any**
  routing table. `ip -j route` alone omits policy tables (for example
  Tailscale's), so the collection command is
  `ip -j route show table all`; every entry must have a valid `dst`, and an
  empty/malformed entry is an error rather than a silent skip;
- a WAN interface that does not exist, is `lo`, or is a lab interface;
- a host where the `DOCKER-USER` chain is absent, or where `FORWARD` does not
  jump to `DOCKER-USER` **before** Docker's own rules
  (`DOCKER-FORWARD`/`DOCKER-ISOLATION-STAGE-1`/...). The plan's scoped accepts
  could not be installed or reached, so this is a collision even when the
  current `FORWARD` policy is `ACCEPT`. The check always reports the observed
  `FORWARD` policy, whether `DOCKER-USER` exists, and whether the jump precedes
  Docker's rules;
- malformed inventory entries instead of silently skipping them. Non-UTF-8 or
  unreadable inventory files exit `2` with a `netplan:` message, never a
  traceback.

A JSON snapshot is a preflight, not ownership proof; the exclusive owner
record, `nft create`, and the per-run `vprlab-owned:<token>` checks are the
runtime guards.

Capture command printed by the plan (note `--immediate-mode` and `-s 0`, full
frames; `-B 8192` gives the kernel capture ring 8 MiB instead of libpcap's
2 MiB default, because a 58-minute phase lost 3 frames to kernel drops with
the default and any drop makes the phase INVALID). The default is inside the root-owned run directory, not the CWD:

```sh
tcpdump -i vprlab-tap0 -nn -U --immediate-mode -B 8192 -s 0 \
  -w "$RUN_DIR/manual-capture.pcap" 2> "$RUN_DIR/manual-capture.pcap.stderr"
```

On Debian the `tcpdump` binary is documented to start as root, open the
savefile, then drop to the `tcpdump` user; the exact order for this build and
its AppArmor profile must be **qualified on the host** before the first live
phase (this is a live gate, not an offline claim).  Its enforcing AppArmor
profile only allows savefiles matching `/**.pcap` (and similar patterns), so
every generated capture name must end in `.pcap`; `netplan.py` and `guest.py`
both do this.  The M2 runner stops tcpdump with SIGINT only after QEMU has
exited and the after-control is present; a tcpdump that exited earlier makes
the phase INVALID (`capture_ended_early`).

`--immediate-mode` makes each packet reach the file as it is read. Do not stop
the capture immediately after sending the after-control: wait until the
after-control nonce has appeared in the pcap, then wait 2 s of quiet, then send
SIGINT. That drain is what the strict `received by filter == captured` check
qualifies. `-s 0` records full frames; a snaplen-truncated record is `INVALID`
because hidden bytes could be a control or a leak. The banner and summary are
written to stderr when tcpdump exits. Save the exact argv as JSON (the shell
redirection is not part of argv) and pass both files, the argv file, both
nonces and the tunnel expectation to the scanner. The argv's `-w` value must
resolve (`realpath`) to the same file passed as `--pcap`, so a capture command
that wrote somewhere else is `INVALID`:

```sh
cat > capture-argv.json <<'JSON'
["tcpdump", "-i", "vprlab-tap0", "-nn", "-U", "--immediate-mode",
 "-B", "8192", "-s", "0", "-w", "/run/vprlab/manual-capture.pcap"]
JSON

python3 -B tools/leak-lab/pcapscan.py \
  --policy policy.json \
  --pcap /run/vprlab/manual-capture.pcap \
  --tcpdump-stats /run/vprlab/manual-capture.pcap.stderr \
  --capture-argv-file capture-argv.json \
  --expect-tunnel up \
  --control-before <before-nonce> --control-after <after-nonce>
```

Exit codes: `0` = PASS, `1` = LEAK, `2` = INVALID or usage/policy error.

### Inbound ICMP errors are findings, on purpose

An ICMP error arriving from the Internet addressed to the VM (for example a
fragmentation-needed from a PPPoE hop, or a port-unreachable) is reported as
`icmp_not_allowed`, even though the host's conntrack `RELATED` accept may
forward it. The monitor cannot tell a genuine path-MTU message from injected
traffic, and the phase contract says the VM's WAN carries only the declared
WireGuard UDP flows. A real PMTU error therefore makes the phase `LEAK`, not
`PASS`; read the finding's `src` before assuming a router fault. Prevent it
operationally by setting the VM WAN and WireGuard MTU below the path MTU. The
same rule means an inbound ICMP error is never a hidden exception to the
endpoint-only policy.

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
  IPv4 direction is classified by the declared VM IP. On an allowed relay tuple
  the Ethernet shape is also checked (`vm_wan_mac`/`gateway_mac` in the correct
  direction, no VLAN tag), so a VM-emitted inbound-shaped frame with the wrong
  L2 is `allowed_tuple_wrong_l2`; a frame that spoofs the gateway MAC is still
  indistinguishable from real return traffic. ARP has the stricter sender and
  `gateway_mac` rules above.
- A VM can still forge a frame that matches an allowed ARP shape or a complete
  allowed-tuple L2 shape; the monitor has no cryptographic authentication.
- It **cannot** make the monitor ignore a frame that reaches the tap: every
  captured frame is classified, and any nonzero tcpdump drop counter in any
  summary, a `captured != received` summary, a decreasing summary counter, a
  final captured-count mismatch, or an unread ring tail invalidates the
  capture.
- It **can** suppress traffic before it reaches the tap (by not sending it, or
  by causing tcpdump/kernel drops). Suppression is detected only when the drop
  counters, the received/captured equality or the record count expose it; a
  completely silent VM is indistinguishable from a clean VM by this monitor.
  That is why `--expect-tunnel up` requires allowed traffic in both directions
  on the same flow label inside the window; use it for every phase that claims
  a working tunnel.
- It **cannot** make the monitor authenticate WireGuard or prove that the
  tunnel carried real traffic. Matching an allowed outer UDP tuple proves only
  the endpoint, not encryption or a working tunnel.
- The allowed tuple has a **WireGuard shape check**, not a cryptographic one.
  Every non-control UDP datagram on an allowed tuple must start with message
  type 1, 2, 3 or 4, have three zero reserved bytes, and have a plausible
  length: type 1 exactly 148 bytes, type 2 exactly 92, type 3 exactly 64, and
  type 4 at least 32 bytes (16-byte header plus the Poly1305 tag). There is
  no 16-byte alignment rule for type 4: WireGuard pads plaintext to a
  multiple of 16 but clamps the padding at the tunnel MTU, so full-size data
  packets at MTU 1420 (1452 bytes) or 1500 (1532 bytes) are not aligned
  (controller fix after the round-4 gate). A plaintext payload shaped like a
  type-4 message still passes; that is an inherent limit of a shape check.
  A reassembled
  fragmented datagram is checked with the same length rule; a first fragment
  that does not expose the four-byte header is refused. Anything else is the
  LEAK finding `allowed_tuple_not_wireguard`. This stops a plaintext payload
  on the declared outer flow from being certified, but it does not
  authenticate the ciphertext or prove a working tunnel.

- **Narrow ICMP quote allowance** (user decision, 2026-11-09, after the first
  live LEAK). Exactly one ICMP shape is not a leak: an outbound ICMP type 3
  code 3 (port unreachable) from the VM to an allowed endpoint, with the
  correct lab MACs, whose quoted datagram is an option-free IPv4 UDP packet
  from that same endpoint and port to the VM, with a WireGuard-shaped payload
  prefix. Such a reply quotes only the endpoint's own ciphertext and goes only
  back to it. It is counted in `allowed_icmp_quotes`, never as tunnel
  evidence, and is accounted like allowed traffic outside the control window.
  Every other ICMP, and any inbound ICMP, is still `icmp_not_allowed`. Live
  cause: after a VM restart, the Mullvad server's handshake to the old NAT
  mapping reached the VM before wg0 existed, and the kernel answered with
  port-unreachable.

This milestone does **not** cover:

- the client-side WAN; that needs a separate capture and policy;
- traffic inside the WireGuard tunnel (the monitor sees only the outer UDP
  endpoint, sizes and timing, not decrypted destinations);
- traffic the VM drops before it reaches the WAN, or traffic on any other
  interface;
- a compromised capture host. Root on debdev could tamper with tcpdump, the
  pcap, the stats file or the argv file. Keep the capture host trusted, store
  evidence off-box, and cross-check hashes/controls if the result matters;
- host forwarding problems that prevent the tunnel from coming up at all.
  Docker's FORWARD `DROP` is handled by the plan's `DOCKER-USER` accepts and
  checked by the preflight, but live forwarding is not exercised by this
  offline milestone; `--expect-tunnel up` is the guard against a silent
  outbound-only PASS;
- periods without captures, or captures whose tcpdump stats show drops, an
  unread ring tail, or a count mismatch. Any structurally truncated record or
  snaplen-truncated record is `INVALID`, not a partial pass;
- IPv6 by any means: `ipv6_allowed` is always false and any IPv6 frame is a
  finding;
- the outbound UDP source port. Any source port to an allowed relay endpoint is
  accepted; only the destination tuple is declared. Note this when interpreting
  a `PASS`.

**Skipped Minors:** the M1 foreground/manual capture still uses
`/run/vprlab` (tmpfs on many hosts) and has no separate size bound.  The M2
path never starts it (it uses `netplan.py setup`), so this is deferred until
someone uses the M1 capture mode on a host with a small `/run`.  The Debian
tcpdump privilege-drop order/AppArmor qualification remains a live gate, as
stated above.

There is no `--allow-no-stats`, `--allow-filter` or no-control escape hatch.
Missing stats, a mismatched capture argv, a missing control, a decreasing
timestamp or unmet `--expect-tunnel` evidence is `INVALID` (or `LEAK` when a
finding is also present). Reusing the same nonce for before and after is a usage
error (exit 2), and a nonce replayed in the capture is a `LEAK` finding; neither
is ever a `PASS`.

## Tests

```sh
python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py -v
```

The suite synthesizes all pcaps with `struct`; it covers both pcap byte orders
and timestamp resolutions, Ethernet/802.1Q/ARP/IPv4/IPv6/UDP/TCP/ICMP,
directional allowed counts and `--expect-tunnel` (including same-label
evidence), fragments (expiry, replacement, zero payload, and unfinished
associations before/after/at both control markers), positive-control windows
and replays, timestamp monotonicity, out-of-window allowed flows, malformed
frames versus structural truncation, every tcpdump stats rule (banner position,
one-line SIGUSR1 captured/received/drop parsing, per-summary consistency,
non-decreasing counters, final count binding), capture-argv provenance
(including `-w`/`--pcap` realpath equality), policy rejection cases, test-node
naming, netplan setup order/fixed MACs/per-run owner record/`ifalias`
ownership/preflight, generated-script teardown behavior under stub commands
(foreign ownership, isolation failure, duplicate rule removal, retained owner
record on failure, signal trap), the generated M1 setup state as accepted by
the M2 `hostcheck` (with every single-field mutation refused), streaming
scanner memory bounds over 50k records, fragment-table overflow and
outside-window index caps, and control nonce freshness.
