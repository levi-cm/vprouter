# Leak-lab M1 re-review (round 2, adversarial, Opus) — 2026-11-09

Scope: commit `2fc1779`, files `tools/leak-lab/{policy.py,policy.schema.json,pcapscan.py,control.py,tsnames.py,netplan.py,test_leak_lab.py}` and `docs/rust-v2/leak-lab.md`.

Method:
- Read every file in scope, plus the three round-1 reports (gpt, opus, pi).
- Re-ran every round-1 reproducer, about 110 cases in total including new attack cases. The scripts lived in `/var/tmp/leaklab-rr-opus`, built on the suite's own in-memory packet builders, and that directory was deleted afterwards.
- No sudo, VM, network, nft or ip command was used. The only host commands were read-only: `tcpdump --version`, `/proc/sys/net/ipv4/ip_forward`, the presence of `docker.sock` and `systemctl is-active docker`, and `ls /sys/class/net`.

Suite, `python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py`: **Ran 150 tests, OK** (0 failures, 0 errors, 0 skipped).

## Verdict: **FAIL** (0 Critical, 2 Important, 7 Minor)

Every round-1 Critical and Important finding is fixed, and each reproducer now fails closed (table below). I found **no new false-PASS path** in:
- the scanner or the stats parser, including a realistic tcpdump 4.99.5 stderr file;
- fragment bookkeeping, trailer/padding handling, or the LEAK-over-INVALID precedence.

The two remaining Important findings are not missed leaks, but each prevents a trustworthy PASS under the stated intended use:
- **I-1:** the new strict control window makes a clean PASS a matter of luck on a live WireGuard tunnel.
- **I-2:** on this host Docker's FORWARD drop policy blackholes the lab WAN, and the report cannot tell a tunnel-up PASS from a tunnel-never-came-up PASS.

---

## 1. Round-1 findings: status (all reproducers re-run)

| Round-1 ID(s) | Claim | Now |
|---|---|---|
| gpt C1, pi F-02 | first zero summary hides a later nonzero drop | `INVALID packet_drops` (kernel 0→6, iface 0→7, duplicate summary with 500) ✔ |
| pi F-01 (Critical), gpt I1, opus M1 | `captured` not compared with records; partial stats | prefix pcap → `stats_packet_count_mismatch`; captured=300 → mismatch; captured=0 → mismatch; interface-only stats → `stats_incomplete`; `pcap_loop`/"went down" → `stats_error_line` ✔ |
| opus I1, pi F-03/F-04 | PASS with no controls or stats | `scan_capture` now needs both nonces as positional arguments and the stats keyword (TypeError when absent); `None` stats → ValueError; CLI flags are `required=True` (exit 2); unreadable stats → INVALID ✔ |
| opus I2, gpt I6, pi F-05 | duplicate nonce collapses | API ValueError; CLI exit 2 "must be distinct"; a replay in the capture is a `replayed_control` LEAK; `control.py --nonce` needs `--used-nonces` and refuses reuse ✔ |
| opus I3 | VM-controlled malformed frame aborts the scan | short IPv4, IHL=4 and a 10-byte runt each become a `malformed_frame` finding, and the DNS that follows is still found → LEAK; drops + DNS → LEAK with `packet_drops` listed ✔ |
| opus I4, pi F-06 | host ICMP unreachable for the sink; host exposed | `input iifname "vprlab0" drop` plus `output oifname "vprlab0" meta nfproto ipv4 drop` in the plan; analysis in §3 ✔ |
| gpt I2, opus M5/M8 | snaplen truncation ignored; trailers ignored | `snaplen_truncated_record` INVALID; 264-byte trailer, nonzero padding, or zero padding past 60 bytes → `ethernet_trailer`; exact zero padding to 60 bytes → PASS ✔ |
| gpt I3 | UDP length ignored; extra bytes on controls | UDP lengths 0/1/7/65535/18 on an allowed flow → `malformed_frame/udp_length_mismatch`; control with extra IP-payload bytes → malformed, and the control is not counted as seen ✔ |
| gpt I4 | fragment association unvalidated | orphan at offset 64000 and conflicting overlap → `fragment_after_complete`; never-completed → `fragment_incomplete`; non-first before first → `fragment_without_first` ✔ |
| gpt I5, opus M2 | LSRR options allowed | `ipv4_options` ✔ |
| gpt I7, pi F-08 | masquerade not scoped | `ip saddr 10.250.0.0/24 iifname "vprlab0" oifname "<wan>" masquerade` ✔ |
| gpt I8, pi F-14, opus M7 | table ownership; fail-open inventories; altnames | `nft create table` (exclusive) with an ownership comment; teardown greps the tag; malformed inventory raises; all four inventories required; altnames, address and route overlap checked; WAN `lo`/`.`/`-x`/lab names rejected ✔ |
| pi F-07 | `allow_arp:false` unusable | documented (but see M-6) ✔ |
| opus M3, pi F-12 | semantically wrong addresses | 0/8, 127/8, 224/4, 240/4 and 169.254/16 rejected; VM, gateway and sink must be in the lab /24; sink must equal the gateway; relay may not be in the lab /24; multicast or zero MAC rejected ✔ (residual: M-2) |
| opus M4, pi F-11 | ARP spoofing | Ethernet/ARP sender mismatch, VM claiming another lab IP, gratuitous ARP and op 3 → `arp_not_allowed` ✔ (residual: M-1) |
| pi F-09, F-10, F-13 | ip_forward; immediate mode; per-control evidence | ip_forward check/restore printed; `--immediate-mode -s 0`; `controls.{before,after}` with packet index and timestamps; `stats_sha256` ✔ |

---

## 2. New false-PASS hunt (no false PASS found)

### Stats parser, using a realistic Debian 13 tcpdump 4.99.5 / libpcap 1.10.5 stderr file

This tcpdump/libpcap version is installed on the host.

```
tcpdump: listening on vprlab-tap0, link-type EN10MB (Ethernet), snapshot length 262144 bytes
4 packets captured
4 packets received by filter
0 packets dropped by kernel
```

| Input | Result |
|---|---|
| Sample above | parsed `{captured:4, received:4, dropped_kernel:0, dropped_interface:None}` → PASS (correct) |
| Same, with CRLF line endings | PASS (correct) |
| Same, plus `3 packets dropped by interface` | `packet_drops` |
| `^C4 packets captured` (tty echo mixed into the file) | `stats_incomplete`, fail-safe |
| `pcap_stats: …` line with no summary | INVALID |
| `received by filter` > `captured` (packets left in the ring at SIGINT) | PASS. This is sound: the ring is FIFO and the after-control was processed, so unprocessed packets arrived after the after-control, outside the judged window. |

### Control window (`pcapscan.py:1092-1106`)

| Case | Result |
|---|---|
| Records before the before-control, after the after-control, or at the same timestamp | INVALID |
| A leak outside the window | still LEAK, because findings are classified regardless of the window |
| After-control before before-control | `control_order` |
| Replayed before-control | `replayed_control` LEAK |
| Unexpected nonce | LEAK |
| VLAN-tagged control | counted, correct: the tap saw it |

No path makes an unseen window look seen.

### Fragments

- `finalize_fragments` judges only in-window datagrams. An out-of-window incomplete datagram is already INVALID through `outside_control_window`.
- The key `(src,dst,proto,id)` pins the destination, so no fragment can reach a non-relay destination.

### ARP

The shapes the doc promises are allowed. Ethernet/ARP sender mismatch, op 3, gratuitous ARP and other-IP claims are findings. One doc mismatch remains (M-1).

### Trailer and padding

Zero padding to exactly 60 bytes passes. 61 bytes, any nonzero byte, or a long tail → `ethernet_trailer`.

### LEAK vs INVALID

Findings always win. Structural damage stops the scan as INVALID, never PASS. Fragment finalization is skipped on structural damage, as documented.

### Other classifier probes

| Probe | Result |
|---|---|
| foreign source in the lab /24 → 1.1.1.1:53 | `foreign_frame` |
| IPv4 `tot_len=0` (BIG-TCP style) | malformed |
| IPv6 | LEAK |
| foreign MAC carrying the VM IP | classified by IP (documented) |

---

## Important

### I-1. The strict control window makes PASS unreachable or flaky on the intended system (no false PASS; evidence-availability defect)

Locations: `pcapscan.py:1092-1106`; doc `docs/rust-v2/leak-lab.md:169-172` and `:182-188`.

**The rule.** Every non-control record must lie strictly between the two control timestamps.

**Why it fails in practice.** The intended VM keeps a live WireGuard tunnel, with keepalives, handshakes every ~120 s, and return traffic from the test action. It also performs ARP neighbour maintenance: NUD unicast probes about every 15-45 s while traffic flows, and a cold-neighbour ARP before the first control. Meanwhile the host side cannot start or stop tcpdump atomically at the control packets. Any one such frame in either gap (tcpdump start → before-control, or after-control → SIGINT) makes the run INVALID.

Reproduced:

```
WG keepalive before before-control            -> INVALID outside_control_window
VM ARP for gw before before-control (cold)    -> INVALID outside_control_window
WG reply after after-control                  -> INVALID outside_control_window
NUD ARP probe after after-control             -> INVALID outside_control_window
```

**Effect.** With traffic active at the end of a test action this is close to certain INVALID. On an idle tunnel it is still a non-trivial per-run probability.

**The rule adds no soundness.** Out-of-window records are already fully classified, so an out-of-window leak is LEAK. The design is also asymmetric: packets that tcpdump never wrote (`received` > `captured`, the ring tail) are tolerated, while packets it did write and classify are penalised.

**Why this matters.** The doc presents the start/before/action/after/SIGINT sequence as sufficient and says nothing about quiescing traffic. That pushes the M2 runner toward trimming the pcap (`editcap -A/-B`) and patching the stats count, which is exactly the evidence handling the tool is meant to prevent. Round-1 opus I4, where the documented protocol could not produce a clean PASS, was rated Important for the same reason.

**Fix (either option):**
- (a) Keep classifying everything, but make out-of-window *allowed* records informational (`outside_window_allowed: N`, with packet indexes) rather than an invalid reason. Keep `control_order`, missing, replayed and unexpected controls as they are.
- (b) Keep the rule, but document a mandatory quiesce protocol: warm the neighbour cache, stop client traffic, wait for quiet before the after-control, and send SIGINT within a bounded delay. Also state that INVALID may be retried while LEAK is terminal, and record the retry count in the evidence.

Option (a) is simpler and loses nothing.

### I-2. On this host Docker's FORWARD drop policy blackholes the lab WAN; the report cannot reveal that the tunnel never came up

Locations: `netplan.py:138-144`; doc `docs/rust-v2/leak-lab.md:25` and `:354-355`; `pcapscan.py:209-211` and `:597-598` (`allowed_counts` merges both directions).

**Host facts (read-only):** `docker` is active, about 29 `br-*` networks exist, `/proc/sys/net/ipv4/ip_forward` is 1, and `tailscale0` is present.

**Mechanism.** Docker sets the iptables `FORWARD` policy to DROP by default. In netfilter every base chain on a hook must accept, so the `accept` rules in `inet vprlab forward` do not override Docker's drop. Unless a reviewed `DOCKER-USER` accept for `vprlab0 <-> <wan>` exists, the VM's WireGuard packets are dropped after the tap.

This is not runtime-verified, because nft and iptables listing was out of scope. It is Docker's documented default behaviour. Docker ≥ 28 only skips it with `ip-forward-no-drop`.

**Effect.**
- The tunnel never completes a handshake.
- The router may sit in kill-switch mode.
- The tap shows only outbound handshake initiations, so the result is PASS.
- That PASS is accurate about what the VM emitted, but the leak-relevant conditions (tunnel up, reconnect, DNS through the tunnel) were never exercised.
- The report cannot tell the difference. `allowed_counts` is per label, with no out/in split. Reproduced: inbound-only and outbound-only captures both give `{"mullvad-wg": 1}`.

**Doc gap.** The doc's topology says "forward: accept only vprlab0 <-> WAN" without this caveat.

**Fix:**
- Report `allowed_counts` per label and direction, for example `{"mullvad-wg": {"out": n, "in": m}}`, so M2 can require `in > 0` for tunnel-up phases.
- Document that another table's FORWARD drop (Docker on debdev) still applies, and that the operator must add and review a scoped `DOCKER-USER` accept for `vprlab0 <-> <wan>`, or must verify forwarding end-to-end before a phase.
- Optionally have the preflight read `nft -j list ruleset` and flag any FORWARD base chain with `policy drop`.

---

## Minor

**M-1. The ARP doc claims are stronger than the code.** (`pcapscan.py:443-447` vs doc `:309-311`)

`gateway_to_vm` constrains only the sender *IP*: no gateway MAC is declared, and the sender MAC may even be the VM's own. The doc says a "VM claiming another IP (including the gateway)" and a "foreign MAC claiming the … gateway IP" are `arp_not_allowed`. Both are reproduced as **PASS**:
- `arp(2, VM_MAC, GW_IP, VM_MAC, VM_IP)` (VM claims the gateway IP);
- `arp(1, VM_MAC, GW_IP, 0, VM_IP)` (same, as a request);
- `arp(2, 02:00:00:00:00:01, GW_IP, VM_MAC, VM_IP)` (foreign MAC claims the gateway IP).

The ARP target MAC is also unconstrained for requests, which leaves 6 free bytes per frame, and the Ethernet destination is never checked. None of this leaves the port-less bridge, so it is not a WAN leak.

Fix: require `sender_mac != vm_wan_mac` in `gateway_to_vm` (or add an optional `gateway_mac` to the policy), and reword the doc.

**M-2. The relay allowlist accepts non-global addresses and port 53.** (`policy.py:309-319`)

Accepted:
- `192.168.1.1:53` (LAN resolver);
- `100.100.100.100:53` (Tailscale MagicDNS; tailscale is present on this host);
- `1.1.1.1:53`.

Each, if ever put into a policy, silently whitelists a DNS leak. The doc warns that an over-broad policy is an evidence defect, but the loader could reject `not ipaddress.ip_address(x).is_global` (Mullvad relays are global) and well-known service ports (53, 853, 123, 67/68, 5353), with an explicit, logged override.

**M-3. The stats parser drops tcpdump's one-line SIGUSR1 summary, and the banner is unbound.** (`pcapscan.py:170-182`)

`tcpdump: 2 packets captured, 5 packets received by filter, 3 packets dropped by kernel` is neither matched nor flagged. This is harmless in reality, because libpcap's drop counters are cumulative and the final summary carries them. My synthetic "drops in SIGUSR1 line, final 0" case PASSes, but that state cannot occur.

The `listening on <iface>, link-type …, snapshot length …` banner is not checked either: a stats file naming `eth0` PASSes. The controls already bind the capture to the VM, but a cheap check would be to require exactly one banner naming `vprlab-tap0` and EN10MB, and to treat a `tcpdump: N packets captured,` line with a nonzero drop as `packet_drops`.

Separately, nothing binds the capture *command*. A BPF filter such as `udp` on the tcpdump line would hide TCP/ICMP/IPv6 leaks while the controls and the count still agree. M2 should generate the exact command and record its argv in the evidence.

**M-4. The preflight reads only the main routing table.** (`netplan.py:261-280`, doc `:383-398`)

`ip -j route` omits policy tables. With tailscale on this host, table 52 is consulted at rule 5270, before main, so a subnet route there (`--accept-routes`) could shadow `10.250.0.0/24` without the preflight noticing. The forward chain's `oifname != wan drop` contains the result: the lab breaks rather than leaking. Use `ip -j route show table all` together with `ip -j rule`.

**M-5. Inbound ICMP errors from the WAN path are a false LEAK.**

The host forwards conntrack-RELATED ICMP, for example frag-needed from a PPPoE hop for 1500-byte WireGuard packets, back to the VM, and the scanner reports `icmp_not_allowed`. This fails safe but will look like a leak. Document setting the VM WAN MTU or WireGuard MTU below the path MTU, and tell operators to read the `src` of any `icmp_not_allowed` finding before assuming a router fault.

**M-6. The `allow_arp:false` doc is incomplete.** (doc `:113-117`, `:312-313`)

A static neighbour for the gateway inside the VM is not enough. The host must also hold a static neighbour for the VM, otherwise it ARPs for `10.250.0.2` whenever it forwards inbound WireGuard, and that frame is `arp_not_allowed`.

**M-7. Plan shell hygiene.** (`netplan.py:115`, `:160-184`)

`set -eu` in section 1, if pasted into an interactive root shell, stays active, so any later failing command closes that shell. In teardown, a failing `ip link del` aborts the remaining steps despite the "idempotent per object" claim. Put each section in a `( … )` subshell, or use `|| echo …` per object in teardown.

---

## 3. Host-safety review of the generated plan

- **Scope.** No `flush`, no global sysctl (ip_forward is only checked and printed), and no edit of another table. `nft create table` is exclusive and its comment is the ownership tag. Links are tagged with an alias and teardown greps the tag. Every IPv6 sysctl names a fixed lab interface.
- **Effect on Docker and other networks.** Every drop is scoped to `iifname/oifname "vprlab0"`, and masquerade is scoped to source /24 + `iifname vprlab0` + WAN. These rules cannot affect Docker bridges, `tailscale0` or host services. The `accept` rules in `inet vprlab` cannot weaken another table's drops (netfilter needs acceptance from every base chain). The reverse direction, Docker breaking the lab, is I-2.
- **Control sink with no ICMP unreachable.** A UDP datagram to `10.250.0.1:39001` arriving on `vprlab0` passes prerouting, is routed locally, and hits `NF_INET_LOCAL_IN`. The `inet vprlab input` chain (priority filter) drops it there, before `udp_rcv()`/`__udp4_lib_rcv()` could call `icmp_send(ICMP_PORT_UNREACH)`.
  - Same-priority ordering against another table's input chain is undefined, so a host firewall chain could `reject` first. Even then, the generated ICMP leaves through `ip_local_out` → `NF_INET_LOCAL_OUT`, where `output oifname "vprlab0" meta nfproto ipv4 drop` discards it.
  - The output chain also suppresses ICMP generated on the forwarding path (frag-needed, TTL exceeded, unreachable) and host IGMP/mDNS/LLMNR.
  - ARP is not in the `inet` family, so gateway ARP keeps working, and IPv6 is disabled on both links before they come up.
  - Conclusion: the plan prevents the ICMP unreachable, with a second layer of protection. Not runtime-verified (no nft/VM per scope).
- **`iifname` in postrouting.** For forwarded packets `ip_output()` passes `skb->dev` (the input device) to `NF_INET_POST_ROUTING`, so `iifname "vprlab0"` matches. Not runtime-verified.

## 4. Doc vs code

All claims match the code except:
- the ARP spoof claims at `:309-311` (M-1);
- the topology/forward claim at `:25` and `:354-355`, which omits that other tables' FORWARD policies still apply (I-2);
- the `allow_arp:false` guidance at `:113-117` (M-6);
- the operational sequence at `:182-188`, which does not mention that the window rule needs a quiet tunnel at both edges (I-1).

Verified as matching:
- verdict precedence `:211-216`;
- the invalid-reason list `:218-230`;
- the stats rules `:250-269`;
- malformed-vs-structural `:232-236`;
- the fragment rules `:317-335`;
- the trailer rule `:291-294`;
- the policy loader rules `:86-119`;
- the plan contents `:339-359`;
- the preflight rejections `:394-400`;
- CLI exit codes `:427`;
- "no escape hatch" `:492-495`;
- the `control.py` freshness rules `:148-161`.

## Reproducer index (run; scratch deleted)

| ID | Input | Observed |
|---|---|---|
| I-1 | `[wg, ctlA, wg, ctlB]`; `[ctlA, wg, ctlB, wg_in]`; ARP before ctlA; NUD probe after ctlB | INVALID `outside_control_window` (each) |
| I-2 | `scan_middle([wg_inbound()])` vs `scan_middle([wg_outbound()])` | both `allowed_counts={"mullvad-wg":1}`; no direction split |
| M-1 | `arp_frame(2, VM_MAC, GW_IP, VM_MAC, VM_IP)`, foreign-MAC variant | PASS, `arp:1` |
| M-2 | policy relay `192.168.1.1:53`, `100.100.100.100:53`, `1.1.1.1:53` | accepted |
| M-3 | banner naming `eth0`; SIGUSR1 one-liner with drops | PASS; one-liner ignored |
| M-5 | inbound ICMP 3/4 from `203.0.113.1` to the VM | LEAK `icmp_not_allowed` |
