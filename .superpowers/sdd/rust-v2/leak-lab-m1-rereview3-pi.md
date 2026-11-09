# leak-lab M1 — third independent adversarial re-review (pi)

- **Reviewed commit:** `b0c06f8` ("fix(leak-lab): round 2 — unread-tail check,
  directional tunnel evidence, Docker forward exceptions, safe teardown").
  The working tree later advanced to `e1a6601` (M2 VM provisioner); that commit
  adds only `tools/leak-lab/vm/` and `docs/rust-v2/leak-lab-vm.md`. Every file
  reviewed here is byte-identical to `b0c06f8`
  (`git diff --stat b0c06f8 e1a6601 -- <reviewed files>` is empty).
- **Scope:** `tools/leak-lab/{pcapscan,policy,netplan,control,tsnames}.py`,
  `policy.schema.json`, `test_leak_lab.py`, `docs/rust-v2/leak-lab.md`.
  `tools/leak-lab/vm/` and `docs/rust-v2/leak-lab-vm.md` were ignored.
- **Test command/result:**
  `python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py`
  → `Ran 209 tests in 0.399s` / `OK` (209 passed, 0 failed/skipped).
- **Constraints honoured:** no sudo, no VM, no network, no `nft`/`ip`/`iptables`
  execution, no repository changes other than this review. All probes only built
  bytes and inspected generated text. Scratch `/var/tmp/leaklab-rr3-pi` was used
  and deleted.
- **Prior art:** round‑1 `leak-lab-m1-review-*.md`; round‑2
  `leak-lab-m1-rereview-{gpt,opus,pi}.md` (all FAIL).

---

## Verdict

**FAIL — 0 Critical, 1 Important, 7 Minor.**

Every round‑2 Critical/Important reproducer now fails closed (table below), and
the changed window, ARP, argv and tunnel-count logic survived a large
adversarial battery. One Important defect remains in the exact rule round 2
added: `pcapscan` recognises tcpdump's one-line summary but discards its
`captured` and `received by filter` values. A stats file that reports
`100 packets received by filter`, `4 packets captured`, `0 packets dropped by
kernel` in that line yields **PASS / exit 0**, including under
`--expect-tunnel up`, while the report shows the (agreeing) multi-line counters
and no trace of the contradiction. That is the same evidence class as the
round‑2 `unread_capture_tail` fix, and it contradicts the documented "every
occurrence of every counter is parsed" / "received must equal captured" rules.

The seven Minor findings are evidence/lifecycle gaps, not hidden leaks: a
VM-forgeable inbound "tunnel up" packet, an in-window-only fragment finalizer,
a second foreign banner, teardown run-binding/duplicate-rule residuals, the
ephemeral bridge MAC vs mandatory `gateway_mac`, the library's permissive
`expect_tunnel="any"` default, and a traceback on non-UTF‑8 preflight input.

---

## Round‑2 closure audit (all reproducers re-run)

| Round‑2 finding | Re-run result | Status |
|---|---|---|
| **gpt I1 / pi C1 (C1 class)** — excess `received` permits completeness PASS | multi-line `3 captured / 100 received / 0 drops` → **INVALID**, `unread_capture_tail`; `received=2` → INVALID; `captured=4` vs 3 records → INVALID `stats_packet_count_mismatch` | fixed for multi-line; **one-line bypass, I‑1 below** |
| **gpt I2** — expired/replaced incomplete fragment erased | `times=[100,101,132,133,134]`, `[A, first, first, last, B]` → **LEAK**, `incomplete_fragment` (`datagram_not_completed`) | fixed |
| **gpt I3 / pi M1** — VM/foreign MAC claiming gateway IP accepted | VM MAC claim (op 1 and 2), foreign MAC reply → **LEAK** `arp_not_allowed`; the legitimate pair and gateway request still **PASS**; `allowed_counts.arp` directional | fixed |
| **gpt I4** — substring teardown ownership | teardown has no `grep`; embedded checker returns 0 only for exact table `comment`; a rule comment elsewhere → 1; alias `NOT-OWNED-<tag>-backup` → 1; exact owned link → 0 | fixed (run-binding residual M4) |
| **gpt I5** — firewall removed before isolating tap | order: `tap down` < `tap nomaster` < `iptables -D` < `nft delete table` < `ip link del` | fixed |
| **gpt I6** — cold-neighbour ARP before before-control → INVALID | `[req, rep, A, wg_out, B]` → **PASS**, `outside_window_allowed=2`, `outside_window_allowed_packets=[0,1]` | fixed |
| **opus I‑1 / pi M5** — keepalive outside the marker window → INVALID | `[wg_out, A, wg_out, wg_in, B]`, `--expect-tunnel up` → **PASS**, `outside_window_allowed=1`; out-of-window **leak** still LEAK | fixed |
| **opus I‑2 / pi M2** — Docker FORWARD DROP blackholes lab WAN; report can't tell direction | two scoped, tagged `DOCKER-USER` inserts with byte-identical `-D`; `allowed_counts` split by direction; `up` gate; preflight Docker check | fixed statically; see M1 for the forgeable inbound nuance |
| **pi M1** — ARP doc promise vs code | see gpt I3 | fixed |
| **pi M2** — plan's forward accept can't override FORWARD DROP | scoped `DOCKER-USER` accepts present, tagged, exact removal | fixed |
| **pi M3** — `gateway_ipv4` not tied to the bridge | `gateway_ipv4: 10.250.0.9` → `PolicyError`; sink must equal gateway | fixed |
| **pi M4** — documented `control.py --pair` fails on fresh tree | fresh `used.txt`: rc 0, file created mode `0600`, two distinct nonces printed | fixed |
| **pi M5** — keepalives outside markers | see opus I‑1 | fixed |
| **pi M6** — PASS with no allowed flow | controls-only + `up` → **INVALID**, `tunnel_not_observed`; controls-only + `any` → PASS (documented) | fixed for `up` |

No round‑2 Critical or Important finding is still reproducible in its original
multi-line/window form. The new hole is a bypass of the same rule, not a
regression of the previous multiple-line parser.

---

## Important

### I‑1 — The one-line summary's `captured`/`received` are discarded, so an unread-tail PASS survives

**Files:**
`tools/leak-lab/pcapscan.py:105-110` (the `_STATS_ONELINE_RE` definition),
`:207-210` (the branch reads only `one_line.group(3)` and `continue`s),
`:237-238` (`stats["received"] != stats["captured"]` is computed only from the
multi-line values);
`tools/leak-lab/test_leak_lab.py:602-617` (the only one-line tests: a nonzero
kernel drop, and a 3/3/0 line — never a disagreeing captured/received);
`docs/rust-v2/leak-lab.md:13-15`, `:353-357`, `:368-369`, `:666-667`.

**Reproducer (API, `python3 -B -W error`):**

```python
import sys
sys.path.insert(0, "tools/leak-lab")
import test_leak_lab as T, pcapscan as S

A, B = T.NONCE_A, T.NONCE_B
frames = [T.control_frame(A), T.wg_outbound(), T.wg_inbound(), T.control_frame(B)]
stats = T.zero_stats(4) + (
    "tcpdump: 4 packets captured, 100 packets received by filter, "
    "0 packets dropped by kernel\n")

r = S.scan_capture(
    T.pcap(frames), T.make_policy(), A, B,
    tcpdump_stats_text=stats,
    capture_argv=T.CAPTURE_ARGV,
    expect_tunnel="up",
)
print(r["verdict"], r["capture_meta"]["invalid_reasons"],
      r["capture_meta"]["stats"], r["capture_meta"]["tunnel_expectation"])
# => PASS [] {'captured': 4, 'received': 4, ...} {... 'satisfied': True ...}
```

Observed: `verdict=PASS`, `findings_total=0`, `invalid_reasons=[]`,
`stats={"captured":4,"received":4,"dropped_kernel":0,"dropped_interface":0}`,
`tunnel_expectation.satisfied=true`. The same input through the CLI
(`pcapscan.py --expect-tunnel up ...`) returns **exit 0 / PASS**. The variant
`tcpdump: 100 packets captured, 100 packets received by filter, 0 packets
dropped by kernel` appended to a valid `4/4/0` multi-line is also **PASS**,
even though 100 records were never written; the one-line's `captured` is
discarded exactly like its `received`.

**Why it matters.** The one-line is a recognised, documented summary format
(the docs call it "tcpdump's one-line SIGUSR1 summary"). The parser's own
contract is all-or-nothing: "every occurrence of every counter is parsed",
"the same counter reported with different values is `stats_contradictory`",
"`captured` must equal the number of complete pcap records", and "`received by
filter` must equal `captured` exactly, otherwise `unread_capture_tail`"
(`pcapscan.py:169-190`, `docs/rust-v2/leak-lab.md:340-370`). The document's
"Explicit limits" repeats that "any nonzero tcpdump drop counter, a
captured-count mismatch, or an unread ring tail invalidates the capture"
(`:666-667`). The one-line path violates all of these: the report silently
shows only the multi-line counters, so an operator reading
`capture_meta.stats` cannot see that the file also claimed an unread tail.

**Why Important, not Critical.** In one genuine tcpdump run the counters are
cumulative, so a mid-run SIGUSR1 one-line can only be smaller than the final
multi-line summary; `received > captured` at that instant is normal. The
reproducer's impossible ordering therefore requires a spliced/stale/forged
stats file (the capture host is trusted), not a live ring tail. It is the same
evidence-integrity defect the round‑2 I1/C1 fix was meant to close, and the
tool explicitly says it rejects "concatenated or stale summaries".

**Suggested fix.** Track the one-line values separately and reject any one-line
counter that exceeds the final multi-line value (a genuine mid-run status line
must be ≤ the final cumulative summary); if the one-line is the last summary,
apply `captured == records` and `received == captured` to it as well. Add tests
for (a) one-line `received > final received`, (b) one-line `captured >
records`, (c) a legitimate mid-run one-line with smaller values (must not be
`stats_contradictory`).

---

## Minor

### M1 — `--expect-tunnel up` inbound evidence is forgeable by the VM (L2 is ignored)

**Files:** `tools/leak-lab/pcapscan.py:949-956` (inbound label is selected only
by `(src, src_port)`), `:1250-1256` and `:1273-1274` (window counts and `up`);
docs `:296-298` ("prevents 'the tunnel never came up' from being reported as a
clean phase") vs `:676-678` ("cannot ... prove that the tunnel carried real
traffic").

**Reproducer:** the VM emits one frame with Ethernet src `VM_MAC`, IP src
`185.65.134.10` (the declared relay), IP dst `10.250.0.2`, UDP src port 51820:

```python
forged = T.ipv4_frame(T.udp_segment(T.WG_PORT, 40000, b"forged"),
                      src_ip=T.WG_IP, dst_ip=T.VM_IP,
                      src_mac=T.VM_MAC, dst_mac=T.GW_MAC)
frames = [T.control_frame(A), T.wg_outbound(), forged, T.control_frame(B)]
r = S.scan_capture(T.pcap(frames), T.make_policy(), A, B,
                   tcpdump_stats_text=T.zero_stats(4),
                   capture_argv=T.CAPTURE_ARGV, expect_tunnel="up")
# => PASS, outbound_in_window=1, inbound_in_window=1
```

Even a foreign Ethernet src MAC is accepted (`02:00:00:00:00:09` → PASS). The
frame is on the tap and the host will drop it later, but the monitor has
already counted it. The Ethernet/ARP layer has the observable identity
(`gateway_mac`, the VM MAC); the ARP branch rejects exactly this
"contradictory identity", while IPv4 does not. **Impact:** a phase can claim
the tunnel was exercised with two frames the VM emitted; no leak is hidden
(any non-allowed frame is still a finding), and the docs' limit already says
the monitor cannot prove real traffic, but the `up` doc sentence overstates.
A minimal check (`src_mac != vm_wan_mac` for inbound allowed flows, ideally
`src_mac == gateway_mac && dst_mac == vm_wan_mac`) closes the trivial case; a
MAC-spoofing VM remains indistinguishable and should stay documented.

### M2 — Fragment finalisation judges only first fragments inside the window, docs say any incomplete datagram is a finding

**Files:** `tools/leak-lab/pcapscan.py:829-865` (`finalize_fragments` returns
early and skips states outside the control window); docs
`docs/rust-v2/leak-lab.md:460-463` ("a datagram that never completes by the end
of a structurally complete capture is also `fragment_incomplete`").

**Reproducer:** `[first_fragment, A, wg_outbound, wg_inbound, B]`, no final
fragment, structurally complete pcap, `--expect-tunnel up` → **PASS**,
`findings_total=0`, `outside_window_allowed=1`. The same datagram wholly inside
the window → LEAK `fragment_incomplete`. The code docstring discloses the
window restriction; the user-facing fragment section does not. It is an
allowed-endpoint datagram either way, so this is evidence hygiene, not a
missed leak. Either document the restriction in the fragment section or
finalise every allowed state (the verdict is already non-PASS if the capture is
invalid).

### M3 — The banner check accepts a valid banner plus a second foreign banner

**Files:** `tools/leak-lab/pcapscan.py:1199-1205`
(`count(REQUIRED_STATS_BANNER) == 1`); docs `:349-351` ("a concatenated/
duplicated banner is not this plan's capture").

**Reproducer:** `zero_stats(3) + "tcpdump: listening on eth0, link-type EN10MB
(Ethernet), snapshot length 262144 bytes\n"` with a valid 3-record pcap →
**PASS**, `stats_banner_ok=true`, `invalid_reasons=[]`. Only a *second copy of
the required* banner is rejected. A concatenated file whose second banner names
another interface but whose counters happen to match is accepted. Low
realism (the counters usually contradict), but the check is narrower than the
documented rule. Reject any additional `listening on` line that is not the
required one.

### M4 — Teardown ownership is exact but not bound to this setup; duplicate `DOCKER-USER` rules are not removed exactly

**Files:** `tools/leak-lab/netplan.py:164-180` (exact table comment / link
alias checks), `:246-247` (one `-D` per spec); docs `:508-519` ("teardown can
never claim a resource that setup did not create under a passing preflight").

The substring defect is fixed. Two residuals remain:

1. `./lab.sh teardown` deletes any link/table carrying the exact fixed tag
   `vprlab-leak-lab-m1`, regardless of whether *this* setup created it (a prior
   run or another tool using the same tag). The docs' "under a passing
   preflight" qualifier does not hold for the documented "after a failed setup"
   path. A per-run tag/record would bind it; the fixed tag alone does not.
2. If a run's links and `inet vprlab` table are removed without the two
   `DOCKER-USER` rules (manual cleanup, or a teardown whose `-D` failed while
   the table delete succeeded), the next setup passes the preflight, inserts a
   second pair, and the next teardown's two `-D` calls remove only one pair.
   The stale pair is still lab-scoped (`-i/-o vprlab0` + 10.250.0.0/24), so it
   cannot admit non-lab traffic, but it contradicts "removed exactly" and
   leaves state behind. A pre-setup check for the tagged rules (or a `-D` loop
   until absent) would close it.

Neither path produces a false PASS: the monitor still sees every tap frame.

### M5 — `vprlab0` gets a random MAC, but `gateway_mac` is mandatory; docs do not say to regenerate the policy per setup

**Files:** `tools/leak-lab/netplan.py:292` (`ip link add vprlab0 type bridge`,
no address), `tools/leak-lab/policy.py:354-363` (`gateway_mac` required when
`allow_arp`), docs `:118-123` ("read it with `ip link show vprlab0`").

A bridge created without `address` gets a kernel-generated MAC, so every new
setup changes `gateway_mac`. A policy reused across runs (as the docs' fixed
example suggests) makes the real gateway's ARP reply `arp_not_allowed` → LEAK.
This fails closed, but it is a repeat-run trap that the round‑2 MAC binding
introduced. Either pin the bridge MAC in the plan (or derive it from the
policy/tag) or state in the `gateway_mac` bullet that the value must be
re-read after every bridge creation.

### M6 — The library default for `expect_tunnel` is the permissive `"any"`

**Files:** `tools/leak-lab/pcapscan.py:1150`
(`expect_tunnel: str = "any"`); docs `:11-17` ("A capture must supply ... an
explicit `--expect-tunnel up|down|any` phase expectation") and `:672-678`.

The CLI requires the flag, but `scan_capture` silently defaults to `"any"`, so
a library caller (for example an M2 runner) that omits it gets a PASS for a
controls-only or outbound-only capture. `stats`, both nonces and
`capture_argv` are mandatory in the API precisely because of earlier
fail-open findings; `expect_tunnel` is the odd one out. Make it a required
argument (the tests already pass it explicitly in the helpers) or default it to
a value that cannot PASS without evidence.

### M7 — Non-UTF‑8 preflight inventory crashes with a traceback instead of exit 2

**Files:** `tools/leak-lab/netplan.py:630-641` (`read_text(encoding="utf-8")`);
docs `:578-580` ("2 = unreadable/malformed input").

A binary/garbage `links.json` raises `UnicodeDecodeError`, which is not an
`OSError`/`NetplanError`, so `main` emits a traceback and exits 1. This fails
closed (no false OK), but violates the documented exit-code contract and is
easy to fix by catching `UnicodeError` alongside `OSError`.

---

## Host plan review (requested)

Generated with `python3 -B tools/leak-lab/netplan.py --wan-interface eno1`,
checked with `sh -n` (**OK**); never executed. No `nft`/`ip`/`iptables` was
run.

**`DOCKER-USER` correctness for iptables-nft on Debian 13 with Docker.** The
two inserts are correct in principle:

```
iptables -I DOCKER-USER -i vprlab0 -o eno1 -s 10.250.0.0/24 \
  -m comment --comment vprlab-owned -j ACCEPT
iptables -I DOCKER-USER -i eno1 -o vprlab0 -d 10.250.0.0/24 \
  -m conntrack --ctstate ESTABLISHED,RELATED \
  -m comment --comment vprlab-owned -j ACCEPT
```

Docker's `FORWARD` policy `DROP` lives in the `ip filter` base chain;
iptables-nft maps `-j ACCEPT` in the user-defined `DOCKER-USER` chain to an
`accept` verdict that terminates that base chain, so the policy drop does not
apply to the matched packet. `-I` places both rules before Docker's terminating
`RETURN`; the matches are scoped by bridge and WAN interface, source/destination
subnet and, inbound, conntrack state; nothing outside the lab pair matches. The
two `-D` lines are byte-identical to the `-I` lines except for `-I`→`-D`
(`netplan.py:161-162`, tests re-check this), so removal targets only these
rules. The rules are removed in 4b after 4a has brought the tap down and
detached it; the nft table is deleted in 4c; the links in 4d. New unsolicited
inbound is not accepted by the inbound rule (no `NEW`), so Docker still drops
it; that is correct for an egress-leak lab. The `inet vprlab` forward chain
accepts all lab↔WAN traffic (not only WireGuard), which is intentional: the tap
must see any leak.

**Isolation/ownership.** No `flush ruleset`, no `iptables -F`, no edit of any
table other than Docker's `DOCKER-USER` and the dedicated `inet vprlab` table.
The input chain silently drops all `iifname vprlab0` IPv4/IPv6; the output
chain drops host-originated IPv4 to the bridge; the forward chain drops
non-WAN forwarding and IPv6; the postrouting masquerade is scoped to
`ip saddr 10.250.0.0/24 iifname vprlab0 oifname <WAN>`. `sysctl -w` only touches
`net.ipv6.conf.vprlab{0,-tap0}.disable_ipv6`; `net.ipv4.ip_forward` is printed
as a check, never changed. `nft create` is exclusive and the table carries the
exact comment; teardown's embedded checks compare the table's structured
`comment` and the link's exact `ifname` + `alias`/`altnames` member, and
reject a rule comment elsewhere and a `NOT-OWNED-...` alias (independently
re-ran: owner 0/foreign 1). The teardown function is defined before setup and
reachable as `./lab.sh teardown`; every risky step is `||`-guarded.

**Residuals/limits.** M4 (no run binding; duplicate `DOCKER-USER` pair after a
manual link deletion), M5 (random bridge MAC). One assumption could not be
verified offline: teardown requires `nft -j list table inet vprlab` to expose
the table `comment` field. The man page confirms the table-comment syntax
(`{"add"|"create"} table ... [comment ...]`), but the JSON field is not
inspectable without running `nft`. If libnftables omits it, the checker refuses
and leaves `inet vprlab` in place — fail-closed, but the "removed exactly"
claim would need re-verification on the real host.

---

## Docs vs code

1. **One-line stats (I‑1).** Docs `:13-15` ("`captured`/`received by filter`
   counters agree exactly with each other and with the pcap"), `:353`
   ("every occurrence of every counter is parsed"), `:368-369` (`received`
   must equal `captured`) and `:666-667` (an unread ring tail invalidates) are
   contradicted by `pcapscan.py:207-210`. The narrower one-line bullet
   `:355-357` (only a nonzero kernel drop) is the only place that hints at the
   omission; it should not coexist with the all-or-nothing claims.
2. **Fragment finalisation (M2).** Docs `:460-463` say any never-completing
   datagram is `fragment_incomplete`; code only judges first fragments with
   `before_ts < first_ts < after_ts`.
3. **Banner (M3).** Docs `:349-351` say a concatenated/duplicated banner is
   rejected; only a second copy of the required banner is.
4. **Teardown (M4).** Docs `:508-519` say teardown "can never claim a resource
   that setup did not create under a passing preflight"; the tag-based check
   deletes any exact-tag resource, and teardown is explicitly documented for
   the post-failed-setup path where no preflight guarantee exists.
5. **`gateway_mac` (M5).** The docs say to read the bridge MAC but not that
   the bridge MAC changes on every setup; a reused policy leaks (fails closed).
6. **`expect_tunnel` (M6).** The docs require an explicit expectation; the
   library default is `"any"`.
7. **`down` semantics (note).** Docs `:290-297` define `down` as "zero inbound
   allowed flows anywhere"; a capture containing only the two controls
   (`--expect-tunnel down`, 2 records) returns **PASS**. `down` therefore does
   not prove the tunnel is down, only that no inbound allowed flow was captured.
   The "completely silent VM" limit (`:668-671`) covers this, but the
   `tunnel_expectation` paragraph should say a `down` phase also needs an
   expected outbound attempt (or should require one) before it is phase
   evidence. Not a code bug.
8. **Schema.** `policy.schema.json` is weaker than the loader (documented). One
   description is wrong independently of that: `$defs.unicast_ipv4` claims to
   reject `0.0.0.0/8` but its `$ref` pattern accepts `0.1.2.3`; the binding
   loader rejects it (`policy.py:258-275`). Cosmetic for CI/editor users.
9. The `outside_window_allowed` wording is accurate: out-of-window ARP is
   counted (verified `[req, rep]` before A → 2), in-window ARP is not counted
   (verified 0), and out-of-window findings are still LEAK.

---

## Verified-good (adversarial checks that produced no false PASS)

- **stats:** multi-line `received`>captured and `received`<captured → INVALID
  `unread_capture_tail`; `captured`≠records → INVALID; nonzero kernel/interface
  drop in any summary → `packet_drops`; missing `captured`/`received`/kernel →
  `stats_incomplete`; conflicting multi-line counters → `stats_contradictory`;
  `pcap_loop`/`went down`/`permission denied` → `stats_error_line`; wrong
  interface/link type/missing/duplicated required banner → INVALID; a
  counter-shaped malformed line → `stats_unparseable`; empty stats → INVALID.
- **controls/window:** missing before/after → INVALID; equal nonces → ValueError
  (CLI exit 2); reversed timestamp order → `control_order`; replayed nonce →
  LEAK; unexpected control nonce/malformed control → LEAK; non-monotonic
  timestamps → INVALID; out-of-window leak → LEAK; out-of-window allowed flow →
  PASS with packet indexes; a leak at/before `before_ts` or after `after_ts` is
  still a LEAK.
- **tunnel:** `up` with out+in in-window → PASS; out-only or in-only → INVALID
  `tunnel_not_observed`; in-window out + out-of-window in → INVALID; ARP does
  not count (in-window or out); `down` sees an out-of-window inbound →
  INVALID; `down` with outbound only → PASS (documented); `any` reports only;
  unknown value → ValueError.
- **ARP:** VM MAC claiming the gateway IP (op 1 and 2) → LEAK; foreign MAC
  claiming the gateway/VM IP → LEAK; gateway MAC claiming the VM IP → LEAK;
  Ethernet/ARP sender mismatch → LEAK; unsupported htype/ptype/opcode →
  LEAK; legit VM→gateway request/reply and gateway→VM request/reply → PASS;
  `allow_arp:false` makes every ARP a finding.
- **capture provenance:** extra filter element, missing `-U`/`-nn`/
  `--immediate-mode`, changed `-s 0`, changed interface, empty/duplicate `-w`,
  non-list/empty-string argv → INVALID; only the `-w` path may differ (a path
  that looks like `udp port 53` is still only a filename). The `-w` value is
  never executed.
- **policy:** RFC1918/CGNAT/Tailscale/loopback/link-local/multicast/reserved/
  test-net destinations rejected; ports 53/853/123/5353/5355 rejected;
  `gateway_ipv4 != 10.250.0.1` rejected; `gateway_mac` required with
  `allow_arp`; `gateway_mac == vm_wan_mac` rejected; non-unicast/zero MAC
  rejected; sink must equal gateway; duplicate labels/endpoints and
  control-endpoint overlap rejected; `ipv6_allowed` must be literal `false`;
  duplicate JSON keys and non-finite numbers rejected; labels closed/regexed.
- **frames:** TCP/ICMP/other IP protocols, IPv6, IPv4 options, QinQ/unknown
  ethertypes, foreign frames, VM↔VM, trailers/nonzero padding, bad UDP/IP
  lengths, truncated headers, zero-payload fragments, overlaps/gaps/out-of-range
  fragments, stale/orphan/replaced/duplicated fragments, and a finding plus a
  drop all fail closed (LEAK or INVALID, never PASS).
- **host plan:** `sh -n` OK; no `flush`; no edit of another table/chain; only
  the two tagged `DOCKER-USER` rules; exact `-D` specs; teardown isolation
  order; structured ownership checks; `ip_forward` untouched; sysctls
  device-scoped; the preflight rejects an existing lab link/altname/table,
  address/route overlap (including policy tables), a missing/loopback/lab WAN
  interface, and a Docker FORWARD-DROP host without `DOCKER-USER`.
- **tests:** 209/209 pass under `-B -W error`; the suite exercises the
  round‑2 identifiers (gpt I1-I6, opus I-1/I-2, pi C1/M1-M6).

---

## Limits of this review

- No live VM, tap, tcpdump, nft, iptables or Docker state was exercised; the
  host-plan section is a static/command-semantics review, and the
  `DOCKER-USER` accept finality and the nft JSON table-comment field are
  reasoned, not observed. `nft`/`ip` execution was out of scope.
- The I‑1 reproducer requires a mixed-format stats file (a genuine mid-run
  SIGUSR1 line has counters ≤ the final summary). It is therefore an
  evidence-integrity defect, not a live unread-tail exploit.
- The M1 forgery is a deliberate VM action with no leak payload; a compromised
  VM can also spoof the gateway MAC, which no endpoint-only monitor can
  distinguish (documented).
- M2/M3/M4/M5/M7 are fail-closed or report-only; they do not hide a WAN leak.
- Scratch `/var/tmp/leaklab-rr3-pi` was removed after the run; no repository
  file other than this review was written.
