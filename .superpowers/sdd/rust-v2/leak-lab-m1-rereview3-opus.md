# Leak-lab M1 re-review, round 3 (adversarial, Opus), 2026-11-09

## Scope and method

**Commit:** `b0c06f8`.

**Files reviewed:**
- `tools/leak-lab/{pcapscan,policy,netplan,control,tsnames}.py`
- `policy.schema.json`
- `test_leak_lab.py`
- `docs/rust-v2/leak-lab.md`

Out of scope, as instructed: `tools/leak-lab/vm/` and `docs/rust-v2/leak-lab-vm.md`.

**Method:**
- Read all files in scope and the three round-2 reports (`leak-lab-m1-rereview-{opus,gpt,pi}.md`).
- Re-ran every round-2 Critical/Important reproducer, and most Minor ones, against the new API.
- Ran about 30 new attack probes on the changed logic.
- Statically checked the generated host script:
  - extracted its embedded ownership checkers and fed them iproute2/nft JSON in its real shape;
  - checked the order of setup and teardown steps;
  - ran `sh -n` on it.
- Ran one dash signal experiment: a harmless script whose Python child catches SIGINT, with no network.

**Limits:**
- Scratch work lived in `/var/tmp/leaklab-rr3-opus` and was deleted afterwards.
- No sudo, VM, network, `nft`, `ip` or `iptables` command was run.
- Host facts were read only from package metadata, `strings` on `/usr/bin/ip` and libnftables, the AppArmor profile, and `getent`.
- Installed versions: docker-ce 29.7.2, iptables 1.8.11 (`iptables` → `iptables-nft`), nftables 1.1.3, iproute2 6.15.0, tcpdump 4.99.5, libpcap 1.10.5, Python 3.13.5.

**Suite:** `python3 -B -W error -m unittest tools/leak-lab/test_leak_lab.py`: **Ran 209 tests, OK** (0 failures, 0 errors, 0 skipped).

## Verdict: **FAIL**: 0 Critical, 1 Important, 8 Minor

**Scanner (pcapscan/policy):**
- Every round-2 Critical and Important finding is fixed in the scanner and policy, and each reproducer now behaves as intended (§1).
- I found **no new false-PASS path that hides a leak.** Findings are classified no matter where they fall in the window, so an out-of-window or non-monotonic leak is still `LEAK`.
- `received == captured` closes the unread-ring-tail gap.
- Neither ARP nor controls can satisfy `--expect-tunnel up`.

**Host plan (netplan) — one Important defect:**
- **I-1:** the new "exact structured" link-ownership check reads a JSON key that iproute2 does not emit.
- As a result, the generated teardown never deletes `vprlab0` or `vprlab-tap0` on this host.
- The unit tests pass only because their fixtures use the same wrong key.
- It fails closed: no exposure and no leak. But the plan does not remove what it created, which the brief's item (3) requires.

---

## 1. Round-2 findings: reproducers re-run

| Round-2 ID | Reproducer | Now |
|---|---|---|
| pi C1, gpt I1 (received ≠ captured) | `received=100, captured=3` | INVALID `unread_capture_tail` ✔. `received=2 < captured=3` is also INVALID ✔ |
| opus I-1, gpt I6, pi m5 (window flake) | keepalive before A; reply after B; cold ARP req/rep before A; NUD probe after B | each is PASS, with `outside_window_allowed` = 1, 1, 2, 1 ✔ |
| opus I-2, pi m2 (no tunnel evidence) | `--expect-tunnel up` with outbound only, or inbound only | INVALID `tunnel_not_observed` ✔ |
| | `up` with both directions | PASS ✔ |
| | `down` with an inbound packet after B | INVALID ✔ |
| | `allowed_counts` | split into `outbound`/`inbound` ✔ |
| | docs | Docker caveat added; preflight reads `iptables-save` ✔ |
| gpt I2 (fragment state replaced) | `[A, first, first, last, B]` at ts 100/101/132/133/134 | LEAK `incomplete_fragment` ✔ |
| gpt I3, opus M-1, pi m1 (ARP gateway claims) | VM MAC claims GW IP (op 1 and op 2); foreign MAC claims GW IP | LEAK `arp_not_allowed` ✔ |
| | `allow_arp:true` without `gateway_mac` | rejected ✔ |
| | `gateway_mac == vm_wan_mac` | rejected ✔ |
| gpt I4 (substring ownership) | NOT-OWNED alias; a rule comment carrying the tag | refused ✔. **But the real `ifalias` key is also refused: new I-1** |
| gpt I5 (teardown removes protection first) | teardown order | tap `down`+`nomaster` → `DOCKER-USER -D` → `nft delete` → links ✔ (residual in M-4) |
| gpt M1 (timestamp order) | `[B, wg, A]` at ts 103/102/101; `[A, B, wg]` at 101/103/102 | INVALID `non_monotonic_timestamps` ✔ |
| gpt M2 (zero-payload fragments) | empty last fragment; empty middle fragment; MF first with `udp_len == payload` | LEAK `zero_payload_fragment` / `malformed_frame` ✔ |
| gpt M3, opus M-4 (route coverage) | plan collects `ip -j route show table all`; an entry without `dst` raises | ✔ |
| gpt M4, pi m3 (gateway address) | `gateway_ipv4 = 10.250.0.9` | rejected; it must be `10.250.0.1` ✔ |
| opus M-2 (relay allowlist) | `192.168.1.1:53`, `100.100.100.100:51820`, `1.1.1.1:53`, `185.65.134.10:123` | all rejected (non-public address or prohibited port) ✔ |
| | labels `arp` and `positive-control` | reserved and rejected ✔ |
| opus M-3 (banner, SIGUSR1 line, argv) | banner naming `eth0` | INVALID `capture_banner_mismatch` ✔ |
| | SIGUSR1 one-liner with drops | `packet_drops` ✔ |
| | argv with an extra `udp` filter, or `-s 96` | `capture_argv_mismatch` ✔ |
| opus M-5 (inbound ICMP) | | documented as an intentional LEAK (doc `:617-628`) ✔ |
| opus M-6 (static neighbours) | | both sides documented (doc `:242-257`) ✔ |
| opus M-7 (shell hygiene) | | standalone-script framing; teardown steps use `|| echo` ✔ |
| pi m4 (fresh `used.txt`) | | `control.py --pair` on a missing file creates it with mode 600 and prints both commands ✔ |
| pi m6 (PASS with no allowed flow) | controls only, with `up` | INVALID ✔ (residual in M-6: the API default) |

## 2. New false-PASS hunt (no leak can be hidden)

| Probe | Result | Assessment |
|---|---|---|
| DNS leak before A or after B | LEAK | outside-window does not excuse findings ✔ |
| Non-monotonic timestamps plus DNS | LEAK, with `non_monotonic_timestamps` also listed | ✔ |
| All timestamps equal | INVALID `control_order` | ✔ |
| WG packet with `ts == ts(before)` under `up` | not counted in the window, so INVALID | conservative ✔ |
| `up` with only ARP both ways, or only the controls | INVALID | ARP is excluded from `window_counts`; `arp` cannot be a flow label; controls never reach `count_allowed` ✔ |
| Banner twice | INVALID | ✔ |
| Allowed first fragment before A, last fragment inside the window | PASS | same 4-tuple, destination pinned to the relay ✔ |
| Allowed first fragment outside the window that never completes | **PASS** | not a leak; doc mismatch → M-3 |
| VM-emitted inbound-shaped frame (src MAC = VM) under `up` | **PASS** | tunnel evidence forgeable → M-2 |
| VLAN-tagged inbound under `up` | **PASS** | → M-2 |
| Outbound to relay A plus inbound from relay B under `up` | **PASS** | → M-2 |
| `scan_capture()` with `expect_tunnel` omitted, controls only | PASS | → M-6 |
| argv with `-w /dev/null` or `-w -` | PASS | → M-7 |
| VM ARP request with an arbitrary target MAC and Ethernet destination | PASS | L2-only; the host never forwards ARP (nit) |

**Why `received == captured` is sound here:**
- On Linux TPACKET_V3, `ps_recv` is `tp_packets`, and the kernel adds `tp_drops` to it.
- With zero drops, any excess over `captured` can only be unread ring entries.
- An unlucky packet arriving between `breakloop` and `pcap_stats` gives a false INVALID, never a false PASS.

## Important

### I-1. The teardown link-ownership check reads `alias`; iproute2 JSON emits `ifalias`, so the links are never deleted

**Locations:**
- `tools/leak-lab/netplan.py:185`: `entries[0].get("alias") == "<tag>"`, used at `:263` and `:273`;
- the tests encode the same wrong shape: `test_leak_lab.py:2107` and `:2116` (`{"ifname": ..., "alias": ...}`), and the assertion at `:2041`;
- the docs claim exact link `alias` ownership at `docs/rust-v2/leak-lab.md:511-515`.

**Evidence.**
- iproute2 prints the interface alias with `print_string(PRINT_ANY, "ifalias", "%s    alias %s", ...)`. The JSON key is `ifalias`; `alias` is only the text-mode label.
- `strings /usr/bin/ip` (iproute2 6.15.0) shows `alias %s` next to `ifalias` and no bare `alias` key. `ip` itself was not run, per the brief.
- Reproduced with the checker extracted verbatim from the plan:

```
link check, test-fixture key 'alias'   -> 0   (would delete)
link check, real iproute2 key 'ifalias' -> 1   (refuses)
nft check, table "comment" present      -> 0   (table path OK; libnftables emits table comments)
```

**Effect on the real host.**
- `./lab.sh teardown`, or the teardown at the end of the script:
  - isolates the tap;
  - removes the `DOCKER-USER` rules and `inet vprlab`;
  - then prints "refusing to delete vprlab-tap0/vprlab0 (exact ownership alias absent)".
- The bridge stays up with `10.250.0.1/24` and its connected route, and the persistent tap remains.
- The next preflight then reports `link vprlab0 already exists`. The operator has to delete the links by hand, outside the reviewed script — exactly the unreviewed manual cleanup the ownership design was meant to remove.
- There is no exposure: the tap is down and detached.
- But the plan does not remove what it created, and the tests that "prove" exact ownership are built on a schema the tool never sees.

**Fix:**
- Compare `entries[0].get("ifalias")`.
- Optionally also require `linkinfo.info_kind` to be `tun` with `info_data.type == "tap"` for the tap, and `bridge` for the bridge.
- Replace the test fixtures with a captured, real-shape `ip -j -d link show` document, including `ifalias` and `linkinfo`.
- Keep the negative cases: a `NOT-OWNED-…` alias, a wrong ifname, and an `alias`-only object, which must refuse.

## Minor

**M-1. Ctrl-C at the capture step kills the script before its automatic teardown.**
- Locations: `netplan.py:340-346` (the comment "send SIGINT (Ctrl-C)", then `do_teardown`); doc `:233`.
- Mechanism: Debian `/bin/sh` is dash. A terminal Ctrl-C delivers SIGINT to the whole foreground process group. dash defers it while it waits for tcpdump, then `onint()` re-raises SIGINT on itself.
- Reproduced: a script with the same `set -eu; child || echo; echo AFTER; do_teardown` shape, where the child catches SIGINT and exits 0, ended with status −2 and printed neither `AFTER` nor `TEARDOWN-RAN`.
- Effect: the lab is left up, which fails safe, and nothing tells the operator that teardown did not run.
- Fix (either option):
  - run `trap : INT` before the capture line and `trap - INT` after it (the child still gets default SIGINT handling);
  - or document `kill -INT <tcpdump-pid>` from another shell.

**M-2. `--expect-tunnel up` accepts frames that cannot be real return traffic.**
- Locations: `pcapscan.py:615-618`, where direction comes from IP only; `:1273-1274`.
- Each of the following satisfies `up` (all PASS):
  - an inbound-shaped frame emitted by the VM, with src `relay:51820`, dst VM, and Ethernet source = VM MAC;
  - an 802.1Q-tagged inbound frame (the host never tags);
  - outbound to relay A plus inbound from relay B.
- A non-adversarial router cannot produce these, and none of them hides a leak.
- Now that `gateway_mac` is declared, the fix is cheap:
  - require untagged inbound frames with Ethernet source `gateway_mac` and destination `vm_wan_mac`, and outbound frames with source `vm_wan_mac`;
  - count `up` per label: both directions on the same relay.
- The doc's limits section (`:660-662`) still says IPv4 MACs are not distinguished.

**M-3. An out-of-window allowed fragment that never completes is PASS, which contradicts the doc.**
- Locations: `pcapscan.py:847-849` (`finalize_fragments` judges only in-window first fragments); doc `:463-464` ("a datagram that never completes by the end of a structurally complete capture is also `fragment_incomplete`").
- Reproduced: `[A, wg, B, first()]` and `[first(), A, wg, B]` → PASS with `outside_window_allowed=1`.
- Before round 2, any out-of-window record made the capture INVALID, which covered this case. The window relaxation silently removed that coverage.
- This is not a leak, because the destination is pinned to the relay.
- Fix (either option): judge every incomplete allowed datagram at EOF, or scope the doc sentence to in-window datagrams.

**M-4. Teardown mutates the tap before any ownership check, and keeps going after an isolation failure.**
- Location: `netplan.py:237-247`.
- Step 4a runs `ip link set vprlab-tap0 down` and `nomaster`, and step 4b deletes the 10.250.0.2 neighbour on `vprlab0`. Both run unconditionally, before the ownership checks in 4d.
- The documented use, "run teardown after a failed setup", is exactly the case where a same-name foreign link may exist (setup failed at `ip tuntap add`). So this contradicts doc `:516-519`.
- If 4a fails, 4c still deletes the DROP table, which the round-2 gpt I5 remedy said to avoid.
- The neighbour IP is hard-coded instead of taken from the policy.
- Fix:
  - check ownership first;
  - skip 4c when 4a failed;
  - take the VM IP from the policy or a flag.

**M-5. Setup opens forwarding before the host protections exist.**
- Location: `netplan.py:290-331`.
- The links come up with `10.250.0.1/24`, and both `DOCKER-USER` ACCEPTs are installed, before `nft create table`, the input drop, the forward restrictions and the masquerade.
- If `nft create` fails, `set -e` stops in the following state:
  - lab→WAN forwarding is accepted;
  - there is no NAT, so packets would leave with a 10.250.0.x source;
  - there is no host-input drop.
- That state is harmless only while no guest is attached.
- Fix: create the nft table and chains first, add the `DOCKER-USER` rules next, and bring the links up last.
- Separately, on a host with FORWARD ACCEPT and no `DOCKER-USER` (no Docker, or Docker's nftables backend), the preflight prints OK but setup aborts at `iptables -I DOCKER-USER`. This fails closed; it should be reported as a preflight collision.
- What is otherwise correct for iptables-nft and Docker 29:
  - `FORWARD` jumps to `DOCKER-USER` first, so an ACCEPT there accepts in that base chain, and `inet vprlab forward` accepts as well;
  - `-s`/`-d 10.250.0.0/24` match before SNAT and after de-NAT;
  - the inbound rule is ESTABLISHED,RELATED only;
  - `-D` with the identical specification removes exactly one copy;
  - re-running setup aborts at the exclusive `ip tuntap add` before reaching the inserts, so duplicate copies cannot accumulate;
  - nothing touches other tables or chains.

**M-6. The API default `expect_tunnel="any"`.**
- Location: `pcapscan.py:1150`.
- The CLI requires `--expect-tunnel`, but a programmatic caller such as the M2 runner gets a no-requirement PASS by omission (probe N13).
- Doc `:11` says the tool has "no fail-open defaults".
- Fix: make it a required keyword argument.

**M-7. The provenance check leaves `-w` free and matches the banner by substring.**
- Locations: `netplan.py:93-115`; `pcapscan.py:1201-1203`.
- `-w /dev/null` and `-w -` are accepted, and the `-w` value is never compared with `--pcap`.
- The banner check is satisfied by its text appearing in any line.
- Debian's tcpdump AppArmor profile only permits writes to `*.pcap`/`*.cap`/`*.pcapng`, so a non-`.pcap` `--capture-file` fails at run time.
- Fix: require a `.pcap` suffix and `basename(-w) == basename(--pcap)`, and anchor the banner as a whole line starting with `tcpdump: `.
- The value is low, because the capture host is trusted by the stated design.

**M-8. `gateway_mac` changes on every setup.**
- Location: doc `:121-123`.
- A Linux bridge with a random address takes the lowest port MAC (`br_stp_recalculate_bridge_id`). Once the freshly created tap is enslaved, the bridge MAC equals the tap's random MAC.
- So the policy must be rewritten after section 1 of every run. A stale value shows up as a LEAK (`arp_not_allowed` on the host's ARP probe): safe, but misleading.
- Fix (either option): pin the bridge address in the plan (`ip link set dev vprlab0 address <fixed>` before enslaving, which makes it `NET_ADDR_SET`), or document the per-run step.

**Nit.** The `netplan.py` module docstring (`:14`) says "per-run ownership tag", but the tag is the fixed `vprlab-leak-lab-m1`. The doc (`:516`) states that correctly.

## 3. Generated host script, other checks

- `sh -n` passes.
- The WAN name is regex-validated, so nothing can be injected into the `iptables`/`nft` lines.
- `nft create table … { comment "<tag>"; }` is exclusive. The nft ownership checker matches only the `table` object's `comment`, so a rule comment cannot authorize deletion.
- Teardown isolates the guest (tap down plus `nomaster`) before deleting the table. A down tap rejects guest writes, so there is no window in which a guest can reach host services.
- The input/output DROP and ICMP-suppression analysis from round 2 still holds, and the rules are unchanged.
- No `flush`, no global sysctl write, and no IPv6 sysctl outside the two lab links.

## 4. Docs vs code

The code matches the doc for:
- the stats rules (`:347-377`), including `unread_capture_tail`, the banner and the SIGUSR1 line;
- the capture-provenance list (`:385-398`);
- the window rules (`:198-221`);
- the `tunnel_expectation` semantics (`:289-298`);
- ARP (`:425-447`);
- the policy loader (`:109-151`);
- the preflight (`:564-577`);
- the exit codes.

Mismatches:
- `:511-515`, link `alias` ownership (I-1);
- `:463-464`, fragments completing at EOF (M-3);
- `:11`, "no fail-open defaults", versus the API default (M-6);
- `:516-519`, "teardown can never claim a resource…", versus step 4a (M-4);
- `:223-235` and the plan comment, Ctrl-C followed by automatic teardown (M-1).

## Reproducer index (all run; scratch deleted)

| ID | Input | Observed |
|---|---|---|
| I-1 | plan checker on `[{"ifname":"vprlab-tap0","ifalias":"vprlab-leak-lab-m1",…}]` | exit 1, so the link is not deleted |
| M-1 | dash script: SIGINT-catching child, then `killpg(SIGINT)` | script status −2; `AFTER`/teardown never printed |
| M-2 | `[A, wg, forged_in(src_mac=VM), B]`; `[A, wg, wg_inbound(vlan=5), B]`; relay-a out + relay-b in, all with `up` | PASS (each) |
| M-3 | `[A, wg, B, first()]`; `[first(), A, wg, B]` | PASS, `outside_window_allowed=1` |
| M-6 | `scan_capture(...)` without `expect_tunnel`, `[A, B]` | PASS |
| M-7 | argv `-w /dev/null`; argv `-w -`; banner text in a non-banner line | PASS |
