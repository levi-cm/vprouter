# Leak lab round-5 adversarial review (Opus)

Scope: `git diff 0097e78..649a5e2 -- tools/leak-lab docs/rust-v2/leak-lab.md docs/rust-v2/leak-lab-vm.md`
Reviewer: claude-opus-5-5, 2026-11-09. Read-only except this report; scratch /var/tmp/leaklab-r5-opus.

## Findings


### F1 — Important — ICMP quote allowance accepts unbounded, unchecked bytes (wider than the user's narrow rule)

`tools/leak-lab/pcapscan.py:1154-1184` (`_allowed_icmp_quote`), wired at `:1331` and `:846-859`.

The check reads only: ICMP type/code, quoted byte 0 (`0x45`), quoted protocol, quoted
src/dst, quoted source port, and the first 4 quoted UDP payload bytes. Nothing bounds or
checks the rest. All of these PASSED with `allowed_icmp_quotes={'mullvad-wg': 1}` and zero
findings (reproducer `/var/tmp/leaklab-r5-opus/repro_icmp.py`, using the
`test_leak_lab` frame builders, `scan_middle(..., expect_tunnel="up")`):

| crafted outbound ICMP 3/3, VM -> endpoint | verdict |
|---|---|
| valid quote + **1000 bytes of plaintext after the quoted datagram** (`REAL-CLIENT-IP 203.0.113.77 GET /secret ...`) | PASS |
| ICMP "unused" bytes 4..7 = `b"LEAK"` | PASS |
| quoted IPv4 total_length = 1, or 65535 | PASS |
| quoted UDP length = 0 | PASS |
| quoted header is a non-first fragment (offset 800) | PASS |
| quoted payload `04 00 00 00` + 852 bytes plaintext | PASS |
| 1400-byte ICMP (Linux never sends an ICMP error larger than 576 bytes) | PASS |

Minimal reproducer (run from `tools/leak-lab`; the scratch scripts were deleted as instructed):

```python
import test_leak_lab as T
inner = T.ipv4_packet(T.WG_IP, T.VM_IP, 17, T.udp_segment(T.WG_PORT, 40410, T.wg_initiation()))
icmp = bytes([3, 3, 0, 0, 0, 0, 0, 0]) + inner + b"REAL-CLIENT-IP 203.0.113.77 GET /secret " * 25
r = T.scan_middle([T.ipv4_frame(icmp, protocol=1),
                   T.ipv4_frame(T.udp_segment(40000, T.WG_PORT, T.wg_initiation())),
                   T.ipv4_frame(T.udp_segment(T.WG_PORT, 40000, T.wg_initiation()), src_ip=T.WG_IP,
                                dst_ip=T.VM_IP, src_mac=T.GW_MAC, dst_mac=T.VM_MAC)],
                  expect_tunnel="up")
assert r["verdict"] == "PASS" and r["allowed_icmp_quotes"] == {"mullvad-wg": 1}   # holds at 649a5e2; LEAK at 819547b
```

Impact: the user's decision was "ICMP 3/3 to the endpoint *quoting a WireGuard-shaped
datagram* from endpoint:port to the VM". The implementation accepts any ICMP 3/3 whose first
44 bytes look like that, followed by up to MTU-worth of arbitrary bytes. That is a non-WireGuard
frame carrying arbitrary content which PASSes. It is NOT a new real-IP leak *destination*: the
outer destination must be the declared endpoint, and the allowed type-4 UDP shape already
lets arbitrary bytes reach the endpoint (shape-only check). So I do not think it invalidates the
six live PASSes. The kernel-generated quotes seen live would also pass a strict check. But
this is a safety filter that is wider than the rule it was approved under, so it should be
tightened before more evidence is collected.

Also (same root cause): a forged quote with no matching inbound datagram in the capture is
accepted (`forged quote alone, expect_tunnel=down` -> PASS). A genuine port-unreachable can
only exist if the quoted inbound datagram crossed the tap, so it must be in the pcap.

Suggested fix (all in `_allowed_icmp_quote`):
1. `payload[4:8] == b"\0\0\0\0"` and a valid ICMP checksum over the ICMP message.
2. Quoted header: `quoted[0] == 0x45`, fragment field `& 0x3FFF == 0` (MF clear, offset 0),
   quoted total_length `qtl >= 20+8+4`, quoted UDP length `== qtl - 20`.
3. Length: `len(quoted) == min(qtl, 576 - 20 - 8)` (Linux `icmp_send` quotes as much as fits
   in 576 bytes), so no byte after the quoted datagram exists and nothing longer than 576 is
   accepted.
4. Best: bind the quote to a real frame. Keep a small ring (e.g. last 64, within 2 s) of
   inbound allowed WireGuard frames' IPv4 header+payload bytes, and require the quoted bytes
   to be a byte-exact prefix of one of them (TTL may differ by 0 on a bridge; compare the
   rest exactly). That makes the allowance "the VM bounced a datagram we saw arrive" and
   nothing else.
5. Add tests for each case in the table (they are reproducible with the existing helpers).

Doc note: `docs/rust-v2/leak-lab.md` ("Narrow ICMP quote allowance") says such a reply
"quotes only the endpoint's own ciphertext". The code does not enforce that, so fix the code
or the sentence. After the fix, re-scan the six live pcaps (login re-scan, stop-router,
kill-container, ...) with the tightened scanner. That is a cheap way to confirm the 1+1+2
live quotes were genuine kernel quotes. I could not do it here because the evidence is under
/var/lib/vprlab, which I was not allowed to read.

### F1 addendum — status at 819547b (landed during this review, outside the assigned scope)

819547b ("ICMP quote allowance must be structurally exact", from the GPT r5 report C1)
closes most of the F1 table. I re-ran the same cases against both trees:

| case | 649a5e2 | 819547b |
|---|---|---|
| 800 B plaintext after the quoted datagram | PASS | LEAK |
| unused word = `LEAK` | PASS | LEAK |
| quoted total_length 1 / 65535, quoted UDP length 0, quoted non-first fragment | PASS | LEAK |
| quoted datagram `04 00 00 00` + 800 B plaintext, quoted **whole** (832-byte quote) | PASS | **PASS** |
| 1400-byte ICMP quoting a whole 1392-byte "type-4" datagram | PASS | **PASS** |
| forged quote with no matching inbound frame, `expect_tunnel=down` | PASS | **PASS** |

Residual (Important until fixed, since it is still wider than the documented rule):
`pcapscan.py` (819547b) accepts `len(quoted) == quoted_total` at **any** size. Linux never
quotes more than 548 bytes, so a whole quote longer than 548 cannot come from the kernel. Fix:
`if len(quoted) != min(quoted_total, ICMP_QUOTE_LIMIT): return None`, plus a test for an
832-byte whole quote. Even with that fix, up to 520 quoted bytes after the WireGuard header
are arbitrary. Only F1 fix 4 (the quote must be a byte-exact prefix of an inbound allowed
frame seen shortly before) makes the docs' sentence "quotes only the endpoint's own
ciphertext" true. The commit message says all retained live captures were re-scanned with 0
findings, which addresses my re-scan request (I did not verify it myself).

## Minor notes

M1 — `_safe_text` lets IPs, hostnames and chunked secrets through
(`tools/leak-lab/vm/run_phase.py:1502-1514`). I ran it directly. These are all returned
verbatim: `"public exit 203.0.113.77 via ch-zrh-wg-001.relays.mullvad.net"`,
`"2a03:1b20:3:f011::a01f"`, `"max-vprouter.tail1234.ts.net"`,
`"tskey-auth-kAbCdEf123CNTRL-x"`, and a 76-hex-char secret split into 19-char chunks
(`"k 0123456789abcdef012 0123456789abcdef012 ..."`). Base64 WireGuard keys (`+/=`) and
`https://` URLs are rejected. Today this has no impact: `router_runtime.py` only writes fixed
`RuntimeErrorClosed` strings and exception class names to the health reason, and the refusal
text is runner-authored. The docstring's claim that "a guest cannot smuggle arbitrary bytes
through" is still false. Fix: map `reason` to an explicit allowlist of the release's known
reason strings (or record only `sha256(reason)[:12]` and the length) instead of using a
character-class filter. This matters before the rust/v2 release, whose health reasons may
include addresses.

M2 — `verify_image_tar_chain` crashes on a non-dict manifest entry
(`tools/leak-lab/vm/provision.py:~232`, `m.get` in the list comprehension). Reproducer
(`repro_chain.py`): `index.json = {"manifests": ["x", {...}]}` -> uncaught `AttributeError`.
It fails closed (provision aborts before QEMU), so this only affects diagnostics. Fix: check
`isinstance(m, dict)` and add `AttributeError` to the caught tuple. Every chain attack I tried
was refused: a claimed evil config, a duplicate tar member with the tampered copy last, and a
symlink blob. Binding: the index digest fixes the manifest and the config. The guest then
requires `docker image inspect EXPECTED` == expected config ID, and the runner starts the
container by `image_ref = image_id`. I found no way for a different image to pass.

M3 — `IcmpQuoteAllowanceTests` is defined after `if __name__ == "__main__": unittest.main()`
(`tools/leak-lab/test_leak_lab.py:4516-4520`). At 649a5e2, `python3 -B test_leak_lab.py` runs 255
tests and `python3 -B -m unittest test_leak_lab` runs 261 (265 at 819547b, where the guard is
still at :4516), so running the file directly silently skips every ICMP test. Fix: move the class above the main guard.

M4 — `verify_tree` now always skips `__pycache__` (`tools/leak-lab/vm/hostcopy.py:713`), and
the installed scanner runs with `-I` but not `-B` (`run_phase.py:2023`), so root writes `.pyc`
files under `/opt/vprlab-tools/leaklab`. An unchecked-hash `.pyc` there would replace
`pcapscan`/`policy` code without failing the manifest check. Exploiting this needs root, so
it does not cross a privilege boundary. Fix: add `-B` to `scanner_launch_argv`, and make
setup and `verify_leaklab_manifest` refuse (or delete) any `__pycache__` under `LEAKLAB_ROOT`
instead of skipping it.

M5 — The type-4 length rule is now `>= 32` only (`pcapscan.py:200-208`). That is correct for
MTU-clamped packets but weaker than needed. A tighter rule that still accepts the real
traffic: `(len-16) % 16 == 0 or len == mtu + 32` for the profile MTU. This is shape-only
either way, not a real-IP leak path.

M6 — `kill_qemu` now signals only the QEMU pid through a pidfd, not the process group
(`run_phase.py:2284-2302`). The pidfd use is correct (QEMU is an unreaped child, so its pid
cannot be reused, and it is re-checked after `pidfd_open`). Any helper process in QEMU's group
would no longer be SIGKILLed. QEMU runs with `-sandbox ... spawn=deny`, so this is
theoretical.

M7 — A forged quote with no matching inbound datagram PASSes a `down` expectation
(`repro_icmp.py`: `phase_frames(quote)`, `expect_tunnel="down"` -> PASS). No phase currently
uses `down` (`run_phase.py:94-103`, all `up`). F1 fix 4 closes this.

## Checked and OK (with reproducers)

- ICMP precedence and window (`repro_icmp.py`): a quote + TCP frame gives LEAK; a quote with
  a missing after-control gives INVALID; a quote as the only outbound in window under `up`
  gives INVALID `tunnel_not_observed` (never tunnel evidence); quotes before and after the
  controls are counted in `outside_window_allowed` and do not invalidate. These all give LEAK:
  MF set (`icmp_not_allowed`), 802.1Q tag or wrong src/dst MAC (`allowed_tuple_wrong_l2`),
  outer IHL 6 (`ipv4_options`), outer destination != quoted source (`icmp_not_allowed`),
  code 4 and type 8, a quote from a different IP or port, a quote of VM->endpoint, and
  inbound ICMP. IPv6 is unchanged (ICMPv6 is still parsed by `_parse_ipv6`, outside the
  allowance).
- Non-first fragments of ICMP go through `_handle_nonfirst_fragment` and become
  `fragment_without_first` (no state is registered for an ICMP first fragment because MF ICMP
  is already `icmp_not_allowed`).
- `-B 8192` contract: `netplan.capture_argv`, `guest.tcpdump_argv`, both docs and the tests
  agree. `check_capture_argv` compares length and every element exactly, so the old 9+2
  argv (no `-B 8192`) gives `capture_argv_mismatch` (also covered by
  `test_leak_lab.py:812`).
- tcpdump RLIMIT_FSIZE = cap + 256 MiB through `apply_child_limits`. If tcpdump hits the
  limit it gets SIGXFSZ, leaving a truncated last record, which the scanner treats as
  structural INVALID. That direction is safe.
- `stop_capture` now retries `wait(0.5)` until the full deadline. It no longer forces a stop
  after the first 0.5 s.
- Deferred provision signals: the handler only records the signal; `check_interrupt()` runs
  after `Popen` (handle exists, so `finally: _terminate`), in the marker loop and in the
  poweroff loop. There is no path where a signal orphans QEMU.
- Readiness diagnostics cannot turn a refusal into PASS: `record_readiness_refusal` runs
  inside the `except Refusal` branch. Any exception it raises reaches the outer
  `except BaseException` and becomes `phase_exception:*`. `tailscale_problems` are fixed
  runner strings, `tailscale_self` holds booleans or None only, and `release_health_state` is
  allowlisted.
- Login (24faa07): a phase PASS still requires `backend_state == "Running"` after the wait
  (`run_phase.py:3103-3105`). An unrecognized `login.tailscale.com/...` string is never
  written out. Only a URL matching `https://login\.tailscale\.com/a/[0-9a-f]{8,16}` reaches
  `login-url.txt`/stderr, which was already the case before this change.
- Boot fixes: `-bios` points into the root-owned staged tools tree; `if=none` +
  `virtio-blk-pci,bootindex=0` adds no device or NIC. The journal dump goes only to the
  provisioning serial console, only on Docker start failure, before any profile exists.
  `docker-cli` is a Debian package installed during provisioning. I found no host-safety or
  secrecy regression.

## Tests

Commit 819547b landed on `rust/v2` while this review was running (15:53). My first in-repo run
therefore tested 819547b. I re-ran on a `git archive 649a5e2` export of tools/leak-lab and
docs/rust-v2 in scratch:

- 649a5e2: `python3 -B -W error -m unittest test_leak_lab` -> **Ran 261 tests, OK**;
  `python3 -B -W error -m unittest vm.test_vm` -> **Ran 202 tests, OK**
- 819547b (working tree): test_leak_lab **265 OK**, vm.test_vm **202 OK**

Scratch `/var/tmp/leaklab-r5-opus` deleted at the end. No repository file other than this
report was modified.

## Verdict

**FAIL**: one Important finding at 649a5e2 (F1: the ICMP quote allowance is wider than the
approved rule and accepts arbitrary trailing or unchecked bytes). It is still partly open at
819547b: whole quotes longer than Linux's 548-byte limit are accepted, and the quote is not
bound to an observed inbound frame. No Critical: no reproducer gets a
frame to a non-endpoint destination, or a non-ICMP non-WireGuard frame, past the scanner, and
the six live PASS verdicts are not shown to be false. Fix F1, add its tests, re-scan the live
pcaps, then re-gate.
