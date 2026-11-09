# Leak lab — independent adversarial review, round 5 (pi)

Reviewed artifact: `rust/v2` at **649a5e2** (`0097e78..649a5e2`), scope
`tools/leak-lab`, `docs/rust-v2/leak-lab.md`, `docs/rust-v2/leak-lab-vm.md`.
The code was read and executed from an exact `git archive 649a5e2` snapshot in
`/var/tmp/leaklab-r5-pi` (`pcapscan.py` hash-checked against
`git rev-parse 649a5e2:tools/leak-lab/pcapscan.py`), because the
branch HEAD moved during the review: at 15:53 a controller commit
**819547b** ("ICMP quote allowance must be structurally exact (r5 review C1)")
was added on top of 649a5e2. 819547b is *outside* the reviewed range; see the
note at the end of the Critical finding. No file other than this report was
modified; scratch is deleted at the end.

No privileged or network execution was performed: no sudo, QEMU, tcpdump, ip,
nft, iptables, docker, useradd or network. No `/etc/vprouter`,
`/DATA/AppData/vprouter/conf`, `/root`, `/var/lib/vprouter`,
`/var/lib/vprlab`, archive or key file was read. Only Python stdlib.

Required suites, each run on the 649a5e2 snapshot (and the same two runs on the
live tree before it moved produced identical counts):

- `python3 -B -W error -m unittest test_leak_lab` — **261 tests, OK** (8.03 s).
- `python3 -B -W error -m unittest vm.test_vm` — **202 tests, OK** (16.56 s).
- **463 tests, zero failures/errors/skips.**

## Critical R5-P1 — the ICMP quote allowance accepts arbitrary cleartext after the quoted datagram (false PASS)

Location (649a5e2): `tools/leak-lab/pcapscan.py:1154-1184`
(`_Scanner._allowed_icmp_quote`) and the accepting path at
`tools/leak-lab/pcapscan.py:846-859`.

**Actually reproduced.** A single 1514-byte Ethernet frame (IP total length
1500, the lab MTU, so it is wire-possible unfragmented) contains a complete,
internally well-formed ICMP 3/3 to the allowed endpoint, quoting the endpoint's
own 148-byte WireGuard initiation to the VM, followed by 1296 bytes of
cleartext (`REAL_IP=198.51.100.77;SECRET=synthetic-canary …`) **outside the
quoted datagram's IPv4 total length**. With genuine shape-valid WireGuard UDP
in both directions and both controls, the scanner as reviewed returns:

```text
verdict: PASS  findings_total: 0  allowed_icmp_quotes: {'mullvad-wg': 1}
packets: 5    invalid_reasons: []
```

Executed probe (from `tools/leak-lab`, using the repository's own packet
helpers; the frame is byte-for-byte the one above):

```python
import test_leak_lab as t
inner = t.ipv4_packet(t.WG_IP, t.VM_IP, 17,
                      t.udp_segment(t.WG_PORT, 40410, t.wg_initiation()))
head = b"REAL_IP=198.51.100.77;SECRET=synthetic-canary "
extra = head + b"A" * (1296 - len(head))          # fits one 1500-byte MTU
icmp = bytes([3, 3]) + bytes(6) + inner + extra
frame = t.ipv4_frame(icmp, protocol=1)            # 1514-byte Ethernet frame
r = t.scan_middle([frame, t.wg_outbound(), t.wg_inbound()],
                  expect_tunnel="up")
assert r["verdict"] == "PASS" and r["findings_total"] == 0
assert r["allowed_icmp_quotes"] == {"mullvad-wg": 1}
```

The frame carries zero ICMP/IP checksums because the scanner never validates
them; a real tap frame would carry valid ones and this monitor would classify it
identically. A VM can compute them trivially, so that is not a defence.

Additional variants I executed against the same scanner, all `PASS` with
`findings_total=0` and `allowed_icmp_quotes={"mullvad-wg": 1}`:

| crafted quote | result |
|---|---|
| complete quote + 1000 B / 1400 B / 60000 B trailing cleartext | PASS (1400 B/60000 B exceed one MTU, 1000 B fits) |
| ICMP unused word set to `de ad be ef` | PASS |
| quoted IPv4 `total_length` = 0, 20, 600 (actual 176) | PASS |
| quoted UDP `length` = 0 or 9999 (actual 156) | PASS |
| quoted datagram has MF set / fragment offset 8 | PASS |

The same secret-bearing frame **before the before-control and after the
after-control also PASS**, recorded only as one
`outside_window_allowed` packet. The same frame with a wrong L2 is `LEAK`
(`allowed_tuple_wrong_l2`), and a quote with no genuine tunnel is `INVALID`
(`tunnel_not_observed`), so those controls hold.

The parser never reads the quoted IPv4 `total_length`, the quoted UDP `length`,
the quoted fragment field, or the ICMP unused word; it checks only the quoted
src/dst, the UDP source port, and four bytes of the quoted payload. The user
decision permitted one narrow, kernel-generated shape; the implementation does
not enforce the edges of that shape, so any remaining bytes ride along as
'allowed'. A phase can therefore PASS while the VM sent non-WireGuard cleartext
to the declared relay. Impact: the
outer destination is still pinned to the declared endpoint, so this is **not a
third-party real-IP leak**; it is a false PASS of the monitor's stated
frame-level invariant, an unmonitored VM→Mullvad plaintext channel (≈1.3 KB per
in-window frame, unbounded across frames), and it makes
`allowed_icmp_quotes` misleading as evidence.

Coverage gap that let this pass the suite: `IcmpQuoteAllowanceTests`
(`test_leak_lab.py:4520-4578`) tests the correct/narrow shapes and several
negatives, but never trailing bytes beyond the quote, quoted length
mismatches, quoted fragmentation, or the unused word. The suite was green at
649a5e2 with the defect present.

Suggested fix (implemented post-gate in 819547b, not reviewed here): require a
zero unused word; an unfragmented, option-free quoted IPv4 packet (DF allowed);
quoted IPv4 total length == present quote length (or exactly Linux's 548-byte
truncation of a longer datagram); quoted UDP length == quoted IPv4 length − 20;
`wireguard_length_problem` applied to the declared WireGuard payload length;
and nothing after the quote. Add these as full-scanner in-window and
outside-window regressions. Re-scan every retained live capture with the fixed
scanner before the live PASS evidence is relied upon; the live phases were
produced with the reviewed, lax scanner. My read scope excludes
`/var/lib/vprlab`, so I did not verify the controller's "re-scanned: 0
findings" claim.

## Minor R5-P2 — `_safe_text` does not keep IPs/hostnames out of phase.json, and a chunked encoding carries arbitrary chosen bytes

Location: `tools/leak-lab/vm/run_phase.py:1502-1514` (`_safe_text`) and
`:1517-1555` (`record_readiness_refusal`), called from `run_phase.py:2954` and
`:2995`.

The filter rejects the raw WireGuard key shape and any `https://` AuthURL, but
it accepts addresses and hostnames, and it accepts a re-encoded secret. Each
line below was executed against the 649a5e2 code:

```text
_safe_text("185.65.134.10")                        -> '185.65.134.10'
_safe_text("de-fra1-wg-001.mullvad.net")           -> 'de-fra1-wg-001.mullvad.net'
_safe_text("52:54:00:76:70:02")                    -> '52:54:00:76:70:02'
_safe_text("yAnz5TF+lXXJte14tji3zlMNq+...Bmk=")    -> 'unrecognized'
_safe_text("https://login.tailscale.com/a/1873...") -> 'unrecognized'
_safe_text("ab cd ef 01 23 45 67 89")              -> 'ab cd ef 01 23 45 67 89'
```

A fake QGA client returning `{"state":"BLOCKED","reason":"the wireguard key is
ab cd ef 01 …"}` produced `record["readiness"]["release_health_reason"]`
containing the whole chunked value (up to 160 chars; the `_LONG_TOKEN` rule only
blocks ≥20-char alphanumeric runs, so hex/base32 in short groups passes). This
is a guest-controlled write channel into host evidence on any readiness
refusal, not covered by the "Accepted risks" list in
`docs/rust-v2/leak-lab-vm.md:799-820`.

Impact/limits: the phase result is `INVALID` (`router_not_ready`), so this
cannot manufacture a PASS; the file is 0600 inside a 0700 evidence directory;
the WireGuard key is host-injected and already known to the host, so no new
trust boundary is crossed (the same reasoning as the accepted login-URL
channel). No diagnostic value is written to stdout (the stdout summary has no
`readiness` field; `errors` contains only fixed reason strings). Keep as Minor:
either reduce the reason to a fixed vocabulary, drop guest-authored text, or add
this channel to the accepted-risks section and correct the docstring's "a guest
cannot smuggle arbitrary bytes through".

## Minor R5-P3 — type-4 WireGuard lengths that cannot occur on the wire are accepted

Location: `tools/leak-lab/pcapscan.py:197-208` (`wireguard_length_problem`).

The MTU-clamp reasoning is right for the case the round-4 review raised:
`padded = min(ALIGN(len,16), mtu)`, so a full-size packet at MTU 1420/1500 is
1452/1532 bytes and not 16-aligned; removing the alignment rule is necessary.
But the replacement `length >= WIREGUARD_DATA_MIN` also accepts lengths that
the kernel can never emit, e.g. 33…47, 49…63, … (only `32 + 16n` up to the
tunnel MTU, plus exactly `mtu + 32` when the MTU is not 16-aligned, are
realisable). Executed: `wireguard_length_problem(4, 33) is None`, and a
two-direction fixture with a 33-byte type-4 payload scans `PASS`, 0 findings.

Impact: none on the third-party real-IP property — the type-4 shape check is
documented as shape-only and any 16-aligned plaintext already passed. It only
widens the existing "plaintext shaped like type 4 is accepted" limitation, so
it is a Minor consistency note, not the round-5 Critical. If a tighter rule is
wanted: accept `{32 + 16n : 32 + 16n <= mtu + 32} ∪ {mtu + 32}` and thread the
tunnel MTU (1420/1500) into the scanner policy; otherwise say explicitly in the
docs that *any* length ≥ 32 is accepted.

## Minor R5-P4 — image-tar duplicate member names are accepted by the last-wins lookup

Location: `tools/leak-lab/vm/provision.py:196-260` (`verify_image_tar_chain`).

`tarfile.getmember` returns the *last* member with a given name. I built a tar
whose `blobs/sha256/<pinned-manifest-digest>` appears twice: the first member is
a different, well-formed manifest (different config), the last member is the
genuine pinned manifest. `verify_image_tar_chain` **ACCEPTED** it. A second tar
with the tampered copy last was correctly refused (hash mismatch), so the hash
chain itself works. Docker was not executed (forbidden), so I cannot show that
`docker load` would pick the first member; Go's `archive/tar` consumers usually
overwrite earlier entries with later ones, which would match the verifier, and
the provisioning guest script additionally checks that the loaded image ID is
exactly the expected config digest (`guest.py:913`). Keep as an unreproduced
hardening note: reject duplicate member names in the blob paths (content-
addressed blobs should appear once) so the verifier never depends on a
reader-ordering assumption. Separately, the top-level `index.json` is read with
no member-size cap (the blobs are capped at 64 MiB), so a hostile tar can make
provisioning allocate up to RLIMIT_AS before refusing; that is availability
only (no state directory is created yet).

## Minor R5-P5 — the new test classes are defined after the `__main__` guard

Locations: `tools/leak-lab/test_leak_lab.py:4516` (guard) vs `:4520`
(`IcmpQuoteAllowanceTests`); `tools/leak-lab/vm/test_vm.py:5016` (guard) vs
`:5020` (`ControllerR4Tests`), `:5112` (`LiveBringUpTests`), `:5153`
(`ImageTarChainTests`), `:5211` (`ReadinessDiagnosticsTests`).

The mandated `python3 -m unittest …` command discovers and runs them (261 and
202 tests above), but a developer running `python test_leak_lab.py` or
`python vm/test_vm.py` directly calls `unittest.main()` before the classes are
defined and silently skips every new round-4/5 regression. Move the classes
above the guard. Test hygiene only; no safety impact.

## Minor R5-P6 — `-B 8192` cannot enlarge the capture ring on this host (docs overstate it)

Locations: `tools/leak-lab/netplan.py:154-160`,
`tools/leak-lab/vm/guest.py:1289-1296`, `docs/rust-v2/leak-lab.md:689`.

The host's `net.core.rmem_max` is **212992** (208 KiB), and the host's
`/usr/lib/x86_64-linux-gnu/libpcap.so.1.10.5` sets the buffer with
`setsockopt(SOL_SOCKET, SO_RCVBUF, …)` (optname 8) — disassembly at
`0xd6a8-0xd6c2`; I found no `SO_RCVBUFFORCE` (33) call in the library. Linux
silently clamps the requested value to `rmem_max` and stores twice it. libpcap
itself defaults `opt.buffer_size` to 2 MiB when unset (disassembly at
`0xa019-0xa024`), so both the default 2 MiB request and the new 8 MiB request
are clamped to the same effective ~416 KiB (2 x 212992) on this host: `-B 8192`
is a no-op here, and the "8 MiB kernel ring" in the docs and commit message is
not what the kernel grants. tcpdump was not run (forbidden), so I did not
observe the effective size, and a live host with a raised `net.core.rmem_max`
would behave differently; that is not recorded in the ledger. Consequence: the
long-phase drops the commit targets may persist; drops still make the phase
INVALID (`packet_drops`), so there is **no false PASS**. Fix the docs (state the
rmem_max prerequisite) or raise `net.core.rmem_max` on the lab host, and
verify the effective ring before relying on "long phases cannot drop".

## Minor R5-P7 — readiness diagnostics read an unbounded guest file and add up to ~55 s of QGA calls

Location: `tools/leak-lab/vm/run_phase.py:1528-1543`.

`docker exec … cat /run/vprouter-health.json` reads a file the guest controls
with no size bound; the QGA reply is buffered whole before `json.loads`
(MemoryError is caught, and the runner has RLIMIT_AS 2 GiB). The three
diagnostic calls run after the readiness refusal with 15 s/20 s timeouts each
and no `check_interrupt()` between them, delaying signal handling. The phase is
already INVALID, so this is availability only. Bound the `cat` output (e.g.
`head -c 4096`).

## Notes / checked, no finding

- **Scope commit drift.** 819547b (post-gate) is the controller's fix for this
  same C1; it is not part of `0097e78..649a5e2` and was not otherwise reviewed.
  The report verdict below is for the reviewed artifact, which is what produced
  the live PASS evidence.
- **Item 1, ICMP allowance boundaries (all executed).** Rejected as `LEAK`:
  ICMP 3/1, ICMP 8/0, quoted src/dst swapped, quoted source port 40000 or 53,
  quoted IHL 6, quoted proto TCP, outer dst 1.1.1.1 (with or without a matching
  quoted source), quoted IPv6 datagram, outer IPv6 ICMPv6, outer MF fragment,
  outer non-first fragment, outer IPv4 options, VLAN tag, wrong source/dest MAC.
  A wrong-L2 quote is `allowed_tuple_wrong_l2` even before the before-control.
  A quote alone with `--expect-tunnel up` is `INVALID` (`tunnel_not_observed`);
  a quote is never counted in `allowed_counts`/`window_counts`. A quote before
  the before-control or after the after-control is counted in
  `outside_window_allowed`, not `outside_window_other`, and does not change the
  verdict. Precedence holds: leak finding + missing after-control → `LEAK`;
  quote + missing after-control → `INVALID`; quote + DNS leak → `LEAK`.
- **Item 2, round-4 fixes.** `stop_capture` waits the whole timeout: a child
  that ignores SIGINT was forced (`status=-9`, `forced_stop=True`) after 1.00 s
  with `timeout=1.0`, not after 0.5 s. `kill_qemu` signals through a pidfd; the
  suite's `ControllerR4Tests` pass, and a `pidfd_open` failure (mocked EMFILE)
  leaves the child alive but returns False, which the guard/caller handles by
  bringing the tap down first (fail-safe; availability-only process leak).
  `CAPTURE_FSIZE_MARGIN` is applied on the production `start_capture` call
  (`cap + 256 MiB`); `apply_child_limits` still swallows prlimit failures (known
  residual, truncation would be INVALID). `hostcopy --exclude=leaklab` plus the
  separately verified leaklab manifest is consistent; no host-safety issue.
  Provision signals are deferred to `check_interrupt()` checkpoints with the
  QEMU handle already retained; the `finally` terminates it.
- **Item 3, image binding.** With the pinned index and config, `verify_image_tar_chain`
  accepted only the genuine chain (probe results: wrong expected config → refused;
  wrong index → refused; two linux/amd64 manifests → refused; missing platform →
  refused; Docker media type → refused; tampered manifest blob → refused). The
  config digest includes `rootfs.diff_ids`, so a different layer set cannot keep
  the same image ID; I found no way for a different image to pass other than the
  duplicate-member ordering note above and the inherent fact that the guest
  reports its own image ID in the completion marker.
- **Item 4, boot/package fixes.** The staged SeaBIOS file exists
  (`/opt/vprlab-tools/usr/share/seabios/bios-256k.bin`, 262144 bytes) while
  `/opt/vprlab-tools/usr/share/qemu/bios-256k.bin` does not — exactly the live
  bug; `-bios` names it in both modes. `virtio-blk-pci,drive=root,bootindex=0`
  makes the root disk first and the payload has no bootindex (not bootable;
  the seed/payload ISOs have no El Torito). The Docker failure dump goes to
  ttyS0 only during provisioning, into the state serial file (0700 state dir
  owned by the QEMU account, 64 MiB cap); the container is not started at
  provisioning time, so the Docker/containerd journal holds no WireGuard
  profile. No host-safety or secrecy regression found.
- **Item 5, login URL.** `find_login_url_result` only ever returns the exact
  `https://login.tailscale.com/a/[0-9a-f]{8,16}` shape; only that value is
  written to `login-url.txt` (0600) and printed. Executed runner probe:
  `(None, False)` + `BackendState=Running` → `PASS` with no URL file (intended:
  already authenticated); `(None, True)` → `INVALID`
  (`login_url_unrecognized`, nothing written); a valid URL and a later invalid
  candidate → `PASS` (the live fix). No raw key/AuthURL can be written, and no
  new false PASS was introduced. The 64-bit guest-chosen token channel is the
  documented accepted risk.
- **Item 6, readiness diagnostics.** No diagnostic path can turn the refusal
  into a PASS: the call sites set `setup/active` False and `note("router_not_ready")`
  first, so the result stays `INVALID`; the diagnostics only add the `readiness`
  dict to phase.json. Raw key/AuthURL are filtered (Minor R5-P2 covers IPs,
  hostnames and chunked encodings).
- **Item 7, `-B 8192` argv contract.** `netplan.capture_argv`,
  `guest.tcpdump_argv`, `test_leak_lab.CAPTURE_ARGV`, the plan golden strings
  and all three docs snippets agree. `check_capture_argv` requires exact item
  equality and equal length; the pre-buffer argv (missing `-B 8192`), a smaller
  ring, and a duplicated `-B` all return `capture_argv_mismatch` (executed).
  Production `-w` is `/proc/self/fd/<evidence fd>/capture.pcap`; the scanner is
  spawned with `pass_fds=(evidence.fd,)`, so the `realpath` equality check
  resolves in the scanner and still binds the argv to the scanned pcap. No path
  for the old argv was found.
- **C1 residual (design, not a new finding).** Even with the post-gate
  exactness fix, the quoted bytes are chosen by the VM, so a VM can fabricate a
  structurally valid quote carrying up to 144 arbitrary bytes (type 1) or up to
  548 bytes (a truncated type-4 quote) of arbitrary "ciphertext" to the declared
  endpoint. That is inherent to a passive shape
  check and to the user's allowance; it stays confined to the declared endpoint.

## Verdict

**FAIL — one Critical (R5-P1), on the reviewed commit 649a5e2.** No other
Critical/Important findings; the remaining items are Minor. The controller's
post-gate 819547b appears to address R5-P1, but the live PASS evidence was
produced with the reviewed scanner; retained captures should be re-scanned with
the fixed scanner before that evidence is relied upon (not verified here).

VERDICT: FAIL
