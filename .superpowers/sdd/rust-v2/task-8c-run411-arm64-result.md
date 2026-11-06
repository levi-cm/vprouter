# Task 8c run 411 ARM64 result and read-only diagnosis

2026-11-06. **FAIL; consumed one-shot budget = 0. No fix or further experiment implemented.**

The evidence rules out the lab's 250/75/120/110-second limits. The strongest source localization is the **product's ordinary two-second HOST baseline admission window**, after producer binding and before the first host-link operation, inside `handoff.host`. This is **not** the later three-scope Bootstrap exchange's two-second window. The frozen source and retained state support that localization, but the failed baseline's absolute `requested_at`, exact failing poll/check and per-operation CPU/wait breakdown were not exported. They cannot honestly be supplied as measured facts.

TCG execution overhead is the leading explanation. An ARM-specific functional defect is not demonstrated, and neither universal failure nor eventual success on this x86 host is established. Increasing a lab timeout would not address the implicated product deadline.

## Scope and evidence authority

The brief named workspace `rust/v2 @d4c7f73`; the actual checkout at this diagnosis was `ad83192eec1068ab3b6f056e5ddd0221acb48c75`, initially with empty `git status --short`. No checkout/index/branch/ref writes were made. Product analysis uses candidate source commit **`da7556282d5fc828a9391a64ab47adab05a55510`**, as bound by both raw runs and candidate.json, rather than assuming the workspace is the executed source.

All Rust `file:line` references below refer to archive members extracted from the verified `target/candidates/run410-da75562-20261104/source.tar` into **`/tmp/run411-diag/source/`**, then made non-writable. For example, `crates/vprouter-launch/src/attachment/host_addition.rs:116` means `/tmp/run411-diag/source/crates/vprouter-launch/src/attachment/host_addition.rs:116`. Captured runner/guest references use directory **`target/candidates/run410-da75562-20261104/bootstrap411-arm64/`**, abbreviated **B/** below. Those captured bytes were checked against raw-record hashes. No current product source was substituted.

Offline verification rehashed all **61** entries in C's retained-file receipt and all **35** reservation bindings, with zero mismatches; it also verified source, payload, context, captured guest/runner/builders and exact equality between captured controller.stderr and raw.stderr. These are preservation checks, not a rerun of the executable, provenance program, parser, admission or tests.

Read-only strict SSH used port 22034, dedicated `target/lab-state/id_ed25519`, pinned `target/platform-lab/debian-arm64/known_hosts`, `-F /dev/null`, `GlobalKnownHostsFile=/dev/null`, `IdentitiesOnly=yes`, `IdentityAgent=none`, `StrictHostKeyChecking=yes`; privileged reads used `sudo -n python3 -I -` **inside the guest only**, as the 411 tools do. No sudo was run on debdev. No guest writes, signals, unmounts, Docker changes, QEMU/QMP calls, reservation creation, subagents or Git writes were requested or performed. Inspection scripts/output and offline derivations are under `/tmp/run411-diag/`; this report is the only requested workspace output.

## Immutable facts and hashes

Claim start: `2026-11-06T15:02:29.548047+00:00`; raw record completion: `2026-11-06T15:03:17.960407+00:00`. Raw wall **40.092s** measures the guest harness subprocess, including fixture work and postprocessing, starting after upload (`B/controller-runner.py:90–98`); it is not a 40-second product operation.

Raw exit 1, owner launcher exit 1 with empty launcher stderr, last payload stderr `secret_bootstrap_lab: deadline`; one Bootstrap phase marker (`handoff.host begin`), 48 successful attachment phase rows, 150 journal-stage rows, zero closed Bootstrap boundary rows, zero Bootstrap witnesses. C reports `failed_bootstrap_preserved`, `provenance_valid=true`, `runtime_acceptance=false`, `release_ready=false`. P's retained error is `invalid_closed_bootstrap_diagnostic`; its requirement for exactly one boundary is `tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py:108–115`. P refusal is correct and supplies no zero-valued cost sample.

| Artifact | Verified SHA256 |
| --- | --- |
| `target/candidates/run410-da75562-20261104/candidate.json` | `ea3634b4e4140b3b3db8fdaf12b9c47c1b3757c9862f33001cbc022ef2d225f6` |
| `target/candidates/run410-da75562-20261104/source.tar` | `899dd5c843f6af2d86305e0380ca79006570de874d9356b725f24e91b09d8959` |
| `target/candidates/run410-da75562-20261104/arm64.payload` | `5b78458c995556227417cb7939e13cc811dba3ad8dbcdfdd342404df84e09631` |
| `target/candidates/run410-da75562-20261104/arm64.context.tar` | `51023de0b7bbab71a40e1882662d50327d8643f1f45051c466655207666f406d` |
| `target/lab-state/actual-program-run-411.json` | `a69050610bde2a1d78b23aabf30335afb4576919bc897c9cb872435a3cea9f61` |
| `target/lab-state/actual-program-run-410.json` | `bd3d1819f6387491c69388b371f9b05fa28d5e773658223f950ffd743413f0ff` |
| `target/lab-state/run-411-consumed.json` | `4d4e9a94f7d05ca10e13378ea365f395728371b47a8a953868cfb361d042b210` |
| `target/run411-evidence/receipt.json` | `c6cc9a82dd7104b23f4449f26b7c9b5fba06b5074038f6c256fddcca0694c422` |
| `target/run411-evidence-post-state.json` | `5bf3a6aebde38bd9092cbee45ee9c869a57a2eb739b21870122e1f94b8604b19` |
| `target/lab-state/secret-bootstrap-failure-run-411.json` | `44abbf1af8e9a7ac44fa43cf0bbe780370c777f19d70366290fae69a5f737857` |
| `target/run411-prep/tcg-budgets.json` | `9c2d8579935e7810bb98b2429c04ccd9ffd578ee01158219ace940c6d8ee503e` |
| `/DATA/vprouter-lab/run411-exec/P.err` | `75e961be9b275e0a70968294bae3889420b195000d81db45fab380fb56814a8f` |
| `target/candidates/run410-da75562-20261104/bootstrap411-arm64/controller-runner.py` | `a8590b6e30837b052a655ace45d670daaa6485706d10eb37f6fc09533d47cb2d` |
| `target/candidates/run410-da75562-20261104/bootstrap411-arm64/controller-guest.py` | `12a4d66ec4284a6d5de06bb3ac9fa6387514b94a4d7f3b78d9d8f525b86548a1` |
| `target/candidates/run410-da75562-20261104/bootstrap411-arm64/controller-context.py` | `66be3dc0ba17ec34e551a39f37218259af8df5d3eb996f9f7986f4bdf37b9635` |
| `target/candidates/run410-da75562-20261104/bootstrap411-arm64/controller-host-declaration.py` | `c5a1bd0afa835854be4558237c36bb50c1e38758614b96f55a5bf97f5832e164` |
| `target/candidates/run410-da75562-20261104/bootstrap411-arm64/controller-baseline-declaration.py` | `367d2322ea841a81d9ec00006f7c38cf694300cffb77783e4f72903317d1a212` |

Source binding also records 203 tracked build inputs and aggregate SHA256 `3ebe34b0755fa622ffb0fc5f61dbd61605d90647373c7463d18bff7fea3085cb`. Reservation SHA256 is `85f4502ba9d79f037f9d2c69e97d42822d06079bc8192cc9d4037e32b632aa2b`. ARM64 baseline template SHA256 is `0c12af862d43f61c81cbafa8da3ad1ba19456c1c100180f8cecad971a6783951`; reconciliation SHA256 is `e1bb0958da3a568753ef15adcd29371516693346f6b670ef346d1484f445525f`.

## 1. Which deadline and where

### Error propagation and timer owner

The exact printer is `crates/vprouter-launch/src/actual_lab_main.rs:157–172`: `--ignored-secret-bootstrap` selects fault 0, `run_secret_bootstrap(0)` returns an error, line 170 prints `secret_bootstrap_lab: {error}`, line 171 exits1. `transport_lab.rs:2403–2405` calls the operational lab runner. Its `attachment/operational/bootstrap.rs:640` calls `lab_handoff` **before** Measurements construction at 662 or PendingBootstrap construction at 697. `attachment/operational.rs:473–475` emits host-begin, calls `host_addition::lab_added()?`, and only then emits host-ok. Thus the printed prefix does not identify the later Bootstrap protocol as the failing operation.

Within host addition, `attachment/host_addition/operation.rs:697–710` first obtains the producer-bound assembly, then constructs PendingHostAddition. Lines720–728 poll admission **before** the four-operation host-link loop at756–814. An error in that later loop would emit `LAB_SECRET_HOST_ADDITION_FAILURE` at825–837; none exists. A producer-binding poll error would emit `LAB_SECRET_PRODUCER_BINDING_FAILURE` at `attachment/producer_binding.rs:809–822`; none exists. Canonical F already contains producer-binding query, native birth, result, verified time and published producer identity, but contains no host-link histories or host endpoint. Its 75 journal constructors match the source's 75-writer producer-binding prefix (`producer_binding.rs:964–1006`); run410 reaches 87 before the host-summary markers.

The intervening production timer is created by `attachment/host_addition.rs:159–181`, **owned by PendingHostBaseline::Native.requested_at**. Its check is:

```rust
// frozen attachment/host_addition.rs:116–123
self.check_custody()?;
self.binding.verify(self.input.host_service()?)?;
let now = vprouter_core::health::boot_seconds();
if !now.is_finite() || now < self.requested_at || now >= self.requested_at + 2. {
    return Err(Error::Deadline);
}
```

The same end `requested_at + 2.` is passed to HostAuthority::begin_declared (`host_addition.rs:205–213`). Checks occur in construction at 199/215 and before/after every admission poll at 228/245. The native two-read admission and HostRead also enforce that same end (`crates/vprouter-network/src/guarded/host_admission.rs:73–79,100–142`; `native/host_read.rs:75–80`), but network-layer errors are mapped to launch `NetworkOperation` at `host_addition.rs:213,234`. The observed top-level **Deadline** therefore points to the launch-side `check_current` path, assuming the ordinary finite, forward clock observed elsewhere in this run. The constructor's invalid-clock guard at159–162 is another theoretical direct Deadline return; there is no observed invalid clock supporting it.

**Precision limit:** the retained evidence does not distinguish constructor check 199/215 from poll check 228/245, reveal the failed baseline's actual numeric start/end, count its polls, or identify which of its two native reads/dump phases was outstanding. Source localization to this two-second window is strong; it is not a captured closed failure boundary. Do not relabel any of the three logged attachment deadlines below as the expired baseline deadline. A producer-binding postfault row cannot be expected on fault 0: its Drop diagnostic is explicitly restricted to `fault != 0` (`producer_binding.rs:661–670`).

The last canonical native producer result was verified at7920.442190480; owner exit was recorded at7923.100368. Under the above localization, the baseline start is later than the former and its two-second end no later than the latter. This brackets the start approximately within `(7920.442190480, 7921.100368]` and end within `(7922.442190480, 7923.100368]`; these are **derived bounds**, not recovered timestamps. The canonical result's time precedes its writer ACK and final parent checks (`producer_binding.rs:530–546`), so it is not the baseline start.

### Lab timer exclusion

| Budget | Source | Observed disposition |
| --- | --- | --- |
| Guest outer250s | B/controller-runner.py:95–98 | Returned exit 1 at40.092s; outer timeout path would set124. |
| Docker build75s | B/controller-guest.py:88 | Build exit 0, fixture/image/container and owner execution followed. |
| Owner launcher120s | B/controller-guest.py:172–176 | Returned exit 1, not Python TimeoutExpired. |
| RuntimeMaxSec110s | same line 172 | Journal reports normal `code=exited,status=1`, result `exit-code`, after13.851122s from Started; no runtime-limit kill. |
| Product ordinary window2s | frozen host_addition.rs:116–123,159,211 | Implicated HOST baseline admission window; frozen and not adjustable here. |

Read-only guest journal `/tmp/run411-diag/guest-journal.txt:75–81` records service starting7909.169881, started7909.249246, exit7923.100368; consumed **12.946s aggregate service CPU**, memory peak23.2M. Aggregate cgroup CPU includes descendants and does not identify parent CPU, fork cost, journal cost or baseline CPU. Owner absence afterwards is expected from the runner's `--wait --collect`; it is not evidence of a vanished pre-run unit or a 110-second kill.

## 2. Timeline and comparison with run410

All numeric operation timestamps below are guest CLOCK_BOOTTIME seconds. Different boots' absolute values are not compared. `health.rs:184–187` uses rustix ClockId::Boottime; this is not an x86 syscall number hard-coded in the product.

The first **123 stderr row signatures match** between410 and411 after replacing attachment timestamps with their `(scope,phase,ok)` signature. This includes every one of the 48 phase rows; all are `ok=true`. After line 123,411 has76 further journal-stage rows (38 pairs), then the final error at 200. Run410 has100 further rows (50 pairs), then `host.writer_summary begin` at 224 and subsequently host/handoff/Bootstrap success. **No ARM phase reordering is observed.**

The 48-phase diagnostic cap explains why constructors after movement have no phase timestamps: `attachment.rs:181,193–198` allows48 emissions. The last logged phase is not the last executed operation. Full paired phase timestamps and durations are in `/tmp/run411-diag/attachment-phases.tsv`; original line numbers refer directly to B/controller.stderr and the extracted 410 stderr.

| Stderr lines | Window / milestone | ARM64 start → end or completion | ARM64 elapsed | x86 elapsed |
| --- | --- | --- | --- | --- |
| 8–61, except60 | Initial inspection original window | 7909.800756453 → 7911.800756453 | pending_attachment_new finishes +0.948621s | +0.182019s |
| 19–22 | Initial query constructor | 7909.872372879 → 7909.889949565 | 0.017577s | 0.000697s |
| 22→27 | Initial clone complete → result acceptance starts | 7909.889949565 → 7910.318225688 | 0.428276s | 0.078833s |
| 28 | Open original process | 7910.319699895 → 7910.354115269 | 0.034415s | 0.001388s |
| 34–37 | Second query constructor | 7910.411340141 → 7910.419884868 | 0.008545s | 0.000642s |
| 37→42 | Second clone complete → result acceptance starts | 7910.419884868 → 7910.705808827 | 0.285924s | 0.057441s |
| 48 | Final original inspection deadline check | finishes 7910.723685146, before 7911.800756453 | +0.922929s from request | +0.180999s |
| 60,72–75 | Data mount/recheck original window | 7910.731259890 → 7912.731259890 | clone finishes +0.282199s | +0.080861s |
| 122–123 | Movement recheck constructor (last emitted phase) | request 7913.165147904, deadline 7915.165147904 | sockets finish +0.100667s | +0.018446s |

The clone-to-accept gaps include native execution, durable journal work, polling and scheduling. They are **not isolated fork/exec or Docker latency measurements**.

F's canonical preparation fills the post-cap gap. Here “finish” is the stored native verified time, or published time for namespace mounts; it is **not** the enclosing writer ACK/final parent completion time. Most grouped query/operation pairs share a single original deadline, so they must not be counted twice.

| Operation/window | Requested at | Deadline | Canonical finish | ARM64 elapsed(s) | x86 elapsed(s) |
| --- | --- | --- | --- | --- | --- |
| secret validation | 7909.572898999 | 7911.572898999 | 7909.741186672 | 0.168288 | unavailable here |
| initial + recheck inspection | 7909.800756453 | 7911.800756453 | 7910.666891762 | 0.866135 | 0.165819 |
| data namespace mount + recheck | 7910.731259890 | 7912.731259890 | 7911.315759142 | 0.584499 | 0.130872 |
| fresh transport create | 7911.373895309 | 7913.373895309 | 7911.488956125 | 0.115061 | 0.030761 |
| fresh transport mount | 7911.525810393 | 7913.525810393 | 7911.699417983 | 0.173608 | 0.050833 |
| wireguard sockets | 7911.754369994 | 7913.754369994 | 7911.902640649 | 0.148271 | 0.030854 |
| wireguard provision | 7911.969882855 | 7913.969882855 | 7912.673764636 | 0.703882 | 0.194213 |
| wireguard query | 7912.731533876 | 7914.731533876 | 7912.920991212 | 0.189457 | 0.072417 |
| wireguard data_sockets | 7912.993430166 | 7914.993430166 | 7913.115344448 | 0.121914 | 0.050534 |
| wireguard move | 7913.165147904 | 7915.165147904 | 7914.204381287 | 1.039233 | 0.187862 |
| netfilter sockets 1 | 7914.403529432 | 7916.403529432 | 7914.765045245 | 0.361516 | 0.049378 |
| netfilter initial_quarantine 1 | 7914.980385391 | 7916.980385391 | 7915.325211702 | 0.344826 | 0.052888 |
| netfilter sockets 2 | 7915.535300622 | 7917.535300622 | 7915.759919336 | 0.224619 | 0.045058 |
| netfilter initial_quarantine 2 | 7915.895492598 | 7917.895492598 | 7916.144839177 | 0.249347 | 0.071491 |
| netfilter sockets 3 | 7916.269680195 | 7918.269680195 | 7916.515995850 | 0.246316 | 0.045016 |
| netfilter initial_quarantine 3 | 7916.695726768 | 7918.695726768 | 7917.667856411 | 0.972130 | 0.160596 |
| producer creation + query | 7918.139021632 | 7920.139021632 | 7918.988991397 | 0.849970 | 0.140472 |
| producer binding + query | 7919.359268780 | 7921.359268780 | 7920.442190480 | 1.082922 | 0.174059 |

These are **18 distinct, canonically recorded preparatory windows** with native results before their ends; post-result ACK/final checks consume additional time. MovementRecheck shares the WireGuard move window; QuarantineRecheck shares the third initial_quarantine window; producer creation/binding each share their recheck window. No completed host-baseline admission or host-link window is recorded in411.

In410, host-baseline admission starts4645.667325702, ends4647.667325702, accepts4645.810334896: **0.143009194s,23 polls**. Its four later host-link operations start4645.820818890 /4645.943664771 /4646.147702387 /4646.249580764. All complete, host handoff finishes, then the 20-job operational handoff and all three Bootstrap scopes complete. In411, none of those four host-link jobs or20 handoff retirements is established. “handoff.host begin” does not mean the 20-job transfer began.

The 150 `LAB_JOURNAL_STAGE` rows are **75 constructor invocations, each with inventory and inventory_verified**, not150 stuck iterations of one inventory loop. Their source is `kernel.rs:1757–1785`: verify descriptor inventory, create IPC, then fork with pidfd for a specific journal write. The markers have no timestamps or write-phase labels. Their paired presence proves inventory verification passed at those constructor points; it does not independently export each child wait status, fsync latency or parent ACK. Later canonical producer publication demonstrates progression through the prefix, while410 exports the complete75-writer prefix and reaches12 further host-link writers. No new journal constructor is observed for the failed baseline admission; that stage is read-only.

## 3. Cause, ARM-specific alternatives and feasibility

**Leading mechanism: insufficient execution time for HOST admission and its repeated ordinary-owner validation under TCG.** Two complete ROUTE observations, each covering links/IPv4+IPv6 addresses/routes/rules, must fit the same original 2s. Native reads yield after bounded receives and phase advances (`native/host_read.rs:126–168`); admission takes two such reads (`guarded/host_admission.rs:100–142`). Launch surrounds each poll with `check_current`, which rechecks custody, protected declaration, existing producer history, retained namespace descriptors and binding before checking time (`host_addition.rs:80–123,227–245`). There is no systemd-run or Docker CLI launch in this baseline stage. It is plausible that repeatedly validating the now-long prefix consumes the budget even though a standalone native GET projection is fast. **No per-poll timing was recorded, so parent validation versus netlink receive/scheduling cannot be quantitatively separated.**

| Hypothesis | Evidence and disposition |
| --- | --- |
| Slow TCG execution / repeated parent validation | Strongly supported by broad slowdowns: query constructors ~13–25×, original-process open~25×, initial full assembly0.949s versus0.182s, canonical producer binding1.083s versus0.174s; normal product Deadline, heavy aggregate service CPU. This is an uncontrolled cross-architecture/cross-boot comparison, not a causal CPU attribution experiment. |
| A single fork/exec or systemd-run exceeded2s | Unsupported. Observed query clone/identity phases are ~0.0027–0.0032s and include more than the syscall. Prep systemd-run max0.313s. The expired baseline read stage performs no new native child fork or systemd launch. Successful earlier journal/native births rule out general inability to fork. |
| Docker build/run consumed a product deadline | Build and inert container creation precede the product's operation windows. Fixture build succeeded. Native Docker query exchanges are slower but completed before their respective original ends. There is one pre-owner dockerd HTTP2 connection-reset log at7892.074811 (`guest-journal.txt:61`); owner starts7909.249246 and later Docker inspections succeed. No evidence links that isolated log to the later baseline timeout. |
| Infinite journal io_inventory loop or missing descriptor feature | Markers are75 paired constructors, not one inventory spin; no unpaired inventory marker, descriptor-inventory error or failed birth is observed. Journal/fsync work can contribute earlier elapsed time, but its cost within the failed baseline is not measured and baseline itself starts no writer. |
| ARM clock/syscall/seccomp/cgroup/page-size defect | No affirmative evidence. Guest is 6.12.113+deb13-cloud-arm64, 4096-byte pages, clocksource arch_sys_counter. Prep directly tested aarch64 clock_gettime syscall 113 for clocks 3/7; product uses rustix Boottime. Original deadlines differ by exactly2s and recorded times progress forward. Native secret validation, mounts, WireGuard sockets/provision/move, nftables and producer cgroup creation/publication all progressed. F records AppArmorBuiltinSeccomp Docker query facts. These facts do not qualify every later ARM-specific syscall. |
| Missing kernel feature / EPERM / OOM / fatal security denial | Read-only full system journal for the run and warning/error dmesg were inspected as guest root. No run-time EPERM, seccomp/AppArmor denial, ENOSYS, OOM, clocksource instability or missing-feature error explaining this failure was found. Earlier boot has GPT capacity warnings, KASLR seed absence and AF_VSOCK generator failures (last before run at569.666284); not attributed to this failure. Kernel audit suppression exists at160.724309, so absence of an audit message is not proof that every syscall succeeded. Gateway OOMKilled=false; process exit is1, not SIGSYS/SIGKILL. |
| Product ARM-only logic defect | Not established, not exhaustively excluded. Same logged ordering and successful prerequisite features favor a timing failure. A performance/timing defect in product validation could coexist with TCG overhead; there is no controlled native ARM comparison or cost sample to decide that. |

Read-only journal/dmesg evidence was collected at15:09:07Z on original boot525e9103-b2f9-4611-a663-ced9d001245a. The first unprivileged dmesg attempt was denied; the subsequent guest-root read succeeded. No denial is being misreported as successful inspection.

### Could any ARM64 run on this host pass?

**Unknown; this run failed, and no pass probability or impossibility proof exists.** All18 recorded preparatory windows fit 2s, with canonical spans0.115–1.083s; this does not bound the failed admission or later Bootstrap. The standalone frozen HOST projection measured0.127042s outer /0.086322s internal before the run, but omitted the accumulated live custody/polling path. It cannot qualify that path.

Existing TCG prep measurements: Python startup0.073–0.091s; systemd-run /bin/true0.158–0.313s; two synthetic no-cache48MiB scratch builds17.137/19.787s versus75s; payload/context SCP1.751/2.331s versus30/45s. They justified retaining lab budgets, not a claim of native protocol fit (`target/run411-prep/tcg-budgets.json` and prep report, Measured TCG overhead and budgets). The actual owner duration13.851s and harness40.092s likewise leave ample outer lab headroom.

A **KVM-capable aarch64 machine** is the preferred next substrate for unchanged-product qualification; debdev's x86 KVM cannot accelerate an aarch64 guest. Faster TCG execution or materially reduced host contention might pass, but neither a sufficient speedup nor the failed baseline's required duration is measured. Even on native ARM, every ordinary window and later three-scope exchange would still need a separately authorized real run. **No reviewed LAB-TIMEOUT-ONLY adjustment is indicated:** none of those lab timers fired. Relaxing the product's 2s window would change the frozen acceptance target and is outside this task.

## 4. Selector archival A disposition

**Technical GO for the exact six-selector archival, at the inspected state, subject to A's own fresh fail-closed checks. A is NOT_RUN; executing it is NO-GO within this expressly read-only task.** This is a review disposition, not a cleanup authorization, experiment authorization or new reservation. I's retained `archival_authorized=false` remains unchanged.

F is present, read_only=true, bound to raw SHA/source/platform, owner unit not-found, original owner cgroup absent (`target/lab-state/secret-bootstrap-failure-run-411.json:4034–4042`). C is provenance-valid; all referenced 35 reservation bindings and 61 retained hashes still match. Fresh guest reads at15:09:07Z and15:11:50Z supplied the additional owner/child/mount/selector review required by the controller's failure policy (`B/controller-guest.py:202`):

- Original owner is unit `vprouter-v2-owner@d2bd209fec0f486714392b1b933bc2d99d6eb582969fde481dde45c8a98db569.service`, canonical PID 3581/start 790916/invocation709efd70462241fb861eba626a8c27d8. Unit remains not-found; original cgroup inode 11155 is absent. Process listing has no surviving owner payload/native child; the retained producer child cgroup(dev 29,ino 11245) has empty cgroup.procs and populated 0. This is post-exit quiescence, not recovered child wait-status proof.
- Original inert gateway container665c7439a93cfe618245faec02f9f0da573cb3ba257862e27890a4465eb73a87 remains running, PID 3550/start 790656/StartedAt2026-11-06T15:03:01.638818431Z, live pidfd, original netns[4,4026532208], Docker network none, Mounts[], OOMKilled=false. Parent cgroup(dev 29,ino 10050) contains3550; nested producer group(dev 29,ino 11245) remains retained and empty.
- Exact canonical owner-directory mounts remain data `vr-data-a31a3a8d907e77e4` → nsfs[4,4026532208] and transport `vr-trans-a31a3a8d907e77e4` → nsfs[4,4026532266]. They match F's canonical identities. Canonical allocations/namespaces remain retained; no host endpoint was added according to the completed controller summary. No mount is to be unmounted by A.
- Exactly six fixed selectors match F's device 65025, inode, size and SHA; all root:root 0600, regular, nlink 1. Inodes in order are 135473/135472/135480/135481/135476/135477 for owner-domain-nonce / secret-attachment.json / secret-attachment-spec.json / secret-attachment-staging.json / secret-quarantine-host.json / secret-host-baseline.json. Inputs directory is root:root 0700(dev 65025,ino 262202); all six 411-failed destinations are absent. task8b2-image and task8b2-host-acceptance are absent and are not part of this archive.

A's code (`target/archive-secret-bootstrap411-selectors.py:8–23,37–57`) checks failed raw/F/source/provenance bindings, original boot, owner absence, gateway identity/pidfd/netns and exact selector metadata/content. For each selector it **hard-links the original inode** into `/var/lib/vprouter-v2-lab/secret-inputs-<nonce>/411-failed-<name>`, then unlinks only the fixed pathname and fsyncs both directories (`:49–55`). It writes a new local selector-archive receipt (`:61–62`). It leaves gateway, profiles, canonical records, cgroups and namespace mounts in place. It sends no signals, performs no unmount, and does not erase the failed experiment. Its source SHA is `3adf1409d095ae2c3763f655f4a4c567d2edad77691dbfa9b8be145746011f5a`, matching the reservation.

If an authorized controller later performs A, the exact existing invocation is:

```text
python3 -B target/archive-secret-bootstrap411-selectors.py 411 target/candidates/run410-da75562-20261104/bootstrap411-arm64/directory-binding.json
```

This command was **not executed**. A's predicates must still hold at that future instant; this report cannot pre-approve changed selectors, a different boot, replacement processes or extra cleanup.

## 5. What411 establishes and what remains open

Established by this evidence chain:

- Frozen ARM64 static payload/context admitted with exact hashes and ELF 183/no dynamic interpreter checks in the retained preparation inventory; no rebuild or product deadline change.
- Actual arm64 Docker fixture build exit 0, exact inert gateway image/container created and retained, strict SSH read path worked.
- Real owner payload executed on aarch64; secret validation and the 18 canonical preparatory windows above progressed through namespace attachment, fresh transport, WireGuard provision/move, quarantine and producer publication.
- Same48 logged attachment phases and ordering as 410; 75 paired journal constructor inventory checks; failure preserved with selectors/canonical resources and no new HOST link.
- Product ordinary timing failure localized with the precision limits stated above; outer lab exhaustion ruled out. C's preservation/provenance success is distinct from protocol acceptance.

**NOT_RUN / NOT_ESTABLISHED:** completed HOST two-read baseline admission on411; exact failed baseline start/end/poll/native-read phase; per-operation parent CPU/off-CPU/scheduler/fork/fsync/Docker attribution; closed Bootstrap cost parsing or fabricated substitute rows; four host-link operation completions; 20-job handoff retirement; Bootstrap constructor/three-scope exchange/ACK completion; full typed Bootstrap witness validation; fault variants; new timing measurement or rerun; KVM/native ARM comparison; A execution/cleanup/unmount; real-provider profile use, real clients, health READY, UP/placement/producer exception, multi-exit runtime, migration, performance/soak or release acceptance. `release_ready=false`; Task 8c remains open. Existing prep's two synthetic samples are not a statistical bound.

## Exact next steps, with no implementation in this task

1. Preserve run411's consumed claim, raw/C/I/F/P refusal, frozen source/payload/context, guest disk/seed/key/pin, live inert gateway and canonical/mount resources. Do not rerun411, change a timeout, synthesize parser input or normalize selectors. Budget remains 0.
2. Hand this report to the controller for the exact selector-only A disposition above. Any actual A remains outside this read-only assignment; recheck its live predicates and preserve its output if separately authorized. Do not equate selector archival with guest cleanup or acceptance.
3. For exact baseline-call localization, review a narrowly scoped observer proposal **before any implementation or new run**: capture existing PendingHostBaseline start/end, constructor/poll entry/exit, admission read/dump phase and bounded parent CPU/wall counters without changing clocks, windows, custody, state transitions, or issuing additional native work. The present source provides no recoverable absolute baseline timestamp, so further static inference cannot close that gap. Any candidate/observer change needs fresh binding/review and separate one-shot authorization; none was made here.
4. Prefer unchanged frozen ARM64 qualification on a separately authorized KVM-capable aarch64 substrate. If continuing TCG instead, first review whether improved execution capacity can meet the same ordinary window; do not infer sufficiency from SCP/build/systemd measurements. No reservation or host provisioning is created by this report.
5. Only after a newly authorized run supplies a qualifying result, apply its proper typed witness/closed diagnostic validation and remaining acceptance gates. Preserve the distinction between static admission, component progression, Bootstrap success and release readiness.

## Reproducibility of this diagnosis

Scratch files: `analyze.py`, `analysis.json`, `hashes.txt`, `canonical-timeline.tsv`, `attachment-phases.tsv`, `run410.stderr`, `run411.stderr`, extracted frozen source, `guest-inspect.py`/`.jsonl`/`.stderr`, `guest-journal.txt`, `guest-dmesg.txt`, `archive-review.py`/`.jsonl`/`.stderr`, initial unprivileged SSH read output and report-generation script. Only original public evidence was read; private profile contents and key bytes were not printed or inspected. New SSH reads are later observations, not relabeled original execution samples.

The report uses existing prep and 409/410 reports for context; causal conclusions and hashes above were refreshed from the specified run411/run410 records and frozen source. No historical 402–408 data was promoted into new ARM runtime evidence.
