# Task 8c run 409 diagnosis: inventory order, not foreign ownership

2026-11-04. Research-only investigation in `/DATA/AppData/vprouter-rust-v2`, branch `rust/v2`, workspace HEAD `a4f564b6a6fe59c46adec9c475f39982c545a5c7`.

## Root cause

Run 409 exposes an order-sensitive **lab oracle defect**, triggered by the fresh baseline's JSON serialization order. It does not show an unexpected Docker link, a missing foreign object, or a failed native ownership check.

The failing Rust block is `crates/vprouter-launch/src/attachment/host_addition/operation.rs:1065–1088`, inside the `#[cfg(test)] lab_build` function declared at lines 652–656. At lines 1068–1071 it compares `operations[3]["host_observation"]` against the authored declaration with **ordered JSON-array equality** for namespace, addresses, routes and rules. The guaranteed mismatching predicate is:

```rust
// operation.rs:1069–1071, key == "routes"
if actual[key] != declaration[key] {
    return Err(Error::OwnershipMismatch);
}
```

The baseline stores seven IPv6 routes before twelve IPv4 routes; the native reader always appends IPv4 before IPv6. Both contain the same nineteen complete records, including multiplicity. Rules have the same secondary problem: two IPv6 rules precede three IPv4 rules in the baseline, while native reads use the opposite family order.

The frozen projection and the preserved live snapshot both reproduce `routes` as the first failing key in the loop. Namespace and addresses compare exactly; rules would also fail if execution reached them. The error label `ownership_mismatch` therefore overstates what this assertion actually detected.

### How the order discrepancy was created

1. `tools/rust-v2-lab/fresh-baseline.py:29–31` collects route/rule families in numeric order `[2, 10]` (IPv4, IPv6).
2. Its `canonical`/`save` functions at lines 60–67 serialize dictionaries using `sort_keys=True`. In the saved `target/rebuild-phase3/independent-netlink.json`, the dump keys consequently become:
   `18/0, 22/0, 26/10, 26/2, 34/10, 34/2`.
3. `decode` iterates `data["dumps"].items()` at lines 94–99 after that file is reloaded at line 142. Lexicographic dictionary order thus becomes array order: IPv6 before IPv4. Offline decoding of this original saved dump reproduces the authored baseline exactly.
4. `target/platform-lab/host_baseline_declaration.py:128–144` preserves the baseline arrays when constructing the run declaration. The raw run's `secret_host_baseline.declaration.baseline` equals the authored template exactly.
5. The run controller compares full multisets before staging (`target/candidates/rebuild-20261103T231415Z/bootstrap409-driver-cost/controller-guest.py:138–145`). The independent comparison also sorts complete records (`fresh-baseline.py:161–167`). Both correctly accept these equal inventories.
6. The native parent read uses a fixed phase chain, IPv4 then IPv6, and appends records without sorting (`crates/vprouter-network/src/native/host_read.rs:5–24,83–103,229–233`). The final lab oracle then applies a stricter, inconsistent sequence comparison.

Concrete examples: baseline `routes[0]` is `fe80::/64`, output 2, table 254; frozen/native-family-order `routes[0]` is the IPv4 default route via `10.0.2.2`, output 2, table 254. Baseline `rules[0].ipv6` is true; projection/live `rules[0].ipv6` is false. Those are different positions, not added or modified network objects.

## Evidence and limits

The workspace HEAD is not the run's source commit. Run 409 binds source commit `1b65709a1189a5fff0fb62c47877e349d4f4f0c4`, source archive SHA256 `4b0c5af101405476e130c61cbedf041a6542c401e2eb324045982488b9c70807`, and amd64 payload SHA256 `d8ae01f00e540879fe0e3cd68200b2f13677f441e057d2718137ec5d965ba715`. Both files were hashed against these bindings. The ten cited Rust implementation files were compared byte-for-byte with the frozen archive and match the current workspace; final verification compares all 179 archived Rust sources byte-for-byte and checks their tracked paths. Two tracked standalone lab cost probes are outside the build archive: tools/rust-v2-lab/allocation-comparison-cost.rs and digest-hex-cost.rs.

Evidence files, all retained:

- Raw `target/lab-state/actual-program-run-409.json`: SHA256 `dcc98329705e32789a27ec3b70af36921b08c6f1d0066c868afa0f62e3e220ce`; exit 1. Its final markers are `host.writer_receipts event=ok`, `host.inventory event=begin`, then `secret_bootstrap_lab: ownership_mismatch`. There is no inventory-ok marker.
- Authored template `target/candidates/rebuild-20261103T231415Z/authored-host-baseline-debian-clean-x86_64.json`: file SHA256 `4817afb853dea681b52954f863007f59ab286d2896d8358264bd92fc357144e1`; inner baseline SHA256 `da3f80f0da4c717443fcb9a2118ed938a6d5c4edeea69d40e755b97291b5a01a`.
- Reconciliation in that directory: SHA256 `b2f247d17b1c05ced086611fe88ebda8cadfc5438429cf823fdf2c836afe453d`. It explicitly records fresh discontinuous provenance, counts 3/6/19/5, and no causal speedup control.
- Frozen `host-projection-debian-clean-x86_64/record.json`: SHA256 `702cf3176a9828075cb7befb6b5f96be8dff02492b831781da1ab01270891e36`. Namespace and all complete record multisets match the template. Routes and rules differ only in array order.
- Existing C/I/F outputs were read, not regenerated. I reports original gateway identity matching; F's canonical `namespaces.json` contains four host-link histories with non-null results and verification times. Its move result identifies the planned down veth described below.

One new SSH inspection at `2026-11-04T16:16:58Z` used only the dedicated key and pinned known-hosts file, with the exact confinement argv in `target/run409-diagnosis/guest-receipt.json`. Guest commands were RTM_GET link/address/route/rule dumps and two narrow `docker inspect --format` reads. No product executable, Bootstrap, controller or selector operation was invoked.

The guest boot remains `e14efc10-050b-41b0-89d8-1e946725098c`; kernel `6.12.113+deb13-cloud-amd64`; HOST namespace `[4,4026531840]`. The original gateway PID/start, StartedAt, namespace and live pidfd still match. Docker network mode is `none`.

| Inventory | Authored baseline | Preserved live snapshot | Comparison |
| --- | --- | --- | --- |
| HOST namespace | [4,4026531840] | same | Exact equality |
| Foreign links | lo/1, ens2/2, docker0/3 | same three, plus planned link | All original complete link values equal |
| Addresses | 6 | 6 | Exact ordered equality |
| Routes | 19, IPv6 first | 19, IPv4 first | Equal complete multisets; unequal arrays |
| Rules | 5, IPv6 first | 5, IPv4 first | Equal complete multisets; unequal arrays |
| Added link | absent | vh830667b5b5c4/616680572 | Matches F's move result and planned index; down |

The added veth has MTU 1420, peer index 3, alias `vprouter-v2:secretlab-e5e7bc1e7993:1:ae5e7bc1e7993`, and no additional HOST addresses/routes/rules. It is the intended native addition. Docker0 and its IPv4 routes/addresses were already in the baseline.

Normal native validation had already succeeded before this lab assertion. Movement requires a complete HOST multiset check at `crates/vprouter-network/src/secret_role/veth/movement.rs:493–505`, then commits the same observation through `guarded/host_addition.rs:249–273`. `guarded.rs:1208–1214` uses `same` for every record collection; `audit.rs:180–193` implements full-value multiset equality with multiplicity. The later lab block disagrees with those established semantics.

**Limit:** the exact in-memory run-time `operations[3].host_observation` was not exported before the oracle returned. It is not recoverable from F's link-only public result. The route-family mismatch is deterministic from the frozen source and declaration; the reported first failing key is additionally reproduced using both the pre-run frozen projection and the later live snapshot. The later snapshot is not relabeled as the original operation's observation. Successful native validation and completed journal histories independently rule against an unnoticed foreign-record mismatch at native acceptance.

## Hypotheses

| Hypothesis | Evidence for | Evidence against / disposition |
| --- | --- | --- |
| Lab oracle compares array order as ownership | Direct return at operation.rs:1071; frozen and live replay fail on routes; rule ordering also differs | **Confirmed mechanism.** Normal ownership/multiset validation had accepted the same inventory shape. |
| Fresh-baseline serialization artifact | Saved sorted dump keys put family 10 before family 2; decoder preserves that iteration order | **Confirmed trigger.** Inventory content is complete; the gap is order semantics, not omitted records. |
| Docker/inert container added unaccounted HOST objects | Docker is present and docker0 has addresses/routes | Gateway is network-none; docker0 is already declared; only extra HOST link exactly matches the native planned result. No supporting evidence. |
| Cloud-kernel-specific ownership/attribute defect | Fresh guest uses kernel 6.12.113 and differs from the old lab | All complete records match the frozen baseline as multisets; the order change is explained by Python JSON and fixed Rust family sequencing. No kernel defect established. |
| Genuine production/native bootstrap ownership defect | Error name is broad and originates in Rust | This return is cfg(test); native checks use multiset equality and completed successfully. No production ownership failure demonstrated. |
| Stale guest, replacement gateway, or vanished owner caused the inventory error | I/F show owner unit not-found and cgroup absent | New boot/pidfd identity checks match the preserved gateway; no owner-unit lookup occurs in the failing assertion. Controller uses systemd-run --wait --collect at controller-guest.py:172, consistent with post-exit unit disappearance. |

## What 409 says about 402–408

**409 did not get past the earlier Bootstrap Deadline location. It stopped earlier in the call graph.** This corrects the premise in the diagnosis brief.

`attachment/operational/bootstrap.rs:636–662` calls `super::lab_handoff(fault)?` at line 640 before constructing Measurements at line 662 or PendingBootstrap at line 697. That handoff calls `host_addition::lab_added()?` at `attachment/operational.rs:473–475`. Run 409 fails inside that call, before handoff.host-ok, operational handoff construction and the measured Bootstrap loop.

Run 408's entire `host_addition/operation.rs` from Git commit `4d9658fce6d206161023ec3487409680a30f4c23` is byte-identical to the current file, including this oracle. Thus the old lab did reach and pass the same oracle; its later Deadline did not hide this assertion by failing earlier.

The checked-in historical public records are more precise than “402–408 all result”: 402 is Deadline/UNLOCALIZED; 403 is native_poll/intent; 404–405 are native_poll/result; 406–407 are native_poll/reading; 408 is native_poll/result. All report zero completed cases and no native-bootstrap acceptance. Historical raw files were not available for a new raw-data verification; these details are from the public records and existing 408 diagnosis.

The fresh 3-link environment versus old 61-link environment, different baseline/guest identities, rebuilt artifact and added observers are not a controlled comparison. 409 establishes that this fresh fixture completed the pre-Bootstrap native host-link sequence, then failed its final lab oracle. It gives **no parent-CPU, off-CPU, scheduler, sleep, constructor-prefix, throughput, speedup, or original two-second Bootstrap-fit evidence**, and it neither resolves nor reproduces the old measured Deadline boundary.

There are zero `LAB_SECRET_BOOTSTRAP_BOUNDARY_FAILURE` rows and zero `LAB_SECRET_BOOTSTRAP_DRIVER_*` rows. The closed parser correctly fails at `tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py:108–115`, which requires one Deadline boundary. Do not weaken that parser or synthesize zero measurements.

A second wording correction: diagnostic emission is not intrinsically restricted to Error::Deadline. The measured wrapper invokes Measurements.failure on any error (`bootstrap.rs:666–693`), and failure emits the driver rows at lines 1511–1573. The closed parser specifically accepts Deadline. In 409, neither wrapper nor collector construction was reached.

## Recommended next step and cost

No fix or new experiment was implemented here. Run 409 remains consumed, budget_remaining=0.

1. **Preferred: repair only the cfg(test) inventory oracle** in `attachment/host_addition/operation.rs:1069–1073`. Keep namespace exact; compare addresses/routes/rules as complete multisets, matching existing guarded::exact semantics. A local test-only helper can sort complete canonical JSON records and compare lengths/values without widening the production API. Preserve every field, multiplicity, link/index/down assertion, original custody check and deadline. Do not replace arrays with sets or compare only counts/selected keys. Estimated implementation and focused offline test work: 1–3 engineer hours.
2. Add an offline regression using the independently authored declaration and native-ordered fixture: IPv4/IPv6 reordering must pass; missing/extra/duplicated/replaced records and any changed route metric, rule table, address flags or namespace must fail. The current failure can be reproduced without a guest. The analysis replay in this task already demonstrates the old predicate failing and a full-multiset predicate passing; three reorder cases pass and twelve missing/extra/duplicate/field-change cases fail. This is an analysis check, not a claim that a Rust fix was tested.
3. **Optional lab hardening:** make `fresh-baseline.py:94–99` decode an explicit request/family sequence rather than JSON object iteration order. Test both insertion orders and a sort_keys JSON round-trip. Estimate 0.5–1 hour. This improves deterministic rendering but does not by itself justify ordered equality for kernel dumps. No network correction, object deletion, kernel change, or live adoption is indicated. An order-only baseline workaround would require a newly bound declaration/reconciliation; never overwrite 409's baseline, reservation or evidence to make it pass.
4. Review the narrow fix, run focused meaningful tests with `-j 4`, and build/freeze a new coherent candidate under Root's normal source/artifact/provenance gates. Estimate another 2–4 hours plus build capacity. Preserve all 409 resources and selectors. A prospective **410** must use a separately admitted guest/selector context or a separately reviewed preservation procedure; the current post-409 guest has retained resources and cannot simply be treated as the old pristine three-link fixture. Create forward-only 410 controller/reservation support separately; do not edit, reuse or bypass the consumed 409 claim.
5. **A new run is needed for runtime validation and for the original driver-cost question; it is not needed to establish this ordering mechanism.** Estimate roughly 0.5–1 engineer day overall for fix, review, candidate and lab gates, assuming a stable host; actual run time is small compared with those gates. No new run is authorized or performed by this report.

For a separately authorized 410, require host.inventory-ok and completion of handoff first. Preserve ordinary two-second windows, exact held coverage and negatives. If it reaches a measured Deadline, retain the old diagnostic rows plus all 15 new driver rows, source/guest bindings and fresh preservation evidence. Apply task-8c-driver-cost-brief.md attribution rules: compare CPU/wall only for complete unsaturated helper rows; report sample loss, observer overhead and differing brackets; low parent CPU supports combined blocking/preemption/child-progress time, not scheduler causality; actual sleep/prefix observations are separate measurements. If it succeeds, the failure-only diagnostic path need not emit rows; do not label absent samples as zero cost or trigger an automatic rerun. A further pre-handoff failure is still not a driver-cost result.

Full task-8c/ARM/client/migration/performance/release acceptance remains open/NOT_RUN where unaccepted.

## SyntaxWarning assessment

Both warnings are caused by textual substitution of a nonempty unit string into a valid None identity test.

- I: `tools/rust-v2-lab/inspect-run409-state.py:36` contains `if UNIT is not None:`; substitution happens at line 77. The reconstructed remote line 20 is `if '<actual unit name>' is not None:`.
- F: `target/inspect-secret-bootstrap-failure.py:56` contains the same test; substitution happens at line 64, with the fresh-boot prefix at line 65. The reconstructed remote line is 24.

Offline compilation reproduces exactly one SyntaxWarning at the recorded line in each payload. AST inspection shows a string constant on the left, `IsNot`, and the singleton None on the right. The expression is correctly true for the actual string; it does **not** compare string identity against another string and does not depend on interning. A missing unit would substitute None and correctly skip the branch.

The warning therefore did not make these I/F outputs wrong. Both inspected the expected unit; I's identity checks and F's canonical data are unaffected. The reports remain point-in-time observations, not new runtime acceptance. To suppress warnings in future controller revisions, assign UNIT to a remote variable via a structured parameter object and test that variable against None; do not mechanically replace legitimate None checks with string-value comparisons.

## Work performed and verification

Only this report and new local analysis files under `target/run409-diagnosis/` were written. No product source, test, controller, baseline, existing evidence, reservation, claim or selector was changed. No sudo ran on debdev; guest sudo executed read-only Python inspection only. No Bootstrap, rerun 409, selector archival, C/I/F rerun, cleanup, service action, Git staging/commit/push, subagent, Cargo command or release build occurred.

Local guard hashes cover twelve existing files, including run409 state/claims/raw evidence, the dedicated key, pin and Git index. Before/after hashes agree; final verification rechecks them. Initial tracked/index diffs were empty; final verification checks HEAD/branch, empty tracked/index diffs and source-archive equality.

Supporting analysis artifacts:

- `target/run409-diagnosis/inspect.py`, `remote.py`, `guest-receipt.json`, `guest.json`: exact single-session confined inspection and raw public netlink metadata.
- `analyze.py`, `comparison.json`: baseline/projection/live full-record comparison, original saved-dump reproduction and offline positive/negative checks. The copied independent decoder was adapted only to permit the preserved veth kind; no existing collector or product parser was edited.
- `syntax-warning-analysis.json`: reconstructed warning expressions and AST conclusions; reconstructed payloads were compiled, never executed.
- `protected-before.json`, `protected-after.json`, `verify.py`, `verification.json`: local preservation and deliverable verification.
- `commands.json`: the same exact shell command batches reproduced below. File creation used apply_patch; no file-creation shell command is omitted.

Key new evidence SHA256:
`guest-receipt.json=ef36f460dd977c59f4879c2581c851a22dea8f49b36026a7fc2ee0f0a95a6608`;
`comparison.json=ffbacf5c09e1ea999b3975dd834849affe8b9874007bcc7b926820e9c512e4e4`;
`syntax-warning-analysis.json=3a347a3997919c1457271e7aeae8134b76c2f646a1e0f2ff4076c7ddd2c080ed`.

Cargo/Rust fix tests: **NOT_RUN** (no fix requested). Offline evidence replay and warning reconstruction: completed with assertions passing. Native runtime reproduction/new Bootstrap: **NOT_RUN** by scope.

## Exact commands

All shell batches ran from `/DATA/AppData/vprouter-rust-v2`. Independent read batches sometimes ran concurrently; numbering records submission order. Early searches included nonexistent guessed source/inspector paths and one broad AGENTS search returning exit 2; these were corrected through read-only path discovery. They did not execute controllers. Output truncation on some broad reads was followed by the focused line reads shown below.

The only SSH command was launched by batch 26's inspect.py (locate it by the exact command text if numbering changes). Its full argv is in guest-receipt.json and its exact stdin is remote.py. Those files specify every guest read, including all RTM_GET families. The first final-verifier attempt found a verifier scope mistake: it assumed the build archive contained every tracked Rust path. Read-only set inspection found the two standalone lab cost probes listed above; the archive contains all 179 build Rust files unchanged. The local verifier was corrected to allow exactly those two excluded paths, then rerun. This was a verification-script assertion failure, not a product or guest failure. The final listed batch verifies this report locally.

### 1

```bash
pwd && rg -n 'task-8c|ownership_mismatch|bootstrap409|22036|strict' /home/opsec/.codex/memories/MEMORY.md
```

### 2

```bash
cat .superpowers/sdd/rust-v2/task-8c-bootstrap409-diagnosis-brief.md
```

### 3

```bash
rg --files -g AGENTS.md -g '!target' -g '!vendor' . /DATA 2>/dev/null
```

### 4

```bash
cat /home/opsec/.codex/skills/investigate-first/SKILL.md && cat /home/opsec/.codex/skills/verification-before-completion/SKILL.md
```

### 5

```bash
for p in /AGENTS.md /DATA/AGENTS.md /DATA/AppData/AGENTS.md /DATA/AppData/vprouter-rust-v2/AGENTS.md; do if test -f "$p"; then printf '%s\n' "$p"; cat "$p"; fi; done
 git status --short
 git branch --show-current
 git rev-parse HEAD
 git diff --stat
 git diff --cached --stat
```

### 6

```bash
sed -n '854,878p' /home/opsec/.codex/memories/MEMORY.md
 cat /home/opsec/.codex/memories/rollout_summaries/2026-11-03T22-46-34-ynb5-rust_v2_bootstrap409_lab_rebuild_assessment.md
```

### 7

```bash
rg -n 'ownership_mismatch|host\.inventory|OwnershipMismatch' crates
 cat .superpowers/sdd/rust-v2/task-8c-driver-cost-brief.md
 rg --files target/run409-exec target/run409-preserved-initial target/candidates/rebuild-20261103T231415Z target/lab-state | rg '409|baseline|reconcil|projection|known_hosts|inspection|failure|run-context'
```

### 8

```bash
sed -n '1,260p' target/inspect-run409-state.py
 sed -n '1,260p' target/inspect-secret-bootstrap-failure.py
```

### 9

```bash
rg -n 'host\.inventory' crates
```

### 10

```bash
rg -n 'OwnershipMismatch|inventory|baseline' crates/vprouter-launch/src/attachment.rs crates/vprouter-launch/src/operational_bootstrap.rs
```

### 11

```bash
cat .superpowers/sdd/rust-v2/task-8c-driver-cost-brief.md
```

### 12

```bash
sed -n '1,220p' tools/rust-v2-lab/inspect-run409-state.py
cat target/run409-exec/stderr target/run409-exec/parse.stderr target/run409-exec/inspect.stderr target/run409-exec/failure.stderr
```

### 13

```bash
python3 - <<'PY'
import json,pathlib
paths=['target/lab-state/actual-program-run-409.json','target/lab-state/run-409-state-inspection.json','target/lab-state/secret-bootstrap-failure-run-409.json','target/candidates/rebuild-20261103T231415Z/authored-host-baseline-debian-clean-x86_64.json','target/candidates/rebuild-20261103T231415Z/host-baseline-reconciliation-debian-clean-x86_64.json','target/candidates/rebuild-20261103T231415Z/host-projection-debian-clean-x86_64/record.json']
for p in paths:
 d=json.loads(pathlib.Path(p).read_bytes());print(p); print('keys:',list(d))
 if 'actual-program-run-409' in p:
  print(json.dumps({k:d[k] for k in ['exit_code','stderr','guest_boot_id','source_binding','artifact_sha256'] if k in d},indent=2));print('stdout row types:');print([list(json.loads(l)) for l in d['stdout'].splitlines() if l.startswith('{')])
 elif 'record.json' not in p: print(json.dumps(d,indent=2)[:20000])
PY
```

### 14

```bash
nl -ba crates/vprouter-launch/src/attachment/host_addition/operation.rs | sed -n '950,1120p'
rg -n 'fn .*inventory|fn .*baseline|OwnershipMismatch|fn .*foreign|fn .*host' crates/vprouter-launch/src/attachment/host_inventory.rs crates/vprouter-launch/src/attachment/host_baseline.rs crates/vprouter-launch/src/attachment/host_addition/*.rs
```

### 15

```bash
python3 - <<'PY'
import json,pathlib,hashlib
p=pathlib.Path('target/lab-state/actual-program-run-409.json');d=json.loads(p.read_bytes())
print('RAW',hashlib.sha256(p.read_bytes()).hexdigest());print('keys',list(d));print('binding',d.get('source_binding'));print('exit',d['exit_code'],'boot',d.get('guest_boot_id'));print('stderr tail\n'+d['stderr'][-4500:]);print('driver rows',d['stderr'].count('LAB_SECRET_BOOTSTRAP_DRIVER_'))
for l in d['stdout'].splitlines():
 try:r=json.loads(l)
 except ValueError:continue
 print('ROW',list(r))
 if any(k in r for k in ['secret_attachment_gateway','owner_probe','secret_quarantine_host','secret_host_baseline']):
  if 'secret_host_baseline'in r:
   v=r['secret_host_baseline'];print('baseline keys',list(v));print('baseline hash',v.get('sha256'))
  else:print(json.dumps(r)[:4000])
for p in ['target/lab-state/run-409-state-inspection.json','target/lab-state/secret-bootstrap-failure-run-409.json']:
 d=json.loads(pathlib.Path(p).read_bytes());print(p,'keys',list(d));print(json.dumps({k:v for k,v in d.items() if k in ['owner','gateway','owner_unit','owner_cgroup_exists','gateway_state','expected_owner_unit','read_only','signals_unmount_or_cleanup']}))
for p in ['target/run409-exec/parse.stderr','target/run409-exec/inspect.stderr','target/run409-exec/failure.stderr']:
 print(p,pathlib.Path(p).read_text()[-2000:])
PY
```

### 16

```bash
nl -ba tools/rust-v2-lab/inspect-run409-state.py | sed -n '15,115p'
nl -ba target/inspect-secret-bootstrap-failure.py | sed -n '30,85p'
rg -n 'docker|network|baseline|host-projection|host_declaration' target/candidates/rebuild-20261103T231415Z/bootstrap409-driver-cost/controller-guest.py
```

### 17

```bash
nl -ba crates/vprouter-launch/src/attachment/host_addition/operation.rs | sed -n '1,155p;640,810p'
rg -n 'host_observation|lab_host|declaration' crates/vprouter-launch/src/attachment/host_addition/operation.rs
rg --files crates/vprouter-launch/src | rg 'host|network|netlink'
```

### 18

```bash
python3 - <<'PY'
import json,pathlib
r=json.loads(pathlib.Path('target/lab-state/actual-program-run-409.json').read_bytes());print('PHASE TAIL:');print('\n'.join(l for l in r['stderr'].splitlines() if l.startswith('LAB_SECRET_BOOTSTRAP_PHASE')or l.startswith('secret_bootstrap_lab:'))[-5000:])
for l in r['stdout'].splitlines():
 try:d=json.loads(l)
 except ValueError:continue
 if not isinstance(d,dict):continue
 print('ROW',list(d))
 if 'secret_attachment_gateway'in d:print(json.dumps(d))
 if 'secret_quarantine_host'in d:print(json.dumps(d))
 if 'secret_host_baseline'in d:
  v=d['secret_host_baseline'];print('baseline declaration keys',list(v['declaration']));print('baseline declaration ancillary',{k:v for k,v in v['declaration'].items() if k!='baseline'})
s=json.loads(pathlib.Path('target/lab-state/run-409-state-inspection.json').read_bytes());o=json.loads(s['stdout']);print('I',s['exit_code'],o['owner'],o['gateway']['original_identity_matches'])
f=json.loads(pathlib.Path('target/lab-state/secret-bootstrap-failure-run-409.json').read_bytes());print('canonical keys',{k:list(v)if isinstance(v,dict)else type(v).__name__ for k,v in f['canonical'].items()})
PY
```

### 19

```bash
rg -n 'host_observation|host_link|observation|result|journal' crates/vprouter-launch/src/kernel/host_link.rs crates/vprouter-launch/src/owned/preparation/host_link.rs
nl -ba crates/vprouter-launch/src/attachment/host_addition/operation.rs | sed -n '180,255p;545,610p;890,935p'
rg -n 'host_observation|validate_host_addition|HostObservation|sort' crates/vprouter-network/src/*.rs
```

### 20

```bash
nl -ba crates/vprouter-launch/src/attachment/operational/bootstrap.rs | sed -n '1,150p'
rg -n 'lab_added|lab_phase|lab_run|handoff.host' crates/vprouter-launch/src/attachment/operational/*.rs
nl -ba target/candidates/rebuild-20261103T231415Z/bootstrap409-driver-cost/controller-guest.py | sed -n '135,180p'
python3 - <<'PY'
import json,pathlib
p=pathlib.Path('target/candidates/rebuild-20261103T231415Z/host-projection-debian-clean-x86_64/record.json');d=json.loads(p.read_bytes());print('projection report',list(d['report']));print('remote type',type(d['remote']).__name__);print('report excerpt',str(d['report'])[:1500])
PY
```

### 21

```bash
python3 - <<'PY'
import json,pathlib,collections
b=json.loads(pathlib.Path('target/candidates/rebuild-20261103T231415Z/authored-host-baseline-debian-clean-x86_64.json').read_bytes())['baseline'];p=json.loads(pathlib.Path('target/candidates/rebuild-20261103T231415Z/host-projection-debian-clean-x86_64/record.json').read_bytes())['report']['projection']
for k in ['namespace','links','addresses','routes','rules']:
 print(k,'exact',b[k]==p[k],'counts',len(b[k]),len(p[k]));
 if k!='namespace':
  key=lambda v:json.dumps(v,sort_keys=True);print('multisets',collections.Counter(map(key,b[k]))==collections.Counter(map(key,p[k])))
  if b[k]!=p[k]:print('baseline order',[v.get('destination',v.get('address',v.get('priority',v.get('name'))))for v in b[k]]);print('projection order',[v.get('destination',v.get('address',v.get('priority',v.get('name'))))for v in p[k]])
PY
nl -ba crates/vprouter-launch/src/kernel/host_link.rs | sed -n '60,140p;240,330p'
rg -n 'host_observation|pub.*lab_evidence|observation' crates/vprouter-launch/src/kernel/host_link.rs
```

### 22

```bash
nl -ba crates/vprouter-network/src/guarded.rs | sed -n '970,1100p'
nl -ba crates/vprouter-network/src/host_observation.rs | sed -n '1,115p'
nl -ba crates/vprouter-network/src/audit.rs | sed -n '130,205p'
rg -n 'preparation|journal|namespaces.json' crates/vprouter-launch/src/owned.rs crates/vprouter-launch/src/owned/*.rs | head -65
```

### 23

```bash
nl -ba crates/vprouter-launch/src/kernel/host_link.rs | sed -n '525,605p;785,850p'
rg -n 'host_observation|HostObservation|struct HostAddition|struct .*Addition|complete_audit|same\(' crates/vprouter-network/src/async_native*.rs crates/vprouter-network/src/guarded.rs
python3 - <<'PY'
import json,pathlib
f=json.loads(pathlib.Path('target/lab-state/secret-bootstrap-failure-run-409.json').read_bytes());n=f['canonical']['namespaces.json'];print('entries',len(n['entries']))
for e in n['entries']:
 print('entry keys',list(e));p=e.get('preparation',{});print('preparation keys',list(p));print('host_link',json.dumps(p.get('host_link'),indent=2)[:7500]);print('generation_baseline',json.dumps(p.get('host_baseline'),indent=2)[:500])
PY
```

### 24

```bash
sed -n '1,240p' tools/rust-v2-lab/fresh-baseline.py
```

### 25

```bash
rg -n 'host_observation|struct Moved|HostAddition|complete_audit' crates/vprouter-network/src -g '*.rs' | head -75
nl -ba crates/vprouter-network/src/guarded.rs | sed -n '390,475p;520,555p;1195,1220p'
rg -n 'fn snapshot|routes\(|rules\(' crates/vprouter-network/src/native.rs | tail -25
nl -ba crates/vprouter-launch/src/attachment/operational/bootstrap.rs | sed -n '636,665p'
rg -n 'handoff.host|lab_added' crates/vprouter-launch/src/attachment -g '*.rs' | head -25
```

### 26

```bash
python3 -B target/run409-diagnosis/inspect.py
```

### 27

```bash
nl -ba crates/vprouter-network/src/secret_role/veth/movement.rs | sed -n '330,460p;500,535p'
nl -ba crates/vprouter-network/src/native/host_read.rs | sed -n '1,260p'
nl -ba crates/vprouter-network/src/native.rs | sed -n '1058,1095p'
```

### 28

```bash
nl -ba crates/vprouter-network/src/guarded/host_addition.rs | sed -n '1,240p'
nl -ba crates/vprouter-launch/src/attachment/host_baseline.rs | sed -n '1,155p'
rg -n 'archive|source_archive|artifact|binding' target/candidates/rebuild-20261103T231415Z/candidate.json | head -30
```

### 29

```bash
python3 - <<'PY'
import ast,pathlib,json,warnings
r=json.loads(pathlib.Path('target/lab-state/actual-program-run-409.json').read_bytes());rows=[]
for l in r['stdout'].splitlines():
 try:rows.append(json.loads(l))
 except ValueError:pass
unit=next(x['owner_probe']['unit']for x in rows if 'owner_probe'in x);gateway=next(x['secret_attachment_gateway']for x in rows if 'secret_attachment_gateway'in x)
t=ast.parse(pathlib.Path('tools/rust-v2-lab/inspect-run409-state.py').read_text());remote=next(ast.literal_eval(n.value)for n in t.body if isinstance(n,ast.Assign)and any(isinstance(x,ast.Name)and x.id=='REMOTE'for x in n.targets));remote=remote.replace('EXPECTED_BOOT',repr(r['guest_boot_id'])).replace('UNIT',repr(unit)).replace('GATEWAY',repr(gateway))
with warnings.catch_warnings(record=True)as ws:
 warnings.simplefilter('always');code=compile(remote,'I-reconstructed','exec')
for w in ws:
 print(w.category.__name__,w.lineno,str(w.message));print('expression:',remote.splitlines()[w.lineno-1]);node=next(n for n in ast.walk(ast.parse(remote)) if isinstance(n,ast.If)and n.lineno==w.lineno);print('AST',ast.dump(node.test));print('test evaluates',eval(compile(ast.Expression(node.test),'expression','eval')))
for s in ["'some unit' is not None","'some unit' is not 'None'","''.join(['some',' unit']) is not None"]:
 with warnings.catch_warnings(record=True)as ws:
  warnings.simplefilter('always');c=compile(s,'small-example','eval')
 print(repr(s),'=',eval(c),'warnings',[str(w.message)for w in ws])
PY
cat target/candidates/rebuild-20261103T231415Z/candidate.json | head -70
rg --files target/candidates/rebuild-20261103T231415Z target | rg '(source.*(tar|zst|gz)|\.tar\.gz$|run-40[2-8]\.json$)' | head -50
```

### 30

```bash
nl -ba crates/vprouter-network/src/secret_role/veth/movement.rs | sed -n '475,507p;525,543p'
nl -ba crates/vprouter-network/src/guarded/host_addition.rs | sed -n '245,300p'
nl -ba crates/vprouter-launch/src/attachment/operational.rs | sed -n '465,510p'
rg -n 'measurements.failure|Error::Deadline|measurements.*failure' crates/vprouter-launch/src/attachment/operational/bootstrap.rs
nl -ba tools/rust-v2-lab/parse-bootstrap-cost-diagnostics.py | sed -n '85,120p'
```

### 31

```bash
python3 - <<'PY'
import json,pathlib,tarfile,hashlib
root=pathlib.Path('.');c=json.loads((root/'target/candidates/rebuild-20261103T231415Z/candidate.json').read_bytes());raw=json.loads((root/'target/lab-state/actual-program-run-409.json').read_bytes());print('archive_sha',hashlib.sha256(pathlib.Path(c['source']).read_bytes()).hexdigest());print('payload_sha',hashlib.sha256(pathlib.Path(c['platforms']['amd64']['artifact']).read_bytes()).hexdigest());print('record artifact',raw['artifact_sha256'])
paths=['crates/vprouter-launch/src/attachment/host_addition/operation.rs','crates/vprouter-launch/src/attachment/host_baseline.rs','crates/vprouter-launch/src/attachment/operational.rs','crates/vprouter-launch/src/attachment/operational/bootstrap.rs','crates/vprouter-launch/src/kernel/host_link.rs','crates/vprouter-network/src/native/host_read.rs','crates/vprouter-network/src/secret_role/veth/movement.rs','crates/vprouter-network/src/guarded.rs','crates/vprouter-network/src/audit.rs','crates/vprouter-network/src/host_observation.rs']
with tarfile.open(c['source'])as t:
 for p in paths:
  data=t.extractfile(p).read();print(p,hashlib.sha256(data).hexdigest(),'equals_HEAD_worktree',data==pathlib.Path(p).read_bytes())
print('claim',json.loads(pathlib.Path('target/lab-state/run-409-consumed.json').read_bytes()).get('budget_remaining'))
PY
rg -n '402|403|404|405|406|407|408|61|Deadline|native_poll' .superpowers/sdd/rust-v2/task-8c-bootstrap408-diagnosis.md | head -55
nl -ba crates/vprouter-launch/src/attachment/operational/bootstrap.rs | sed -n '665,712p'
nl -ba tools/rust-v2-lab/fresh-baseline.py | sed -n '85,103p;175,204p'
```

### 32

```bash
python3 -B target/run409-diagnosis/analyze.py
```

### 33

```bash
cat .superpowers/sdd/rust-v2/task-8c-bootstrap408-diagnosis.md
python3 - <<'PY'
import pathlib,json,subprocess,hashlib
for p in sorted(pathlib.Path('docs/rust-v2').glob('task8c-bootstrap-attempt40[2-8].json')):
 d=json.loads(p.read_bytes());print(p,'keys',list(d));print(json.dumps(d)[:1400])
p='crates/vprouter-launch/src/attachment/host_addition/operation.rs';r=subprocess.run(['git','show','4d9658fce6d206161023ec3487409680a30f4c23:'+p],capture_output=True);print('run408 oracle source available',r.returncode==0)
if r.returncode==0:
 lines=r.stdout.decode().splitlines();start=next(i for i,v in enumerate(lines)if 'lab_phase("host.inventory", false)'in v);print('\n'.join(lines[start:start+24]));print('entire operation same bytes',r.stdout==pathlib.Path(p).read_bytes())
PY
```

### 34

```bash
nl -ba tools/rust-v2-lab/fresh-baseline.py | sed -n '25,79p;94,101p;155,188p'
nl -ba target/platform-lab/host_baseline_declaration.py | sed -n '1,150p'
rg -n 'fn failure|BOUNDARY_FAILURE|DRIVER_' crates/vprouter-launch/src/attachment/operational/bootstrap.rs | head -20
 git status --short --untracked-files=all
```

### 35

```bash
python3 - <<'PY'
import json,pathlib
for p in sorted(pathlib.Path('docs/rust-v2').glob('task8c-bootstrap-attempt40[2-8].json')):
 d=json.loads(p.read_bytes());print(d['run'],{k:d.get(k)for k in ['failure','failure_helper','failure_step','completed_cases','native_bootstrap_accepted']})
for name in ['guest-receipt.json','comparison.json','syntax-warning-analysis.json']:
 p=pathlib.Path('target/run409-diagnosis')/name;d=json.loads(p.read_bytes());print(name,d.get('observed_at_utc',''))
PY
nl -ba crates/vprouter-launch/src/attachment/operational/bootstrap.rs | sed -n '1511,1577p'
rg -n 'fe80::|fec0::|"ipv6"|"routes"|"rules"' target/candidates/rebuild-20261103T231415Z/authored-host-baseline-debian-clean-x86_64.json | head -20
nl -ba tools/rust-v2-lab/fresh-baseline.py | sed -n '130,151p'
```

### 36

```bash
python3 - <<'PY'
import json,pathlib,hashlib
root=pathlib.Path('target/run409-diagnosis');before=json.loads((root/'protected-before.json').read_bytes());now={p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()for p in before};assert before==now;print('Protected files unchanged:',len(before))
r=json.loads(pathlib.Path('target/lab-state/actual-program-run-409.json').read_bytes());rows=[]
for l in r['stdout'].splitlines():
 try:rows.append(json.loads(l))
 except ValueError:pass
b=next(v['secret_host_baseline']for v in rows if 'secret_host_baseline'in v);template=json.loads(pathlib.Path('target/candidates/rebuild-20261103T231415Z/authored-host-baseline-debian-clean-x86_64.json').read_bytes());assert b['declaration']['baseline']==template['baseline'];print('Raw staged baseline equals authored template:',True)
print('driver/boundary rows:',sum(l.startswith('LAB_SECRET_BOOTSTRAP_DRIVER_')for l in r['stderr'].splitlines()),sum(l.startswith('LAB_SECRET_BOOTSTRAP_BOUNDARY_FAILURE')for l in r['stderr'].splitlines()))
for p in ['target/lab-state/actual-program-run-409.json','target/candidates/rebuild-20261103T231415Z/authored-host-baseline-debian-clean-x86_64.json','target/candidates/rebuild-20261103T231415Z/host-baseline-reconciliation-debian-clean-x86_64.json','target/candidates/rebuild-20261103T231415Z/host-projection-debian-clean-x86_64/record.json','target/run409-diagnosis/guest-receipt.json','target/run409-diagnosis/comparison.json','target/run409-diagnosis/syntax-warning-analysis.json']:
 print(hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest(),p)
PY
nl -ba /home/opsec/.codex/memories/rollout_summaries/2026-11-03T22-46-34-ynb5-rust_v2_bootstrap409_lab_rebuild_assessment.md | sed -n '22,35p'
git diff --check
git diff --cached --check
```

### 37

```bash
python3 -B target/run409-diagnosis/verify.py
```

### 38

```bash
python3 - <<'PY'
import json,pathlib,tarfile,subprocess
c=json.loads(pathlib.Path('target/candidates/rebuild-20261103T231415Z/candidate.json').read_bytes())
with tarfile.open(c['source'])as t:archived={m.name for m in t.getmembers()if m.isfile()and m.name.endswith('.rs')}
tracked=set(subprocess.check_output(['git','ls-files','*.rs'],text=True).splitlines())
print('archived',len(archived),'tracked',len(tracked));print('only archived',sorted(archived-tracked));print('only tracked',sorted(tracked-archived))
PY
```

### 39

```bash
python3 -B target/run409-diagnosis/verify.py
```
