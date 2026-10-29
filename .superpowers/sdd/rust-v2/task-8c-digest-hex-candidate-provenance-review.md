# Digest-hex candidate provenance, artifacts, preservation and public scope

2026-10-29. Independent read-only saved-candidate/artifact/preservation/publication
audit. Only this Markdown written. No source/tool edit, Git command, tests/builds/
benchmark, helper main, VM/native/SSH/Docker/privilege, profile/credential contents,
resource operation or subagent. Root owns execution/publication. Source review
5222aa87 and the prior experiment review are separate and are not duplicated.

**Final candidate/provenance PASS. Preservation baseline PASS. Immutable public
scope/sensitivity PASS. No findings.** The initial audit and final immutable
checks below bind the exact two review-flag changes and append-only completion
ledger. These verdicts grant no native performance, Bootstrap/client/runtime/ARM/
release acceptance. Original398-406 failures remain preserved; native effect
NOT_RUN, full8c ACTIVE and release_ready=false remain.

## Exact source and reviewed one-file binding

Candidate target/continuation-20261029T174000Z/candidate.json SHA256
69cb6ddc7f8cf4e2c1a082e4abd736fe15a422459d849c36f4247b4d0ae3f83a:

```text
source_commit 51c15016353936288067f5cd3e4c2a6715be1061
source_archive_sha256 f5cecc2f3af90a7e638f9bfdcb1d2db3a70abb7666d678b2133fe88601d9aa7c
tracked_build_inputs_verified 203
source_aggregate_sha256 d9fe3200b57f73d8cf5c6e847277dbf463c5ab672559f208383c49f81de12167
```

Actual archive hash matches; its203 unique regular input files exactly equal
the previously reviewed203-path set. Every byte/hash matches current files and
root-verification.json current_input_hashes. The independent sorted path/NUL/
digest/newline aggregate reproduces d9fe3200. Root's saved verifier supplies the
exact Git/commit equality assertion; this audit independently checks retained
archive/current/hash identity without running Git or any verifier main.

Root proof root-verification.json SHA256
6eb7f12d0dd3df3c98ef813ec360b74662e58bee6b09f7f3667994504152f90f
has the same binding. Exact implementation report
f81f347379246f0e8fc679523932490444d37a522280bf659434f3cd912ff69a,
fresh independent source review
5222aa87c1192da00ead293bffda85cba798e3e34779154e821ec536a867f3a6
and frozen source.diff
49cd18642eb365826aa9e66d62321d50093b321ebf30924c6584c0a22abdcba4
all match retained bytes.

Before/after maps and current filesystem contain exactly179 Rust paths, with
only crates/vprouter-worker/src/bootstrap.rs changed. All178 unowned paths remain
identical, no Rust path added/deleted, and every current hash equals the frozen
after snapshot f31ce696bd7f647a841da2904f8a383d4ab8fee37662d3678539e86a6ac03b3b.
Current owned SHA256 is
f4b01c3d7cbc04ee9b1a2133bc9354d6ca8f2b8d893fa58d21310479f7732fdd.
The independent source review binds exact input/hash/output preservation and
original-worker reconstruction plus meaningful oracle/mutation evidence. This
audit binds its source to the candidate; it does not redo source/experiment
reasoning or infer native savings from the host mechanism.

## Exact manifest deltas and rebuilt strict contexts

Comparing this source archive with the prior17c914f4 proof finds exactly three
changed build inputs: that one worker source and the two normal program manifests.
For each architecture, an independent structured manifest comparison confirms
only worker_observer and worker_monitor bytes/sha256 fields changed. Program
array order, role/key sets, paths, policy, architecture, schema, base image/index/
platform and all gateway_init/tailscaled fields remain identical. This reproduces
Root's program-manifest-scope.json SHA256
92195589cb3f157fa28c84820ba296943daf481ac2e9646d38e80fe316c24751.
Normal contexts are expected to change and are checked against the new manifests.

| Architecture | Static lab payload SHA256 | Rebuilt normal context SHA256 |
| --- | --- | --- |
| amd64 | fe3567ab22819b05ecf0523ddcfb6dd14fea8869d6b6a6e7f77b9804b2a926d3 | cd73f32df6db96f8a8c091abab7c0796a3e88e54be09e0c73d7b074abc7b1e48 |
| arm64 | 8653ede4bcd30a594db2dbc5c32383e7065d8b64b7f0cfa8413df85b215bf825 | bcdd948c2236defd91e54a133f668c1ecab55bc0ad7a5e0ee4e476ec93d6a4fa |

Both actual payloads are ELF64 little-endian for their exact machine, with
bounded valid program headers, PT_LOAD and no PT_DYNAMIC/PT_INTERP. Retained
context copies match current normal contexts and candidate hashes. Independently
checking exact tar membership/uniqueness, directory/regular-file types, uid/gid/
mtime0, no links/PAX headers, exact modes, Dockerfile, fixed CA certificate,
embedded manifest and all four executable sizes/hashes/static ELF headers yields
exactly seven files per architecture, with no extra file or changed authority.

New manifest SHA256 values are
cd6a283df0bb1703fb12c0ba13b5e54069f49408d0c14cec3af17b35e0b7ab0d amd64 and
49ada75c283e52ba3b229778a91153b78a1775660732452d913c4d90cdece267 arm64.
Dockerfile program labels and embedded programs.json exactly bind those bytes.
Unchanged init/tailscaled identities, executable policies and CA remain intact;
updated observer/monitor artifacts are provenance-bound, not runtime accepted.

The exact amd64.filter-preflight executable equals the amd64 candidate payload.
Its retained log SHA256
0fd4c87450468b3b4d7bbc3d1e725f8044b2d925c4dea1af5d23a108ab032dc1
matches Root proof and includes terminal exact-filter/native-deny PASS. Current
Root verifier303b231a and strict-context checker66be3dc0 hashes match saved proof.
No helper/preflight execution was repeated by this auditor.

## Retained Root checks

Workspace log independently totals413 passed,0 failed,2 ignored across27 result
rows, including worker65/0. Root summary records workspace/fmt/Clippy exit0;
empty fmt and completed no-warning Clippy output agree. Strict workspace/all-targets
scope is Root-reported. Coherent-build log records both architecture builds,
updated normal context hashes and exact51c15016 candidate. Local source-oracle
counts299/2known/8450 and wrong-nibble refusal are bound through the exact separate
source review; no timing is rerun or new experiment verdict issued here.

Retained hashes under target/task8c-digest-hex-root-20261029:

```text
workspace-tests.log f240564fd0ca066e0c4022ddc44cf47c0792b3059c32c230cab9a14cd5f274a6
workspace-summary.json 5e88c78bf2ead2bf82b2e10f89ca6d4c344bd3aaafb6ddce759fb32a10ff4ad6
fmt.log e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
clippy.log c55398bfc6e42f8dc50ce5f40b37f7d4f1ce39337c910c955ab21498b4cf2954
root-coherent-build.log f47188e57c051ba2d120ca147fe65e0c63e7a714b6622710c68fe0b33c435567
```

These are saved Root execution/proof results, not tests/builds by this reviewer.
Component/static PASS does not establish native effect, budget or acceptance.

## Read-only projection and59-link foreign-preservation baseline

Saved projection record SHA256
bf84936c11551b4d27e49b613f75df7108b337ace7fdb77aa5cba22429ec22fe
binds current source/payload and the exact unchanged captured controller. Captured
ssh.stdout equals its remote envelope; parsed remote stdout equals the report,
with empty stderr. Exact creator PID/start match the reaped non-root x86_64
child, exit0/no timeout, namespace and14-poll provenance. Verification precedes
original requested_at+2s deadline. Read-only is true; declaration/host-change
and staging/production/private-profile-read flags are false. This checks saved
Root evidence and performs no live VM observation.

The unchanged author-host-baseline-after-bootstrap-v2.py SHA256
67421abe95c77c793332044a5ab2ca95a751f4dc0d175211519fd7eb47ab9958
and host_baseline_declaration.py SHA256
367d2322ea841a81d9ec00006f7c38cf694300cffb77783e4f72903317d1a212
retain their previously reviewed exact reconstruction/closed-shape behavior;
no helper main ran. Independent reconstruction begins with406's original58-link
authored input and its exact canonical four-step host_link history, whose
births/results/verifications remain. Appending only its complete canonical
veth/DOWN endpoint vhc8a5b0f824c8,index855633355 gives59links/51addresses/
154routes/5rules. The original406 outer preservation identifies that exact single
allowed addition and unchanged addresses/routes/rules/stable neighbors.

Namespace and complete row multisets, including duplicate multiplicities,
independently equal saved projection and new template. Addresses/routes/rules
retain prior multisets exactly. Only row order is aligned after full multiset
equality. Every value comes from prior authored bytes or the exact canonical
endpoint; no live field substitution or unexplained observed adoption occurs.

New protected template SHA256
31e3fdd6b93ec330586c86c00b3dc64447a5b30ec3f733910c5d5b609ea69048
and reconciliation SHA256
028c76506f26b1047ad09b600ac19df14b4b640361063a0405790275ac113b8b
bind the current candidate. Canonical baseline digest is
315e5f3cc7e083050e4cb456428b3968c1a0fa480c5510426fa482e403ec8adb.
All five prior template/reconciliation/raw406/inspection/projection reference
hashes, previous evidence links and both helper hashes match. Candidate directory
is0700; template/reconciliation are0600. Staging and host authority remain false.
This foreign preservation grants no membership/removal/activation or accepted
failed406 result; the original58-link input is not rewritten.

Original406 raw e1b62ae23e6f7eedaaf40ebb99b9bf7692f9d6c2acd54cdfa483439e02eda693,
inspection2b0eeb02ffe56dc810e2f03f3133d4d42ccef91640c01bd370b670aa04c7d2d7
and exact-six archival receipt
cbcfc37280d48f5d70eff8f3884d8950a6d47e921e959b298fa7746c3a60a1c0
remain hash-preserved. All original failures/resources/identity state retain
their prior acceptance boundary; this audit authorizes no resource change.

## Preliminary public scope and remaining finalization

Public docs/rust-v2/task8c-digest-hex-verification.json SHA256
f7e6774ebbf06a7655370024511e7f7d2ef2408adff5329cb50b938acd4bbea7
exactly matches reviewed binding/platform/static/evidence references, Root check
counts, bounded source-review claims, program manifest scope and59/51/154/5
baseline/template/reconciliation values. candidate_provenance_review and
preservation_baseline_review remain PENDING in this preliminary version. Root
may finalize those two flags from this PASS, then obtain immutable final audit.

Current ledger SHA256
af7c4943c213b1b6fd58bfb74b97c1af5fa29e9b5c88c7e3521ffff704f239a7
correctly separates host mechanism and local/source/static/projection checks
from pending native effect. Public native_bootstrap/runtime_cost_effect and ARM
runtime remain NOT_RUN; release_ready=false and original398-406 failures remain.
No native share/speedup/saved-budget/original2s-fit/complete-Bootstrap/release
performance claim follows from source tests, timings or entry counts.

Expected publication scope is the one reviewed worker path, two bounded updated
program manifests, digest verification JSON, implementation report, independent
source review, this provenance review and ledger. Public docs/source diff were
contextually scoped and bounded credential-pattern checked; no embedded private
profiles/credentials found. Raw target artifacts, projection/canonical/runtime/
VM metadata, captures, fixture/profile/key/identity state, binaries and logs are
excluded. Root owns final flags, source/checkpoint/tag publication and any later
owned native experiment. Only this Markdown was written. Whitespace/newline
checks pass. Initial review frozen for Root's exact two-flag finalization.

## Final immutable publication audit

Initial formal review was frozen as SHA256
06973592bbe02837c8e101ee55ebc87ee0eece20fb31d7255fa8dfd1fd78864e
and supplied to Root before finalization. Comparing the retained initial JSON
object with the final object finds exactly two changed top-level fields:
candidate_provenance_review and preservation_baseline_review, each PENDING to
PASS. Every other nested value is identical. Final public JSON SHA256:

```text
11f5136ead82a14d54b03c9fa35febd8fa016821cfce8a0d491c6e60ae046a9d
```

Final progress.md SHA256:

```text
bf9c84f21aa534ab6c72ee6028033298992187633c64231a7eff1d1bb2bf1516
```

The original ledger prefix reproduces af7c4943c213b1b6fd58bfb74b97c1af5fa29e9b5c88c7e3521ffff704f239a7
exactly, with one separating newline before exactly one appended Digesthex
completion block. That block accurately refers to initial review06973592 and
the retained413/0/2 checks, candidate/artifact/preservation PASS and limited
observer/monitor manifest delta. It keeps native cost, Bootstrap and ARM NOT_RUN,
releasefalse, original398-406 and the no-native-savings/no-2s-fit boundaries.
Final audit precedes Root's intended source/checkpoint/tag publication.

Fresh read-only rehash checks after finalization find all203 current build inputs
and all203 unique source-archive regular files unchanged, with the same aggregate.
Candidate metadata, source archive, both payloads, both retained and current normal
contexts, both manifests, exact preflight executable/log, all public evidence-hash
references, retained test/fmt/Clippy logs, source diff, baseline template and
reconciliation, projection record and both unchanged baseline helpers retain the
initially audited hashes. No ELF/tar execution, build/test/helper or native action
was repeated. Since artifact bytes are identical, the complete initial static
ELF/strict-context inspection remains bound to this final publication audit.

Final publication scope remains exactly the reviewed worker source, two normal
program manifests, digest verification JSON, implementation report, independent
source review, this candidate review and append-only ledger. All target/private
artifacts, binaries, captures and identity/profile/runtime/resource state remain
outside that scope. Final public documents pass bounded credential-pattern and
whitespace/newline checks. Candidate/provenance, preservation and immutable public
scope/sensitivity are PASS with no findings. Native benefit, original two-second
fit, full Bootstrap/client/runtime/ARM and release acceptance remain unproved.
