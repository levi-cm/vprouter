# Allocation-comparison candidate, preservation baseline and public-scope review

2026-10-29. Independent read-only source/artifact/provenance/preservation and
publication audit. Only this Markdown written. No Git mutation, application edit,
build/test/benchmark, helper main, VM/SSH/Docker/privilege, profile/credential
contents, resource operation or subagent action. Root owns execution/publication.
Source-quality review7968a825 is separate and is not duplicated here.

**Candidate/provenance PASS. Preservation baseline PASS. Public scope/sensitivity
and final immutable metadata audit PASS. No open findings.** These are frozen-candidate and saved-evidence
verdicts, not native/performance/Bootstrap/client/runtime/release acceptance.
Original398-404 failures remain unaccepted; full8c ACTIVE, ARM runtime NOT_RUN,
native comparison effect NOT_RUN and release_ready=false remain binding.

## Exact source and one-file preservation binding

Candidate target/continuation-20261029T164255Z/candidate.json SHA256
93f833fabfd52351c3feb95dcbb6cf166a858f8196beb1e2a12a80b1acb7f310:

```text
source_commit 05238109d41e8ba4376e27c16aaa1bd41caffede
source_archive_sha256 c32d6c1bf51d888f89fb16fc34a66e7356d073ef263d357f64151a8ab0b644ed
tracked_build_inputs_verified 203
source_aggregate_sha256 4386b3a9d46ec99dee76c7dafb7cac6a04923c428bc60b0126af8576e3fdf43a
```

The archive hash matches actual source.tar. Its exact203 required build-input
paths, bytes and per-path SHA256 values independently match current files, the
immutable05238109 Git object and root-verification.json current_input_hashes.
The sorted path/NUL/digest/newline aggregate independently reproduces4386b3a9.
No extra, duplicate or missing input file is present. This is identity/provenance
checking, not an application source-quality re-review or fresh build.

Implementation report940b40b64a6b8d3a298368c14a113a0a9013927d4cd14c40f938b750e4320d70,
source review7968a825aa6cbe321cad4fe2578b1c688146b3a1ad3a0add36d9bc4500e4e80a,
owned.rs b14900907cba93637bed606130467bdf82dbb864da3e4953129dba1ffdb9b6c7
and frozen diff87b0f28892f304023b3c568d4349bbf6816097d9990a21a6d4706942cd89f010
all match retained bytes. Before/after maps contain the same179 Rust paths;
exactly owned.rs changed and all178 unowned paths remain equal. Every current
Rust path matches its after hash. Root source-verification.json independently
records that same result, SHA256
cea5c1fb85b2bf084be938900ceb3e7326098ee7149581a66eadfc46f09610b4.
The separate source review establishes the import/comparator/helper/test-only
reconstruction and actual Result/UTF8/raw-path semantics; this audit binds its
reviewed source to the frozen candidate rather than expanding its approval.

## Static payloads, normal contexts and retained checks

Root proof target/continuation-20261029T164255Z/root-verification.json SHA256
e32aa29a829ccbc0966dab2abe47d51747a4ae9dd8a0e8dcade274d35b0abee1
has the same source binding and following independently checked artifacts:

| Architecture | Static lab payload SHA256 | Normal context SHA256 |
| --- | --- | --- |
| amd64 | 4435526772afaf82ca584adde1ceadbdad4c710106bcac99c525580c21dcdce9 | f95434ea47702d720772ce10f5b23237c00f4e93837f8ddbcfb9d61711d7b9bc |
| arm64 | b8477ef81ff2e854c43a2a0cd10a29ba2911ee2bfa484bb4d8e43cbd87e1b90c | faf493db1398d974b1c806ea1750c241387650d1f47777ddc424d0d451bff992 |

Both payloads are ELF64 little-endian for their exact machine, with bounded valid
program headers, PT_LOAD and no PT_DYNAMIC/PT_INTERP. Retained context copies
match the current normal context bytes and candidate hashes. Independently
checking exact tar membership, uniqueness, regular-file/directory types,
uid/gid/mtime0, no links/PAX headers, exact modes, Dockerfile, CA certificate,
embedded manifest and all four executable hashes/sizes/static ELF headers yields
exactly seven files per context. Manifest digests are
20b80264a521c030c52af56ba8645b232b22c035ba46f3b71653cb1f7480f65a amd64 and
4d266ef01b48e33bc38ca3e49c94af9bb97d604fc640bf081bc4005432c9ff1b arm64.
Both manifests and context hashes remain those of the earlier4451c8a candidate;
this one-file lab change did not replace the normal gateway program inventory.

The exact amd64.filter-preflight executable hashes to the amd64 candidate payload.
Its retained log SHA256
908f3e39414afa23ff718dae4131f0be0da4249cad3be5eab5c2a2ef039326c4
matches Root proof and includes pending-core/ownership/IO boundary checks and
terminal exact-filter/native-deny PASS. This is saved local preflight evidence,
not a Bootstrap run or replay by this auditor. Root verifier303b231a and context
checker66be3dc0 hash fields match current helper bytes; no helper main ran here.

Root's fresh workspace log independently totals407 passed,0 failed,2 ignored
across27 result rows, matching workspace-summary.json; the launch suite row is
156/0. Workspace log SHA256
10aa5b1f19018be7ef827170d90a1a44ab75ad81bb496a415e7a0068c8a3d26a;
summarycb98ed8185a5fe50e34e185c0571d68950eb20858d97e7ca4a30c5ba0467e03f.
Root reports workspace formatting and strict workspace/all-targets Clippy PASS;
retained fmt output is empty and Clippy completes without warnings. Their hashes
are e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 and
7a211fc8ab1a0eb6a4970778df5684aee12d6747a65a186e693650ecd4ccb4b1.
Coherent-build log8ed87d20ee3df1d7389b055a9aac69ed6031a996b70b4ee7ce9531368f6b1a97
records both architecture builds/context hashes and exact source candidate.
These are retained Root executions, not new tests/builds by this reviewer.

## Read-only projection and exact preservation reconstruction

Saved projection record SHA256
3c76206fab19338a04d1787a2b7802ca77548f5b16eb6e411a92807d359cb98e
binds the current candidate source/payload and captured controller bytes. Captured
ssh.stdout equals its remote envelope; parsed remote stdout equals its report,
with empty stderr. Exact creator PID/start match the reaped non-root x86_64 child,
exit0/no timeout, namespace and route-socket identity,14 polls and original
requested_at+2s deadline with verification strictly before it. Read-only is true;
declaration/host-change authority, staging, production changes and private-profile
reads are false. These are checked saved Root observations, not a live VM check.

Fully read unchanged author-host-baseline-after-bootstrap-v2.py SHA256
67421abe95c77c793332044a5ab2ca95a751f4dc0d175211519fd7eb47ab9958
and host_baseline_declaration.py SHA256
367d2322ea841a81d9ec00006f7c38cf694300cffb77783e4f72903317d1a212
retain closed-shape/hash/binding checks and never adopt unexplained live values.
No helper was executed. Independent reconstruction started from the exact prior
56-link authored baseline and run404's saved canonical host_link history.
All four transport_sockets/pair/host_sockets/move entries have retained birth,
result and verified_at. Its exact final endpoint is veth vh77a3564e5240,
index180499957, DOWN; the original outer404 preservation record confirms that
single allowed addition and unchanged addresses/routes/rules/stable neighbors.

Appending only that complete canonical endpoint to the prior authored baseline
gives57 links/51 addresses/154 routes/5 rules. Namespace and complete row
multisets, including duplicate multiplicities, independently equal both saved
projection and new template. All fields come from the prior authored values or
exact canonical endpoint. Only order is aligned to the observed projection after
full multiset equality; no live field substitution or unexplained adoption occurs.
Addresses/routes/rules retain the prior multisets exactly.

New protected template SHA256
e7c41cd08192d10a56b9b8a9774ab26a4afbe8a4cb919a9281997c5d4b0d949f
and reconciliation SHA256
7ec60d8c491097dcbc0041eba3f65254cd31e8980f57d31cfb829dffce546cb8
are coherent with the current source binding. The canonical baseline digest is
e7a4ed7eefc052ea2558405e18b395c194243d21cb265b56ec37feab9e134a43.
All referenced prior template/reconciliation, original404 inspection/raw and
projection hashes match, as do prior evidence and helper references. Candidate
directory is0700; new template/reconciliation are0600. declaration_staged and
host_authority_granted remain false. No membership/removal/activation authority
or accepted native404 result is created by this foreign-preservation baseline.

Original404 rawb476430ff8ce442397bdde466df102bb9306bf999554099323a0702d0305efd1,
inspection7d58bdc2bf9d6153346427664ad8876831894626b0abb7d547e8d23f0ea3edfb
and completed exact-six archival receipt
42fd4d4f689773965123934430327590eff163d59c3229883d0c80adca187bac
remain hash-preserved. The new baseline does not rewrite that original56-link
input, change the failed result or recreate/clean up retained resources.

## Preliminary public scope and finalization boundary

Public docs/rust-v2/task8c-allocation-comparison-verification.json currently has
SHA256 cc10384541d29fd754b871db9c3e34b5cde3b5a9e49f1c93a42e762a16a06969.
Its binding, platform/artifact/context values, referenced evidence hashes,
57/51/154/5 counts and template/reconciliation hashes equal reviewed evidence.
Source review SPEC/QUALITY PASS and the local check counts agree with retained
records. candidate_provenance_review and preservation_baseline_review remain
PENDING in this preliminary version. Root may finalize those two flags from
this PASS, then obtain the requested immutable final metadata/ledger audit.

Current ledger SHA256
040b60d12184e685afb8f24044270ecfacc6e59c8610295be99e2b16199987e1
accurately records the offline/source/static/projection scope, earlier404FAIL and
pending final audit. It makes no native saved-budget or2s-fit claim. Public
native_bootstrap/runtime_cost_effect/arm64_runtime remain NOT_RUN and
release_ready=false; static/component PASS does not change those gates.
The host microbenchmark remains only a local mechanism result, without native
comparator-share or performance acceptance.

Reviewed publication scope is owned.rs, this bounded verification JSON, the
implementation report, source review, this provenance review and ledger. Earlier
safe benchmark/catalog/docs checkpoint446845b is Root-reported remote-confirmed;
this auditor performs no remote check or publication. Exact-source tag05238109
and checkpoint publication remain Root actions. Public source/doc changes were
contextually scoped and bounded credential-pattern checked; no embedded private
profiles/credentials were found. Raw target evidence, fixtures/binaries, VM
metadata/captures, profiles/keys/identity/runtime state and private artifacts are
excluded. No acceptance or resource authority is bundled into publication.


## Final immutable public metadata and ledger

Root subsequently finalized exactly the two review flags from PENDING to PASS.
Final public verification SHA256
161918dba699d71f290dc86fc6e908e17bbc9db0e5dfa327e89193f5199e4fd4
was compared against the preliminary JSON saved in this review session: only
candidate_provenance_review and preservation_baseline_review changed, and every
other field/value is identical. Final ledger SHA256
e145fc57b289cd9596f887a23989f2b15be4614008c3b2f162d9b1d77967dc32
preserves the exact earlier content and appends the bounded PASS/checkpoint
chronology. Its final paragraph retains nativecost/Bootstrap/ARM NOT_RUN,
releasefalse and no claimed budget/performance/acceptance fix.

Fresh final hash checks again match all203 current inputs, source archive,
public evidence references, both payloads/contexts and template/reconciliation.
The finalized public JSON and ledger remain within the reviewed sanitized scope.
The intended stage set remains owned.rs, public verification JSON, implementation
report, source review, this final provenance review and ledger. Private target
artifacts remain excluded. No additional source/resource/acceptance approval is
created by finalizing the metadata. Candidate/provenance, preservation baseline
and final public-scope audit PASS; no open findings. Root owns exact-source
05238109 tag, checkpoint publication and any later owned native experiment.
Final git diff --check passes. Review frozen for Root staging.
