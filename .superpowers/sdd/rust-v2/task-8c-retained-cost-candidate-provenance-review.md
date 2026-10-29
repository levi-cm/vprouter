# Retained-cost candidate provenance, preservation baseline and public scope

2026-10-29. Independent narrow read-only saved-candidate/evidence/preservation/
publication audit. Only this Markdown written. No application/tool source edit,
Git command, test/build/benchmark, helper main, VM/native/SSH/Docker/privilege,
profile/credential content, resource operation or subagent. Root owns execution
and publication. Source semantics/quality review95c85554 is separate; the prior
parser implementation and its independent review are not re-reviewed here.

**Candidate/provenance PASS. Preservation baseline PASS. Public scope/sensitivity
and final immutable metadata audit PASS. No open findings.** Initial two-flag
finalization chronology is retained below, followed by the completed final audit. These verdicts are not native performance,
Bootstrap/client/runtime/ARM/release acceptance. Original398-405 remain failed;
retained-cost native witness NOT_RUN, full8c ACTIVE and release_ready=false.

## Exact reviewed source and saved Root proof

Candidate target/continuation-20261029T170915Z/candidate.json SHA256
96854e572d72fdf8e7de6acf89d62c7a6214633cd9ce4ced3aba220394ddb7d3:

```text
source_commit 17c914f4d0d0bab8b206b71f843b8a7e0af784f8
source_archive_sha256 c022151af9eb96ca0d28f9ec7081a6149b24e0b55aa0698d92a5194db8687820
tracked_build_inputs_verified 203
source_aggregate_sha256 c2e1052c7a52bb9e4d506380914a0c459299b16e1a16ba833d6c26686c4c559c
```

Actual source.tar SHA256 matches. Its203 unique regular input files equal the
previously reviewed203-path set exactly; all bytes/hash values match current
files and root-verification.json current_input_hashes. Independently recomputing
the sorted path/NUL/digest/newline aggregate gives c2e1052c. No extra, duplicate
or missing source-archive input is present. Root's saved verifier supplies the
exact commit/Git equality assertion; this auditor independently checks retained
archive/current/hash identity and does not execute Git or a verifier main.

Root proof root-verification.json SHA256
1ffa8c4cf58a2d27ab2488110bcb3dc1c3beced0c0762ae3fa24b67ec6b925c5
has the same source binding. Implementation report
b806467156f42010c53cb39c258d5e589bdb91e17854f3ba8417206f22795893,
independent source review
95c8555457c937da461b02fd87bdd85665b53f020702eb21a86a839cbcb66fbc
and exact source.diff
941a4638993b585c87b464475c4e06dfccbcefbc922b2f4693b73d58489e351e
all independently match retained bytes.

Before/after maps and actual current filesystem contain exactly179 Rust paths.
All current hashes equal the frozen after snapshot
0fc869e607e2a987abeaff7724dee2824d0e25d448500f88967b2d5f162ff38d.
Exactly the five authorized paths changed;174 unowned paths remain equal and no
Rust path was added/deleted. Paths below are relative to crates/vprouter-launch/src:

| Owned path | Frozen current SHA256 |
| --- | --- |
| owned/preparation/quarantine.rs | f7ec6cddcf345ceacd26b448844d49598b8fe3cafd60f9cf0c785f3de20e0336 |
| owned/preparation.rs | 4ad1d063d86907e14ce8a2067f7c2baf231b0bfa6850d332c1b18bf1f1321369 |
| kernel/producer_creation.rs | 9f37b22c66f3e1bc9f66b93951a90caa95a1f100f1e56423ba34940ec1724e11 |
| attachment/quarantine/producer.rs | 34d66c2f7e91b1c7b0f35766a2c5360b69c048bb07d14f4508a10eda3c1ea018 |
| owned/preparation/lab_cost.rs | a7e5d4f832559d66d7cc6fa4193b2c82d051b4629850c0021ef47e5999601f68 |

The bound independent source review establishes cfg(test)-only diagnostic scope,
normal-source reconstruction, original State/Timer/13+30-row preservation and
new24 fixed rows. This audit binds that reviewed source to the candidate; it
adds no semantic or parser approval and no native witness.

## Static payloads, unchanged normal contexts and retained checks

| Architecture | Lab payload SHA256 | Normal context SHA256 |
| --- | --- | --- |
| amd64 | 90998682a45eca26370efd1c2d828da5b07c04ef1e729ddb0636cc11307482a5 | f95434ea47702d720772ce10f5b23237c00f4e93837f8ddbcfb9d61711d7b9bc |
| arm64 | 392c108d0be63ecde1a18efd6c826027c68d2081531048d9dc28b22b0725d27b | faf493db1398d974b1c806ea1750c241387650d1f47777ddc424d0d451bff992 |

Both actual payload hashes agree and independently have ELF64 little-endian
headers, correct architecture machines, bounded valid program headers, PT_LOAD
and no PT_DYNAMIC/PT_INTERP. Both retained contexts equal the current normal
contexts and the previously fully checked seven-file context bytes. Embedded
source manifest hashes remain20b80264a521c030c52af56ba8645b232b22c035ba46f3b71653cb1f7480f65a
amd64 and4d266ef01b48e33bc38ca3e49c94af9bb97d604fc640bf081bc4005432c9ff1b
arm64. Thus the existing exact seven-file membership, modes, identities,
Dockerfile/CA/manifest and static executable checks remain bound by identical
context bytes; normal gateway inventory was not replaced by this lab diagnostic.
Root's fresh strict-context results agree with that identity check.

The amd64.filter-preflight executable equals the exact amd64 payload. Its log
SHA2565b4566c463bd0508ccfbeffbed1577c8756c3a08fbf57aa30667e8866f4b1f80
matches Root proof and contains the exact-filter/native-deny terminal PASS.
Root verifier303b231a and context checker66be3dc0 hash fields match current helper
bytes. These are saved local preflight/proof results, not a Bootstrap execution
or helper replay by this auditor.

Root's workspace log independently sums410 passed,0 failed,2 ignored over27
result rows, including launch159/0. workspace-summary.json records workspace,
fmt and Clippy exit0; empty fmt and completed no-warning Clippy output agree.
Root reports strict workspace/all-targets Clippy scope. Retained log hashes under
 target/task8c-retained-cost-root-20261029 are:

```text
workspace-tests.log c899d8b3f3331688d1338dc02a786f77abdd7b8248535154dd29aabae2075080
workspace-summary.json 00c59adc2f1028c1add03906d9f44b802e26e1c0513da7450fe3ff209c9d5091
fmt.log e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
clippy.log da6be44cfb431d265b9f1f4eb01ba4f282447b96e86ac3563b37fd687915766b
root-coherent-build.log ee718e2f64c32e0999a5e37464c8f382bab9d443b05e43ddc36fc414f12ad684
```

Coherent-build output records both architecture builds/context hashes and exact
17c914f4 source candidate. These are retained Root executions, not fresh tests,
formatter, Clippy or builds by this reviewer.

## Read-only projection and exact58-link preservation reconstruction

Saved projection record SHA256
b37991493d8b0f0082a88b52fb9115a931292d7ceb697486a54256dc0a18580a
binds current candidate source/artifact and exact unchanged captured controller
bytes. Captured ssh.stdout equals its remote envelope; decoded remote stdout
equals the report, with empty stderr. Creator PID/start match the reaped non-root
x86_64 child, exit0/no timeout, namespace and14poll read provenance. Original
requested_at+2s deadline and strictly-before-deadline verification are retained.
Read-only is true; declaration/host-change authority, staging, production changes
and private-profile reads are false. This is saved Root evidence, not a live check.

The unchanged author-host-baseline-after-bootstrap-v2.py SHA256
67421abe95c77c793332044a5ab2ca95a751f4dc0d175211519fd7eb47ab9958
and host_baseline_declaration.py SHA256
367d2322ea841a81d9ec00006f7c38cf694300cffb77783e4f72903317d1a212
retain the previously reviewed exact reconstruction/closed-shape behavior.
Neither helper main ran. Independent reconstruction starts from405's original
57-link authored input and its exact canonical four-entry host_link history.
All transport_sockets/pair/host_sockets/move births/results/verifications remain.
The final canonical endpoint is veth vh1725555785a4,index1758018966,DOWN,
matching the complete saved endpoint and original outer405 allowed addition.

Appending only that complete endpoint to the prior authored values gives
58links/51addresses/154routes/5rules. Namespace and complete row multisets,
including duplicate multiplicities, independently equal the saved projection
and new template. Addresses/routes/rules equal their prior multisets. Only row
ordering aligns to the observed projection after exact multiset equality;
no live field or unexplained observed value is adopted.

New authored template SHA256
1286200c52685951f4d197b84b0e95d803cd4d569b4b35fa51c7f4b32bbf8c12
and reconciliation SHA256
716ffb9be9184532447f8aba72303f740060dcb65e0d3e3c2aded103d82fa9b5
bind the current source. Canonical baseline digest is
d69598292af0ce2f788a2bfae08060298e9eea0bccc01651db6c9edaa581f603.
All prior template/reconciliation,405 raw/inspection, projection and helper
references match retained bytes, as do prior evidence links. Candidate directory
is0700; new template/reconciliation are0600. declaration_staged and
host_authority_granted remain false. This is a foreign-preservation declaration,
not membership/removal/activation authority or an accepted405 result.

Original405 raw426dfae8b336943c7dcefe3e2bbae3b945568a44bf0d04f07f5869fdaf62ba1a,
inspection891951dab0260c7e61d0419b1f30424bca13f281ba8fc8d4ca16d9d121948fc0
and exact-six completed archival receipt
be9621acfe7ff32de3b6c0ffa1011c91bf8b665e3468a8d14f33b9c2d211cd3e
remain hash-preserved. The original failed record/57-link input is not rewritten;
all retained resources, credentials and identity state receive no new authority.

## Preliminary public metadata, sensitivity and remaining boundary

Public docs/rust-v2/task8c-retained-cost-verification.json SHA256
f586b795cf3e73c28c1e7c21de8b0a0e25d6b4c73e7fd02241858146a05b3f60
has exact reviewed source/platform/static/evidence bindings, local check counts,
58/51/154/5 baseline and template/reconciliation hashes. The source review
SPEC/QUALITY PASS and the5/174 reconstruction/13+30/24-row claims are bounded
by the exact independent source review. candidate_provenance_review and
preservation_baseline_review remain PENDING in this preliminary version.
Root may finalize those two flags from this report's PASS, then obtain the
requested immutable final metadata/ledger audit.

Current ledger SHA256
e509e021c809e913bcf719990d1bf61e0b62b635f296ed4392aa53b785b13c2b
accurately distinguishes source/static/local/projection checks from the pending
native retained-cost witness. Public native_bootstrap/runtime_cost_effect and
ARM runtime remain NOT_RUN; release_ready=false and original398-405FAIL remain.
Inclusive rows overlap and include observer/scheduling/error/partial-work effects;
none establishes CPU, exclusive cost, successful ACK count, optimization or2s fit.

The intended publication scope is the five reviewed Rust paths, retained-cost
verification JSON, implementation report, independent source review, this
provenance review and ledger. Previous parser/docs work remains separate from
this audit. Public docs/source diff were contextually scoped and bounded
credential-pattern checked; no embedded private profiles/credentials found.
Raw target evidence, projection/VM/canonical/runtime artifacts, fixture values,
profiles/keys/identity state, logs and binaries stay excluded from publication.
Only this Markdown was written. Root owns finalization, source/checkpoint/tag
publication and any subsequent owned native experiment. Whitespace/newline
checks on this review pass. Initial review frozen for Root's two-flag finalization.


## Final immutable metadata, ledger and publication scope

Root subsequently finalized exactly candidate_provenance_review and
preservation_baseline_review from PENDING to PASS. Final public verification
SHA2568122be5a02092ee31014ee1e399a90733be6fc996d4f6909b76888b4ea27b01b
was compared with the preliminary JSON saved in this review session. These are
the only two changed fields; every other value is identical. Final ledger SHA256
2b70922946cba2f653be3afdd11a44e43414031f7e67ba9a9efde9fdabadc1c4
preserves the exact earlier content and appends completion chronology referring
to this review's initial ce41945d freeze. Its final block retains cfg(test)-only
scope, nativecost/Bootstrap/ARM NOT_RUN, releasefalse and no native optimization,
live-check/deadline/authority change. It requires publication before a new VM run.

Fresh final hash checks again match all203 current inputs, source archive,
public evidence references, both payloads/contexts and template/reconciliation.
Only the review flags and ledger completion were finalized; no source/artifact/
baseline change is represented. The intended checkpoint remains exactly the five
owned Rust paths, retained-cost verification JSON, ledger, implementation report,
independent source review and this provenance review. Raw/private target data,
profiles/keys/captures/identity state, logs and binaries remain excluded.
No source or parser semantics review is duplicated and no runtime acceptance or
resource authority is added by this finalization.

Final public/ledger additions and this review remain within the bounded sanitized
scope; no embedded credential/private-profile patterns were found. Whitespace/
newline checks pass. Candidate/provenance, preservation baseline and immutable
final public scope PASS, with no open findings. Completed review frozen for Root
staging, exact-source17c914f4 tag/checkpoint publication and any later separately
controlled owned native experiment. No Git action was used for this audit.
