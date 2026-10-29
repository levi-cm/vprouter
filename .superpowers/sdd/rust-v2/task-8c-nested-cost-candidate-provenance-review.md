# Nested-cost frozen candidate, provenance and56-link preservation review

2026-10-29. Independent read-only candidate/artifact/evidence/publication audit.
Only this review written. No source edit,Git mutation,build/test/native execution,
VM/SSH/Docker/privilege,helper main,profile/credential contents or resource action.
No subagents. Root owns all execution,authoring,staging and publication.

**Candidate/provenance prerequisite: PASS. Protected preservation baseline: PASS.
Public scope/sensitivity prerequisite: PASS. No findings.** Separate source review
SPEC+QUALITYPASS is bound below,not duplicated. This diagnostic candidate has no
native nested-cost/Bootstrap acceptance; ARM runtime NOT_RUN,release_ready=false,
full8c ACTIVE. Original403FAIL and earlier failures/resources remain retained.
Final public flag/ledger verification follows in the addendum below.

## Frozen source and exact source-review binding

Candidate target/continuation-20261029T161134Z/candidate.json SHA256:
2ca4543108366b503a46d40c39e1e2e4e8f6e81460eab87262dda19749d36a98.

```text
source_commit 4451c8a75bcedcc330d4b59087a85f0bb5dca342
source_archive_sha256 4fc3b75ebc397c0857cdc83d9c20eb335f23ed23f1b648d6ce8b985a48f4abcf
tracked_build_inputs_verified 203
source_aggregate_sha256 4e28ac6571e0be8928ecc476aaf310120ba953b859b1c2c1f741763601f581e3
```

I independently enumerated the frozen commit's required build inputs with Git
read operations. Exactly203 unique bounded regular archive entries equal those
Git objects,current workspace bytes and the entire root-proof hash map. The
sorted name/NUL/hash/newline aggregate matches candidate and public binding.
No verifier/helper main was executed;equivalent read-only checks ran in memory.

Frozen implementation report SHA256
bcd7e6f0aa4afbb4111dc41ea5c7bb364502bd5bed033d687d3528d3a471b3a3;
separate source review SHA256
fa70e3e59b07465e7252d74f4f9d6523e9faa8a5f79bff3b18d551d944316862.
The retained complete source.diff SHA256 is
84efdde3f26dd1c184d961dce9afd793fa8d2f4e292be6aa02018a2d5c17c34f.
I independently rebuilt that exact diff from e213b39 base Git bytes/current
source and matched every byte,including the new support file. All178 pre-edit
Rust hashes match that base;all179 current Rust hashes match the frozen final
snapshot. Exactly five existing files plus new lab_cost.rs differ;the other173
Rust files remain identical. Each final owned hash matches the report and203
frozen inventory. Source semantics/exclusion/child-filter correctness remain the
separate source review's scope;this audit binds its exact bytes and claims.

## Artifacts, strict contexts and retained Root proof

| Architecture | Payload SHA256 | Context SHA256 |
| --- | --- | --- |
| amd64 | 649ab51fbafc89b58b783a41fc468d3f31c20288cfdd4712fd75d4ddfeaba860 | f95434ea47702d720772ce10f5b23237c00f4e93837f8ddbcfb9d61711d7b9bc |
| arm64 | 3e7bc79ddd96258f6cc1188676c3a86d38dd23670d6833260a015d063f1be35a | faf493db1398d974b1c806ea1750c241387650d1f47777ddc424d0d451bff992 |

Both actual payload hashes agree. Independent ELF64/little-endian/machine and
bounded program-header checks show LOAD and no dynamic/interpreter segments.
Both retained candidate-local contexts equal candidate-referenced current
contexts and the preceding candidate's normal-context hashes. Existing pure
strict context_check was invoked without any helper main:exactly7 public files,
all expected directories,pinned base/platform/daemon/CA,exact manifest and program
hashes/sizes,static ELF roles,archive modes/owners/time,no links/extras all PASS.
Manifest hashes remain unchanged:

```text
amd64 20b80264a521c030c52af56ba8645b232b22c035ba46f3b71653cb1f7480f65a
arm64 4d266ef01b48e33bc38ca3e49c94af9bb97d604fc640bf081bc4005432c9ff1b
```

Payloads,retained contexts and root proof are regular,current-author UID,
single-link0600. Candidate and projection directories are current-author0700.
Exact retained amd64 musl preflight copy equals payload and is0700.
Root-verification.json SHA256:
f11fb103fdc646a0ee93077f2cb9f5ed0e879ae7573a14f4063519e7e0cb9ad0.
Its source/platform/file/hash map matches independently checked evidence.

Unchanged builder SHA256
0b6afdae0761439900782a010ec1fa48e27b02037c0305c296cfe5483804fc58
executes the exact retained musl copy with --inspection-filter-selftest,
check=True and timeout30 before publishing the candidate. Preflight log SHA256
079eef51010c580066efa3a92a3bd4d76b4501b74831ef91059275ba6c652525
ends with the exact existing filter idle/request/native-deny PASS line.
Root reports successful coherent builder execution;that actor-reported execution
is bound to the exact copy,source and log,not inferred from log existence alone.
Coherent build log SHA256
5cd3a90f6509dd1041ccb3c48bff33a0aafef4bc15e812e8f90eaf5a0ab4b810.
This is a component preflight,not a native Bootstrap or real-client witness.

Unchanged root verifier SHA256
303b231a16aa1d697434570d8c4a8cf898b15818439bffd08969ba5c792d7ae9;
strict checker SHA256
66be3dc0ba17ec34e551a39f37218259af8df5d3eb996f9f7986f4bdf37b9635.
Retained Root launch-tests.log has152 individual ok records and152passed/0failed/
0ignored,SHA2562bd1ab21e9a0f4e5d43630f786bf3d346b9dd626e10f6f6b0293857b1fd18372.
Strict launch lib/tests Clippy completed,SHA256
a5f4c585ee974ca44916ac30a98bbc189e067a7e0a6bc6d2e8d6bc525be724af;
fmt.log is empty,consistent with Root's reported successful invocation. Empty log
alone is not exit-status proof. Root source-check.log equals the retained final
implementer verification log. No workspace-wide suite is claimed by these152.

## Read-only projection and preserved403 history

Projection record path:
target/continuation-20261029T161134Z/host-projection-debian-clean-x86_64/record.json.
SHA2562db41cf63c7502c1588f7d12e032ae526ba8ed72b1f4555ff494bc7642301707.
Captured controller unchanged SHA256
687ed1627b0a5f1efac5d1a90be283ac185d8e5710b46646c57e2e7b6a9e08af.
I extracted only pure envelope-validation definitions,not its executable main.
Saved ssh.stdout equals remote envelope,ssh.stderr is empty,and validated report
matches exact remote stdout. Original PID/start,reaped bounded success,machine,
route socket/namespace and original2s observation order PASS. Exact candidate
source/artifact/platform binding agrees. Read_only=true;declaration/HOST-change/
production/private-profile authority remains false.

Prior input directory is
continuation-20261029T153856Z/bootstrap-helper-diagnostic-20261029 under target.
Its55-link template SHA256c2aacc8f867f358e2d149d9521630bff62d17ff98f29de87040e17077227f8af
and review8f89c5db097744b4d91cedf0e09272ae73a3e8f6686790c944e803511a278b69
bind to exact raw4038e63c00123fca75a1fbf8347566fd226e794cfd214a87c0e1b7f085654901241
and inspection80ad66bd3d10804cdde2b3adea39ba925332cf1ca6ea4832c73075f1fca05431.
Full directory/source/artifact/platform bindings and old prior-evidence hashes
agree. Original403 remains FAIL/exit1/secret_bootstrap_success,absent owner and
no owner cgroup. Its complete four-phase canonical host-link history has original
birth/result/verified fields and exact final veth/DOWN endpoint:

```text
name vh7bd6c60869d0
index 1542016454
```

Whole endpoint fields,name/index and original outer single-DOWN-link/preserved
address/route/rule/stable-neighbor booleans agree. I copied the entire prior55-link
baseline and appended only that exact whole endpoint after rejecting name/index
collision. No projection field contributed to expected state.

```text
expected links56 addresses51 routes154 rules5 namespace[4,4026531840]
unaligned expected digest
225d67e913f23fe383e8d8b422f286735b91785f96fc313f7e3a6911b1ade1d9
```

Full expected/projection/new-template multisets,including duplicates,PASS.
Independent order alignment consumed only equal original expected rows;final
baseline digest004804503fe1c768dbea413949acfab2d3ae5bc7f5ad11765a00bd90619e4460
differs solely by ordering. Strict old/new template and expected shape validation
PASS. The new protected regular current-author single-link0600 outputs are:

```text
authored-host-baseline-debian-clean-x86_64.json
fcef34276439e5df3e7426cc9122a0a8f7930bc0d8fd68c64af2f3a22210bb4e
host-baseline-reconciliation-debian-clean-x86_64.json
8fd30944cf82311c5782ec04b7109aea7cb490f40f47820e95676abad73b1de8
```

Exactly5 matching relative target/*.json references contain no traversal and bind
prior captured template/review,inspection/raw403 and new projection. Actual hashes,
counts,namespace,new source/platform and template review hash agree. Unchanged v2
helper67421abe95c77c793332044a5ab2ca95a751f4dc0d175211519fd7eb47ab9958
and schema367d2322ea841a81d9ec00006f7c38cf694300cffb77783e4f72903317d1a212
match actual approved bytes. Reconstruction/alignment/preservation flags are true;
declaration_staged/live_fields_substituted/host_authority_granted remain false.

Original403 exact-six archival receipt SHA256
1899f4010aa7b68e339d0864768eef1b73b32c5fa8e74a38a981ac86b44d3a32
remains unchanged,with exact six same-nonce destinations,original raw/source/
absent owner and all other fixture resources retained/no private read/signals/
unmounts. Prior preservation review bdd94512539ad8b2e78c51bd059b8e06c09b516ad53a3c081581179a7fbdec10
remains bound. These are saved Root resource observations,not a new auditor live
recheck. No removal/membership/activation/new owner authority is conferred.

## Preliminary publication scope and limits

The current public JSON/source report/review/ledger bind the exact evidence above.
At preliminary review,public candidate_provenance_review and preservation_baseline_review
were honestly PENDING. I issued prerequisite PASS so Root may finalize only those
flags and its current ledger audit milestone. Six-path source and new support
file match the frozen reviewed diff;no raw private target/log/profile/key/state
publication is in this scope. Bounded sensitivity patterns and contextual reading
of public report/review/JSON/ledger found no embedded credentials/private profiles.

Diagnostic statements retain closed30-row inclusive categories,overlapping costs,
lab-loop-entry grouping rather than inner phase,and parent/COW-private child
observer overhead. No exact CPU,dominant mechanism,speedup,cache approval or
sufficient2s budget claim is accepted. Final public hash/flags follow below.
No source/runtime acceptance promotion or privileged action is approved here.

## Final immutable public flags, ledger and publication scope

**Final candidate/provenance/preservation/public scope+sensitivity: PASS.
No findings.** Root finalized the two review flags. Public JSON SHA256 is now
127a2f260e22b206473d2ec2eade07729520ca6a553d931aacb982be276b994f.
I independently reversed only those two values to PENDING and reproduced the
exact preliminary8173d9f16c91bf275a02d31322399257bc543f4c13709b0f73cadbbc9377a538
hash. No other public field changed. All evidence/platform/baseline hashes and
all203 current source bytes were rechecked after finalization. Source review,
provenance and preservation flags are PASS;native_bootstrap and arm64_runtime
remain NOT_RUN,release_ready=false.

Final ledger SHA256
648fe1997b68051835f5a6ae48149a44e9d5500330a4e617b3003357a3807d7e
accurately records the independently reviewed candidate/component checks,
protected56-link expectation,diagnostic-only scope,no semantic optimization and
no new runtime authority. Prior pending chronology is followed by explicit final
PASS. Full8c ACTIVE/original failures and acceptance boundaries remain intact.

Root's intended explicit publication scope is the six exact reviewed source
paths,new public verification JSON,implementation report,separate source review,
this final audit and ledger;only the exact4451c8a source tag is in the stated
checkpoint scope. Target artifacts/logs,raw private runtime evidence,profiles,
keys and state are excluded. Bounded sensitivity patterns and contextual public
review of those source/report/JSON/ledger bytes found no embedded credentials or
private profiles. This audit performs no staging,commit,tag,push or external write.

Normal contexts/manifests remain unchanged. Component/static/source-review PASS
does not prove the filtered child paths in a real new Bootstrap run,all scopes,
clients,runtime,performance,migration,reboot or release. Inclusive nested metrics
remain overlapping and observer-affected. Final `git diff --check` passes.
This report and the exact final public evidence above are frozen for Root staging.
