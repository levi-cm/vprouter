# Ancestry candidate final provenance and preservation review

2026-10-29. Independent narrow read-only source/artifact/controller/provenance
audit; only this report written. No Rust semantic review/edit, build/compiler/
filter/payload execution, author/verifier main, VM/SSH/Docker/privilege, profile/
credential contents, resource action, Git mutation or subagent operation.

**Final prerequisite verdict: PASS, no findings, for the exact frozen candidate,
read-only projection and protected54-link baseline below.** Separate source
SPEC+QUALITYPASS remains the semantic approval. Root may proceed with the existing
isolated synthetic runner and all fresh refusal gates. No native Bootstrap,
runtime/client/full8c/release acceptance is granted by this prerequisite audit.

## Frozen202-input source/current/Git binding

Candidate `target/continuation-20261029T141400Z/candidate.json`,SHA256
`7c564cbc6870346c7179f218b80ab138886545ef01710ad14a198baeae697081`:

```text
source_commit ab20f1d7ce5f366da327c7b0193a489810cb67a8
source_archive_sha256 7e284b0dbd88a935cc55cee9a0328588541c15647b6e8ffe855fae7b5a542ffb
tracked_build_inputs_verified 202
source_aggregate_sha256 e7bf990e30d3c36c3cfd3f25eb110692f62a6c4b5d1b3bc9ef08e2dc9c62c6f3
```

The existing read-only frozen-input verifier independently compares all202
archive inputs to Git at that exact commit and returns candidate.binding exactly.
I separately compared all202 archived files to current workspace bytes and
recomputed their SHA256 map: exact equality with root proof current_input_hashes.
Top-level source commit/archive hashes and complete candidate/proof binding agree.
No HEAD/index/ref or source was mutated.

## Static artifacts, strict contexts, retained proof and preflight

| Arch | Payload SHA256 | Context SHA256 | Source manifest SHA256 |
| --- | --- | --- | --- |
| amd64 | 82e0e3b644794540798a9a050dc404b5d7aad8627a2f17320e42fb4357703199 | f95434ea47702d720772ce10f5b23237c00f4e93837f8ddbcfb9d61711d7b9bc | 20b80264a521c030c52af56ba8645b232b22c035ba46f3b71653cb1f7480f65a |
| arm64 | a7ea79217aa8bb1e6431a5284cf106c6597b2651114fafcd1ec66e4469745214 | faf493db1398d974b1c806ea1750c241387650d1f47777ddc424d0d451bff992 | 4d266ef01b48e33bc38ca3e49c94af9bb97d604fc640bf081bc4005432c9ff1b |

Both actual candidate-referenced payloads hash-match candidate/proof and pass
independent ELF64/machine62-or183/bounded-program-header/load/no-dynamic-or-
interpreter checks. Both retained candidate-local contexts byte-equal the
candidate-referenced paths and hashes. The existing strict pure checker validates
exact seven public files, no links/extras, fixed archive uid/gid/mtime/modes,
pinned base/platform/daemon/CA/source manifest hashes/sizes and static ELF. Its
returned manifest/file counts equal proof. Payload/context/proof files are
regular,current-author-UID,single-link,mode0600; candidate directory mode0700.

Root proof SHA256:
`404f3e78d05537a9f531f73f67d15cc1db4e53febf7357fcac852ad575f72493`.
Actual verifier303b231a... and context-checker66be3dc0... hashes match proof and
the unchanged previously reviewed tools. Root artifact summary matches binding/
platform fields. Root proof remains native_bootstrap/arm64_runtime=NOT_RUN and
release_ready=false. Strict duplicate-key/nonfinite-rejecting JSON decoding was
used for candidate/proof/projection/templates/reconciliation.

The unchanged builder SHA256
`0b6afdae0761439900782a010ec1fa48e27b02037c0305c296cfe5483804fc58`
executes the exact retained musl amd64 copy with --inspection-filter-selftest,
check=True and timeout30 before candidate publication. Actual copy hash equals
the new amd64 payload. Preflight log SHA256 matches proof:
`b6ac05a06b1f81cea93d3cb3984ed23ee78cf0e8f16fba75d9ff6c9918a5538b`;
its final line is the exact frozen-source filter PASS. Coherent build log SHA256
`39383d3500c10aa84b0d005adbe19ee931123f4fab9868345c9f363cb92131fe`
ends with this exact new candidate/commit. Root observed actual builder exit0;
the audit binds that actor-reported execution to reviewed check=True source and
actual copy/log bytes, not mere logfile existence. It does not infer Bootstrap
success, ARM runtime or installed ancestry-role filter success from the preflight.

Retained Root workspace summary totals399passed/0failed/2ignored; fmt log is
empty and strict Clippy log records completion. These are inspected saved Root
evidence, not auditor-run tests/builds/filter execution.

## Exact read-only projection and reconstructed preservation history

Projection record SHA256
`94f622ad162b7c09644e061d7854adb2108e568806696c0096f26c1aa9fb9689`
binds the exact candidate source/amd64 artifact/Debian-clean platform. Its actual
retained controller is unchanged SHA256
`687ed1627b0a5f1efac5d1a90be283ac185d8e5710b46646c57e2e7b6a9e08af`.
Saved ssh.stdout decodes exactly to remote,ssh.stderr is empty; extracted pure
envelope validation accepts original PID/start,reaped success,bounds,namespace/
route-socket shape,request/verification/deadline ordering and original two-second
window. Validated remote stdout equals captured report. read_only=true and
declaration/HOST/production/private-profile authority flags are false.

Previous run directory is
`target/continuation-20261029T134857Z/bootstrap-pending-progress-20261029`.
Its directory binding, raw401 hash40a6ca6c...,inspectioncd827898...,captured
53-link templatec119742f... and reconciliation4f9a8723... exact hash/source/
platform chain and every original prior_evidence hash pass again. The four
durable canonical HOST histories retain their full final known veth/DOWN endpoint
`vh7828b913cc58`,index1243536425, matching original outer exact name/index and
single-DOWN-addition/address/route/rule/neighbor-preservation observations.

I independently deep-copied that whole prior53-link authored input, rejected
name/index collision and appended only the complete known canonical endpoint.
No new observed value supplied expected state. Unaligned expected digest remains
`fb0ba09a1ab43a64f2162a4f63b5a193ede2553e01648b9d4bf200de9a749f8f`.
Expected history/new projection/generated baseline have equal complete multisets,
including duplicates:54links/51addresses/154routes/5rules,namespace[4,4026531840].
Independent order alignment selects/removes only equal original expected rows
and reproduces the complete generated baseline; digest difference is ordering
alone, not live-field substitution or adoption.

| Protected generated output | SHA256 |
| --- | --- |
| authored-host-baseline-debian-clean-x86_64.json | 2f9ae1315cd3a99b3ea07979209b1d4eb6af2042ba2632a809ea4a177dff764b |
| host-baseline-reconciliation-debian-clean-x86_64.json | 58af37a2c5d37e7e94bbd1dc17691c7f5ed9b9c28a1c02c94c7a046f06e795fd |
| canonical final baseline | 40ed104caf399f3c0fffd11a876c2d38c8c9983d722c80e531400d681b84651c |

Both generated files are bounded regular,current-author-UID,single-link,mode0600.
Strict old/new template shape/source/platform checks pass. Template review hash,
reconciliation source/platform/namespace/counts/digest/whole durable endpoint agree.
Exactly five references equal template.prior_evidence/review.references: captured
prior template/review,inspection/raw401,new projection; relative target/*.json,
no traversal,actual hashes all pass. Actual v2helper67421abe... and schema367d2322...
hashes equal approved values; helper is unchanged. Durable-endpoint metadata is
accurate, reconstruction/alignment/preservation flags true and declaration_staged/
live_fields_substituted/host_authority_granted false. Disk fields still do not
prove parent ACK or grant membership/removal/new owner authority.

## Exact public scope, evidence claims and sensitivity

**Public scope/sensitivity verdict: PASS** for the exact source increment's
report/review package, this provenance report, generated two public program
manifests, public ancestry verification and component-only ledger milestone.
The three actual source hashes match the frozen reviewer inventory; actual
review.diff equals current exact three-path ten-context-line diff from semantic
basee986cfda...,SHA256
`74c2c9c8b7c3ceff607bee543313532749f59c32cafd3573e936861655041519`.
This is byte/provenance confirmation, not a duplicate semantic review.

Both generated program manifests change **only** program SHA256/byte-size values
against HEAD; all other policy/base/path/role/architecture fields are unchanged.
They are the exact frozen hashes validated by strict contexts above. All293
archived public controller files still match manifest sizes/hashes and their
target originals byte-for-byte; the recovery/tooling archive is preserved.

Final `docs/rust-v2/task8c-ancestry-verification.json`,SHA256
`07fa39355170b552a954e6a5a0ddd9400238f282cc36921aed3a0db94a0fb38d`,
matches exact source/platform/root proof and actual evidence hashes. Separate
source/provenance/baseline verdicts and read-only projection are PASS; exact54/
51/154/5/template/review hashes and authorityfalse agree. Native Bootstrap/ARM
runtime remain NOT_RUN,release_ready=false. Ledger explicitly limits milestone
claims to source/component/static evidence/full8c ACTIVE and preserves401FAIL.

Complete implementer/reviewer documents distinguish real borrowed-FD comparisons
and interpreted actual-generated BPF from full cgroup2 admission/installed role
filter/native-chain validation. Their own NOT_RUN statements remain historical
actor-specific evidence, not contradicted by later Root component builds. Root's
new execution cannot retroactively prove the exact old401 executed-return trace.
Bounded credential-pattern search and contextual reading of these publication
paths found no embedded credentials/private profiles/raw private artifacts.
Only the explicit public source/test/docs/review/provenance/manifests/ledger
scope belongs in the checkpoint. Root alone stages and publishes it.

Final `git diff --check` passes. No prerequisite blocker remains for the exact
new frozen isolated invocation with all fresh collision/selector/owner/original-
gateway/clock/preservation gates. No identical-payload retry, cleanup, resource
adoption, membership/removal/activation or broad acceptance authority is granted.
Original398/399/400/401 remain preserved FAIL; full8c remains ACTIVE.
